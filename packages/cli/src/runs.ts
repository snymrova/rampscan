import { createHash, createPublicKey, randomBytes } from "node:crypto";
import { toIngestedBundle } from "@rampscan/core";
import type { LedgerStore, SignedEnvelope } from "@rampscan/core";
import type { AwsRecipe } from "@rampscan/dataset";
import { bundleDigest, createLocalLedger } from "@rampscan/ledger";
import {
  IN_TOTO_STATEMENT_TYPE,
  RAMPSCAN_RUN_EVENT_TYPE,
  RAMPSCAN_RUN_REQUEST_EVENT_TYPE,
  RUN_REQUEST_TYPE,
  RUN_TOKEN_PAYLOAD_TYPE,
  RunTranscript,
  canonicalJson,
  isRunEvent,
  isRunRequestEvent,
  methodId,
  submissionVerdict,
} from "@rampscan/schema";
import type { AwsActionAllowlist, AwsConfig, AwsLiteralBindings, AwsStepLabels, RecipeAssertion, RunEvent, RunRequest, RunRequestEvent } from "@rampscan/schema";
import { createLocalDetachedSigner, createLocalSigner } from "@rampscan/signer";
import { applyLiteralBindings, bindAwsParams } from "./aws-bindings.js";
import type { RequestWindow } from "./aws-bindings.js";
import { classifyAwsRecipe, describeReason } from "./aws-classify.js";
import { stepLabels } from "./aws-labels.js";
import { requestDigest } from "./runs-intake.js";
import { intakeTranscript } from "./runs-intake.js";
import type { IntakeOutcome } from "./runs-intake.js";
import { runnerRegistry, verifyRunnerEnvelope, verifyRunnerTranscript } from "./runner-registry.js";
import type { RegisteredRunner } from "./runner-registry.js";

// The appliance's side of a run (docs/PLAN-CLOUD-RUNNER.md T4-1, T4-2,
// T4-3; SPEC §14.2, §14.2b): the click mints a signed RunRequestEvent; a
// runner claims it (`nextRun`) and hands back a transcript (`intakeRun`);
// every state change is a signed RunEvent. Ledger first, projection
// follows — the Runs page is `runsLifecycle` over these statements, never
// a row written by a route. Nothing here calls AWS.

export interface RunsDeps {
  ledgerDir: string;
  keysDir: string;
  repo: string;
  datasetVersion: string;
  aws: AwsConfig;
  list: AwsActionAllowlist;
  table: AwsLiteralBindings;
  labels: AwsStepLabels;
  recipes: readonly AwsRecipe[];
  /** emulator only: accept transcripts without a self-check (T3-3) */
  requireSelfCheck?: boolean;
  now?: () => Date;
  log?: (line: string) => void;
}

const sha256 = (text: string) => createHash("sha256").update(text).digest("hex");
const subjectOf = (name: string, text: string) => ({ name, digest: { sha256: sha256(text) } });

export interface MintRequestOptions {
  recipeId: string;
  ksi: string;
  requester: string;
  window: RequestWindow;
  /** how long a runner has to claim and finish; default one hour */
  ttlMs?: number;
}

export type MintOutcome =
  | { kind: "requested"; nonce: string; request_digest: string; digest: string; steps: string[][] }
  /** the recipe is manual under this config: every reason, the way `recipes --aws` prints them */
  | { kind: "manual"; reasons: string[] };

/**
 * T4-1: the click. Classify the recipe under the config and the request's
 * window; refuse with every reason if it is manual; otherwise mint the
 * request — nonce, window, bound argv, per-step transform and label — and
 * sign it into the ledger. Single-key: it requests a read.
 */
export async function mintRunRequest(deps: RunsDeps, options: MintRequestOptions): Promise<MintOutcome> {
  const recipe = deps.recipes.find((r) => r.id === options.recipeId);
  if (recipe === undefined) throw new Error(`no pinned recipe ${options.recipeId}`);
  if (!recipe.ksi_ids.includes(options.ksi)) throw new Error(`recipe ${options.recipeId} does not evidence ${options.ksi} (it names ${recipe.ksi_ids.join(", ")})`);
  const params = bindAwsParams(deps.aws, options.window);
  const bound = applyLiteralBindings(recipe, deps.table).recipe;
  const cls = classifyAwsRecipe(bound, deps.list, params);
  if (cls.kind === "manual") return { kind: "manual", reasons: cls.reasons.map(describeReason) };
  const now = (deps.now ?? (() => new Date()))();
  const request: RunRequest = {
    _type: RUN_REQUEST_TYPE,
    nonce: randomBytes(16).toString("hex"),
    recipe_id: recipe.id,
    recipe_digest: sha256(canonicalJson(recipe)),
    ksi: options.ksi,
    params,
    issued_at: now.toISOString(),
    expires_at: new Date(now.getTime() + (options.ttlMs ?? 3_600_000)).toISOString(),
    requester: options.requester,
  };
  const request_digest = requestDigest(request);
  const steps = cls.steps.map((s) => s.argv);
  const event: RunRequestEvent = {
    _type: IN_TOTO_STATEMENT_TYPE,
    subject: [{ name: `run-request-${request.nonce.slice(0, 8)}.json`, digest: { sha256: request_digest } }],
    predicateType: RAMPSCAN_RUN_REQUEST_EVENT_TYPE,
    predicate: {
      request,
      request_digest,
      steps,
      transforms: cls.steps.map((s) => s.transform ?? null),
      labels: stepLabels(recipe.id, steps, deps.labels),
      cadence: recipe.cadence,
      repo: deps.repo,
      dataset_version: deps.datasetVersion,
      timestamp: now.toISOString(),
    },
  };
  const signer = createLocalSigner(deps.keysDir, deps.log ? { log: deps.log } : {});
  const digest = await createLocalLedger(deps.ledgerDir).append(event, await signer.sign(event));
  deps.log?.(`run requested: ${recipe.id} for ${options.ksi} — nonce ${request.nonce.slice(0, 8)}…, ${steps.length} step(s), expires ${request.expires_at}`);
  return { kind: "requested", nonce: request.nonce, request_digest, digest, steps };
}

async function appendRunEvent(deps: RunsDeps, predicate: Omit<RunEvent["predicate"], "repo" | "dataset_version" | "timestamp">): Promise<string> {
  const now = (deps.now ?? (() => new Date()))();
  const event: RunEvent = {
    _type: IN_TOTO_STATEMENT_TYPE,
    subject: [subjectOf(`run-${predicate.nonce.slice(0, 8)}-${predicate.state}.json`, `${predicate.nonce}:${predicate.state}:${now.toISOString()}`)],
    predicateType: RAMPSCAN_RUN_EVENT_TYPE,
    predicate: { ...predicate, repo: deps.repo, dataset_version: deps.datasetVersion, timestamp: now.toISOString() },
  };
  const signer = createLocalSigner(deps.keysDir, deps.log ? { log: deps.log } : {});
  return createLocalLedger(deps.ledgerDir).append(event, await signer.sign(event));
}

export type RunState = "requested" | "claimed" | "submitted" | "accepted" | "refused" | "failed" | "expired";

export interface RunRow {
  nonce: string;
  recipe_id: string;
  ksi: string;
  requester: string;
  issued_at: string;
  expires_at: string;
  state: RunState;
  runner?: string;
  reason?: string;
  class?: string;
  evidence_digest?: string;
  /** the ledger digest of the request event — what `rampscan verify` reads */
  request_event_digest: string;
  updated_at: string;
}

/** T4-3: the lifecycle, folded — every request, its latest state, expired read from the clock */
export async function runsLifecycle(ledger: LedgerStore, now: Date = new Date()): Promise<RunRow[]> {
  const rows = new Map<string, RunRow>();
  const entries = await ledger.list();
  for (const e of entries) {
    if (!isRunRequestEvent(e.bundle)) continue;
    const p = e.bundle.predicate;
    rows.set(p.request.nonce, {
      nonce: p.request.nonce,
      recipe_id: p.request.recipe_id,
      ksi: p.request.ksi,
      requester: p.request.requester,
      issued_at: p.request.issued_at,
      expires_at: p.request.expires_at,
      state: "requested",
      request_event_digest: e.digest,
      updated_at: p.timestamp,
    });
  }
  const order: RunState[] = ["requested", "claimed", "submitted", "accepted", "refused", "failed"];
  for (const e of entries) {
    if (!isRunEvent(e.bundle)) continue;
    const p = e.bundle.predicate;
    const row = rows.get(p.nonce);
    if (row === undefined) continue;
    // a later state wins; a terminal state is never overwritten by an earlier one arriving late
    if (order.indexOf(p.state) >= order.indexOf(row.state) || p.timestamp > row.updated_at) {
      row.state = p.state;
      row.updated_at = p.timestamp;
      if (p.runner !== undefined) row.runner = p.runner;
      if (p.reason !== undefined) row.reason = p.reason;
      if (p.class !== undefined) row.class = p.class;
      if (p.evidence_digest !== undefined) row.evidence_digest = p.evidence_digest;
    }
  }
  for (const row of rows.values()) {
    if ((row.state === "requested" || row.state === "claimed") && Date.parse(row.expires_at) < now.getTime()) row.state = "expired";
  }
  return [...rows.values()].sort((a, b) => (a.issued_at < b.issued_at ? 1 : -1));
}

/** the lifecycle over a ledger directory — the console's read, which holds no ledger handle of its own */
export function runsLifecycleAt(ledgerDir: string, now: Date = new Date()): Promise<RunRow[]> {
  return runsLifecycle(createLocalLedger(ledgerDir), now);
}

export interface RunAssignment {
  request: RunRequest;
  request_digest: string;
  steps: string[][];
}

const CLAIM_PAYLOAD_TYPE = "application/vnd.rampscan.run-claim+json";
const CLAIM_FRESHNESS_MS = 5 * 60_000;

export type NextOutcome = { status: 200; assignment: RunAssignment } | { status: 204 } | { status: 401 | 403 | 404 | 400; reason: string };

async function requestEventByNonce(ledger: LedgerStore, nonce: string): Promise<{ event: RunRequestEvent; digest: string } | undefined> {
  for (const e of await ledger.list()) {
    if (isRunRequestEvent(e.bundle) && e.bundle.predicate.request.nonce === nonce) return { event: e.bundle, digest: e.digest };
  }
  return undefined;
}

/**
 * T4-2 `/api/runs/next` for `poll`: the claim's signature against a
 * registered key, then the oldest request still `requested` and inside its
 * window, recorded `claimed` by that runner before it is handed out.
 */
export async function nextRun(deps: RunsDeps, claim: SignedEnvelope): Promise<NextOutcome> {
  const ledger = createLocalLedger(deps.ledgerDir);
  const registry = await runnerRegistry(ledger);
  const verified = verifyClaim(claim, registry, (deps.now ?? (() => new Date()))());
  if (!verified.ok) return { status: 401, reason: verified.reason };
  const now = (deps.now ?? (() => new Date()))();
  const rows = (await runsLifecycle(ledger, now)).filter((r) => r.state === "requested").sort((a, b) => (a.issued_at < b.issued_at ? -1 : 1));
  const next = rows[0];
  if (next === undefined) return { status: 204 };
  const found = await requestEventByNonce(ledger, next.nonce);
  if (found === undefined) return { status: 204 };
  await appendRunEvent(deps, { nonce: next.nonce, state: "claimed", runner: verified.runner.name });
  const p = found.event.predicate;
  return { status: 200, assignment: { request: p.request, request_digest: p.request_digest, steps: p.steps } };
}

function verifyClaim(claim: SignedEnvelope, registry: ReadonlyMap<string, RegisteredRunner>, now: Date): { ok: true; runner: RegisteredRunner } | { ok: false; reason: string } {
  const v = verifyRunnerEnvelope(claim, registry, CLAIM_PAYLOAD_TYPE);
  if (!v.ok) return v;
  const parsed = v.payload as { _type?: string; runner?: string; requested_at?: string };
  if (parsed._type !== "https://rampscan.dev/run-claim/v1" || parsed.runner !== v.runner.name) return { ok: false, reason: "the claim does not name the key's runner" };
  const at = Date.parse(parsed.requested_at ?? "");
  if (Number.isNaN(at) || Math.abs(now.getTime() - at) > CLAIM_FRESHNESS_MS) return { ok: false, reason: "the claim is not fresh" };
  return { ok: true, runner: v.runner };
}

/** the `once` token (SPEC §14.2b), minted by the appliance for a request with no registered sidecar */
export interface OnceToken {
  _type: "https://rampscan.dev/run-token/v1";
  console: string;
  nonce: string;
  request_digest: string;
  expires_at: string;
}

export async function mintOnceToken(deps: RunsDeps, consoleUrl: string, nonce: string): Promise<string> {
  const found = await requestEventByNonce(createLocalLedger(deps.ledgerDir), nonce);
  if (found === undefined) throw new Error(`no request with nonce ${nonce}`);
  const token: OnceToken = { _type: "https://rampscan.dev/run-token/v1", console: consoleUrl.replace(/\/+$/, ""), nonce, request_digest: found.event.predicate.request_digest, expires_at: found.event.predicate.request.expires_at };
  const { sig } = await createLocalDetachedSigner(deps.keysDir).sign(RUN_TOKEN_PAYLOAD_TYPE, Buffer.from(canonicalJson(token)));
  return Buffer.from(canonicalJson({ token, signature: sig })).toString("base64url");
}

async function verifyOnceToken(deps: RunsDeps, encoded: string): Promise<{ ok: true; token: OnceToken } | { ok: false; reason: string }> {
  let parsed: { token?: OnceToken; signature?: string };
  try {
    parsed = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8")) as typeof parsed;
  } catch {
    return { ok: false, reason: "the token does not decode" };
  }
  if (parsed.token?._type !== "https://rampscan.dev/run-token/v1" || typeof parsed.signature !== "string") return { ok: false, reason: "not a run token" };
  const ok = await createLocalDetachedSigner(deps.keysDir).verify(RUN_TOKEN_PAYLOAD_TYPE, Buffer.from(canonicalJson(parsed.token)), parsed.signature);
  if (!ok) return { ok: false, reason: "the token was not signed by this appliance" };
  if (Date.parse(parsed.token.expires_at) < (deps.now ?? (() => new Date()))().getTime()) return { ok: false, reason: "the token has expired" };
  return { ok: true, token: parsed.token };
}

/** T4-2 `/api/runs/next` for `once`: the token, then the request it names, recorded `claimed` by `once-<nonce>` */
export async function nextRunByToken(deps: RunsDeps, encoded: string): Promise<NextOutcome> {
  const v = await verifyOnceToken(deps, encoded);
  if (!v.ok) return { status: 401, reason: v.reason };
  const ledger = createLocalLedger(deps.ledgerDir);
  const found = await requestEventByNonce(ledger, v.token.nonce);
  if (found === undefined || found.event.predicate.request_digest !== v.token.request_digest) return { status: 404, reason: "no such request" };
  const row = (await runsLifecycle(ledger, (deps.now ?? (() => new Date()))())).find((r) => r.nonce === v.token.nonce);
  if (row === undefined || row.state !== "requested") return { status: 404, reason: `the request is ${row?.state ?? "unknown"}, not open` };
  await appendRunEvent(deps, { nonce: v.token.nonce, state: "claimed", runner: `once-${v.token.nonce.slice(0, 8)}` });
  const p = found.event.predicate;
  return { status: 200, assignment: { request: p.request, request_digest: p.request_digest, steps: p.steps } };
}

export interface IntakePost {
  envelope: SignedEnvelope;
  outputs: Record<string, string>;
  token?: string;
  public_key?: string;
}

export type IntakeReply = { status: 200 | 401 | 404 | 422; kind: IntakeOutcome["kind"]; reason?: string; class?: string; digest?: string; verdict?: string };

/**
 * T4-2 `/api/runs/intake`: the envelope against the registry (or, for
 * `once`, the appliance's own signature on the token and the ephemeral
 * key for that nonce); the request the nonce names; `intakeTranscript`
 * over the bytes with the recipe's assertions, the request's transforms
 * and labels; then the ledger — the evidence bundle through the existing
 * mint on `submission`, a `failed` or `refused` RunEvent otherwise. The
 * nonce is spent either way: a second transcript for it is a replay.
 */
export async function intakeRun(deps: RunsDeps, post: IntakePost): Promise<IntakeReply> {
  const ledger = createLocalLedger(deps.ledgerDir);
  const now = (deps.now ?? (() => new Date()))();
  let transcript: RunTranscript;
  let runnerName: string;
  if (post.token !== undefined) {
    const v = await verifyOnceToken(deps, post.token);
    if (!v.ok) return { status: 401, kind: "refused", reason: v.reason };
    if (post.public_key === undefined) return { status: 401, kind: "refused", reason: "a once transcript carries the ephemeral public key that signed it" };
    const ephemeral: RegisteredRunner = { name: `once-${v.token.nonce.slice(0, 8)}`, keyid: keyIdOfPemLoose(post.public_key), publicKeyPem: post.public_key, host: "cloudshell one-shot", account: deps.aws.account_id, partition: deps.aws.partition, registeredAt: now.toISOString(), approvedBy: "token" };
    const verified = verifyRunnerTranscript(post.envelope, new Map([[ephemeral.name, ephemeral]]));
    if (!verified.ok) return { status: 401, kind: "refused", reason: verified.reason };
    if (verified.transcript.nonce !== v.token.nonce) return { status: 401, kind: "refused", reason: "the transcript is not the token's request" };
    transcript = verified.transcript;
    runnerName = ephemeral.name;
  } else {
    const verified = verifyRunnerTranscript(post.envelope, await runnerRegistry(ledger));
    if (!verified.ok) return { status: 401, kind: "refused", reason: verified.reason };
    transcript = verified.transcript;
    runnerName = verified.runner.name;
  }
  const found = await requestEventByNonce(ledger, transcript.nonce);
  if (found === undefined) return { status: 404, kind: "refused", reason: `no request with nonce ${transcript.nonce.slice(0, 8)}…` };
  const p = found.event.predicate;
  const recipe = deps.recipes.find((r) => r.id === p.request.recipe_id);
  const assertions = (recipe !== undefined && Array.isArray(recipe["assertions"]) ? (recipe["assertions"] as RecipeAssertion[]) : []);
  const spent = new Set((await runsLifecycle(ledger, now)).filter((r) => r.state === "accepted" || r.state === "failed" || r.state === "refused" || r.state === "submitted").map((r) => r.nonce));
  await appendRunEvent(deps, { nonce: transcript.nonce, state: "submitted", runner: runnerName });
  const outputs = new Map(Object.entries(post.outputs).map(([digest, b64]) => [digest, new Uint8Array(Buffer.from(b64, "base64"))]));
  const outcome = intakeTranscript(transcript, outputs, {
    request: p.request,
    account: deps.aws.account_id,
    partition: deps.aws.partition,
    assertions,
    transforms: p.transforms.map((t) => t ?? undefined),
    labels: p.labels,
    cadence: p.cadence as never,
    ...(deps.requireSelfCheck !== undefined ? { requireSelfCheck: deps.requireSelfCheck } : {}),
    acceptedNonces: spent,
    receivedAt: now.toISOString(),
  });
  if (outcome.kind === "refused") {
    await appendRunEvent(deps, { nonce: transcript.nonce, state: "refused", runner: runnerName, reason: outcome.reason });
    return { status: 422, kind: "refused", reason: outcome.reason };
  }
  if (outcome.kind === "failed") {
    await appendRunEvent(deps, { nonce: transcript.nonce, state: "failed", runner: runnerName, class: outcome.class, reason: outcome.reason });
    return { status: 200, kind: "failed", class: outcome.class, reason: outcome.reason };
  }
  const bundle = toIngestedBundle(outcome.submission, { repo: deps.repo, datasetVersion: deps.datasetVersion });
  const digest = bundleDigest(bundle);
  if ((await ledger.get(digest)) === undefined) {
    const signer = createLocalSigner(deps.keysDir, deps.log ? { log: deps.log } : {});
    await ledger.append(bundle, await signer.sign(bundle));
  }
  await appendRunEvent(deps, { nonce: transcript.nonce, state: "accepted", runner: runnerName, evidence_digest: digest });
  const verdict = submissionVerdict(outcome.submission);
  deps.log?.(`run accepted: ${methodId("aws-ingested", outcome.submission.recipe_id, outcome.submission.ksi)} → ${verdict} (${digest.slice(0, 12)}…) by ${runnerName}`);
  return { status: 200, kind: "submission", digest, verdict };
}

/** the keyid of an ephemeral key — any P-256 SPKI; a malformed key yields a keyid nothing will match */
function keyIdOfPemLoose(pem: string): string {
  try {
    return createHash("sha256").update(createPublicKey(pem).export({ type: "spki", format: "der" })).digest("hex");
  } catch {
    return "0".repeat(64);
  }
}

/**
 * The console's way in: every dependency from the environment `rampscan
 * serve` sets, the `aws` block from the served repository's config. A
 * repository with no `aws` block has no runner surface — the routes say so.
 */
export async function loadRunsDeps(env: {
  repoRoot: string;
  ledgerDir: string;
  keysDir: string;
  datasetDir: string;
  datasetPin: string;
  allowlistPath: string;
  bindingsPath: string;
  labelsPath: string;
  requireSelfCheck?: boolean;
  log?: (line: string) => void;
}): Promise<RunsDeps | { missing: string }> {
  const { loadAwsConfig } = await import("./aws-recipes.js");
  const { loadAwsActionAllowlist } = await import("./aws-actions.js");
  const { loadAwsLiteralBindings } = await import("./aws-bindings.js");
  const { loadAwsStepLabels } = await import("./aws-labels.js");
  const { loadLocalDataset } = await import("@rampscan/dataset");
  const aws = await loadAwsConfig(env.repoRoot);
  if (aws === undefined) return { missing: `no \`aws\` block in ${env.repoRoot}/rampscan.config.json — declare the account a runner observes before requesting a run` };
  const dataset = await loadLocalDataset(env.datasetDir, env.datasetPin);
  return {
    ledgerDir: env.ledgerDir,
    keysDir: env.keysDir,
    repo: env.repoRoot,
    datasetVersion: env.datasetPin,
    aws,
    list: await loadAwsActionAllowlist(env.allowlistPath),
    table: await loadAwsLiteralBindings(env.bindingsPath),
    labels: await loadAwsStepLabels(env.labelsPath),
    recipes: dataset.recipes(),
    ...(env.requireSelfCheck !== undefined ? { requireSelfCheck: env.requireSelfCheck } : {}),
    ...(env.log !== undefined ? { log: env.log } : {}),
  };
}

/** the recipes a KSI row can ask for: runnable under the config, or manual with reasons — what the button lists (T4-1) */
export function recipesForKsi(deps: RunsDeps, ksi: string, window: RequestWindow): Array<{ recipe_id: string; runnable: boolean; reasons: string[]; has_assertions: boolean }> {
  const params = bindAwsParams(deps.aws, window);
  return deps.recipes
    .filter((r) => r.ksi_ids.includes(ksi))
    .map((r) => {
      const cls = classifyAwsRecipe(applyLiteralBindings(r, deps.table).recipe, deps.list, params);
      return {
        recipe_id: r.id,
        runnable: cls.kind === "runnable",
        reasons: cls.kind === "manual" ? cls.reasons.map(describeReason) : [],
        has_assertions: Array.isArray(r["assertions"]) && r["assertions"].length > 0,
      };
    });
}
