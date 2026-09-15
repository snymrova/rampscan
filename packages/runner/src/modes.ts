import { generateKeyPairSync } from "node:crypto";
import type { RunRequest } from "@rampscan/schema";
import { RUN_CLAIM_PAYLOAD_TYPE, canonicalJson, keyIdOf, signPayload, signTranscript } from "./keys.js";
import type { RunnerKeys, TranscriptEnvelope } from "./keys.js";
import { callerIdentity, runRequest } from "./run.js";
import type { ExecOptions, RunInput } from "./run.js";
import { DENIAL_PROBES, selfCheck } from "./selfcheck.js";

// The two hosts (docs/PLAN-CLOUD-RUNNER.md T3-4, T0-3): `poll`, the sidecar
// with a standing role and a registered key, asking the console for the
// next request and handing back the transcript; and `once`, the CloudShell
// one-shot for accounts that grant no standing role — one paste, a token
// minted for one request, an ephemeral key, the same run and the same
// intake. The wire shapes here are the contract T4-2's routes serve;
// nothing here evaluates anything.

/** what the console hands a runner for one request: the request, its digest, the argv the appliance classified */
export interface RunAssignment {
  request: RunRequest;
  request_digest: string;
  steps: string[][];
}

/** what `poll` signs to ask for work: proof of key possession, fresh */
export interface RunClaim {
  _type: "https://rampscan.dev/run-claim/v1";
  runner: string;
  requested_at: string;
}

/** what the runner posts to intake: the signed transcript, the bytes by digest, and for `once` the token */
export interface IntakePost {
  envelope: TranscriptEnvelope;
  /** the raw bytes each step printed, base64, by the digest the transcript names */
  outputs: Record<string, string>;
  /** `once` only: the token the console minted, and the ephemeral public key that signed the envelope */
  token?: string;
  public_key?: string;
}

export interface IntakeReply {
  kind: "submission" | "failed" | "refused";
  reason?: string;
  digest?: string;
}

/**
 * The one-shot token (`once`): minted by the console when a request has no
 * registered sidecar, carried in the pasted command. It names the console,
 * the request and its window; the console signed it with the appliance's
 * key, and intake accepts the transcript's EPHEMERAL key for this nonce and
 * nothing else. Base64url of the canonical JSON of `{ token, signature }`.
 */
export interface OnceToken {
  _type: "https://rampscan.dev/run-token/v1";
  console: string;
  nonce: string;
  request_digest: string;
  expires_at: string;
}

export function decodeOnceToken(encoded: string): { token: OnceToken; signature: string } {
  const json = Buffer.from(encoded, "base64url").toString("utf8");
  const parsed = JSON.parse(json) as { token?: OnceToken; signature?: string };
  if (parsed.token?._type !== "https://rampscan.dev/run-token/v1" || typeof parsed.signature !== "string") {
    throw new Error("not a run token");
  }
  return { token: parsed.token, signature: parsed.signature };
}

export interface Transport {
  fetch: typeof fetch;
}

async function post<T>(transport: Transport, url: string, body: unknown): Promise<{ status: number; body: T | undefined }> {
  const res = await transport.fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  const text = await res.text();
  return { status: res.status, body: text.length > 0 ? (JSON.parse(text) as T) : undefined };
}

/** sign the claim under the runner's key — its own payload type, never a transcript's */
function signClaim(claim: RunClaim, keys: RunnerKeys): TranscriptEnvelope {
  return signPayload(claim, RUN_CLAIM_PAYLOAD_TYPE, keys);
}

/** the run itself, shared by both modes: identity, self-check, steps, signature */
async function performAssignment(
  assignment: RunAssignment,
  runner: { name: string; region: string },
  keys: RunnerKeys,
  opts: ExecOptions & { skipSelfCheck?: boolean; log?: (line: string) => void },
): Promise<{ post: IntakePost; failed: number }> {
  const log = opts.log ?? (() => {});
  let self_check: RunInput["self_check"];
  if (opts.skipSelfCheck) {
    log("self-check SKIPPED — emulators only; the appliance refuses this unless configured for one");
  } else {
    const identity = await callerIdentity(opts);
    const check = await selfCheck(identity.arn, DENIAL_PROBES, opts);
    if (check.error !== undefined || !check.all_denied) {
      const allowed = Object.entries(check.decisions).filter(([, d]) => d === "allowed").map(([a]) => a);
      throw new Error(`refused to run as ${identity.arn} — ${check.error ?? `the role may ${allowed.join(", ")}`}`);
    }
    self_check = { probes: check.probes, all_denied: true };
  }
  const result = await runRequest(
    { request: assignment.request, request_digest: assignment.request_digest, steps: assignment.steps, runner, ...(self_check !== undefined ? { self_check } : {}) },
    opts,
  );
  const outputs: Record<string, string> = {};
  for (const [digest, bytes] of result.outputs) outputs[digest] = Buffer.from(bytes).toString("base64");
  const failed = result.transcript.steps.filter((s) => s.exit_code !== 0 || s.stderr_class !== "none").length;
  return { post: { envelope: signTranscript(result.transcript, keys), outputs }, failed };
}

export interface PollOptions extends ExecOptions {
  console: string;
  runner: { name: string; region: string };
  keys: RunnerKeys;
  transport?: Transport;
  /** stop after this many requests (tests, `--once-through`); undefined = until `stop()` */
  maxRequests?: number;
  intervalMs?: number;
  skipSelfCheck?: boolean;
  log?: (line: string) => void;
  now?: () => Date;
}

/**
 * `poll`: ask the console for the next request under the runner's key,
 * run it, post the transcript, repeat. Outbound only — the console never
 * reaches into the account. A refusal or a failed run is logged and the
 * loop goes on; only a key the console does not know stops it.
 */
export async function poll(options: PollOptions): Promise<{ handled: number }> {
  const transport = options.transport ?? { fetch };
  const log = options.log ?? (() => {});
  const now = options.now ?? (() => new Date());
  let handled = 0;
  while (options.maxRequests === undefined || handled < options.maxRequests) {
    const claim: RunClaim = { _type: "https://rampscan.dev/run-claim/v1", runner: options.runner.name, requested_at: now().toISOString() };
    const next = await post<RunAssignment | { reason: string }>(transport, `${options.console}/api/runs/next`, signClaim(claim, options.keys));
    if (next.status === 401 || next.status === 403) {
      throw new Error(`the console does not accept this runner's key (${next.status}): ${(next.body as { reason?: string } | undefined)?.reason ?? "not registered"}`);
    }
    if (next.status === 204 || next.body === undefined || !("request" in next.body)) {
      if (options.maxRequests !== undefined) break;
      await new Promise((r) => setTimeout(r, options.intervalMs ?? 30_000));
      continue;
    }
    const assignment = next.body;
    log(`request ${assignment.request.nonce.slice(0, 8)}… — ${assignment.request.recipe_id} for ${assignment.request.ksi}, ${assignment.steps.length} step(s)`);
    const { post: body, failed } = await performAssignment(assignment, options.runner, options.keys, options);
    const reply = await post<IntakeReply>(transport, `${options.console}/api/runs/intake`, body);
    log(`intake ${reply.status}: ${reply.body?.kind ?? "no reply"}${reply.body?.reason ? ` — ${reply.body.reason}` : ""}${failed > 0 ? ` (${failed} step(s) did not complete cleanly)` : ""}`);
    handled++;
  }
  return { handled };
}

export interface OnceOptions extends ExecOptions {
  token: string;
  region: string;
  transport?: Transport;
  skipSelfCheck?: boolean;
  log?: (line: string) => void;
}

/**
 * `once`: the pasted one-shot. Decode the token, fetch the assignment it
 * names, run under an ephemeral key, post transcript + token. The
 * appliance verifies its own signature on the token and accepts the
 * ephemeral key for that nonce alone.
 */
export async function once(options: OnceOptions): Promise<IntakeReply> {
  const transport = options.transport ?? { fetch };
  const log = options.log ?? (() => {});
  const { token } = decodeOnceToken(options.token);
  if (Date.parse(token.expires_at) < Date.now()) throw new Error(`the token expired at ${token.expires_at}`);
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const keys: RunnerKeys = { privateKey, publicKey, keyid: keyIdOf(publicKey), publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString() };
  const name = `once-${token.nonce.slice(0, 8)}`;
  const next = await post<RunAssignment | { reason: string }>(transport, `${token.console}/api/runs/next`, { token: options.token });
  if (next.status !== 200 || next.body === undefined || !("request" in next.body)) {
    throw new Error(`the console did not hand out the request for this token (${next.status}): ${(next.body as { reason?: string } | undefined)?.reason ?? "no assignment"}`);
  }
  const assignment = next.body;
  if (assignment.request.nonce !== token.nonce || assignment.request_digest !== token.request_digest) {
    throw new Error("the assignment does not match the token");
  }
  log(`request ${token.nonce.slice(0, 8)}… — ${assignment.request.recipe_id} for ${assignment.request.ksi}, ${assignment.steps.length} step(s), ephemeral key ${keys.keyid.slice(0, 12)}…`);
  const { post: body } = await performAssignment(assignment, { name, region: options.region }, keys, options);
  const reply = await post<IntakeReply>(transport, `${token.console}/api/runs/intake`, { ...body, token: options.token, public_key: keys.publicKeyPem });
  log(`intake ${reply.status}: ${reply.body?.kind ?? "no reply"}${reply.body?.reason ? ` — ${reply.body.reason}` : ""}`);
  return reply.body ?? { kind: "refused", reason: `no reply (${reply.status})` };
}

/** the token a console mints for `once` — offered here so tests and the console's route share one encoding */
export function encodeOnceToken(token: OnceToken, signature: string): string {
  return Buffer.from(canonicalJson({ token, signature })).toString("base64url");
}
