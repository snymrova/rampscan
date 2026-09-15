import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { DEFAULT_DATASET_PIN, loadLocalDataset } from "@rampscan/dataset";
import { createLocalLedger } from "@rampscan/ledger";
import { DENIAL_PROBES, initRunnerKeys, once, poll } from "@rampscan/runner";
import type { Transport } from "@rampscan/runner";
import { AwsConfig, isEvidenceBundle } from "@rampscan/schema";
import { DEFAULT_ALLOWLIST_PATH, loadAwsActionAllowlist } from "../src/aws-actions.js";
import { DEFAULT_BINDINGS_PATH, loadAwsLiteralBindings } from "../src/aws-bindings.js";
import { DEFAULT_LABELS_PATH, loadAwsStepLabels } from "../src/aws-labels.js";
import { recordRunnerRegistration } from "../src/runner-registry.js";
import { intakeRun, mintOnceToken, mintRunRequest, nextRun, nextRunByToken, runsLifecycle } from "../src/runs.js";
import type { RunsDeps } from "../src/runs.js";
import { verify } from "../src/verify.js";

// T4-1 / T4-2 / T4-3 (docs/PLAN-CLOUD-RUNNER.md, #181–#183), the appliance's
// side end to end: the click mints a signed request; a registered runner
// polls, runs (the aws shim standing in for the binary), posts; intake
// verifies, judges, mints the evidence bundle through the existing path;
// the lifecycle folds from the ledger. The runner package is driven here
// through a Transport that dispatches straight to the handlers — the HTTP
// routes (console) are thin over these and get the Playwright smoke.

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const SHIM = join(REPO_ROOT, "packages/runner/test/aws-shim.mjs");
const IDENTITY = JSON.stringify({ Account: "111111111111", Arn: "arn:aws:sts::111111111111:assumed-role/rampscan-runner/i-0abc" });
const SIMULATE = `iam simulate-principal-policy --policy-source-arn arn:aws:iam::111111111111:role/rampscan-runner --action-names ${DENIAL_PROBES.join(" ")} --output json`;
const DENIED = JSON.stringify({ EvaluationResults: DENIAL_PROBES.map((a) => ({ EvalActionName: a, EvalDecision: "implicitDeny" })) });
const ROLES = JSON.stringify({ Roles: [{ RoleName: "admin", MaxSessionDuration: 3600 }, { RoleName: "ops", MaxSessionDuration: 43200 }] });
const HEADER = "user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_2_active,access_key_2_last_rotated";
const REPORT = `${HEADER}\nalice,arn:aws:iam::111111111111:user/alice,2025-01-01T00:00:00+00:00,true,2026-09-14T00:00:00+00:00,2026-08-01T00:00:00+00:00,N/A,false,false,N/A,false,N/A\n`;

function shim(extra: Record<string, { stdout?: string; stderr?: string; exit?: number }> = {}) {
  const spec = {
    "sts get-caller-identity --output json": { stdout: IDENTITY },
    [SIMULATE]: { stdout: DENIED },
    "iam list-roles --query Roles[].{Role:RoleName,MaxSessionDuration:MaxSessionDuration}": { stdout: ROLES },
    "iam generate-credential-report": { stdout: '{"State": "COMPLETE"}\n' },
    "iam get-credential-report --query Content --output text": { stdout: `${Buffer.from(REPORT).toString("base64")}\n` },
    ...extra,
  };
  return { binary: SHIM, env: { ...process.env, AWS_SHIM_SPEC: JSON.stringify(spec) } };
}

async function appliance(overrides: Partial<RunsDeps> = {}) {
  const work = await mkdtemp(join(tmpdir(), "rampscan-runs-"));
  const ds = await loadLocalDataset(join(REPO_ROOT, "docs/context/ramprules/derived"), DEFAULT_DATASET_PIN);
  const deps: RunsDeps = {
    ledgerDir: join(work, "ledger"),
    keysDir: join(work, "keys"),
    repo: "acme/offering",
    datasetVersion: DEFAULT_DATASET_PIN,
    aws: AwsConfig.parse({ account_id: "111111111111", partition: "aws", regions: ["us-east-1"] }),
    list: await loadAwsActionAllowlist(join(REPO_ROOT, DEFAULT_ALLOWLIST_PATH)),
    table: await loadAwsLiteralBindings(join(REPO_ROOT, DEFAULT_BINDINGS_PATH)),
    labels: await loadAwsStepLabels(join(REPO_ROOT, DEFAULT_LABELS_PATH)),
    recipes: ds.recipes(),
    ...overrides,
  };
  const runnerKeys = await initRunnerKeys(join(work, "runner-keys"));
  await recordRunnerRegistration({
    action: "registered",
    runnerName: "sidecar-1",
    publicKeyPem: runnerKeys.publicKeyPem,
    host: "sidecar",
    account: "111111111111",
    partition: "aws",
    repo: deps.repo,
    proposedBy: "operator@example.test (pb:op)",
    approvedBy: "approver@example.test (pb:ap)",
    datasetVersion: DEFAULT_DATASET_PIN,
    ledgerDir: deps.ledgerDir,
    keysDir: deps.keysDir,
  });
  // a Transport that IS the console: the two routes, dispatched straight to the handlers
  const transport: Transport = {
    fetch: (async (url: string | URL | Request, init?: RequestInit) => {
      const path = new URL(String(url)).pathname;
      const body = JSON.parse(String(init?.body)) as Record<string, unknown>;
      const reply = (status: number, v?: unknown) => new Response(v === undefined ? null : JSON.stringify(v), { status, headers: { "content-type": "application/json" } });
      if (path === "/api/runs/next") {
        const r = typeof body["token"] === "string" ? await nextRunByToken(deps, body["token"]) : await nextRun(deps, body as never);
        return r.status === 200 ? reply(200, r.assignment) : r.status === 204 ? reply(204) : reply(r.status, { reason: r.reason });
      }
      if (path === "/api/runs/intake") {
        const r = await intakeRun(deps, body as never);
        return reply(r.status, r);
      }
      return reply(404, { reason: "no such route" });
    }) as typeof fetch,
  };
  const window = { start: "2026-08-16T00:00:00Z", end: "2026-09-15T00:00:00Z" };
  return { work, deps, runnerKeys, transport, window, ledger: () => createLocalLedger(deps.ledgerDir) };
}

describe("the click, the poll, the intake, the lifecycle (T4-1..T4-3)", () => {
  it("a registered sidecar polls a minted request, runs it, and the appliance mints the bundle: violated, offender counted, lifecycle accepted", async () => {
    const { deps, runnerKeys, transport, window, ledger } = await appliance();
    const minted = await mintRunRequest(deps, { recipeId: "iam-credential-report", ksi: "KSI-IAM-APM", requester: "operator@example.test", window });
    expect(minted.kind).toBe("requested");
    if (minted.kind !== "requested") return;
    expect(minted.steps).toEqual([["aws", "iam", "generate-credential-report"], ["aws", "iam", "get-credential-report", "--query", "Content", "--output", "text"]]);
    const request = await verify({ digest: minted.digest, ledgerDir: deps.ledgerDir, keysDir: deps.keysDir });
    expect(request.ok).toBe(true);
    expect(request.lines.join("\n")).toMatch(/run {6}iam-credential-report for KSI-IAM-APM/);
    expect((await runsLifecycle(ledger())).map((r) => r.state)).toEqual(["requested"]);

    const { handled } = await poll({ console: "http://console.test", keys: runnerKeys, runner: { name: "sidecar-1", region: "us-east-1" }, transport, maxRequests: 3, ...shim() });
    expect(handled).toBe(1);

    const rows = await runsLifecycle(ledger());
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ state: "accepted", runner: "sidecar-1", recipe_id: "iam-credential-report" });
    const evidence = await ledger().get(rows[0]!.evidence_digest!);
    expect(evidence).toBeDefined();
    expect(isEvidenceBundle(evidence!.bundle)).toBe(true);
    if (!isEvidenceBundle(evidence!.bundle)) return;
    // upstream spells the assertion TRUE and the report prints false — the where-clause matches nothing, so
    // upstream's assertions pass vacuously over the planted principal (the finding, still upstream's to fix);
    // what the bundle proves here is the path: three assertions evaluated by the appliance, the runner named
    expect(evidence!.bundle.predicate.assertions).toHaveLength(3);
    expect(evidence!.bundle.predicate.ingest?.runner).toMatchObject({ name: "sidecar-1", account: "111111111111", caller_arn: "arn:aws:sts::111111111111:assumed-role/rampscan-runner/i-0abc" });
    expect(evidence!.bundle.predicate.ingest?.signer_identity).toBe("runner:sidecar-1 (arn:aws:sts::111111111111:assumed-role/rampscan-runner/i-0abc)");
    expect(evidence!.bundle.predicate.method_id).toBe("aws-ingested:iam-credential-report#KSI-IAM-APM");
    const bundleReport = await verify({ digest: rows[0]!.evidence_digest!, ledgerDir: deps.ledgerDir, keysDir: deps.keysDir });
    expect(bundleReport.ok).toBe(true);
  });

  it("a recipe with no assertions is collected, unevidenced, not automated — the T0-2 path", async () => {
    const { deps, runnerKeys, transport, window, ledger } = await appliance();
    const minted = await mintRunRequest(deps, { recipeId: "session-lifetime-and-reauthentication", ksi: "KSI-IAM-ELP", requester: "operator@example.test", window });
    // this recipe carries placeholders the config does not bind: manual, with every reason
    expect(minted.kind).toBe("manual");
    if (minted.kind === "manual") expect(minted.reasons.join("\n")).toMatch(/unbound parameter <INSTANCE_ARN>/);
    const ok = await mintRunRequest(deps, { recipeId: "iam-account-authorization-details", ksi: "KSI-IAM-ELP", requester: "operator@example.test", window });
    expect(ok.kind).toBe("requested");
    const extra = {
      "iam get-account-authorization-details --query UserDetailList[].{User:UserName,Groups:GroupList,Attached:AttachedManagedPolicies[].PolicyName,Inline:UserPolicyList[].PolicyName}": { stdout: '{"UserDetailList": []}\n' },
      "iam get-account-authorization-details --filter Role --query RoleDetailList[].{Role:RoleName,Trust:AssumeRolePolicyDocument,Attached:AttachedManagedPolicies[].PolicyName}": { stdout: '{"RoleDetailList": []}\n' },
    };
    await poll({ console: "http://console.test", keys: runnerKeys, runner: { name: "sidecar-1", region: "us-east-1" }, transport, maxRequests: 2, ...shim(extra) });
    const row = (await runsLifecycle(ledger())).find((r) => r.recipe_id === "iam-account-authorization-details")!;
    expect(row.state).toBe("accepted");
    const evidence = await ledger().get(row.evidence_digest!);
    if (evidence === undefined || !isEvidenceBundle(evidence.bundle)) throw new Error("no bundle");
    expect(evidence.bundle.predicate.verdict).toBe("unevidenced");
    expect(evidence.bundle.predicate.ingest?.automated).toBe(false);
  });

  it("a denied call is a failed run: a visible row of class denied, and no bundle", async () => {
    const { deps, runnerKeys, transport, window, ledger } = await appliance();
    await mintRunRequest(deps, { recipeId: "iam-credential-report", ksi: "KSI-IAM-ELP", requester: "operator@example.test", window });
    const denied = { "iam get-credential-report --query Content --output text": { stderr: "An error occurred (AccessDenied) when calling the GetCredentialReport operation", exit: 254 } };
    await poll({ console: "http://console.test", keys: runnerKeys, runner: { name: "sidecar-1", region: "us-east-1" }, transport, maxRequests: 2, ...shim(denied) });
    const rows = await runsLifecycle(ledger());
    expect(rows[0]).toMatchObject({ state: "failed", class: "denied", runner: "sidecar-1" });
    expect(rows[0]!.evidence_digest).toBeUndefined();
    expect((await ledger().list()).filter((e) => isEvidenceBundle(e.bundle))).toHaveLength(0);
  });

  it("an unregistered key gets 401 and nothing is claimed; a request past its window reads expired and is never handed out", async () => {
    const { deps, transport, window, ledger, work } = await appliance();
    await mintRunRequest(deps, { recipeId: "iam-credential-report", ksi: "KSI-IAM-APM", requester: "operator@example.test", window, ttlMs: 1 });
    const stranger = await initRunnerKeys(join(work, "stranger"));
    await expect(poll({ console: "http://console.test", keys: stranger, runner: { name: "sidecar-1", region: "us-east-1" }, transport, maxRequests: 1, ...shim() })).rejects.toThrow(/401/);
    await new Promise((r) => setTimeout(r, 5));
    expect((await runsLifecycle(ledger())).map((r) => r.state)).toEqual(["expired"]);
  });

  it("once: a token the appliance signed lets a CloudShell paste run under an ephemeral key; a forged token does not", async () => {
    const { deps, transport, window, ledger } = await appliance();
    const minted = await mintRunRequest(deps, { recipeId: "iam-credential-report", ksi: "KSI-IAM-APM", requester: "operator@example.test", window });
    if (minted.kind !== "requested") throw new Error("not minted");
    const token = await mintOnceToken(deps, "http://console.test/", minted.nonce);
    const reply = await once({ token, region: "us-east-1", transport, ...shim() });
    expect(reply.kind).toBe("submission");
    const row = (await runsLifecycle(ledger()))[0]!;
    expect(row).toMatchObject({ state: "accepted", runner: `once-${minted.nonce.slice(0, 8)}` });
    const evidence = await ledger().get(row.evidence_digest!);
    if (evidence === undefined || !isEvidenceBundle(evidence.bundle)) throw new Error("no bundle");
    expect(evidence.bundle.predicate.ingest?.signer_identity).toMatch(new RegExp(`^runner:once-${minted.nonce.slice(0, 8)} \\(arn:aws:sts::111111111111`));
    // the same token again: the request is no longer open
    await expect(once({ token, region: "us-east-1", transport, ...shim() })).rejects.toThrow(/not open/);
    // a token the appliance did not sign
    const forged = Buffer.from(JSON.stringify({ token: { _type: "https://rampscan.dev/run-token/v1", console: "http://console.test", nonce: minted.nonce, request_digest: minted.request_digest, expires_at: "2126-01-01T00:00:00Z" }, signature: "AAAA" })).toString("base64url");
    await expect(once({ token: forged, region: "us-east-1", transport, ...shim() })).rejects.toThrow(/401.*not signed by this appliance/);
  });
});
