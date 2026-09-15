import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { createLocalLedger } from "@rampscan/ledger";
import { initRunnerKeys, signTranscript } from "@rampscan/runner";
import type { RunTranscript } from "@rampscan/schema";
import { createLocalSigner } from "@rampscan/signer";
import { keyIdOfPem, recordRunnerRegistration, runnerRegistry, verifyRunnerTranscript } from "../src/runner-registry.js";
import { verify } from "../src/verify.js";

// T3-2 (docs/PLAN-CLOUD-RUNNER.md, #177), the appliance's half: the fourth
// two-key write, the registry it folds to, and the first check on a
// transcript — its signature against a registered key. The runner package
// is imported here, in a test, to sign what the appliance then verifies;
// the boundary test keeps the direction one-way in src.

const TRANSCRIPT: RunTranscript = {
  _type: "https://rampscan.dev/run-transcript/v1",
  request_digest: "0".repeat(64),
  nonce: "5f2c9a1e7b3d4c6a8e0f1a2b3c4d5e6f",
  recipe_id: "iam-credential-report",
  ksi: "KSI-IAM-APM",
  runner: { name: "sidecar-1", caller_arn: "arn:aws:sts::111111111111:assumed-role/r/i", account: "111111111111", partition: "aws", region: "us-east-1" },
  steps: [{ argv: ["aws", "iam", "generate-credential-report"], exit_code: 0, started_at: "2026-09-16T10:00:00Z", finished_at: "2026-09-16T10:00:01Z", stdout_sha256: "1".repeat(64), stdout_bytes: 0, stderr_class: "none" }],
  started_at: "2026-09-16T10:00:00Z",
  finished_at: "2026-09-16T10:00:02Z",
};

async function appliance() {
  const work = await mkdtemp(join(tmpdir(), "rampscan-registry-"));
  const ledgerDir = join(work, "ledger");
  const keysDir = join(work, "keys");
  const runnerKeys = await initRunnerKeys(join(work, "runner-keys"));
  const base = {
    runnerName: "sidecar-1",
    publicKeyPem: runnerKeys.publicKeyPem,
    host: "sidecar on the appliance host",
    account: "111111111111",
    partition: "aws" as const,
    repo: "acme/offering",
    proposedBy: "operator@example.test (pb:op1)",
    approvedBy: "approver@example.test (pb:ap1)",
    datasetVersion: "2026.07.14.01",
    ledgerDir,
    keysDir,
  };
  return { work, ledgerDir, keysDir, runnerKeys, base };
}

describe("the runner registry (T3-2)", () => {
  it("register: a signed ledger event the registry folds to, that verify renders, with the keyid the runner's envelopes carry", async () => {
    const { ledgerDir, keysDir, runnerKeys, base } = await appliance();
    const { digest, keyid } = await recordRunnerRegistration({ ...base, action: "registered", now: new Date("2026-09-16T09:00:00Z") });
    expect(keyid).toBe(runnerKeys.keyid);
    const registry = await runnerRegistry(createLocalLedger(ledgerDir));
    expect([...registry.keys()]).toEqual(["sidecar-1"]);
    expect(registry.get("sidecar-1")).toMatchObject({ keyid, host: base.host, account: "111111111111", approvedBy: base.approvedBy });
    const report = await verify({ digest, ledgerDir, keysDir });
    expect(report.ok).toBe(true);
    expect(report.lines.join("\n")).toMatch(/registered sidecar-1 — keyid/);
    expect(report.lines.join("\n")).toMatch(/proposed operator@example.test/);
  });

  it("a runner-signed transcript verifies against the registered key; an unregistered key, a tampered payload, a ledger payload type do not", async () => {
    const { ledgerDir, runnerKeys, base, work } = await appliance();
    await recordRunnerRegistration({ ...base, action: "registered" });
    const registry = await runnerRegistry(createLocalLedger(ledgerDir));
    const envelope = signTranscript(TRANSCRIPT, runnerKeys);
    const ok = verifyRunnerTranscript(envelope, registry);
    expect(ok.ok).toBe(true);
    if (ok.ok) {
      expect(ok.runner.name).toBe("sidecar-1");
      expect(ok.transcript).toEqual(TRANSCRIPT);
    }
    const stranger = await initRunnerKeys(join(work, "stranger"));
    const foreign = verifyRunnerTranscript(signTranscript(TRANSCRIPT, stranger), registry);
    expect(foreign).toMatchObject({ ok: false });
    if (!foreign.ok) expect(foreign.reason).toMatch(/no signature verifies against a registered runner key/);
    const tampered = { ...envelope, payload: Buffer.from(JSON.stringify({ ...TRANSCRIPT, ksi: "KSI-IAM-ELP" })).toString("base64") };
    expect(verifyRunnerTranscript(tampered, registry)).toMatchObject({ ok: false });
    // the appliance's own signer produces in-toto envelopes; one is never a transcript, whoever signed it
    const ledgerSigned = await createLocalSigner(join(work, "keys")).sign({ ...TRANSCRIPT } as never).catch(() => undefined);
    expect(ledgerSigned).toBeUndefined();
    expect(verifyRunnerTranscript({ ...envelope, payloadType: "application/vnd.in-toto+json" }, registry)).toMatchObject({ ok: false, reason: expect.stringMatching(/not a run transcript's/) });
    // a transcript that names another runner than the key's
    const renamed = signTranscript({ ...TRANSCRIPT, runner: { ...TRANSCRIPT.runner, name: "sidecar-2" } }, runnerKeys);
    expect(verifyRunnerTranscript(renamed, registry)).toMatchObject({ ok: false, reason: expect.stringMatching(/names runner sidecar-2/) });
  });

  it("revoke supersedes: the registry drops the runner and its transcripts stop verifying; re-register stands again", async () => {
    const { ledgerDir, runnerKeys, base } = await appliance();
    await recordRunnerRegistration({ ...base, action: "registered", now: new Date("2026-09-16T09:00:00Z") });
    await recordRunnerRegistration({ ...base, action: "revoked", now: new Date("2026-09-16T10:00:00Z") });
    let registry = await runnerRegistry(createLocalLedger(ledgerDir));
    expect(registry.size).toBe(0);
    expect(verifyRunnerTranscript(signTranscript(TRANSCRIPT, runnerKeys), registry)).toMatchObject({ ok: false });
    await recordRunnerRegistration({ ...base, action: "registered", now: new Date("2026-09-16T11:00:00Z") });
    registry = await runnerRegistry(createLocalLedger(ledgerDir));
    expect(registry.size).toBe(1);
  });

  it("refuses a name that is not a slug and a key that is not P-256", async () => {
    const { base } = await appliance();
    await expect(recordRunnerRegistration({ ...base, action: "registered", runnerName: "side:car#1" })).rejects.toThrow(/slug-shaped/);
    const { generateKeyPairSync } = await import("node:crypto");
    const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 }).publicKey.export({ type: "spki", format: "pem" }).toString();
    expect(() => keyIdOfPem(rsa)).toThrow(/P-256/);
  });
});
