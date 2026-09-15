import { mkdtemp, readFile, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { canonicalJson as schemaCanonicalJson } from "@rampscan/schema";
import type { RunTranscript } from "@rampscan/schema";
import { canonicalJson, initRunnerKeys, loadRunnerKeys, signTranscript, verifyTranscriptEnvelope } from "../src/keys.js";

// T3-2 (docs/PLAN-CLOUD-RUNNER.md, #177), the runner's half: its own key,
// generated once; a DSSE envelope over the canonical transcript under a
// payload type that is not a ledger statement's; canonical bytes equal to
// the appliance's, held by a test because the runner may not import them.

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

describe("the runner's key (T3-2)", () => {
  it("init generates P-256 once — private 0600, public printable — and a second init reuses it", async () => {
    const dir = join(await mkdtemp(join(tmpdir(), "rampscan-runner-keys-")), "keys");
    const first = await initRunnerKeys(dir);
    expect(first.created).toBe(true);
    expect(first.publicKeyPem).toMatch(/^-----BEGIN PUBLIC KEY-----/);
    expect(first.keyid).toMatch(/^[0-9a-f]{64}$/);
    expect(((await stat(join(dir, "runner.key"))).mode & 0o777).toString(8)).toBe("600");
    const second = await initRunnerKeys(dir);
    expect(second.created).toBe(false);
    expect(second.keyid).toBe(first.keyid);
    expect((await loadRunnerKeys(dir)).keyid).toBe(first.keyid);
    expect(await readFile(join(dir, "runner.pub"), "utf8")).toBe(first.publicKeyPem);
  });

  it("the runner's canonical bytes are the appliance's, byte for byte", () => {
    expect(canonicalJson(TRANSCRIPT)).toBe(schemaCanonicalJson(TRANSCRIPT));
    expect(canonicalJson({ b: [1, { z: null, a: "x" }], a: undefined, c: true })).toBe(schemaCanonicalJson({ b: [1, { z: null, a: "x" }], a: undefined, c: true }));
  });

  it("signs the canonical transcript under the transcript payload type, and verifies only under its own key", async () => {
    const dir = join(await mkdtemp(join(tmpdir(), "rampscan-runner-keys-")), "keys");
    const keys = await initRunnerKeys(dir);
    const envelope = signTranscript(TRANSCRIPT, keys);
    expect(envelope.payloadType).toBe("application/vnd.rampscan.run-transcript+json");
    expect(Buffer.from(envelope.payload, "base64").toString()).toBe(canonicalJson(TRANSCRIPT));
    expect(envelope.signatures).toHaveLength(1);
    expect(envelope.signatures[0]!.keyid).toBe(keys.keyid);
    expect(verifyTranscriptEnvelope(envelope, keys.publicKeyPem)).toBe(true);
    const other = await initRunnerKeys(join(dir, "other"));
    expect(verifyTranscriptEnvelope(envelope, other.publicKeyPem)).toBe(false);
    // a byte moved in the payload is a signature that no longer verifies
    const tampered = { ...envelope, payload: Buffer.from(canonicalJson({ ...TRANSCRIPT, ksi: "KSI-IAM-ELP" })).toString("base64") };
    expect(verifyTranscriptEnvelope(tampered, keys.publicKeyPem)).toBe(false);
    expect(verifyTranscriptEnvelope({ ...envelope, payloadType: "application/vnd.in-toto+json" }, keys.publicKeyPem)).toBe(false);
  });
});
