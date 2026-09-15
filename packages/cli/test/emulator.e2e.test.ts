import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { promisify } from "node:util";
import { describe, expect, it } from "vitest";
import type { RecipeAssertion, RunRequest } from "@rampscan/schema";
import { runRequest } from "@rampscan/runner";
import { intakeTranscript, requestDigest } from "../src/runs-intake.js";

// T3-0 (docs/PLAN-CLOUD-RUNNER.md, #175): the real `aws` binary against the
// emulator (compose.emulator.yaml; the `emulator` job in CI), through the
// runner and into the appliance's intake — which is why it lives with the
// appliance's tests and imports the runner, never the reverse. Skips,
// NAMED, when there is no endpoint or no binary: a missing emulator is a
// skipped collector, not a green run. Nothing here is a claim about any
// account — Moto's 123456789012 is nobody's.

const ENDPOINT = process.env["AWS_ENDPOINT_URL"];
const run = promisify(execFile);

async function awsOnPath(): Promise<boolean> {
  try {
    await run("aws", ["--version"]);
    return true;
  } catch {
    return false;
  }
}
const ready = ENDPOINT !== undefined && (await awsOnPath());
if (!ready) {
  console.warn(`emulator suite skipped: ${ENDPOINT === undefined ? "AWS_ENDPOINT_URL is not set" : "no aws binary on PATH"} — the runner was not exercised against Moto in this run`);
}

const sha256 = (s: string) => createHash("sha256").update(s).digest("hex");
const ENV = { ...process.env, AWS_ACCESS_KEY_ID: process.env["AWS_ACCESS_KEY_ID"] ?? "testing", AWS_SECRET_ACCESS_KEY: process.env["AWS_SECRET_ACCESS_KEY"] ?? "testing", AWS_DEFAULT_REGION: process.env["AWS_DEFAULT_REGION"] ?? "us-east-1" };
const aws = (...argv: string[]) => run("aws", argv, { env: ENV });

const REQUEST: RunRequest = {
  _type: "https://rampscan.dev/run-request/v1",
  nonce: "5f2c9a1e7b3d4c6a8e0f1a2b3c4d5e6f",
  recipe_id: "iam-credential-report",
  recipe_digest: sha256("recipe"),
  ksi: "KSI-IAM-APM",
  params: {},
  issued_at: new Date(Date.now() - 3_600_000).toISOString(),
  expires_at: new Date(Date.now() + 3_600_000).toISOString(),
  requester: "operator@example.test",
};

/** the credential-report recipe's steps as T1 classifies them: generate, then get with the base64 transform */
const STEPS = [
  ["aws", "iam", "generate-credential-report"],
  ["aws", "iam", "get-credential-report", "--query", "Content", "--output", "text"],
] as const;

/** our own spelling of upstream's first assertion; Moto and AWS both print `true`/`false` */
const MFA_WHERE_PASSWORD: RecipeAssertion = {
  field: "mfa_active",
  op: "eq",
  value: "true",
  where: [{ field: "password_enabled", op: "eq", value: "true" }],
  description: "Every principal with a console password has MFA active.",
};
/** upstream's spelling, verbatim from aws-evidence.json */
const UPSTREAM_MFA: RecipeAssertion = { ...MFA_WHERE_PASSWORD, value: "TRUE", where: [{ field: "password_enabled", op: "eq", value: "TRUE" }] };

describe.skipIf(!ready)("T3-0 — the real aws binary, against Moto, through the runner and the intake (#175)", () => {
  it("seeds a principal with a password and no MFA, runs the credential-report recipe, and the intake finds it", async () => {
    // the seed: a mutating call the RUNNER never makes — the test makes it, as an operator would in a sandbox
    await aws("iam", "create-user", "--user-name", "alice-no-mfa").catch(() => undefined);
    await aws("iam", "create-login-profile", "--user-name", "alice-no-mfa", "--password", "Xy7!aaaaaaaaaaaa").catch(() => undefined);
    // Moto answers the first generate with STATE=STARTED like AWS does; the report is ready on the next call
    await aws("iam", "generate-credential-report");

    // no self-check: Moto cannot answer simulate-principal-policy (T3-0's finding); the intake below is told so
    const { transcript, outputs } = await runRequest(
      { request: REQUEST, request_digest: "0".repeat(64), steps: STEPS, runner: { name: "ci-emulator", region: "us-east-1" } },
      { env: ENV },
    );
    expect(transcript.runner.account).toBe("123456789012");
    expect(transcript.runner.caller_arn).toMatch(/^arn:aws:sts::123456789012:/);
    expect(transcript.steps.map((s) => [s.exit_code, s.stderr_class])).toEqual([[0, "none"], [0, "none"]]);
    expect(outputs.size).toBe(2);

    // the appliance's side, over the same bytes
    const request = { ...REQUEST };
    const t = { ...transcript, request_digest: requestDigest(request) };
    const base = {
      request,
      partition: "aws" as const,
      cadence: "monthly" as const,
      transforms: [undefined, "base64-decode" as const],
      // Moto answers simulate-principal-policy with a 500 (T3-0's finding); the sandbox is where the self-check runs for real
      requireSelfCheck: false,
      acceptedNonces: new Set<string>(),
      receivedAt: new Date(Date.now() + 60_000).toISOString(),
    };

    // configured for another account: refused, the emulator's account named
    const other = intakeTranscript(t, outputs, { ...base, account: "111111111111", assertions: [MFA_WHERE_PASSWORD] });
    expect(other).toMatchObject({ kind: "refused" });
    if (other.kind === "refused") expect(other.reason).toContain("123456789012");

    // configured for the emulator's account: violated, the planted principal counted
    const outcome = intakeTranscript(t, outputs, { ...base, account: "123456789012", assertions: [MFA_WHERE_PASSWORD, UPSTREAM_MFA] });
    expect(outcome.kind).toBe("submission");
    if (outcome.kind !== "submission") return;
    const [ours, upstream] = outcome.submission.assertions;
    expect(ours).toMatchObject({ passed: false });
    expect(ours!.population).toBeGreaterThanOrEqual(1);
    expect(ours!.offender_count).toBeGreaterThanOrEqual(1);
    // the finding recorded in the plan (T2-5): upstream compares `TRUE`, the report prints `true`, so
    // upstream's where-clause matches no row and its assertion passes over nothing it should have read
    expect(upstream).toMatchObject({ passed: true, population: ours!.population });
    expect(outcome.submission.runner?.account).toBe("123456789012");
  });

  it("a call the emulator does not implement is a failed run of class error, never a bundle", async () => {
    const { transcript } = await runRequest(
      {
        request: { ...REQUEST, recipe_id: "config-mfa-enabled-console-access" },
        request_digest: "0".repeat(64),
        steps: [["aws", "configservice", "get-compliance-details-by-config-rule", "--config-rule-name", "mfa-enabled-for-iam-console-access"]],
        runner: { name: "ci-emulator", region: "us-east-1" },
      },
      { env: ENV },
    );
    const step = transcript.steps[0]!;
    expect(step.exit_code).not.toBe(0);
    expect(step.stderr_class).toBe("other");
    expect(JSON.stringify(transcript)).not.toContain("Internal Server Error");
  });
});
