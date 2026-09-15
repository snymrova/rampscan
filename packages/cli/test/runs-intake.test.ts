import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import type { RecipeAssertion, RunRequest, RunTranscript, TranscriptStep } from "@rampscan/schema";
import { RUN_REQUEST_TYPE, RUN_TRANSCRIPT_TYPE, submissionVerdict } from "@rampscan/schema";
import { intakeTranscript } from "../src/runs-intake.js";
import type { IntakeContext, IntakeOutcome } from "../src/runs-intake.js";

// T0-4 (docs/PLAN-CLOUD-RUNNER.md, #165): the vacuous passes the runner
// intake must refuse, written before any runner code exists. Each case is a
// transcript that a naive reading — "the command ran, the assertion held
// over what it printed" — would sign `evidenced`, and each asserts that no
// `evidenced` bundle can come of it. They run under `it.fails` until T2-2
// and T2-3 (#172, #173) make them pass, and the plan records the run at
// which they failed and why.
//
// The five, from the plan:
//   1. an AccessDenied transcript — the role could not look;
//   2. `count_eq 0` over output from a command that exited non-zero — zero
//      offenders because zero rows, not because the account is clean;
//   3. a credential report still in STATE=STARTED — the report the
//      assertion would read does not exist yet;
//   4. a transcript whose caller account differs from the configured one —
//      evidence about some other account;
//   5. a replayed nonce — the same run counted twice.
//
// Nothing here executes AWS. Every output is written by hand, the way T2-4
// wants it; none is copied from upstream or from any pilot repository.

const sha256 = (bytes: string) => createHash("sha256").update(bytes).digest("hex");

const ACCOUNT = "111111111111";
const NONCE = "5f2c9a1e7b3d4c6a8e0f1a2b3c4d5e6f";

const REQUEST: RunRequest = {
  _type: RUN_REQUEST_TYPE,
  nonce: NONCE,
  recipe_id: "iam-credential-report",
  recipe_digest: sha256("recipe:iam-credential-report"),
  ksi: "KSI-IAM-MFA",
  params: {},
  issued_at: "2026-09-15T10:00:00Z",
  expires_at: "2026-09-15T11:00:00Z",
  requester: "operator@example.test",
};

/** the assertion a naive reader passes over an empty report: no user without MFA */
const NO_USER_WITHOUT_MFA: RecipeAssertion = {
  field: "mfa_active",
  op: "count_eq",
  value: 0,
  where: [{ field: "mfa_active", op: "eq", value: "false" }],
  description: "No IAM user in the credential report has mfa_active = false.",
};

function step(argv: string[], stdout: string, over: Partial<TranscriptStep> = {}): TranscriptStep {
  return {
    argv,
    exit_code: 0,
    started_at: "2026-09-15T10:05:00Z",
    finished_at: "2026-09-15T10:05:02Z",
    stdout_sha256: sha256(stdout),
    stdout_bytes: Buffer.byteLength(stdout),
    stderr_class: "none",
    ...over,
  };
}

function transcript(steps: TranscriptStep[], over: Partial<RunTranscript> = {}): RunTranscript {
  return {
    _type: RUN_TRANSCRIPT_TYPE,
    request_digest: sha256(JSON.stringify(REQUEST)),
    nonce: NONCE,
    recipe_id: REQUEST.recipe_id,
    ksi: REQUEST.ksi,
    runner: {
      name: "sidecar-1",
      caller_arn: `arn:aws:sts::${ACCOUNT}:assumed-role/rampscan-runner/i-0abc`,
      account: ACCOUNT,
      partition: "aws",
      region: "us-east-1",
    },
    self_check: { probes: ["iam:CreateUser", "s3:PutObject", "ec2:RunInstances"], all_denied: true },
    steps,
    started_at: "2026-09-15T10:05:00Z",
    finished_at: "2026-09-15T10:05:10Z",
    ...over,
  };
}

function outputsOf(...printed: string[]): Map<string, Uint8Array> {
  return new Map(printed.map((s) => [sha256(s), new TextEncoder().encode(s)]));
}

function context(over: Partial<IntakeContext> = {}): IntakeContext {
  return {
    request: REQUEST,
    account: ACCOUNT,
    partition: "aws",
    assertions: [NO_USER_WITHOUT_MFA],
    acceptedNonces: new Set(),
    receivedAt: "2026-09-15T10:06:00Z",
    ...over,
  };
}

/** the one thing every case asserts: whatever came out, it is not a pass */
function expectNoEvidencedBundle(outcome: IntakeOutcome): void {
  if (outcome.kind === "submission") {
    expect(submissionVerdict(outcome.submission)).not.toBe("evidenced");
  }
}

const GET_REPORT = ["aws", "iam", "get-credential-report", "--output", "text", "--query", "Content"];

describe("T0-4 — the vacuous passes the runner intake must refuse (#165)", () => {
  it.fails("1. an AccessDenied transcript is a failed run of class denied, never a bundle", () => {
    const t = transcript([
      step(GET_REPORT, "", { exit_code: 254, stderr_class: "access-denied" }),
    ]);
    const outcome = intakeTranscript(t, outputsOf(""), context());
    expectNoEvidencedBundle(outcome);
    expect(outcome).toMatchObject({ kind: "failed", class: "denied" });
  });

  it.fails("2. count_eq 0 over the empty output of a non-zero exit is a failed run, not zero offenders", () => {
    const t = transcript([step(GET_REPORT, "", { exit_code: 1, stderr_class: "other" })]);
    const outcome = intakeTranscript(t, outputsOf(""), context());
    expectNoEvidencedBundle(outcome);
    expect(outcome.kind).toBe("failed");
  });

  it.fails("3. a credential report still in STATE=STARTED is incomplete: the report does not exist yet", () => {
    const generate = '{"State": "STARTED"}\n';
    const t = transcript([
      step(["aws", "iam", "generate-credential-report"], generate),
      step(GET_REPORT, "", { exit_code: 254, stderr_class: "incomplete" }),
    ]);
    const outcome = intakeTranscript(t, outputsOf(generate, ""), context());
    expectNoEvidencedBundle(outcome);
    expect(outcome).toMatchObject({ kind: "failed", class: "incomplete" });
  });

  it.fails("4. a transcript taken in a different account than the one configured is refused", () => {
    const other = "222222222222";
    const clean = "user,arn,mfa_active\nalice,arn:aws:iam::222222222222:user/alice,true\n";
    const t = transcript([step(GET_REPORT, clean)], {
      runner: {
        name: "sidecar-1",
        caller_arn: `arn:aws:sts::${other}:assumed-role/rampscan-runner/i-0abc`,
        account: other,
        partition: "aws",
        region: "us-east-1",
      },
    });
    const outcome = intakeTranscript(t, outputsOf(clean), context());
    expectNoEvidencedBundle(outcome);
    expect(outcome.kind).toBe("refused");
  });

  it.fails("5. a nonce the ledger has already accepted is a replay, refused before any byte is read", () => {
    const clean = "user,arn,mfa_active\nalice,arn:aws:iam::111111111111:user/alice,true\n";
    const t = transcript([step(GET_REPORT, clean)]);
    const outcome = intakeTranscript(t, outputsOf(clean), context({ acceptedNonces: new Set([NONCE]) }));
    expectNoEvidencedBundle(outcome);
    expect(outcome.kind).toBe("refused");
  });
});
