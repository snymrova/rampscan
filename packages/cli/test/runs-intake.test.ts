import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import type { RecipeAssertion, RunRequest, RunTranscript, TranscriptStep } from "@rampscan/schema";
import { RUN_REQUEST_TYPE, RUN_TRANSCRIPT_TYPE, submissionVerdict } from "@rampscan/schema";
import { toIngestedBundle } from "@rampscan/core";
import { classifyStep, intakeTranscript, outputShape, requestDigest, rowsOfOutput } from "../src/runs-intake.js";
import type { IntakeContext, IntakeOutcome } from "../src/runs-intake.js";

// T0-4 (docs/PLAN-CLOUD-RUNNER.md, #165): the vacuous passes the runner
// intake must refuse, written before any runner code exists. Each case is a
// transcript that a naive reading — "the command ran, the assertion held
// over what it printed" — would sign `evidenced`, and each asserts that no
// `evidenced` bundle can come of it. They ran under `it.fails` until T2-2
// and T2-3 (#172, #173) made them pass; the plan records the run at which
// they failed and why. The second describe is T2-4's: the outputs written
// by hand that the happy path and the planted violations read.
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
    request_digest: requestDigest(REQUEST),
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
    cadence: "monthly",
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
  it("1. an AccessDenied transcript is a failed run of class denied, never a bundle", () => {
    const t = transcript([
      step(GET_REPORT, "", { exit_code: 254, stderr_class: "access-denied" }),
    ]);
    const outcome = intakeTranscript(t, outputsOf(""), context());
    expectNoEvidencedBundle(outcome);
    expect(outcome).toMatchObject({ kind: "failed", class: "denied" });
  });

  it("2. count_eq 0 over the empty output of a non-zero exit is a failed run, not zero offenders", () => {
    const t = transcript([step(GET_REPORT, "", { exit_code: 1, stderr_class: "other" })]);
    const outcome = intakeTranscript(t, outputsOf(""), context());
    expectNoEvidencedBundle(outcome);
    expect(outcome.kind).toBe("failed");
  });

  it("3. a credential report still in STATE=STARTED is incomplete: the report does not exist yet", () => {
    const generate = '{"State": "STARTED"}\n';
    const t = transcript([
      step(["aws", "iam", "generate-credential-report"], generate),
      step(GET_REPORT, "", { exit_code: 254, stderr_class: "incomplete" }),
    ]);
    const outcome = intakeTranscript(t, outputsOf(generate, ""), context());
    expectNoEvidencedBundle(outcome);
    expect(outcome).toMatchObject({ kind: "failed", class: "incomplete" });
  });

  it("4. a transcript taken in a different account than the one configured is refused", () => {
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

  it("5. a nonce the ledger has already accepted is a replay, refused before any byte is read", () => {
    const clean = "user,arn,mfa_active\nalice,arn:aws:iam::111111111111:user/alice,true\n";
    const t = transcript([step(GET_REPORT, clean)]);
    const outcome = intakeTranscript(t, outputsOf(clean), context({ acceptedNonces: new Set([NONCE]) }));
    expectNoEvidencedBundle(outcome);
    expect(outcome.kind).toBe("refused");
  });
});

// T2-4: outputs written by us — a credential report with a planted
// principal, a 120-day-old key, an empty but valid list. Nothing copied.
const REPORT_HEADER = "user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,mfa_active,access_key_1_active,access_key_1_last_rotated";
const CLEAN_REPORT = [
  REPORT_HEADER,
  "alice,arn:aws:iam::111111111111:user/alice,2025-01-01T00:00:00+00:00,true,2026-09-14T00:00:00+00:00,2026-08-01T00:00:00+00:00,true,true,2026-08-20T00:00:00+00:00",
  "bob,arn:aws:iam::111111111111:user/bob,2025-01-01T00:00:00+00:00,true,2026-09-10T00:00:00+00:00,2026-08-01T00:00:00+00:00,true,false,N/A",
].join("\n");
const PLANTED_NO_MFA = CLEAN_REPORT.replace(
  "bob,arn:aws:iam::111111111111:user/bob,2025-01-01T00:00:00+00:00,true,2026-09-10T00:00:00+00:00,2026-08-01T00:00:00+00:00,true,",
  "bob,arn:aws:iam::111111111111:user/bob,2025-01-01T00:00:00+00:00,true,2026-09-10T00:00:00+00:00,2026-08-01T00:00:00+00:00,false,",
);
const PLANTED_OLD_KEY = CLEAN_REPORT.replace("true,true,2026-08-20T00:00:00+00:00", "true,true,2026-05-18T00:00:00+00:00");
const b64 = (s: string) => Buffer.from(s, "utf8").toString("base64") + "\n";

const MFA_ACTIVE_WHERE_PASSWORD: RecipeAssertion = {
  field: "mfa_active",
  op: "eq",
  value: "true",
  where: [{ field: "password_enabled", op: "eq", value: "true" }],
  description: "Every principal with a console password has MFA active.",
};
const KEY_ROTATED_90D: RecipeAssertion = {
  field: "access_key_1_last_rotated",
  op: "max_age_days",
  value: 90,
  where: [{ field: "access_key_1_active", op: "eq", value: "true" }],
  description: "Every active first access key was rotated within the last 90 days.",
};

/** the credential-report recipe as the runner would run it: generate, then get + base64 (T1-4) */
function reportRun(csv: string) {
  const generate = '{"State": "COMPLETE"}\n';
  const encoded = b64(csv);
  return {
    t: transcript([step(["aws", "iam", "generate-credential-report"], generate), step(GET_REPORT, encoded)]),
    outputs: outputsOf(generate, encoded),
    ctx: context({
      assertions: [MFA_ACTIVE_WHERE_PASSWORD, KEY_ROTATED_90D],
      transforms: [undefined, "base64-decode"],
    }),
  };
}

describe("T2-2 / T2-3 — the appliance reads the bytes, never the runner's word (#172, #173)", () => {
  it("classifyStep: ok only for exit 0 with nothing on stderr; every other shape is a class", () => {
    expect(classifyStep(step(GET_REPORT, ""))).toBe("ok");
    expect(classifyStep(step(GET_REPORT, "", { exit_code: 1 }))).toBe("error");
    expect(classifyStep(step(GET_REPORT, "", { stderr_class: "throttled" }))).toBe("throttled");
    expect(classifyStep(step(GET_REPORT, "", { stderr_class: "not-enabled", exit_code: 254 }))).toBe("not-enabled");
    // exit 0 with something on stderr is still not ok: the CLI printed a warning it could not read past
    expect(classifyStep(step(GET_REPORT, "[]", { stderr_class: "other" }))).toBe("error");
  });

  it("a clean report is evidenced: two assertions passed over two rows, the runner named, the request digest carried", () => {
    const { t, outputs, ctx } = reportRun(CLEAN_REPORT);
    const outcome = intakeTranscript(t, outputs, ctx);
    expect(outcome.kind).toBe("submission");
    if (outcome.kind !== "submission") return;
    const s = outcome.submission;
    expect(submissionVerdict(s)).toBe("evidenced");
    expect(s.assertions.map((a) => [a.passed, a.population])).toEqual([[true, 2], [true, 2]]);
    expect(s.artifacts).toEqual([
      { name: "step-1.json", sha256: t.steps[0]!.stdout_sha256 },
      { name: "step-2.b64", sha256: t.steps[1]!.stdout_sha256 },
    ]);
    expect(s.signer_identity).toBe(`runner:sidecar-1 (arn:aws:sts::${ACCOUNT}:assumed-role/rampscan-runner/i-0abc)`);
    expect(s.automated).toBe(true);
    expect(s.evidence_class).toBe("process-generated");
    expect(s.timestamp).toBe(t.finished_at);
    expect(s.runner).toEqual({
      name: "sidecar-1",
      caller_arn: `arn:aws:sts::${ACCOUNT}:assumed-role/rampscan-runner/i-0abc`,
      account: ACCOUNT,
      partition: "aws",
      region: "us-east-1",
      request_digest: requestDigest(REQUEST),
    });
    // and the bundle the existing mint produces carries the block in its ingest provenance
    const bundle = toIngestedBundle(s, { repo: "acme/offering", datasetVersion: "2026.07.14.01" });
    expect(bundle.predicate.ingest?.runner).toEqual(s.runner);
    expect(bundle.predicate.verdict).toBe("evidenced");
  });

  it("a planted principal without MFA turns the run violated, with the offender counted", () => {
    const { t, outputs, ctx } = reportRun(PLANTED_NO_MFA);
    const outcome = intakeTranscript(t, outputs, ctx);
    expect(outcome.kind).toBe("submission");
    if (outcome.kind !== "submission") return;
    expect(submissionVerdict(outcome.submission)).toBe("violated");
    const mfa = outcome.submission.assertions[0]!;
    expect(mfa.passed).toBe(false);
    expect(mfa.offender_count).toBe(1);
    expect(mfa.population).toBe(2);
    // the pipeline's offender pointers are file/package-shaped; an IAM principal has no pointer yet,
    // so the count and the detail carry it (a runner-shaped pointer is T2-5's, with the vocabulary)
    expect(mfa.detail).toBeDefined();
    expect(outcome.submission.assertions[1]!.passed).toBe(true);
  });

  it("a 120-day-old active key is judged against the run's own clock, not the ingest's", () => {
    const { t, outputs, ctx } = reportRun(PLANTED_OLD_KEY);
    const outcome = intakeTranscript(t, outputs, ctx);
    expect(outcome.kind).toBe("submission");
    if (outcome.kind !== "submission") return;
    expect(submissionVerdict(outcome.submission)).toBe("violated");
    expect(outcome.submission.assertions[1]).toMatchObject({ passed: false, offender_count: 1, population: 2 });
  });

  it("an empty but valid list is an ok run over zero rows: population 0, said so, never invented", () => {
    const empty = '{"EvaluationResults": []}\n';
    const t = transcript([step(["aws", "configservice", "get-compliance-details-by-config-rule", "--config-rule-name", "x"], empty)]);
    const outcome = intakeTranscript(t, outputsOf(empty), context({
      assertions: [{ field: "ComplianceType", op: "count_eq", value: 0, description: "No NON_COMPLIANT evaluation." }],
    }));
    expect(outcome.kind).toBe("submission");
    if (outcome.kind !== "submission") return;
    expect(outcome.submission.assertions[0]).toMatchObject({ passed: true, population: 0 });
  });

  it("a recipe with no structured assertion is collected and unevidenced, not automated (T0-2)", () => {
    const list = '[{"RoleName": "a", "MaxSessionDuration": 3600}]\n';
    const t = transcript([step(["aws", "iam", "list-roles"], list)]);
    const outcome = intakeTranscript(t, outputsOf(list), context({ assertions: [] }));
    expect(outcome.kind).toBe("submission");
    if (outcome.kind !== "submission") return;
    expect(outcome.submission.assertions).toEqual([]);
    expect(submissionVerdict(outcome.submission)).toBe("unevidenced");
    expect(outcome.submission.automated).toBe(false);
  });

  it("bytes that do not match the digest the transcript names are refused, not evaluated", () => {
    const { t, ctx } = reportRun(CLEAN_REPORT);
    const wrong = new Map([[t.steps[1]!.stdout_sha256, new TextEncoder().encode("not what was printed")]]);
    wrong.set(t.steps[0]!.stdout_sha256, new TextEncoder().encode('{"State": "COMPLETE"}\n'));
    const outcome = intakeTranscript(t, wrong, ctx);
    expect(outcome).toMatchObject({ kind: "refused" });
    if (outcome.kind === "refused") expect(outcome.reason).toMatch(/do not match the digest/);
    const missing = intakeTranscript(t, new Map(), ctx);
    expect(missing).toMatchObject({ kind: "refused" });
  });

  it("a run outside the request's window, or a request digest for another request, is refused", () => {
    const { t, outputs, ctx } = reportRun(CLEAN_REPORT);
    const late = transcript(t.steps, { started_at: "2026-09-15T10:05:00Z", finished_at: "2026-09-15T11:30:00Z" });
    expect(intakeTranscript(late, outputs, ctx)).toMatchObject({ kind: "refused" });
    const other = transcript(t.steps, { request_digest: requestDigest({ ...REQUEST, recipe_id: "iam-list-roles" }) });
    expect(intakeTranscript(other, outputs, ctx)).toMatchObject({ kind: "refused" });
    const notDenied = transcript(t.steps, { self_check: { probes: ["iam:CreateUser"], all_denied: false } });
    expect(intakeTranscript(notDenied, outputs, ctx)).toMatchObject({ kind: "refused" });
  });

  it("rowsOfOutput: an array, the CLI's one-array object, a single object, a base64 CSV, and nothing", () => {
    const enc = (s: string) => new TextEncoder().encode(s);
    expect(rowsOfOutput(enc('[{"a":1},{"a":2}]'))).toEqual([{ a: 1 }, { a: 2 }]);
    expect(rowsOfOutput(enc('{"Roles":[{"a":1}],"IsTruncated":false}'))).toEqual([{ a: 1 }]);
    expect(rowsOfOutput(enc('{"Locked":true,"MinRetentionDays":30}'))).toEqual([{ Locked: true, MinRetentionDays: 30 }]);
    expect(rowsOfOutput(enc(b64('a,b\n1,"x,y"\n')), "base64-decode")).toEqual([{ a: "1", b: "x,y" }]);
    expect(rowsOfOutput(enc(""))).toEqual([]);
    expect(rowsOfOutput(enc("plain text with no header"))).toEqual([]);
    expect(outputShape(enc('{"State": "COMPLETE"}')).kind).toBe("record");
    expect(outputShape(enc('{"Roles":[]}')).kind).toBe("collection");
    expect(outputShape(enc("x")).kind).toBe("none");
  });
});
