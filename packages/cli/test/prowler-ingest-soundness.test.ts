import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import { DEFAULT_DATASET_PIN, loadKsiCatalog } from "@rampscan/dataset";
import { evaluateAssertion } from "@rampscan/core";
import { PROWLER_OCSF_STANDARD, parseProwlerOcsf } from "../src/prowler-ocsf.js";
import { prowlerSubmissions } from "../src/prowler-ingest.js";
import type { ProwlerRunDeclaration } from "../src/prowler-ingest.js";

// P3-2 (docs/RESEARCH-PROWLER-INGEST.md §4c): the soundness test, WRITTEN
// BEFORE THE ADAPTER.
//
// #147 was the same shape one input earlier: a client script's exit 0 was read
// as its verdict, and the scripts that convention came from exit 0 after
// reading a 0-%-encrypted account. The fix was that the appliance evaluates
// the rows itself. Prowler arrives with a NEW door onto the same room, and
// this file is here before the adapter because that is the only ordering in
// which the test can be shown failing.
//
// The trap, precisely. Prowler's KSI framework routes every requirement no
// check reaches to the universal writer, which emits one synthetic `MANUAL`
// row for it. Thirteen of the 46 indicators are in that state at the pin —
// and they are the thirteen no scanner can see, the ones a human has to
// attest. The obvious assertion, "no FAIL rows for this indicator", is
// `count_eq 0` over the rows where the status is FAIL. Over a KSI whose only
// row is MANUAL, THERE ARE NO FAIL ROWS, so it passes. A naive adapter would
// sign `evidenced` for the thirteen indicators it has the least evidence
// about, and it would do so while running green.
//
// The first describe below shows that hazard is REAL against the shared
// evaluator today — those tests pass, and are characterization, not aspiration.
// The second describe states the three obligations the adapter owes and is
// under `it.fails` until P3-3 exists. P3-3 is not done until it unwraps them.

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");

/** the 46 indicators at THIS checkout's dataset pin — the reader's other side */
let ids: readonly string[] = [];

beforeAll(async () => {
  const cat = await loadKsiCatalog({
    derivedDir: join(REPO_ROOT, "docs/context/ramprules/derived"),
    rulesFile: join(REPO_ROOT, "docs/context/fedramp-rules/fedramp-consolidated-rules.json"),
    pin: DEFAULT_DATASET_PIN,
  });
  ids = cat.ksis.map((k) => k.id);
});

/**
 * One reported OCSF `ComplianceFinding`, in §10a's shape. Same constructor as
 * the reader's own test, duplicated rather than shared: a fixture these two
 * files agreed on could drift into shape by agreement, and this file's whole
 * job is to disagree with a plausible implementation.
 */
function row(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    class_uid: 2003,
    time_dt: "2026-09-18T10:00:00+00:00",
    status: "New",
    status_id: 1,
    status_code: "PASS",
    message: "Cognito user pool up-1 requires a lowercase character.",
    finding_info: { uid: "prowler-aws-cognito-123456789012-us-east-1-up-1-KSI-IAM-APM" },
    metadata: {
      event_code: "cognito_user_pool_password_policy_lowercase",
      product: { name: "Prowler", version: "5.42.0" },
    },
    compliance: {
      standards: [PROWLER_OCSF_STANDARD],
      requirements: ["KSI-IAM-APM"],
      checks: [{ uid: "cognito_user_pool_password_policy_lowercase", status: "PASS" }],
    },
    unmapped: { cloud: { account: { uid: "123456789012" }, region: "us-east-1" } },
    ...over,
  };
}

/** the synthetic row Prowler writes for a requirement no check reaches */
function manualRow(ksi: string): Record<string, unknown> {
  return {
    class_uid: 2003,
    time_dt: "2026-09-18T10:00:00+00:00",
    status: "New",
    status_id: 1,
    status_code: "MANUAL",
    message: "Manual review required.",
    finding_info: { uid: `manual-${ksi}` },
    metadata: { event_code: "manual", product: { name: "Prowler", version: "5.42.0" } },
    compliance: { standards: [PROWLER_OCSF_STANDARD], requirements: [ksi] },
  };
}

/** a FAIL row for `KSI-IAM-APM`, the one a suppressed exit code hides */
function failRow(over: Record<string, unknown> = {}): Record<string, unknown> {
  return row({
    status_code: "FAIL",
    message: "Cognito user pool up-2 does not require a lowercase character.",
    finding_info: { uid: "prowler-aws-cognito-123456789012-us-east-1-up-2-KSI-IAM-APM" },
    compliance: {
      standards: [PROWLER_OCSF_STANDARD],
      requirements: ["KSI-IAM-APM"],
      checks: [{ uid: "cognito_user_pool_password_policy_lowercase", status: "FAIL" }],
    },
    ...over,
  });
}

/**
 * The assertion a plausible adapter would write, verbatim: "this indicator has
 * no failing findings". It is not a strawman — it is the correct assertion
 * over a population that was actually looked at, and the ONLY thing wrong with
 * it is that nothing checks the population is non-empty.
 */
const NO_FAILING_FINDINGS = {
  field: "effectiveStatus",
  op: "count_eq" as const,
  value: 0,
  where: [{ field: "effectiveStatus", op: "eq" as const, value: "FAIL" }],
  description: "No finding Prowler reported for this indicator reads FAIL.",
};

/** exit 0, as `-z` leaves it when unmuted failures exist (§4c defence 3) */
const CLEAN_EXIT: ProwlerRunDeclaration = {
  exit_code: 0,
  signer_identity: "runner:prowler@synthetic-csp",
};

const NOW = new Date("2026-09-18T10:00:00Z");

describe("the vacuous pass this input introduces is real (§4c)", () => {
  it("`count_eq 0` over an EMPTY row set passes — the shared evaluator, as designed", () => {
    // Not a bug in `evaluateAssertion`: a count over nothing is honestly zero,
    // and every pipeline recipe depends on that reading. It is a bug in any
    // CALLER that lets an empty population reach it. This is why §4c puts the
    // non-emptiness check in the adapter rather than in the evaluator —
    // changing it here would move the failure under other callers' feet.
    const result = evaluateAssertion(NO_FAILING_FINDINGS, [], NOW);
    expect(result.passed).toBe(true);
    // N0's population field is what makes the vacuity VISIBLE rather than
    // merely true, and it is the field the adapter's guard reads.
    expect(result.population).toBe(0);
  });

  it("the same assertion over a real looked-at population still discriminates", () => {
    const rows = [
      { effectiveStatus: "PASS", ksi: "KSI-IAM-APM" },
      { effectiveStatus: "FAIL", ksi: "KSI-IAM-APM" },
    ];
    const result = evaluateAssertion(NO_FAILING_FINDINGS, rows, NOW);
    expect(result.passed).toBe(false);
    expect(result.population).toBe(2);
  });

  it("the reader has already closed the first door: a MANUAL-only indicator has NO rows to evaluate", () => {
    // P3-1's structural half. `byKsi` carries reported rows only, so the
    // adapter cannot even reach a row set for KSI-CED-RAT to run the vacuous
    // assertion over — it gets `undefined`, not an empty array. An adapter
    // that forgets the rule is stopped by the shape rather than by memory.
    const doc = parseProwlerOcsf(
      [row(), manualRow("KSI-CED-RAT")],
      "synthetic.ocsf.json",
      ids,
    );
    expect(doc.byKsi.get("KSI-IAM-APM")).toHaveLength(1);
    expect(doc.byKsi.has("KSI-CED-RAT")).toBe(false);
    expect(doc.byKsi.get("KSI-CED-RAT")).toBeUndefined();
    // but it IS named, so the adapter has something to skip and say
    expect(doc.manual).toEqual(["KSI-CED-RAT"]);
  });
});

describe("the adapter's three obligations (P3-2 — unwrapped by P3-3)", () => {
  it.fails("1. a KSI whose only row is MANUAL is skipped and named, never evidenced", () => {
    const doc = parseProwlerOcsf(
      [row(), manualRow("KSI-CED-RAT"), manualRow("KSI-PIY-RES")],
      "synthetic.ocsf.json",
      ids,
    );
    const { submissions, skipped } = prowlerSubmissions(doc, CLEAN_EXIT);

    // no submission for either uncovered indicator — under ANY verdict. Not
    // `unevidenced` either: a bundle says bytes were collected about this
    // indicator, and none were. G1 is where these belong, and G1 is reached
    // by there being nothing to cite.
    expect(submissions.map((s) => s.ksi)).toEqual(["KSI-IAM-APM"]);

    // named, the way #147's failed run is — a skip the operator can read
    expect(skipped.map((s) => s.ksi).sort()).toEqual(["KSI-CED-RAT", "KSI-PIY-RES"]);
    for (const s of skipped) {
      expect(s.reason).toMatch(/no check reaches|MANUAL|uncovered/i);
    }
  });

  it.fails("2. an assertion over zero surviving rows fails — it does not pass vacuously", () => {
    // The route to an empty population that exists at P3-2: every reported row
    // for the indicator is muted. Whatever P3-4 decides about muting — exclude
    // and name, or refuse the submission — the obligation here is the same and
    // is stated so as to hold under both: this indicator does not read
    // `evidenced` off a population of zero.
    const doc = parseProwlerOcsf(
      [
        failRow({ status: "Suppressed", status_id: 3 }),
        failRow({
          status: "Suppressed",
          status_id: 3,
          finding_info: { uid: "prowler-aws-cognito-123456789012-us-east-1-up-3-KSI-IAM-APM" },
        }),
      ],
      "synthetic.ocsf.json",
      ids,
    );
    const { submissions } = prowlerSubmissions(doc, CLEAN_EXIT);

    for (const s of submissions) {
      for (const a of s.assertions) {
        // the guard, stated the way it will read in the bundle: a passing
        // assertion must have looked at something
        if (a.passed) expect(a.population).toBeGreaterThan(0);
      }
      // and therefore no assertion passed over nothing
      expect(s.assertions.some((a) => a.passed && (a.population ?? 0) === 0)).toBe(false);
    }
  });

  it.fails("3. exit 0 does not outvote a FAIL row — `-z` suppresses the code, not the finding", () => {
    // `--ignore-exit-code-3` leaves a scan that failed findings exiting 0, and
    // exit 3 is not emitted at all when every failure is muted. So this exit 0
    // is weaker than the tree adapter's, and the verdict comes from the rows.
    const doc = parseProwlerOcsf([row(), failRow()], "synthetic.ocsf.json", ids);
    const { submissions } = prowlerSubmissions(doc, CLEAN_EXIT);

    const apm = submissions.find((s) => s.ksi === "KSI-IAM-APM");
    expect(apm).toBeDefined();
    // one PASS row and one FAIL row were looked at, and the FAIL decides
    expect(apm!.assertions.length).toBeGreaterThan(0);
    expect(apm!.assertions.every((a) => a.passed)).toBe(false);
    expect(apm!.assertions.some((a) => (a.population ?? 0) === 2)).toBe(true);
  });

  it.fails("3b. a non-zero exit is a failed run — nothing in the document becomes a bundle", () => {
    // #147's rule, unchanged: exit 1 is Prowler's critical error. The account
    // was not fully read, so there is nothing to attest to AND nothing to
    // violate. Every indicator is skipped and named; none is a bundle.
    const doc = parseProwlerOcsf([row(), failRow()], "synthetic.ocsf.json", ids);
    const { submissions, skipped } = prowlerSubmissions(doc, { ...CLEAN_EXIT, exit_code: 1 });

    expect(submissions).toEqual([]);
    expect(skipped.map((s) => s.ksi)).toContain("KSI-IAM-APM");
    expect(skipped.every((s) => s.exit_code === 1)).toBe(true);
    for (const s of skipped) expect(s.reason).toMatch(/exit 1/);
  });
});
