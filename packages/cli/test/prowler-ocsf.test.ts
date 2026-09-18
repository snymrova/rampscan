import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import { DEFAULT_DATASET_PIN, loadKsiCatalog } from "@rampscan/dataset";
import { PROWLER_FRAMEWORK_PIN } from "../src/prowler-framework.js";
import {
  CONFIG_NOT_VALID_PREFIX,
  PROWLER_OCSF_STANDARD,
  loadProwlerOcsf,
  parseProwlerOcsf,
} from "../src/prowler-ocsf.js";

// P3-1 (docs/RESEARCH-PROWLER-INGEST.md §10a, §6): the OCSF reader.
//
// WHY THIS READER EXISTS SEPARATELY FROM THE ADAPTER. §6 puts the reader
// before the soundness test (P3-2) and the adapter (P3-3) on purpose: every
// defence P3 has rests on the reader having already refused the documents
// that cannot be evaluated honestly, so that nothing downstream has to
// remember to. The two that matter most are here rather than in the adapter:
//
//   1. A `MANUAL` row is SET ASIDE AT THE READER. Prowler emits one synthetic
//      row per requirement no check reaches, and the obvious assertion
//      (`count_eq 0` over FAIL rows) passes vacuously over precisely the
//      thirteen indicators nothing looked at (§4c) — #147 arriving through a
//      new door. `byKsi` therefore carries reported rows only, so a KSI whose
//      only row is MANUAL is ABSENT from it rather than present and empty.
//      An adapter that forgets this cannot mint a pass; it gets nothing.
//   2. AN ABSENT OR EMPTY FILE IS A REFUSAL, not zero findings.
//      `OCSFComplianceOutput.__init__` guards `if findings:` before the
//      transform that emits the manual rows, so a scan that found nothing
//      writes NO FILE — and no thirteen MANUAL rows either (§10a). Reading a
//      missing file as "the scan evidenced nothing" would be the vacuous pass
//      one level up from the one above.
//
// WHY THE FIELD NAMES ARE §10a'S AND NOT §2d'S. §2d documented the CSV row,
// because that is what the universal writer's table path emits. The OCSF
// sibling is a different function with different names, and a reader written
// against `Status`, `CheckId`, `Muted`, `Requirements_Id` finds NONE of them.
// The note corrected itself there rather than letting this file discover it.

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");

/**
 * The 46 indicators at THIS checkout's dataset pin. The reader is handed them
 * rather than loading them itself for the reason `loadPinnedProwlerFramework`
 * takes a `repoRoot`: the join is between two pins, and a reader that fetches
 * one of its own sides can never be shown disagreeing with the other.
 */
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
 * One reported (non-MANUAL) OCSF `ComplianceFinding`, in the shape §10a's
 * table names. Everything outside that table is omitted rather than invented:
 * the reader reads what the note established by reading upstream's writer, and
 * a fixture carrying more than that would be testing a guess.
 */
function row(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    class_uid: 2003,
    time: 1789689600,
    time_dt: "2026-09-18T10:00:00+00:00",
    status: "New",
    status_id: 1,
    status_code: "PASS",
    message: "Cognito user pool up-1 requires a lowercase character.",
    status_detail: "Cognito user pool up-1 requires a lowercase character.",
    finding_info: { uid: "prowler-aws-cognito_user_pool_password_policy_lowercase-123456789012-us-east-1-up-1-KSI-IAM-APM" },
    metadata: { event_code: "cognito_user_pool_password_policy_lowercase", product: { name: "Prowler", version: "5.42.0" } },
    compliance: {
      standards: [PROWLER_OCSF_STANDARD],
      requirements: ["KSI-IAM-APM"],
      checks: [{ uid: "cognito_user_pool_password_policy_lowercase", status: "PASS" }],
    },
    resources: [{ uid: "arn:aws:cognito-idp:us-east-1:123456789012:userpool/up-1", region: "us-east-1" }],
    unmapped: { cloud: { account: { uid: "123456789012" }, region: "us-east-1" } },
    ...over,
  };
}

/**
 * The synthetic row Prowler writes for a requirement no check reaches
 * (`_build_manual_compliance_finding`). A DIFFERENT CONSTRUCTOR: no
 * `compliance.checks`, no `resources`, no `unmapped.cloud` — so a reader that
 * reaches for the check id on every row throws on exactly the thirteen
 * indicators §4c is about, which is why this fixture exists before the adapter.
 */
function manualRow(ksi: string, over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    class_uid: 2003,
    time: 1789689600,
    time_dt: "2026-09-18T10:00:00+00:00",
    status: "New",
    status_id: 1,
    status_code: "MANUAL",
    message: "Manual review required.",
    finding_info: { uid: `manual-${ksi}` },
    metadata: { event_code: "manual", product: { name: "Prowler", version: "5.42.0" } },
    compliance: { standards: [PROWLER_OCSF_STANDARD], requirements: [ksi] },
    ...over,
  };
}

describe("the Prowler OCSF reader (P3-1)", () => {
  it("groups reported rows by indicator, and carries §10a's fields off each row", () => {
    const doc = parseProwlerOcsf(
      [
        row(),
        row({
          finding_info: { uid: "prowler-aws-cognito_user_pool_password_policy_lowercase-123456789012-us-east-1-up-2-KSI-IAM-APM" },
          status_code: "FAIL",
          compliance: {
            standards: [PROWLER_OCSF_STANDARD],
            requirements: ["KSI-IAM-APM"],
            checks: [{ uid: "cognito_user_pool_password_policy_lowercase", status: "FAIL" }],
          },
        }),
      ],
      "scan.ocsf.json",
      ids,
    );

    // One check over two IAM users is TWO rows for one indicator (§10e) — the
    // reason P3-3 submits per (check, KSI) rather than per row.
    const rows = doc.byKsi.get("KSI-IAM-APM");
    expect(rows).toHaveLength(2);
    expect(rows?.map((r) => r.effectiveStatus)).toEqual(["PASS", "FAIL"]);
    expect(rows?.[0]?.checkId).toBe("cognito_user_pool_password_policy_lowercase");
    expect(rows?.[0]?.rawCheckStatus).toBe("PASS");
    expect(rows?.[0]?.muted).toBe(false);
    expect(rows?.[0]?.timestamp).toBe("2026-09-18T10:00:00+00:00");
    expect(doc.standard).toBe(PROWLER_OCSF_STANDARD);
    expect(doc.prowlerVersions).toEqual(["5.42.0"]);
    expect(doc.accounts).toEqual(["123456789012"]);
  });

  it("sets MANUAL rows aside: the indicator is absent from byKsi, not present and empty", () => {
    // THE #147 ARM, at the reader. `byKsi.get(ksi)` returning an empty array
    // would let an assertion over "no FAIL rows" pass over an indicator
    // nothing looked at; returning UNDEFINED means the adapter has nothing to
    // evaluate and must skip and name it instead.
    const doc = parseProwlerOcsf(
      [row(), manualRow("KSI-CED-RAT")],
      "scan.ocsf.json",
      ids,
    );
    expect(doc.byKsi.has("KSI-CED-RAT")).toBe(false);
    expect(doc.byKsi.get("KSI-CED-RAT")).toBeUndefined();
    expect(doc.manual).toEqual(["KSI-CED-RAT"]);
    expect(doc.byKsi.has("KSI-IAM-APM")).toBe(true);
  });

  it("reads the EFFECTIVE status, and records a config override disagreeing with the raw check (§10d)", () => {
    // A scan's own config can force a requirement to FAIL while the nested
    // check still reads PASS. Taking the nested one is the looser of the two
    // readings and would reintroduce exactly the hole upstream closed.
    const doc = parseProwlerOcsf(
      [
        row({
          status_code: "FAIL",
          message: `${CONFIG_NOT_VALID_PREFIX} max_unused_access_keys_days is 120.`,
          compliance: {
            standards: [PROWLER_OCSF_STANDARD],
            requirements: ["KSI-IAM-APM"],
            checks: [{ uid: "cognito_user_pool_password_policy_lowercase", status: "PASS" }],
          },
        }),
      ],
      "scan.ocsf.json",
      ids,
    );
    const only = doc.byKsi.get("KSI-IAM-APM")?.[0];
    expect(only?.effectiveStatus).toBe("FAIL");
    expect(only?.rawCheckStatus).toBe("PASS");
    expect(only?.configOverride).toBe(true);
  });

  it("reads muting off `status`, which is Suppressed and not a boolean (§10a)", () => {
    const doc = parseProwlerOcsf(
      [row({ status: "Suppressed", status_id: 3, status_code: "FAIL",
        compliance: {
          standards: [PROWLER_OCSF_STANDARD],
          requirements: ["KSI-IAM-APM"],
          checks: [{ uid: "cognito_user_pool_password_policy_lowercase", status: "FAIL" }],
        } })],
      "scan.ocsf.json",
      ids,
    );
    expect(doc.byKsi.get("KSI-IAM-APM")?.[0]?.muted).toBe(true);
  });

  describe("refusals — the documents that cannot be evaluated honestly", () => {
    it("refuses a document that is not an array", () => {
      expect(() => parseProwlerOcsf({ findings: [] }, "scan.ocsf.json", ids)).toThrow(
        /bare JSON array/,
      );
    });

    it("refuses an EMPTY array — no findings means no file, not zero findings", () => {
      expect(() => parseProwlerOcsf([], "scan.ocsf.json", ids)).toThrow(/no file at all/);
    });

    it("refuses a missing file rather than reading it as an unevidenced scan", async () => {
      const dir = await mkdtemp(join(tmpdir(), "rampscan-ocsf-"));
      await expect(loadProwlerOcsf(join(dir, "absent.ocsf.json"), ids)).rejects.toThrow(
        /no file at all/,
      );
    });

    it("refuses a standard that is not the framework this checkout pins", async () => {
      // The mapping rampscan resolves against must be the mapping the scan ran
      // with. `standards[0]` is `framework + "-" + version`, so a Prowler whose
      // framework moved arrives here as a refusal instead of as a join against
      // the wrong catalog.
      const dir = await mkdtemp(join(tmpdir(), "rampscan-ocsf-"));
      const path = join(dir, "scan.ocsf.json");
      await writeFile(
        path,
        JSON.stringify([
          row({
            compliance: {
              standards: ["FedRAMP-20x-KSI-2027.01.01.01"],
              requirements: ["KSI-IAM-APM"],
              checks: [{ uid: "cognito_user_pool_password_policy_lowercase", status: "PASS" }],
            },
          }),
        ]),
      );
      await expect(loadProwlerOcsf(path, ids)).rejects.toThrow(
        new RegExp(PROWLER_FRAMEWORK_PIN.version),
      );
    });

    it("refuses a KSI id that does not resolve at the dataset pin", () => {
      expect(() =>
        parseProwlerOcsf(
          [
            row({
              compliance: {
                standards: [PROWLER_OCSF_STANDARD],
                requirements: ["KSI-XXX-YYY"],
                checks: [{ uid: "cognito_user_pool_password_policy_lowercase", status: "PASS" }],
              },
            }),
          ],
          "scan.ocsf.json",
          ids,
        ),
      ).toThrow(/KSI-XXX-YYY/);
    });

    it("refuses a row carrying more than one requirement", () => {
      // §10a: one row per (finding × requirement). A row with two would mean
      // the emitter changed shape, and reading `requirements[0]` would then be
      // dropping an indicator per row rather than reading one.
      expect(() =>
        parseProwlerOcsf(
          [
            row({
              compliance: {
                standards: [PROWLER_OCSF_STANDARD],
                requirements: ["KSI-IAM-APM", "KSI-IAM-APM"],
                checks: [{ uid: "cognito_user_pool_password_policy_lowercase", status: "PASS" }],
              },
            }),
          ],
          "scan.ocsf.json",
          ids,
        ),
      ).toThrow(/one requirement/);
    });

    it("refuses a MANUAL row whose three markers disagree", () => {
      // §10a gives three independent markers. A row carrying one and not the
      // others is not a row this reader understands, and guessing which marker
      // wins is guessing whether thirteen indicators get evaluated.
      expect(() =>
        parseProwlerOcsf(
          [manualRow("KSI-CED-RAT", { metadata: { event_code: "cognito_user_pool_password_policy_lowercase", product: { name: "Prowler", version: "5.42.0" } } })],
          "scan.ocsf.json",
          ids,
        ),
      ).toThrow(/markers/);
    });

    it("refuses a reported row with no check to attribute it to", () => {
      expect(() =>
        parseProwlerOcsf(
          [
            row({
              compliance: {
                standards: [PROWLER_OCSF_STANDARD],
                requirements: ["KSI-IAM-APM"],
              },
            }),
          ],
          "scan.ocsf.json",
          ids,
        ),
      ).toThrow(/compliance\.checks/);
    });

    it("refuses a row whose check id and event_code name different checks", () => {
      expect(() =>
        parseProwlerOcsf(
          [
            row({
              compliance: {
                standards: [PROWLER_OCSF_STANDARD],
                requirements: ["KSI-IAM-APM"],
                checks: [{ uid: "cognito_user_pool_password_policy_number", status: "PASS" }],
              },
            }),
          ],
          "scan.ocsf.json",
          ids,
        ),
      ).toThrow(/cognito_user_pool_password_policy_lowercase/);
    });

    it("refuses two different standards in one document", () => {
      expect(() =>
        parseProwlerOcsf(
          [
            row(),
            row({
              compliance: {
                standards: ["FedRAMP-20x-KSI-2027.01.01.01"],
                requirements: ["KSI-IAM-APM"],
                checks: [{ uid: "cognito_user_pool_password_policy_lowercase", status: "PASS" }],
              },
            }),
          ],
          "scan.ocsf.json",
          ids,
        ),
      ).toThrow(/one standard/);
    });

    it("refuses a status_code outside PASS / FAIL / MANUAL", () => {
      expect(() =>
        parseProwlerOcsf([row({ status_code: "WARNING" })], "scan.ocsf.json", ids),
      ).toThrow(/WARNING/);
    });

    it("refuses a `status` outside New / Suppressed on a reported row", () => {
      expect(() =>
        parseProwlerOcsf([row({ status: "Other" })], "scan.ocsf.json", ids),
      ).toThrow(/Other/);
    });
  });
});
