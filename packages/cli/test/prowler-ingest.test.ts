import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import { DEFAULT_DATASET_PIN, loadKsiCatalog } from "@rampscan/dataset";
import { IngestSubmission, submissionVerdict } from "@rampscan/schema";
import { loadPinnedProwlerFramework } from "../src/prowler-framework.js";
import type { ProwlerKsiFramework } from "../src/prowler-framework.js";
import { prowlerSubmissions } from "../src/prowler-ingest.js";
import type { ProwlerRunDeclaration } from "../src/prowler-ingest.js";
import { CONFIG_NOT_VALID_PREFIX, PROWLER_OCSF_STANDARD, parseProwlerOcsf } from "../src/prowler-ocsf.js";

// P3-3, P3-3a and P3-4 (docs/RESEARCH-PROWLER-INGEST.md §6): the adapter
// beyond the three soundness obligations, which live in
// `prowler-ingest-soundness.test.ts`.

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
let ids: readonly string[] = [];
let fw: ProwlerKsiFramework;

beforeAll(async () => {
  fw = await loadPinnedProwlerFramework(REPO_ROOT);
  const cat = await loadKsiCatalog({
    derivedDir: join(REPO_ROOT, "docs/context/ramprules/derived"),
    rulesFile: join(REPO_ROOT, "docs/context/fedramp-rules/fedramp-consolidated-rules.json"),
    pin: DEFAULT_DATASET_PIN,
  });
  ids = cat.ksis.map((k) => k.id);
});

const RUN: ProwlerRunDeclaration = {
  exit_code: 0,
  signer_identity: "runner:prowler@synthetic-csp",
  cadence: "daily",
  artifact: { name: "synthetic.ocsf.json", sha256: "a".repeat(64) },
};

let n = 0;
function row(
  ksi: string,
  check: string,
  status: "PASS" | "FAIL",
  over: Record<string, unknown> = {},
): Record<string, unknown> {
  n += 1;
  return {
    class_uid: 2003,
    time_dt: "2026-09-18T10:00:00+00:00",
    status: "New",
    status_id: 1,
    status_code: status,
    message: `${check}: ${status}`,
    finding_info: { uid: `prowler-aws-${check}-r${n}-${ksi}` },
    metadata: { event_code: check, product: { name: "Prowler", version: "5.42.0" } },
    compliance: {
      standards: [PROWLER_OCSF_STANDARD],
      requirements: [ksi],
      checks: [{ uid: check, status }],
    },
    unmapped: { cloud: { account: { uid: "123456789012" }, region: "us-east-1" } },
    ...over,
  };
}

describe("the Prowler adapter (P3-3)", () => {
  it("groups many rows into one submission per (check, KSI), each valid against the contract", () => {
    const doc = parseProwlerOcsf(
      [
        row("KSI-IAM-AAM", "iam_user_accesskey_unused", "PASS"),
        row("KSI-IAM-AAM", "iam_user_accesskey_unused", "PASS"),
        row("KSI-IAM-AAM", "iam_user_accesskey_unused", "PASS"),
        row("KSI-IAM-AAM", "iam_no_root_access_key", "PASS"),
      ],
      "t.json",
      ids,
    );
    const { submissions } = prowlerSubmissions(doc, RUN, fw);
    expect(submissions.map((s) => `${s.recipe_id}#${s.ksi}`)).toEqual([
      "iam_no_root_access_key#KSI-IAM-AAM",
      "iam_user_accesskey_unused#KSI-IAM-AAM",
    ]);
    for (const s of submissions) {
      expect(() => IngestSubmission.parse(s)).not.toThrow();
      expect(s.automated).toBe(true);
      expect(s.evidence_class).toBe("process-generated");
      expect(s.artifacts).toEqual([RUN.artifact]);
      expect(s.reproduce).toContain("--compliance fedramp_20x_ksi_2026");
      expect(s.reproduce).toContain("not recoverable");
    }
    const unused = submissions.find((s) => s.recipe_id === "iam_user_accesskey_unused")!;
    expect(unused.assertions[0]!.population).toBe(3);
    expect(submissionVerdict(unused)).toBe("evidenced");
  });

  it("reads the EFFECTIVE status: a config-forced FAIL over a raw PASS violates, and says so (§10d)", () => {
    const doc = parseProwlerOcsf(
      [
        row("KSI-IAM-APM", "cognito_user_pool_password_policy_lowercase", "FAIL", {
          message: `${CONFIG_NOT_VALID_PREFIX} threshold too loose`,
          compliance: {
            standards: [PROWLER_OCSF_STANDARD],
            requirements: ["KSI-IAM-APM"],
            checks: [{ uid: "cognito_user_pool_password_policy_lowercase", status: "PASS" }],
          },
        }),
      ],
      "t.json",
      ids,
    );
    const [s] = prowlerSubmissions(doc, RUN, fw).submissions;
    expect(submissionVerdict(s!)).toBe("violated");
    expect(s!.assertions[0]!.detail).toContain("forced to FAIL by the scan's own config");
  });
});

describe("the mapped-check coverage measure (P3-3a)", () => {
  it("states reported / mapped per KSI against the pinned framework's AWS list", () => {
    const doc = parseProwlerOcsf([row("KSI-IAM-AAM", "iam_no_root_access_key", "PASS")], "t.json", ids);
    const { coverage, notes, submissions } = prowlerSubmissions(doc, RUN, fw);
    const aam = coverage.find((c) => c.ksi === "KSI-IAM-AAM")!;
    expect(aam.mapped).toEqual(fw.requirements.find((r) => r.id === "KSI-IAM-AAM")!.checks.aws);
    expect(aam.reported).toEqual(["iam_no_root_access_key"]);
    // every KSI with an AWS mapping is measured, reported or not — 33 at this pin
    expect(coverage).toHaveLength(33);
    expect(coverage.find((c) => c.ksi === "KSI-SVC-SIN")!.reported).toEqual([]);
    expect(notes.join("\n")).toContain(`KSI-IAM-AAM coverage 1/${aam.mapped.length}`);
    expect(submissions[0]!.assertions[0]!.detail).toContain(`coverage 1/${aam.mapped.length}`);
  });
});

describe("muting and the provider guard (P3-4)", () => {
  it("a muted FAIL is counted, not waived — the verdict is violated and the mute is named", () => {
    const doc = parseProwlerOcsf(
      [
        row("KSI-IAM-AAM", "iam_user_accesskey_unused", "PASS"),
        row("KSI-IAM-AAM", "iam_user_accesskey_unused", "FAIL", { status: "Suppressed", status_id: 3 }),
      ],
      "t.json",
      ids,
    );
    const [s] = prowlerSubmissions(doc, RUN, fw).submissions;
    expect(submissionVerdict(s!)).toBe("violated");
    expect(s!.assertions[0]!.population).toBe(2);
    expect(s!.assertions[0]!.detail).toContain("1 muted and counted");
  });

  it("refuses a check the pinned framework maps on another provider, naming it", () => {
    const azure = fw.requirements.flatMap((r) => r.checks.azure.map((c) => [r.id, c] as const))
      .find(([ksi, c]) => !fw.requirements.find((r) => r.id === ksi)!.checks.aws.includes(c))!;
    const doc = parseProwlerOcsf([row(azure[0], azure[1], "PASS")], "t.json", ids);
    expect(() => prowlerSubmissions(doc, RUN, fw)).toThrow(/azure.*AWS provider only/);
  });

  it("refuses an account that is not a twelve-digit AWS account id", () => {
    const doc = parseProwlerOcsf(
      [
        row("KSI-IAM-AAM", "iam_no_root_access_key", "PASS", {
          unmapped: { cloud: { account: { uid: "sub-0000-azure" }, region: "eastus" } },
        }),
      ],
      "t.json",
      ids,
    );
    expect(() => prowlerSubmissions(doc, RUN, fw)).toThrow(/twelve-digit AWS account/);
  });

  it("refuses a MANUAL row on an indicator the pin maps AWS checks to", () => {
    const doc = parseProwlerOcsf(
      [
        row("KSI-IAM-AAM", "iam_no_root_access_key", "PASS"),
        {
          class_uid: 2003,
          time_dt: "2026-09-18T10:00:00+00:00",
          status: "New",
          status_id: 1,
          status_code: "MANUAL",
          finding_info: { uid: "manual-KSI-SVC-SIN" },
          metadata: { event_code: "manual", product: { name: "Prowler", version: "5.42.0" } },
          compliance: { standards: [PROWLER_OCSF_STANDARD], requirements: ["KSI-SVC-SIN"] },
        },
      ],
      "t.json",
      ids,
    );
    expect(() => prowlerSubmissions(doc, RUN, fw)).toThrow(/KSI-SVC-SIN arrives as a MANUAL row/);
  });
});
