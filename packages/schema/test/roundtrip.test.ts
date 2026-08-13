import { describe, expect, it } from "vitest";
import {
  EvidenceBundle,
  Finding,
  IN_TOTO_STATEMENT_TYPE,
  PipelineRecipe,
  RAMPSCAN_PREDICATE_TYPE,
} from "../src/index.js";

// A hand-written recipe — the M0 exit test: it must survive
// parse → serialize → parse unchanged.
const handWrittenRecipe = {
  id: "no-secrets-in-history",
  ksi_ids: ["KSI-SVC-KMG"],
  control_ids: ["ia-5.7", "sa-15"],
  evidence:
    "Full-history secret scan proving no credential material is present in any commit reachable from HEAD",
  collection: {
    kind: "pipeline" as const,
    collector: "gitleaks",
  },
  expected_output:
    "gitleaks JSON report; empty findings array when the history is clean",
  assertions: [
    {
      field: "findings",
      op: "count_eq" as const,
      value: 0,
      description: "No secret detections anywhere in reachable history.",
    },
  ],
  cadence: "weekly" as const,
  caveats:
    "Detection is pattern-based; a novel credential format can evade it. Entropy rules tuned per repo.",
  automatable: "full" as const,
  notes:
    "Runs against the full clone, not the working tree — a secret removed at HEAD but present in history still violates.",
  anchor: "commit" as const,
};

describe("PipelineRecipe", () => {
  it("round-trips a hand-written recipe", () => {
    const parsed = PipelineRecipe.parse(handWrittenRecipe);
    const again = PipelineRecipe.parse(JSON.parse(JSON.stringify(parsed)));
    expect(again).toEqual(parsed);
    expect(again).toEqual(handWrittenRecipe);
  });

  it("rejects the aws-evidence field it deliberately renamed", () => {
    const withGovcloud = {
      ...handWrittenRecipe,
      govcloud: "identical",
    } as Record<string, unknown>;
    // strict about shape: unknown keys are stripped, so the renamed field
    // must never silently survive under its old name
    const parsed = PipelineRecipe.parse(withGovcloud);
    expect("govcloud" in parsed).toBe(false);
  });

  it("rejects a non-pipeline collection kind", () => {
    expect(() =>
      PipelineRecipe.parse({
        ...handWrittenRecipe,
        collection: { kind: "cli", collector: "gitleaks" },
      }),
    ).toThrow();
  });

  it("rejects an anchor other than commit", () => {
    expect(() =>
      PipelineRecipe.parse({ ...handWrittenRecipe, anchor: "tag" }),
    ).toThrow();
  });
});

describe("Finding", () => {
  const finding = {
    id: "f-3c1a",
    variable: "secrets",
    anchor: {
      node: "config/.env",
      span: [3, 3] as [number, number],
      contentHash: "sha256:deadbeef",
    },
    severity: "blocker" as const,
    confidence: 1,
    summary: "AWS access key committed in config/.env",
    failureScenario:
      "Anyone with read access to the repository (or any clone of its history) can use the key to call AWS as the CI principal.",
    evidence: [
      {
        kind: "command" as const,
        command: "gitleaks detect --source . --report-format json",
        exitCode: 1,
        output: '{"RuleID":"aws-access-key-id",...}',
      },
    ],
    reproduce: "gitleaks detect --source . --log-opts=--all",
    provenance: { analyzer: "gitleaks", version: "8.21.0", runId: "run-001" },
    lifecycle: "new" as const,
    ksi_ids: ["KSI-SVC-KMG"],
    control_ids: ["ia-5.7"],
  };

  it("round-trips", () => {
    const parsed = Finding.parse(finding);
    expect(Finding.parse(JSON.parse(JSON.stringify(parsed)))).toEqual(parsed);
  });

  it("requires a failure scenario — no scenario, no finding", () => {
    expect(() => Finding.parse({ ...finding, failureScenario: "" })).toThrow();
  });

  it("requires a reason on suppression — never a bare ignore", () => {
    expect(() =>
      Finding.parse({
        ...finding,
        lifecycle: "suppressed",
        suppression: { reason: "", by: "sunny" },
      }),
    ).toThrow();
  });
});

describe("EvidenceBundle", () => {
  const bundle = {
    _type: IN_TOTO_STATEMENT_TYPE,
    subject: [{ name: "gitleaks-report.json", digest: { sha256: "ab12" } }],
    predicateType: RAMPSCAN_PREDICATE_TYPE,
    predicate: {
      recipe_id: "no-secrets-in-history",
      ksi_ids: ["KSI-SVC-KMG"],
      control_ids: ["ia-5.7", "sa-15"],
      verdict: "evidenced" as const,
      repo: "fixtures/vulnerable-app",
      commit: "0123456789abcdef0123456789abcdef01234567",
      anchor_paths: [{ path: ".", contentHash: "sha256:treehash" }],
      dataset_version: "2026.07.14.01",
      tool_versions: { gitleaks: "8.21.0" },
      assertions: [
        {
          description: "No secret detections anywhere in reachable history.",
          passed: true,
        },
      ],
      cadence: "weekly" as const,
      run_id: "run-001",
      timestamp: "2026-08-13T00:00:00Z",
    },
  };

  it("round-trips", () => {
    const parsed = EvidenceBundle.parse(bundle);
    expect(EvidenceBundle.parse(JSON.parse(JSON.stringify(parsed)))).toEqual(
      parsed,
    );
  });

  it("rejects a bundle with no subject — evidence without artifacts is a claim", () => {
    expect(() => EvidenceBundle.parse({ ...bundle, subject: [] })).toThrow();
  });
});
