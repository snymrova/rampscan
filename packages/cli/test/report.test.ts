import { describe, expect, it } from "vitest";
import type { ScanResult } from "@rampscan/schema";
import { generateFrontierReport } from "../src/index.js";

// FRONTIER-PIPELINE.md (G3): every number computed from the run it cites.
// The generator recounts from the recipe rows — it trusts nothing it can
// recompute — and the test recounts independently of the generator.

const result: ScanResult = {
  run_id: "run-2026-08-13T12-00-00-000Z-abc123",
  repo: "/home/x/rampscan",
  commit: "f".repeat(40),
  dataset_version: "2026-07-01",
  timestamp: "2026-08-13T12:00:00.000Z",
  tool_versions: { "repo-facts": "0.1.0", syft: "1.51.0" },
  skipped_collectors: [{ collector: "grype", reason: "no Dockerfile" }],
  recipes: [
    {
      recipe_id: "lockfile-pinned-deps",
      ksi_ids: ["KSI-SVC-01", "KSI-SCR-02"],
      control_ids: ["cm-2.2", "si-7.1"],
      collector: "repo-facts",
      verdict: "evidenced",
      assertions: [{ description: "lockfile present", passed: true }],
      artifacts: [{ name: "repo-facts.json", path: "repo-facts/repo-facts.json", sha256: "0".repeat(64) }],
      anchor_paths: [{ path: "package-lock.json", contentHash: "1".repeat(64) }],
    },
    {
      recipe_id: "no-secrets-in-history",
      ksi_ids: ["KSI-IAM-04"],
      control_ids: ["ia-5.7"],
      collector: "gitleaks",
      verdict: "violated",
      assertions: [{ description: "no leaks", passed: false, detail: "2 leaks" }],
      artifacts: [],
      anchor_paths: [],
    },
    {
      recipe_id: "container-base-image-patched",
      ksi_ids: ["KSI-SVC-03"],
      control_ids: ["si-2.1"],
      collector: "grype",
      verdict: "unevidenced",
      reason: "collector skipped: no Dockerfile",
      assertions: [],
      artifacts: [],
      anchor_paths: [],
    },
  ],
  findings: [],
  summary: { evidenced: 1, violated: 1, unevidenced: 1 },
};

describe("generateFrontierReport", () => {
  const doc = generateFrontierReport(result);

  it("cites its run and declares the computed-never-typed rule", () => {
    expect(doc).toContain(result.run_id);
    expect(doc).toContain("never typed");
    expect(doc).toContain(result.commit);
    expect(doc).toContain(result.dataset_version);
  });

  it("the register counts are recomputed from the rows and match an independent recount", () => {
    const evidenced = result.recipes.filter((r) => r.verdict === "evidenced").length;
    const violated = result.recipes.filter((r) => r.verdict === "violated").length;
    const unevidenced = result.recipes.filter((r) => r.verdict === "unevidenced").length;
    expect(doc).toContain(
      `Of **${result.recipes.length}** pipeline recipes: **${evidenced} evidenced**, **${violated} violated**, **${unevidenced} unevidenced**`,
    );
  });

  it("KSI/control coverage counts covered (evidenced+violated) against recipe-mapped totals", () => {
    // covered: lockfile (2 KSIs) + secrets (1 KSI) = 3 distinct; total adds grype's = 4
    expect(doc).toContain("**3 of 4** recipe-mapped KSIs");
    expect(doc).toContain("**3 of 4** recipe-mapped controls");
  });

  it("every register section lists its recipes; unevidenced rows say why", () => {
    expect(doc).toContain("### Evidenced (1)");
    expect(doc).toContain("### Violated (1)");
    expect(doc).toContain("### Unevidenced (1)");
    expect(doc).toContain("`container-base-image-patched`");
    expect(doc).toContain("collector skipped: no Dockerfile");
  });

  it("theme rollup, tool provenance, and skipped collectors are tabled", () => {
    expect(doc).toContain("| KSI-SVC | 1 | 0 | 1 |");
    expect(doc).toContain("| syft | 1.51.0 |");
    expect(doc).toContain("| grype | no Dockerfile |");
  });
});
