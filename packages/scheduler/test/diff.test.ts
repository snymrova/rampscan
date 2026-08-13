import { describe, expect, it } from "vitest";
import type { ScanResult } from "@rampscan/schema";
import { diffScanResults } from "../src/index.js";

// The cache-verification diff: silence is only earned by equality.

function result(
  recipes: Array<{
    id: string;
    verdict: "evidenced" | "violated" | "unevidenced";
    assertions?: Array<{ description: string; passed: boolean }>;
  }>,
  overrides: Partial<ScanResult> = {},
): ScanResult {
  return {
    run_id: "run-test",
    repo: "/repo",
    commit: "c".repeat(40),
    dataset_version: "v1",
    timestamp: "2026-08-13T00:00:00.000Z",
    tool_versions: { "repo-facts": "0.1.0" },
    skipped_collectors: [],
    recipes: recipes.map((r) => ({
      recipe_id: r.id,
      ksi_ids: ["KSI-SVC-01"],
      control_ids: ["ac-2.1"],
      collector: "repo-facts",
      verdict: r.verdict,
      assertions: r.assertions ?? [],
      artifacts: [],
      anchor_paths: [],
    })),
    findings: [],
    summary: { evidenced: 0, violated: 0, unevidenced: 0 },
    ...overrides,
  };
}

describe("diffScanResults", () => {
  it("identical results → no divergence", () => {
    const a = result([{ id: "r1", verdict: "evidenced" }]);
    const b = result([{ id: "r1", verdict: "evidenced" }]);
    expect(diffScanResults(a, b).divergences).toEqual([]);
  });

  it("a verdict flip is a divergence", () => {
    const full = result([{ id: "r1", verdict: "violated" }]);
    const inc = result([{ id: "r1", verdict: "evidenced" }]);
    const cmp = diffScanResults(full, inc);
    expect(cmp.divergences).toEqual([
      { recipeId: "r1", field: "verdict", full: "violated", incremental: "evidenced" },
    ]);
  });

  it("same verdict, different assertion outcomes → divergence", () => {
    const full = result([
      { id: "r1", verdict: "violated", assertions: [{ description: "x", passed: false }] },
    ]);
    const inc = result([
      { id: "r1", verdict: "violated", assertions: [{ description: "x", passed: true }] },
    ]);
    expect(diffScanResults(full, inc).divergences[0]?.field).toBe("assertions");
  });

  it("recipes missing on either side are named", () => {
    const full = result([{ id: "only-full", verdict: "evidenced" }]);
    const inc = result([{ id: "only-inc", verdict: "evidenced" }]);
    const fields = diffScanResults(full, inc).divergences.map((d) => d.field).sort();
    expect(fields).toEqual(["missing-in-full", "missing-in-incremental"]);
  });

  it("tool version changes are surfaced as context", () => {
    const full = result([], { tool_versions: { syft: "1.52.0" } });
    const inc = result([], { tool_versions: { syft: "1.51.0" } });
    expect(diffScanResults(full, inc).toolVersionChanges).toEqual([
      { collector: "syft", full: "1.52.0", incremental: "1.51.0" },
    ]);
  });

  it("refuses to compare scans of different commits", () => {
    const full = result([], { commit: "a".repeat(40) });
    const inc = result([], { commit: "b".repeat(40) });
    expect(() => diffScanResults(full, inc)).toThrow(/different commits/);
  });
});
