import type { ScanResult } from "@rampscan/schema";

// The cache verifies itself (plan G2, SPEC's clause proven locally): a
// scheduled full scan re-runs every collector with the cache bypassed and
// diffs the joined result against the last incremental result at the same
// commit. Any divergence means the cache lied — a stale entry, a poisoned
// entry, or (the legitimate and important case) the world moved under a
// cached tool: a new advisory published to OSV/grype's DB, a tool upgraded
// on PATH. Either way the daemon alerts; silence is only earned by equality.

export interface ScanDivergence {
  recipeId: string;
  field: "verdict" | "assertions" | "missing-in-full" | "missing-in-incremental";
  full?: string;
  incremental?: string;
}

export interface ScanComparison {
  divergences: ScanDivergence[];
  /** tool versions that differ between the runs — context for the divergences */
  toolVersionChanges: Array<{ collector: string; full?: string; incremental?: string }>;
}

function assertionSummary(row: ScanResult["recipes"][number]): string {
  return row.assertions.map((a) => `${a.description}=${a.passed ? "pass" : "fail"}`).join("; ");
}

/**
 * Compare a full (cache-bypassed) scan against an incremental one at the
 * same commit. Throws if the commits differ — that comparison would be
 * meaningless, and the caller must guard it.
 */
export function diffScanResults(full: ScanResult, incremental: ScanResult): ScanComparison {
  if (full.commit !== incremental.commit) {
    throw new Error(
      `cannot compare scans of different commits (full ${full.commit.slice(0, 12)} vs incremental ${incremental.commit.slice(0, 12)})`,
    );
  }

  const divergences: ScanDivergence[] = [];
  const fullById = new Map(full.recipes.map((r) => [r.recipe_id, r]));
  const incById = new Map(incremental.recipes.map((r) => [r.recipe_id, r]));

  for (const [id, f] of fullById) {
    const i = incById.get(id);
    if (!i) {
      divergences.push({ recipeId: id, field: "missing-in-incremental", full: f.verdict });
      continue;
    }
    if (f.verdict !== i.verdict) {
      divergences.push({ recipeId: id, field: "verdict", full: f.verdict, incremental: i.verdict });
      continue;
    }
    const fa = assertionSummary(f);
    const ia = assertionSummary(i);
    if (fa !== ia) {
      divergences.push({ recipeId: id, field: "assertions", full: fa, incremental: ia });
    }
  }
  for (const id of incById.keys()) {
    if (!fullById.has(id)) {
      divergences.push({
        recipeId: id,
        field: "missing-in-full",
        incremental: incById.get(id)!.verdict,
      });
    }
  }

  const toolVersionChanges: ScanComparison["toolVersionChanges"] = [];
  const collectors = new Set([
    ...Object.keys(full.tool_versions),
    ...Object.keys(incremental.tool_versions),
  ]);
  for (const collector of collectors) {
    const fv = full.tool_versions[collector];
    const iv = incremental.tool_versions[collector];
    if (fv !== iv) {
      const change: ScanComparison["toolVersionChanges"][number] = { collector };
      if (fv !== undefined) change.full = fv;
      if (iv !== undefined) change.incremental = iv;
      toolVersionChanges.push(change);
    }
  }

  return { divergences, toolVersionChanges };
}
