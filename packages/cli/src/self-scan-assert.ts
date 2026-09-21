import type { Collector } from "@rampscan/core";
import type { ScanResult } from "@rampscan/schema";

// The self-scan's coverage assertion (docs/PLAN-REACH.md N1-1): the check
// the scheduled workflow runs over its own scan-result.json before it lets
// the run count.
//
// The failure it exists to catch is the quiet one. A collector whose tool is
// absent on the runner SKIPS — honestly, with a stated reason, exactly as the
// design says — and every recipe it answers stays `unevidenced`. On a
// developer's machine that is a fact about the machine. On the scheduled
// self-scan it is a coverage unit the clock silently stopped serving, and the
// north star would read lower for a reason nobody printed. So: every
// collector the manifest registers must either have RUN (its tool version is
// in the result) or be NAMED in `skipped_collectors` with its reason; and in
// the workflow's mode a skip whose reason is an absent tool is a failure,
// because the workflow pinned that tool and the pin did not hold.
//
// Pure over the result and the collector set, so the test can plant a run
// where one tool is deliberately absent and watch it fail.

export interface CoverageUnit {
  collector: string;
  /** the recipes the collector's manifest answers for */
  recipes: string[];
  state: "ran" | "skipped" | "missing";
  reason?: string;
  /** a skip whose reason is a tool that could not be resolved — the pin did not hold */
  absentTool: boolean;
}

export interface SelfScanAssessment {
  units: CoverageUnit[];
  /** collectors the result names neither as run nor as skipped — the silent kind */
  missing: string[];
  /** collectors skipped because their tool could not be resolved */
  blocked: string[];
  ok: boolean;
}

/** the shapes `absentReason` and the docker fallback write, matched rather than trusted */
const ABSENT_TOOL = /is not on PATH|is not installed|could not run|pins no image/i;

export function assessSelfScan(
  result: Pick<ScanResult, "tool_versions" | "skipped_collectors">,
  collectors: ReadonlyArray<Pick<Collector, "manifest">>,
  options: { requireTools: boolean },
): SelfScanAssessment {
  const skipped = new Map(result.skipped_collectors.map((s) => [s.collector, s.reason]));
  const ran = new Set(Object.keys(result.tool_versions));
  const units: CoverageUnit[] = collectors.map((c) => {
    const name = c.manifest.name;
    const recipes = [...c.manifest.recipes];
    const reason = skipped.get(name);
    if (reason !== undefined) {
      return { collector: name, recipes, state: "skipped", reason, absentTool: ABSENT_TOOL.test(reason) };
    }
    if (ran.has(name)) return { collector: name, recipes, state: "ran", absentTool: false };
    return { collector: name, recipes, state: "missing", absentTool: false };
  });
  const missing = units.filter((u) => u.state === "missing").map((u) => u.collector);
  const blocked = units.filter((u) => u.absentTool).map((u) => u.collector);
  const ok = missing.length === 0 && (!options.requireTools || blocked.length === 0);
  return { units, missing, blocked, ok };
}

export function renderSelfScanAssessment(a: SelfScanAssessment, requireTools: boolean): string {
  const lines: string[] = ["self-scan coverage — every registered collector, ran or named:"];
  for (const u of a.units) {
    const tag = u.state === "ran" ? "ran    " : u.state === "skipped" ? "skipped" : "MISSING";
    lines.push(
      `  ${tag}  ${u.collector.padEnd(18)} ${u.recipes.length} recipe(s)` +
        (u.reason !== undefined ? ` — ${u.reason}` : ""),
    );
  }
  if (a.missing.length > 0) {
    lines.push(`  ${a.missing.length} collector(s) neither ran nor named as skipped: ${a.missing.join(", ")} — the silent skip this check exists to refuse`);
  }
  if (a.blocked.length > 0) {
    lines.push(
      `  ${a.blocked.length} coverage unit(s) blocked by an absent tool: ${a.blocked.join(", ")}` +
        (requireTools ? " — the workflow pinned that tool and the pin did not hold (--require-tools)" : " — printed, not failed (no --require-tools)"),
    );
  }
  lines.push(a.ok ? "  ok" : "  FAILED");
  return lines.join("\n");
}
