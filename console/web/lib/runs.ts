import type { CollectorRunRecord, ScanRunRecord, ToolResolutionRecord } from "./types";

// The run view (plan J2): pure derivations over the projected `scan_runs`
// collection. Everything here answers "what ran and how did it go" — and
// nothing here may answer "what is true about the repo". A run record states
// no verdict, no register state and no coverage number, so this module has no
// way to compute one; the board stays folded from evidence and scoping alone.
//
// The counts below are a PARTITION of the collectors a scan dispatched:
// ran + cacheHit + skipped === dispatched, always. That is what makes them
// attributable — a reader recounting the expanded table must reproduce the
// timeline row's summary, and overlapping buckets (counting a cache hit as
// "ran") would quietly break that recount.

export interface RunCounts {
  /** every collector the scan dispatched — the sum of the three below */
  dispatched: number;
  /** actually spawned work this run */
  ran: number;
  /** answered from cache: nothing was spawned, the recorded invocations are the producing run's */
  cacheHit: number;
  /** could not run at all, and said why */
  skipped: number;
}

export function runCounts(collectors: CollectorRunRecord[]): RunCounts {
  let ran = 0;
  let cacheHit = 0;
  let skipped = 0;
  for (const c of collectors) {
    if (c.skip_reason !== undefined) skipped += 1;
    else if (c.cache.state === "hit") cacheHit += 1;
    else ran += 1;
  }
  return { dispatched: collectors.length, ran, cacheHit, skipped };
}

/**
 * The one pill a collector row wears. Precedence is deliberate: a skip is the
 * loudest fact about a collector (it is the reason a board cell is
 * unevidenced), a cache hit is the next loudest (nothing was spawned), and
 * only then does how its tools resolved matter. `pure` is a collector that
 * asked for no external tool at all — repo-facts, graph, reachability — which
 * is a fact about the collector, never a missing tool.
 */
export type RunRuntimeKind = "skipped" | "cache-hit" | "docker" | "binary" | "absent" | "pure";

export function runtimeKind(c: CollectorRunRecord): RunRuntimeKind {
  if (c.skip_reason !== undefined) return "skipped";
  if (c.cache.state === "hit") return "cache-hit";
  if (c.tools.length === 0) return "pure";
  if (c.tools.some((t) => t.runtime.kind === "docker")) return "docker";
  if (c.tools.some((t) => t.runtime.kind === "binary")) return "binary";
  return "absent";
}

/** One tool's resolution, as the record states it — never a guess at a path. */
export function toolLabel(t: ToolResolutionRecord): string {
  const version = t.version ? `@${t.version}` : "";
  if (t.runtime.kind === "docker") return `${t.tool}${version} · ${t.runtime.image}`;
  if (t.runtime.kind === "binary") return `${t.tool}${version} · ${t.runtime.path ?? "on PATH"}`;
  return `${t.tool} · absent — ${t.runtime.reason}`;
}

/**
 * The digest a pinned docker tag actually resolved to, when the record
 * carries one. A tag is not a digest, so a tool that could not be asked
 * renders its stated reason instead of an invented value.
 */
export function imageDigestNote(t: ToolResolutionRecord): string | null {
  if (t.runtime.kind !== "docker") return null;
  return t.runtime.digest ?? `digest unresolved — ${t.runtime.digest_reason ?? "reason not stated"}`;
}

/** `syft scan dir:/abs -o json` — the invocation as a reader would type it. */
export function argvLine(inv: { command: string; argv: string[] }): string {
  return [inv.command, ...inv.argv].join(" ");
}

/** How many argv tokens the allowlist replaced — the redaction said out loud. */
export function redactionCount(c: CollectorRunRecord): number {
  let n = 0;
  for (const inv of c.invocations) {
    for (const token of inv.argv) if (token.includes("<redacted:")) n += 1;
  }
  return n;
}

/** Run-scale durations: milliseconds up to minutes, never a bare ms count for a 5-minute scan. */
export function formatRunDuration(ms: number): string {
  if (!Number.isFinite(ms) || ms < 0) return "—";
  if (ms < 1000) return `${Math.round(ms)} ms`;
  const seconds = ms / 1000;
  if (seconds < 60) return `${Math.round(seconds * 10) / 10}s`;
  const minutes = Math.floor(seconds / 60);
  return `${minutes}m ${Math.round(seconds - minutes * 60)}s`;
}

/**
 * Newest first — the order an operator reads a timeline in. Sorted on the
 * run's own clock (the same instant its bundles carry), with the run id as
 * the tiebreak so the order is total and stable across refolds.
 */
export function sortRuns(runs: ScanRunRecord[]): ScanRunRecord[] {
  return [...runs].sort(
    (a, b) => b.run_timestamp.localeCompare(a.run_timestamp) || b.run_id.localeCompare(a.run_id),
  );
}

/**
 * The collectors of one run, ordered so the rows that explain an unevidenced
 * board cell come first: skipped, then everything else alphabetically. A skip
 * buried at line 9 of an 11-row table is the failure mode this page exists to
 * fix.
 */
export function sortCollectors(collectors: CollectorRunRecord[]): CollectorRunRecord[] {
  return [...collectors].sort(
    (a, b) =>
      Number(b.skip_reason !== undefined) - Number(a.skip_reason !== undefined) ||
      a.collector.localeCompare(b.collector),
  );
}
