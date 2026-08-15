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
 * The board's hop to the machinery (plan J3). One link per register row —
 * "how was this produced?" — resolved from what the row already carries after
 * the fold's catalog join, so the board needs no run data of its own and stays
 * folded from evidence and scoping alone.
 *
 * Two shapes, and the difference is the whole point:
 *
 *   evidenced / violated  the row names the run that produced it, so the hop
 *                         is exact: that scan, that collector.
 *   unevidenced           NO run produced this cell — that is what unevidenced
 *                         means. The honest target is the newest recorded run
 *                         for the repo, because that is where the collector's
 *                         skip reason lives, and this is precisely the row an
 *                         operator is staring at when they need it.
 *
 * `notApplicable` deliberately gets NO hop: a scoped-out cell was not produced
 * by a run and is not missing because of one — its provenance is the signed
 * scoping event already rendered on the row, and pointing at a scan here would
 * imply a run is why the cell reads n/a, which is false.
 */
export interface RunHop {
  href: string;
  /** the link's own text — the question this row actually raises */
  label: string;
  title: string;
}

export function runHop(row: {
  repo: string;
  state: string;
  collector: string;
  run_id: string;
}): RunHop | null {
  if (row.state === "notApplicable") return null;
  // nothing to point at: no run produced it and the catalog names no collector
  if (!row.run_id && !row.collector) return null;

  const q = new URLSearchParams();
  if (row.run_id) q.set("scan", row.run_id);
  else q.set("repo", row.repo);
  if (row.collector) q.set("collector", row.collector);

  const unevidenced = !row.run_id;
  return {
    href: `/runs?${q.toString()}`,
    label: unevidenced ? "why is this empty?" : "how was this produced?",
    title: unevidenced
      ? row.collector
        ? `no run produced this cell — open the newest recorded scan of ${row.repo} at the ${row.collector} collector, where the reason is stated`
        : `no run produced this cell — open the newest recorded scan of ${row.repo}`
      : row.collector
        ? `open run ${row.run_id} at the ${row.collector} collector — the tools, versions and argv behind this verdict`
        : `open run ${row.run_id} — the tools, versions and argv behind this verdict`,
  };
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
