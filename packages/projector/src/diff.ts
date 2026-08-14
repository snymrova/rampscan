import type {
  LedgerEntry,
  RegisterChange,
  RegisterChangeKind,
  RegisterDiff,
  RegisterRow,
  RegisterState,
} from "@rampscan/core";
import { isEvidenceBundle } from "@rampscan/schema";

// "Since baseline" (plan I2d): the board diffed against a prior scan. Both
// sides are as-of folds of the same append-only ledger (I1b), so the diff is
// exactly as deterministic as the folds — one hand computes both boards AND
// the comparison; nothing here re-derives state a fold didn't already say.

/**
 * The ledger's scan instants, ascending. Every scan run stamps all its
 * bundles with one clock (the join's single `now`), so the distinct evidence
 * timestamps ARE the scans — no run id bookkeeping, no heuristic grouping.
 * Scoping events are not scans; they move the board between instants and the
 * as-of fold picks them up on whichever side of the baseline they landed.
 */
export function scanInstants(entries: LedgerEntry[]): string[] {
  const instants = new Set<string>();
  for (const entry of entries) {
    if (isEvidenceBundle(entry.bundle)) instants.add(entry.bundle.predicate.timestamp);
  }
  return [...instants].sort();
}

/**
 * Resolve a `--since` value to the baseline instant. `"previous"` means the
 * second-newest scan at or before `upTo` (default: newest overall) — the
 * board as it stood after the scan before the current one. Anything else is
 * taken as an explicit instant (the caller validates parseability). Throws
 * when the ledger does not record enough scans for a previous to exist —
 * an honest error, never a silent empty diff.
 */
export function resolveBaseline(entries: LedgerEntry[], since: string, upTo?: string): string {
  if (since !== "previous") return since;
  const scans = scanInstants(entries).filter((t) => upTo === undefined || t <= upTo);
  if (scans.length === 0) {
    throw new Error("the ledger records no scans — there is nothing to diff against");
  }
  if (scans.length === 1) {
    throw new Error(
      `the ledger records a single scan (${scans[0]}) — there is no previous scan to diff against`,
    );
  }
  return scans[scans.length - 2]!;
}

/** bad news first; the resolutions close the list */
export const CHANGE_KIND_SEVERITY: RegisterChangeKind[] = [
  "newly-violated",
  "evidence-lapsed",
  "unscoped",
  "removed",
  "appeared",
  "scoped",
  "newly-evidenced",
  "resolved",
];

/**
 * Classify one cell's movement from its two states. Total by construction:
 * every (from, to) pair with from ≠ to — including a missing side — lands on
 * exactly one kind. Callers never pass from === to (that is "unchanged").
 */
export function classifyChange(
  from: RegisterState | undefined,
  to: RegisterState | undefined,
): RegisterChangeKind {
  if (to === undefined) return "removed";
  if (to === "violated") return "newly-violated";
  if (from === undefined) return "appeared";
  if (to === "notApplicable") return "scoped";
  if (to === "evidenced") return from === "violated" ? "resolved" : "newly-evidenced";
  // to === "unevidenced"
  return from === "notApplicable" ? "unscoped" : "evidence-lapsed";
}

/**
 * Diff two register boards — typically `fold(ledger, { asOf: baseline })`
 * against the current fold. State-level: a cell whose evidence refreshed but
 * whose state held is unchanged here (the drift view narrates bundle-level
 * movement). Newly-violated changes carry the current row's fix pointers and
 * violated-streak fields (I2c) so the diff points at code, not just at rows.
 */
export function diffRegisters(
  baseline: RegisterRow[],
  current: RegisterRow[],
  baselineAsOf: string,
): RegisterDiff {
  const key = (r: RegisterRow) => `${r.repo} ${r.recipeId}`;
  const before = new Map(baseline.map((r) => [key(r), r]));
  const after = new Map(current.map((r) => [key(r), r]));

  const changes: RegisterChange[] = [];
  let unchanged = 0;
  for (const cell of new Set([...before.keys(), ...after.keys()])) {
    const b = before.get(cell);
    const c = after.get(cell);
    if (b && c && b.state === c.state) {
      unchanged++;
      continue;
    }
    const row = (c ?? b)!;
    const change: RegisterChange = {
      repo: row.repo,
      recipeId: row.recipeId,
      kind: classifyChange(b?.state, c?.state),
    };
    if (b) change.from = b.state;
    if (c) change.to = c.state;
    if (c?.bundleDigest) change.bundleDigest = c.bundleDigest;
    if (b?.bundleDigest) change.baselineDigest = b.bundleDigest;
    if (change.kind === "newly-violated" && c) {
      if (c.pointers) change.pointers = c.pointers;
      if (c.introducedAt) change.introducedAt = c.introducedAt;
      if (c.introducingCommit) change.introducingCommit = c.introducingCommit;
    }
    changes.push(change);
  }

  changes.sort(
    (a, b) =>
      CHANGE_KIND_SEVERITY.indexOf(a.kind) - CHANGE_KIND_SEVERITY.indexOf(b.kind) ||
      a.recipeId.localeCompare(b.recipeId) ||
      a.repo.localeCompare(b.repo),
  );
  const counts = Object.fromEntries(CHANGE_KIND_SEVERITY.map((k) => [k, 0])) as Record<
    RegisterChangeKind,
    number
  >;
  for (const change of changes) counts[change.kind]++;
  return { baseline: baselineAsOf, changes, counts, unchanged };
}
