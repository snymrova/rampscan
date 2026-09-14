import type { DatabaseSync } from "node:sqlite";
import type { ClaimBasis } from "@rampscan/schema";
import { applicationRootCoverage, excludedEntrypointCoverage, readGraphMeta } from "@rampscan/graph";
import type { ApplicationRootCoverage, ExcludedEntrypointCoverage } from "@rampscan/graph";

// The width of a walk (S1-3) — shared by every gate that makes a negative
// claim over graph.db. "Not reachable from the entry points" is only a
// statement about the repository when the entry points cover the repository;
// so a gate measures which application roots its walk entered, signs them
// with the claim, and refuses the negative for the whole run while any root
// was never entered. A graph that predates recorded roots has an unknown
// width, and an unknown width is not a full width.

/**
 * Why not_affected was refused for a run whose walk did not enter every
 * application root the tree declares. `subject` is what the walk missed —
 * "the package" for an advisory, "the file" for a SAST hit — and `counts` is
 * what therefore counts.
 */
export function scopeRefusalNote(
  unwalked: readonly ApplicationRootCoverage[],
  subject = "the package",
  counts = "the advisory",
): string {
  const named = unwalked
    .map((r) => `${r.dir}${r.name ? ` (${r.name}, ` : " ("}${r.file_count} file${r.file_count === 1 ? "" : "s"})`)
    .join(", ");
  return (
    `the walk from the declared entry points did not reach ${subject}, but the tree declares ` +
    `${unwalked.length === 1 ? "an application root" : `${unwalked.length} application roots`} no entry point covers — ${named} — ` +
    `so a negative claim would be scoped to part of the repository; not_affected is refused for this run and ${counts} counts`
  );
}

/**
 * Why not_affected was refused for a run whose config left out an entry point
 * detection found and the walk never reached (S1-4). Config is still honoured
 * for the walk; it is not honoured as a proof.
 */
export function excludedEntrypointsNote(
  unreached: readonly ExcludedEntrypointCoverage[],
  subject = "the package",
  counts = "the advisory",
): string {
  const named = unreached.map((e) => `${e.file} (${e.via}, under ${e.root})`).join(", ");
  return (
    `the walk from the configured entry points did not reach ${subject}, but detection found ` +
    `${unreached.length === 1 ? "an entry point" : `${unreached.length} entry points`} the config left out and the walk never arrived at — ${named} — ` +
    `so the program starts somewhere no walk began; not_affected is refused for this run and ${counts} counts`
  );
}

/** the refusal when a config-narrowed graph predates the record of what it narrowed away */
export function unrecordedExclusionsNote(counts = "every advisory"): string {
  return (
    "graph.db records configured entry points but not what detection found beside them (built by an extractor before 0.5.0), so the narrowing is unknown; " +
    `not_affected is refused for this run and ${counts} the walk did not reach counts`
  );
}

/** the advisory gate's spelling of the unrecorded-exclusions refusal */
export const UNRECORDED_EXCLUSIONS_NOTE = unrecordedExclusionsNote();

/** the refusal when the graph predates recorded application roots */
export function unrecordedRootsNote(counts = "every advisory"): string {
  return (
    "graph.db records no application roots (built by an extractor before 0.3.0), so the width of the walk is unknown; " +
    `not_affected is refused for this run and ${counts} the walk did not reach counts`
  );
}

/** the advisory gate's spelling of the unrecorded-roots refusal */
export const UNRECORDED_ROOTS_NOTE = unrecordedRootsNote();

/**
 * The scope of a claim as structured fields (S1-3): the same facts the
 * signed basis holds, in the shape an OpenVEX statement carries them under
 * `rampscan:scope` — a prefixed key, because the OpenVEX statement vocabulary
 * is closed and a bare `scope` would read as one of its own terms.
 */
export interface ClaimScope {
  commit: string;
  entrypoints: string[];
  entrypoint_source: string;
  application_roots?: Array<{ dir: string; name?: string; walked: boolean }>;
  entrypoints_excluded?: Array<{ file: string; via: string; root: string; reached: boolean }>;
}

export interface WalkWidth {
  /** what every statement of the run says about how wide the walk was */
  scope: ClaimScope;
  /** set when the negative is refused for the run; the row note and `basis.degraded` */
  refusal?: string;
}

/**
 * Measure the width of the gating walk over an open graph.db and record it on
 * the basis: `application_roots` when the graph knows them, `degraded` when
 * the negative has to be refused. Call only when the walk actually ran (entry
 * points exist) — a degraded gate has its own note already.
 */
export function walkWidth(
  db: DatabaseSync,
  basis: ClaimBasis,
  wording: { subject: string; counts: string; countsAll: string },
): WalkWidth {
  const meta = readGraphMeta(db);
  const scope: ClaimScope = {
    commit: meta.commit,
    entrypoints: meta.entrypoints,
    entrypoint_source: meta.entrypointSource,
  };
  const coverage = applicationRootCoverage(db);
  let refusal: string | undefined;
  if (coverage === undefined) {
    refusal = unrecordedRootsNote(wording.countsAll);
  } else {
    basis.application_roots = coverage;
    scope.application_roots = coverage.map((r) => ({
      dir: r.dir,
      ...(r.name !== undefined ? { name: r.name } : {}),
      walked: r.reached_file_count > 0,
    }));
    const unwalked = coverage.filter((r) => r.reached_file_count === 0);
    if (unwalked.length > 0) refusal = scopeRefusalNote(unwalked, wording.subject, wording.counts);
  }
  // the other half of the width (S1-4): not only which applications the walk
  // entered, but which of their entry points it was told to ignore. Recorded
  // whenever the graph knows; a refusal only where the walk never got there
  // — an excluded entry the configured walk reaches anyway narrowed nothing
  const excluded = excludedEntrypointCoverage(db);
  if (excluded === undefined) {
    refusal ??= unrecordedExclusionsNote(wording.countsAll);
  } else if (excluded.length > 0) {
    basis.entrypoints_excluded = excluded;
    scope.entrypoints_excluded = excluded;
    const unreached = excluded.filter((e) => !e.reached);
    if (unreached.length > 0) refusal ??= excludedEntrypointsNote(unreached, wording.subject, wording.counts);
  }
  if (refusal !== undefined) basis.degraded = refusal;
  return refusal !== undefined ? { scope, refusal } : { scope };
}
