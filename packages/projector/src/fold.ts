import type {
  CadenceGap,
  CoverageRow,
  DriftEvent,
  EvidenceStatus,
  LedgerEntry,
  LedgerStore,
  Projection,
  Projector,
  RegisterRow,
  RollupRow,
  ScanRunRow,
  ScopingInfo,
} from "@rampscan/core";
import type {
  EvidenceBundle,
  OffenderPointer,
  PipelineRecipe,
  ScanRun,
  ScopingEvent,
} from "@rampscan/schema";
import { isEvidenceBundle, isScanRun, isScopingEvent } from "@rampscan/schema";

// Projector v2 (plan M3): still a pure fold of the ledger — identical in
// prototype and appliance — now producing three things:
//
//   rows       every evidence bundle ever recorded, live or dead (M2 chains).
//              Two ways evidence dies, both computed, neither by memory:
//              superseded (newer bundle, same anchors) and anchor-drift (the
//              content this evidence is about changed — via its successor or
//              via ANY later bundle that observed one of its anchor paths).
//   registers  the coverage board: (repo, recipe) → current state, joined
//              against the recipe catalog so unevidenced recipes are VISIBLE
//              (the honest default), and against live scoping events so a
//              two-key notApplicable moves its row out of unevidenced.
//   drift      movement, computed from the chains: born / died /
//              verdict-flipped / scoped, each with its cause.

interface EvidenceEntry extends LedgerEntry {
  bundle: EvidenceBundle;
}
interface ScopingEntry extends LedgerEntry {
  bundle: ScopingEvent;
}
interface ScanRunEntry extends LedgerEntry {
  bundle: ScanRun;
}

/**
 * How many run records the projection carries (J1 decision 6). The ledger
 * keeps every one — the daemon appends one per cadence tick — but the
 * projection is rebuildable and drop-and-refilled, so an unbounded copy would
 * buy nothing and cost every refill. `/runs` reads the recent past; the
 * ledger answers anything older.
 */
export const SCAN_RUN_PROJECTION_CAP = 200;

function anchorKey(anchors: Array<{ path: string; contentHash: string }>): string {
  return JSON.stringify(
    [...anchors].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0)),
  );
}

/** the register row's pointer summary carries at most this many entries */
const MAX_REGISTER_POINTERS = 5;

/**
 * Fix pointers for a violated register row (I2c): the failing assertions'
 * offenders, deduplicated and bounded. Pre-I2c bundles carry no offenders and
 * yield [] — the row simply has no pointers until real drift re-keys it.
 */
function fixPointers(
  assertions: Array<{ passed: boolean; offenders?: OffenderPointer[] | undefined }>,
): OffenderPointer[] {
  const pointers: OffenderPointer[] = [];
  const seen = new Set<string>();
  for (const assertion of assertions) {
    if (assertion.passed) continue;
    for (const pointer of assertion.offenders ?? []) {
      const key = JSON.stringify([pointer.file, pointer.line, pointer.check, pointer.call_path]);
      if (seen.has(key)) continue;
      seen.add(key);
      pointers.push(pointer);
      if (pointers.length === MAX_REGISTER_POINTERS) return pointers;
    }
  }
  return pointers;
}

function byTime(a: LedgerEntry, b: LedgerEntry): number {
  const t = a.bundle.predicate.timestamp.localeCompare(b.bundle.predicate.timestamp);
  if (t !== 0) return t;
  const ap = a.appendedAt.localeCompare(b.appendedAt);
  if (ap !== 0) return ap;
  return a.digest.localeCompare(b.digest);
}

export interface FoldOptions {
  /**
   * The recipe catalog. When present, the registers include an `unevidenced`
   * row for every (scanned repo × recipe) with no live evidence and no live
   * scoping — projection × recipe set, the join the M2 board deferred.
   */
  recipes?: PipelineRecipe[];
  /**
   * Point-in-time fold (I1b): only statements whose predicate timestamp is at
   * or before this instant participate. Because the ledger is append-only,
   * the same asOf over the same ledger always folds to the same projection —
   * the deterministic replay the auditor's as-of selector rides on.
   */
  asOf?: string; // ISO 8601
  /**
   * The MVX window in ms (from the target cert class — b=7d, c=3d). When
   * present, the fold computes the cadence-adherence history (I1d): every
   * interval where a cell's evidence sat past 1.0 of the window unrefreshed.
   */
  windowMs?: number;
}

export function foldEntries(
  entries: LedgerEntry[],
  projectedAt: string,
  options: FoldOptions = {},
): Projection {
  const inScope = options.asOf
    ? entries.filter((e) => e.bundle.predicate.timestamp <= options.asOf!)
    : entries;
  const sorted = [...inScope].sort(byTime);
  const evidence = sorted.filter((e): e is EvidenceEntry => isEvidenceBundle(e.bundle));
  const scopings = sorted.filter((e): e is ScopingEntry => isScopingEvent(e.bundle));
  const scanRunEntries = sorted.filter((e): e is ScanRunEntry => isScanRun(e.bundle));

  // latest observation of every (repo, path): who saw this content last, when
  const pathObservations = new Map<
    string,
    { contentHash: string; commit: string; timestamp: string }
  >();
  for (const entry of evidence) {
    const p = entry.bundle.predicate;
    for (const anchor of p.anchor_paths) {
      // sorted order → later entries overwrite earlier ones
      pathObservations.set(`${p.repo} ${anchor.path}`, {
        contentHash: anchor.contentHash,
        commit: p.commit,
        timestamp: p.timestamp,
      });
    }
  }

  const groups = new Map<string, EvidenceEntry[]>();
  for (const entry of evidence) {
    const p = entry.bundle.predicate;
    const key = `${p.repo} ${p.recipe_id}`;
    (groups.get(key) ?? groups.set(key, []).get(key)!).push(entry);
  }

  const rows: CoverageRow[] = [];
  const drift: DriftEvent[] = [];
  // (repo, recipe) → the live tail of its chain, when it has one
  const liveByCell = new Map<string, EvidenceEntry>();

  for (const [cell, chain] of groups) {
    chain.forEach((entry, i) => {
      const p = entry.bundle.predicate;
      const successor = chain[i + 1];
      let status: EvidenceStatus;
      if (successor) {
        const q = successor.bundle.predicate;
        const drifted = anchorKey(p.anchor_paths) !== anchorKey(q.anchor_paths);
        const cause = drifted ? ("anchor-drift" as const) : ("superseded" as const);
        status = { state: "dead", cause, killingCommit: q.commit };
        drift.push({
          at: q.timestamp,
          repo: p.repo,
          recipeId: p.recipe_id,
          kind: q.verdict === p.verdict ? "died" : "verdict-flipped",
          cause,
          killingCommit: q.commit,
          from: p.verdict,
          to: q.verdict,
          bundleDigest: successor.digest,
        });
      } else {
        status = { state: "live" };
        // no successor — but did a later scan see any of our anchors change?
        for (const anchor of p.anchor_paths) {
          const seen = pathObservations.get(`${p.repo} ${anchor.path}`);
          if (seen && seen.timestamp > p.timestamp && seen.contentHash !== anchor.contentHash) {
            status = { state: "dead", cause: "anchor-drift", killingCommit: seen.commit };
            drift.push({
              at: seen.timestamp,
              repo: p.repo,
              recipeId: p.recipe_id,
              kind: "died",
              cause: "anchor-drift",
              killingCommit: seen.commit,
              from: p.verdict,
              bundleDigest: entry.digest,
            });
            break;
          }
        }
        if (status.state === "live") liveByCell.set(cell, entry);
      }
      if (i === 0) {
        drift.push({
          at: p.timestamp,
          repo: p.repo,
          recipeId: p.recipe_id,
          kind: "born",
          to: p.verdict,
          bundleDigest: entry.digest,
        });
      }
      rows.push({
        repo: p.repo,
        recipeId: p.recipe_id,
        ksiIds: p.ksi_ids,
        controlIds: p.control_ids,
        verdict: p.verdict,
        bundleDigest: entry.digest,
        status,
        freshAsOf: p.timestamp,
      });
    });
  }

  // live scoping per (repo, recipe): the latest wins; each one is drift
  const scopingByCell = new Map<string, ScopingEntry>();
  for (const entry of scopings) {
    const p = entry.bundle.predicate;
    scopingByCell.set(`${p.repo} ${p.recipe_id}`, entry); // sorted → latest wins
    drift.push({
      at: p.timestamp,
      repo: p.repo,
      recipeId: p.recipe_id,
      kind: "scoped",
      bundleDigest: entry.digest,
    });
  }

  // The registers: every (scanned repo × catalog recipe), plus any ledger
  // cell whose recipe fell out of the catalog — nothing recorded ever hides.
  const recipeById = new Map((options.recipes ?? []).map((r) => [r.id, r]));
  // Deliberately evidence + scoping only, NOT every statement: a run record
  // names a repo too, and letting it introduce register cells would make the
  // board partly a function of the run log. The board is folded from evidence
  // and scoping alone, and a scan run can never move a cell (J1's standing
  // rule — /runs renders runs, never states).
  const repos = [
    ...new Set([...evidence, ...scopings].map((e) => e.bundle.predicate.repo)),
  ].sort();
  const cells = new Set<string>();
  for (const repo of repos) {
    for (const id of recipeById.keys()) cells.add(`${repo} ${id}`);
  }
  for (const key of groups.keys()) cells.add(key);
  for (const key of scopingByCell.keys()) cells.add(key);

  const registers: RegisterRow[] = [];
  for (const cell of [...cells].sort()) {
    const sep = cell.lastIndexOf(" ");
    const repo = cell.slice(0, sep);
    const recipeId = cell.slice(sep + 1);
    const recipe = recipeById.get(recipeId);
    const live = liveByCell.get(cell);
    const scoping = scopingByCell.get(cell);
    const scopingInfo: ScopingInfo | undefined = scoping
      ? {
          digest: scoping.digest,
          justification: scoping.bundle.predicate.justification,
          proposedBy: scoping.bundle.predicate.proposed_by,
          approvedBy: scoping.bundle.predicate.approved_by,
          timestamp: scoping.bundle.predicate.timestamp,
        }
      : undefined;

    const row: RegisterRow = {
      repo,
      recipeId,
      ksiIds: recipe?.ksi_ids ?? live?.bundle.predicate.ksi_ids ??
        scoping?.bundle.predicate.ksi_ids ?? [],
      controlIds: recipe?.control_ids ?? live?.bundle.predicate.control_ids ??
        scoping?.bundle.predicate.control_ids ?? [],
      state: "unevidenced",
    };
    if (recipe?.cadence !== undefined) row.cadence = recipe.cadence;
    else if (live) row.cadence = live.bundle.predicate.cadence;

    if (live) {
      // evidence outranks scoping: a recipe producing real verdicts is not N/A
      const p = live.bundle.predicate;
      row.state = p.verdict;
      row.bundleDigest = live.digest;
      row.freshAsOf = p.timestamp;
      row.commit = p.commit;
      if (p.verdict === "violated") {
        // fix pointers (I2c): where the violation lives, lifted from the
        // live bundle's failing assertions — absent when the evidence
        // predates offenders (pre-I2c bundles), never invented
        const pointers = fixPointers(p.assertions);
        if (pointers.length > 0) row.pointers = pointers;
        // the current violated streak: walk the chain back to the first
        // consecutive violated bundle. The streak spans evidence gaps (the
        // chain only holds bundles) and breaks on a clean bundle; "first
        // scanned commit the violation appeared at" is the honest claim.
        const chain = groups.get(cell)!;
        let first = chain.length - 1; // live is the chain's tail
        while (first > 0 && chain[first - 1]!.bundle.predicate.verdict === "violated") first--;
        const intro = chain[first]!.bundle.predicate;
        row.introducedAt = intro.timestamp;
        row.introducingCommit = intro.commit;
      }
      if (scopingInfo) row.scoping = scopingInfo;
    } else if (scopingInfo) {
      row.state = "notApplicable";
      row.scoping = scopingInfo;
    }
    registers.push(row);
  }

  drift.sort((a, b) => a.at.localeCompare(b.at) || a.bundleDigest.localeCompare(b.bundleDigest));

  // Control + KSI registers (I1a): a fold OF the fold — rolled up from the
  // register rows so an independent recount from those rows always agrees.
  const controls = rollup(registers, (row) => row.controlIds);
  const ksis = rollup(registers, (row) => row.ksiIds);

  // Cadence-adherence history (I1d): bundle chains × the MVX window. Every
  // consecutive pair whose refresh landed after the window closed is a gap;
  // an unrefreshed tail whose window closed before projectedAt is an ongoing
  // one. Time comes from bundle timestamps and the fold's projectedAt — never
  // from a wall clock, so the same inputs always fold to the same gaps.
  const gaps: CadenceGap[] = [];
  if (options.windowMs !== undefined) {
    for (const chain of groups.values()) {
      chain.forEach((entry, i) => {
        const p = entry.bundle.predicate;
        const expiry = new Date(Date.parse(p.timestamp) + options.windowMs!).toISOString();
        const end = chain[i + 1]?.bundle.predicate.timestamp ?? projectedAt;
        if (end <= expiry) return;
        gaps.push({
          repo: p.repo,
          recipeId: p.recipe_id,
          bundleDigest: entry.digest,
          start: expiry,
          end,
          durationMs: Date.parse(end) - Date.parse(expiry),
          ongoing: chain[i + 1] === undefined,
        });
      });
    }
    gaps.sort(
      (a, b) =>
        a.repo.localeCompare(b.repo) ||
        a.recipeId.localeCompare(b.recipeId) ||
        a.start.localeCompare(b.start),
    );
  }

  // The run records (J1), newest first and capped. Structural — every field
  // is lifted straight off the signed predicate, nothing recomputed, because
  // a number this page derived itself would be a second answer about a run
  // that already stated its own.
  const scanRuns: ScanRunRow[] = scanRunEntries
    .slice(-SCAN_RUN_PROJECTION_CAP)
    .reverse()
    .map((entry) => {
      const p = entry.bundle.predicate;
      return {
        digest: entry.digest,
        runId: p.run_id,
        repo: p.repo,
        commit: p.commit,
        trigger: p.trigger,
        startedAt: p.started_at,
        timestamp: p.timestamp,
        durationMs: p.duration_ms,
        datasetVersion: p.dataset_version,
        collectors: p.collectors,
      };
    });

  const newest = sorted.at(-1);
  return {
    rows,
    registers,
    drift,
    controls,
    ksis,
    gaps,
    scanRuns,
    datasetVersion: newest?.bundle.predicate.dataset_version ?? "",
    projectedAt,
  };
}

/**
 * Roll register rows up by control or KSI id. Verdict precedence: violated
 * beats unevidenced beats evidenced; notApplicable never drags the rollup
 * down and wins only when every mapped recipe is scoped out.
 */
function rollup(registers: RegisterRow[], idsOf: (row: RegisterRow) => string[]): RollupRow[] {
  const cells = new Map<string, { repo: string; id: string; rows: RegisterRow[] }>();
  for (const row of registers) {
    for (const id of idsOf(row)) {
      const key = `${row.repo} ${id}`;
      (cells.get(key) ?? cells.set(key, { repo: row.repo, id, rows: [] }).get(key)!).rows.push(row);
    }
  }
  return [...cells.keys()].sort().map((key) => {
    const { repo, id, rows } = cells.get(key)!;
    const counts = {
      evidenced: rows.filter((r) => r.state === "evidenced").length,
      violated: rows.filter((r) => r.state === "violated").length,
      unevidenced: rows.filter((r) => r.state === "unevidenced").length,
      notApplicable: rows.filter((r) => r.state === "notApplicable").length,
      total: rows.length,
    };
    const state =
      counts.violated > 0
        ? ("violated" as const)
        : counts.unevidenced > 0
          ? ("unevidenced" as const)
          : counts.evidenced > 0
            ? ("evidenced" as const)
            : ("notApplicable" as const);
    return { repo, id, state, recipeIds: rows.map((r) => r.recipeId).sort(), counts };
  });
}

export interface ProjectorOptions extends FoldOptions {
  now?: () => Date;
}

export function createProjector(options: ProjectorOptions = {}): Projector {
  const now = options.now ?? (() => new Date());
  return {
    async fold(ledger: LedgerStore): Promise<Projection> {
      const foldOptions: FoldOptions = {};
      if (options.recipes) foldOptions.recipes = options.recipes;
      if (options.asOf !== undefined) foldOptions.asOf = options.asOf;
      if (options.windowMs !== undefined) foldOptions.windowMs = options.windowMs;
      return foldEntries(await ledger.list(), now().toISOString(), foldOptions);
    },
  };
}
