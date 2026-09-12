import type {
  ArtifactCell,
  CadenceGap,
  ClockWindow,
  CoverageRow,
  DriftEvent,
  EvidenceStatus,
  LedgerEntry,
  LedgerStore,
  MethodCell,
  MethodRegisterRow,
  Projection,
  Projector,
  RegisterRow,
  RollupRow,
  ScanRunRow,
  ScopingInfo,
  ValidationVulnerability,
} from "@rampscan/core";
import type {
  ArtifactJudgment,
  Attestation,
  EvidenceBundle,
  OffenderPointer,
  PipelineRecipe,
  ScanRun,
  ScopingEvent,
  ValidationMethod,
} from "@rampscan/schema";
import {
  isArtifactJudgment,
  isAttestation,
  isEvidenceBundle,
  isScanRun,
  isScopingEvent,
  methodOfAttestation,
} from "@rampscan/schema";

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
interface ArtifactJudgmentEntry extends LedgerEntry {
  bundle: ArtifactJudgment;
}
interface AttestationEntry extends LedgerEntry {
  bundle: Attestation;
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
  /**
   * The derived method register (Q2.3, SPEC §12.2): `deriveCatalogMethods`'
   * output, passed in like the recipe catalog — the fold joins, it never
   * derives, so the register stays a function of reviewed artifacts the
   * caller can name.
   */
  methods?: ValidationMethod[];
  /**
   * The owed catalog's KSI ids (46 at the pin). When present, every scanned
   * repo gets a method-register row for every one of them — a KSI no method
   * touches is a G1 row, never an absent row (invariant 4′).
   */
  ksiIds?: string[];
  /**
   * The FRC-CSX-VVK floor for the configured class — owed-side DATA
   * (`KsiCatalog.floors[class].minPerKsi`), never typed here. Null when the
   * class owes no number (class a).
   */
  methodFloor?: number | null;
  /**
   * The FRC-CSX-MOT history floor for the configured class, in months —
   * owed-side DATA (`KsiCatalog.historyFloors[class].months`), never typed
   * here. Null when the class owes no number (a and b: unquantified).
   */
  historyFloorMonths?: number | null;
  /**
   * The VDR-TFR-MVX window for the configured class (Q3.2) — owed-side DATA
   * (`KsiCatalog.windows[class]`, number and unit only), never typed here.
   * Null when the rules define none (class d — SPEC §11 q6): machine-clock
   * methods then get no freshness judgment, honestly, rather than a window
   * borrowed from a class the offering is not.
   */
  machineWindow?: ClockWindow | null;
  /**
   * The VDR-TFR-NMV window (Q3.2) — owed-side DATA
   * (`KsiCatalog.nonMachineWindow`), flat across classes, in months.
   */
  nonMachineWindow?: ClockWindow | null;
}

/**
 * The instant `months` calendar months before `iso`, day clamped so the
 * subtraction never rolls into an adjacent month (Mar 31 − 1mo → Feb 28).
 * Calendar arithmetic because FRC-CSX-MOT says "the past N months" — a
 * 30-day approximation would judge a legal floor met up to ~3 days early
 * at 18 months. Pure: same inputs, same instant, on every fold.
 */
export function monthsBefore(iso: string, months: number): string {
  const d = new Date(iso);
  const day = d.getUTCDate();
  d.setUTCDate(1);
  d.setUTCMonth(d.getUTCMonth() - months);
  const lastDay = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth() + 1, 0)).getUTCDate();
  d.setUTCDate(Math.min(day, lastDay));
  return d.toISOString();
}

/**
 * The instant one owed window before `iso` (Q3.2): evidence timestamped at
 * or after it is inside the window. Days are exact ms arithmetic; months go
 * through `monthsBefore` — VDR-TFR-NMV says "every 3 months", and the same
 * calendar honesty that G4 owes FRC-CSX-MOT applies here.
 */
export function windowThreshold(iso: string, window: ClockWindow): string {
  if (window.unit === "days") {
    return new Date(Date.parse(iso) - window.num * 86_400_000).toISOString();
  }
  return monthsBefore(iso, window.num);
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
  const judgments = sorted.filter((e): e is ArtifactJudgmentEntry =>
    isArtifactJudgment(e.bundle),
  );
  const attestations = sorted.filter((e): e is AttestationEntry => isAttestation(e.bundle));

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

  // Live artifact judgment per (repo, KSI, artifact) — Q3.3, G5. Sorted
  // order → the latest wins, which is also how a judgment is withdrawn: a
  // signed `insufficient` supersedes, never a deletion.
  const judgmentByCell = new Map<string, ArtifactJudgmentEntry>();
  for (const entry of judgments) {
    const p = entry.bundle.predicate;
    judgmentByCell.set(`${p.repo} ${p.ksi_id} ${p.artifact}`, entry);
  }

  // Live attestation per (repo, statement_id, KSI) — Q4.2, SPEC §12.9. Sorted
  // order → the latest wins, so a signed `withdrawn` retracts a standing
  // claim by superseding it, never by deletion. The withdrawn entry stays in
  // the map: the cell below reads its action, because "this was attested and
  // then retracted" and "this was never attested" are different facts, and
  // only the first of them has a method to stop deriving.
  const attestationByCell = new Map<string, AttestationEntry>();
  for (const entry of attestations) {
    const p = entry.bundle.predicate;
    attestationByCell.set(`${p.repo} ${p.statement_id} ${p.ksi_id}`, entry);
  }

  // The registers: every (scanned repo × catalog recipe), plus any ledger
  // cell whose recipe fell out of the catalog — nothing recorded ever hides.
  const recipeById = new Map((options.recipes ?? []).map((r) => [r.id, r]));
  // Deliberately evidence + the three two-key statements (scoping, artifact
  // judgment, attestation), NOT every statement: a run record names a repo
  // too, and letting it introduce register cells would make the board partly a
  // function of the run log. The board is folded from evidence and signed
  // decisions alone, and a scan run can never move a cell (J1's standing
  // rule — /runs renders runs, never states). An attestation belongs in this
  // set for the Q4.2 reason: for an acts-on-people KSI it may be the only
  // validation that exists, and a repo whose register rests on one would
  // otherwise have no rows at all.
  const repos = [
    ...new Set(
      [...evidence, ...scopings, ...judgments, ...attestations].map((e) => e.bundle.predicate.repo),
    ),
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
    // The catalog join's third field (J3): which collector is supposed to
    // evidence this recipe. Stated only when the catalog says so — a cell
    // whose recipe is gone gets no collector, and the board's hop for it
    // simply does not render rather than pointing somewhere invented.
    if (recipe?.collection.collector !== undefined) row.collector = recipe.collection.collector;
    // The catalog join's fourth field (K1): the recipe's plain-language
    // paragraphs. Same rule as the collector — stated only when the catalog
    // states it. A cell whose recipe is gone gets no prose, because the only
    // alternative is prose about a different recipe or prose invented here,
    // and this file computes; it does not write English.
    if (recipe?.plain !== undefined) row.plain = recipe.plain;

    if (live) {
      // evidence outranks scoping: a recipe producing real verdicts is not N/A
      const p = live.bundle.predicate;
      row.state = p.verdict;
      row.bundleDigest = live.digest;
      row.freshAsOf = p.timestamp;
      row.commit = p.commit;
      // the run that produced THIS evidence, from the predicate's own claim
      row.runId = p.run_id;
      // the domain the verdict was reached over (N0-T1), lifted from the
      // signed assertions. Every assertion of a recipe saw the same
      // observation set, so the first one that states a population states the
      // row's; a bundle minted before N0 states none and the row carries none.
      const population = p.assertions.find((a) => a.population !== undefined)?.population;
      if (population !== undefined) row.population = population;
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

  // The method register (Q2.3): (repo, KSI) → derived methods joined to the
  // register rows they evidence through. A pipeline method's state IS its
  // recipe cell's state — one bundle evidences every method its recipe
  // derives (§1.1 decision (b), rendered at fold time). G1 and G2 are
  // properties of the register itself: computed from which methods exist,
  // not from what the ledger holds. Missing or stale evidence is G3 (Q3.2):
  // each method judged against its own clock family's owed window.
  const methodRegisters: MethodRegisterRow[] = [];
  if (options.methods !== undefined) {
    const methodsByKsi = new Map<string, ValidationMethod[]>();
    for (const method of options.methods) {
      (methodsByKsi.get(method.ksi) ?? methodsByKsi.set(method.ksi, []).get(method.ksi)!).push(
        method,
      );
    }
    // The attestation leg (Q4.2, SPEC §12.9) is LEDGER-derived, not handed in:
    // the catalog cannot carry these, because a human attestation is not a
    // recipe. Keyed by repo as well as KSI — an attestation is about one
    // offering, where a pipeline method applies to every repo the catalog is
    // scanned against. A `withdrawn` claim yields nothing: the supersession
    // above already picked the live event per (repo, statement_id, KSI), and
    // `methodOfAttestation` refuses a retracted one outright.
    const attestationMethodsByCell = new Map<string, ValidationMethod[]>();
    const attestationEntryByMethod = new Map<string, AttestationEntry>();
    const attestationKsis = new Set<string>();
    for (const entry of attestationByCell.values()) {
      const p = entry.bundle.predicate;
      if (p.action !== "attested") continue;
      const method = methodOfAttestation(entry.bundle);
      const cellKey = `${p.repo} ${p.ksi_id}`;
      (
        attestationMethodsByCell.get(cellKey) ??
        attestationMethodsByCell.set(cellKey, []).get(cellKey)!
      ).push(method);
      attestationEntryByMethod.set(`${p.repo} ${method.id}`, entry);
      attestationKsis.add(p.ksi_id);
    }
    const ksiUniverse = [
      ...new Set([...(options.ksiIds ?? []), ...methodsByKsi.keys(), ...attestationKsis]),
    ].sort();
    const registerByCell = new Map(registers.map((r) => [`${r.repo} ${r.recipeId}`, r]));
    const floor = options.methodFloor ?? null;
    const historyFloor = options.historyFloorMonths ?? null;
    // the FRC-CSX-MOT threshold instant, computed once per fold: history
    // reaching at or before it satisfies the floor (Q3.1)
    const historyThreshold =
      historyFloor === null ? null : monthsBefore(projectedAt, historyFloor);
    // The owed windows per clock family (Q3.2), and their threshold instants
    // computed once per fold: evidence at or after a threshold is fresh.
    // Stripped to number + unit even when a caller hands the catalog's own
    // richer object — the projection's bytes carry the judged fact, and the
    // rule id stays on the owed side where it lives.
    const strip = (w: ClockWindow | null | undefined): ClockWindow | null =>
      w == null ? null : { num: w.num, unit: w.unit };
    const windowByClock: Record<"machine" | "non-machine", ClockWindow | null> = {
      machine: strip(options.machineWindow),
      "non-machine": strip(options.nonMachineWindow),
    };
    const thresholdByClock = {
      machine:
        windowByClock.machine === null
          ? null
          : windowThreshold(projectedAt, windowByClock.machine),
      "non-machine":
        windowByClock["non-machine"] === null
          ? null
          : windowThreshold(projectedAt, windowByClock["non-machine"]),
    };
    for (const repo of repos) {
      for (const ksi of ksiUniverse) {
        const cells: MethodCell[] = [
          ...(methodsByKsi.get(ksi) ?? []),
          ...(attestationMethodsByCell.get(`${repo} ${ksi}`) ?? []),
        ]
          .sort((a, b) => a.id.localeCompare(b.id))
          .map((method) => {
            const window = windowByClock[method.clock];
            const cell: MethodCell = {
              methodId: method.id,
              source: method.source,
              automated: method.automated,
              clock: method.clock,
              standing: method.standing,
              state: "unevidenced",
              window,
              freshMet: null,
            };
            if (method.source === "pipeline") {
              cell.recipeId = method.provenance.recipe_id;
              cell.collector = method.provenance.collector;
              cell.scope = method.provenance.scope;
              const row = registerByCell.get(`${repo} ${method.provenance.recipe_id}`);
              if (row !== undefined) {
                cell.state = row.state;
                if (row.bundleDigest !== undefined) cell.bundleDigest = row.bundleDigest;
                if (row.freshAsOf !== undefined) cell.freshAsOf = row.freshAsOf;
              }
              // G6 (Q3.4): the evidence-class assertion, lifted from the live
              // bundle's signed predicate. A bundle minted before the
              // assertion carries none and the cell carries none — this fold
              // states what was signed, never what a convention implies.
              const live = liveByCell.get(`${repo} ${method.provenance.recipe_id}`);
              const evidenceClass = live?.bundle.predicate.evidence_class;
              if (evidenceClass !== undefined) cell.evidenceClass = evidenceClass;
            }
            if (method.source === "attestation") {
              // An attestation has no evidence chain to join: the signed
              // event IS the evidence, so its own timestamp is the instant
              // the VDR-TFR-NMV clock below judges. Without this arm a
              // non-machine method could never be fresh, and putting the
              // path on a clock would be decoration.
              //
              // No `evidenceClass`: G6 asserts whether a MACHINE process is
              // repeatable or a captured state, and a human statement makes
              // no such claim. An unlabeled cell neither triggers G6 nor
              // defends against it, which is the honest reading — what this
              // method is, `automated: false` and `standing: narrative`
              // already say.
              const live = attestationEntryByMethod.get(`${repo} ${method.id}`);
              if (live !== undefined) {
                cell.state = "evidenced";
                cell.bundleDigest = live.digest;
                cell.freshAsOf = live.bundle.predicate.timestamp;
              }
            }
            // G3 per method (Q3.2): the owed clock, judged at projectedAt.
            // Missing evidence is false, not null — nothing is re-validating
            // this method at any cadence; null is reserved for "no window
            // owed" and for a live two-key scoping (a signed N/A is not a
            // lapsed clock), which are different facts.
            const threshold = thresholdByClock[method.clock];
            if (threshold !== null && cell.state !== "notApplicable") {
              cell.freshMet = cell.freshAsOf !== undefined && cell.freshAsOf >= threshold;
            }
            return cell;
          });
        const automatedMethods = cells.filter((c) => c.automated).length;
        // G3 freshness (Q3.2): methods whose owed clock is unmet — stale OR
        // missing evidence, per the cell judgment above
        const staleMethods = cells.filter((c) => c.freshMet === false).length;
        // G6 evidence class (Q3.4, FRR-PVA-AA-06): point-in-time evidence is
        // rejectable as STANDALONE evidence, so the gap is standing-alone —
        // at least one cell asserting point-in-time and none asserting
        // process-generated beside it. Unlabeled cells (pre-Q3.4 bundles, or
        // no live evidence) neither trigger nor defend: an assertion that was
        // never signed cannot be relied on in either direction.
        const pointInTimeMethods = cells.filter(
          (c) => c.evidenceClass === "point-in-time",
        ).length;
        const processMethods = cells.filter(
          (c) => c.evidenceClass === "process-generated",
        ).length;
        // G4 history (Q3.1): where this KSI's validation history begins —
        // the earliest bundle across its methods' chains, dead bundles
        // included, because the superseded record IS the history the
        // FRC-CSX-MOT meter counts. The data was always in the ledger;
        // this is the counting.
        let historySince: string | undefined;
        for (const cell of cells) {
          if (cell.recipeId === undefined) continue;
          const first = groups.get(`${repo} ${cell.recipeId}`)?.[0];
          const t = first?.bundle.predicate.timestamp;
          if (t !== undefined && (historySince === undefined || t < historySince)) {
            historySince = t;
          }
        }
        // G5 artifacts (Q3.3): the five owed artifacts per KSI, ascending.
        // Presence is mechanical for 2 and 5 — artifact 5 IS the methods'
        // own live evidence (a violated verdict still counts: the validation
        // record exists; what it says is G13's business), artifact 2 the
        // cadence record the scheduler already keeps (a declared cadence on
        // an evidenced method — a cycle declared over evidence that does not
        // exist explains the cycle of nothing). Sufficiency of 1, 3, and 4
        // is judgment: present only while the live two-key event says
        // sufficient, and never a checkbox. Artifact 4 (accuracy of the
        // measurement system) is where the #23 class of defect lives.
        const judged = (n: 1 | 3 | 4): ArtifactCell => {
          const entry = judgmentByCell.get(`${repo} ${ksi} ${n}`);
          const cell: ArtifactCell = {
            artifact: n,
            basis: "judged",
            present: entry?.bundle.predicate.action === "sufficient",
          };
          if (entry !== undefined) {
            const p = entry.bundle.predicate;
            cell.judgment = {
              digest: entry.digest,
              action: p.action,
              justification: p.justification,
              proposedBy: p.proposed_by,
              approvedBy: p.approved_by,
              timestamp: p.timestamp,
            };
          }
          return cell;
        };
        const evidencedCells = cells.filter((c) => c.bundleDigest !== undefined);
        const artifacts: ArtifactCell[] = [
          judged(1),
          {
            artifact: 2,
            basis: "computed",
            present: evidencedCells.some(
              (c) =>
                c.recipeId !== undefined &&
                registerByCell.get(`${repo} ${c.recipeId}`)?.cadence !== undefined,
            ),
          },
          judged(3),
          judged(4),
          { artifact: 5, basis: "computed", present: evidencedCells.length > 0 },
        ];
        const artifactsPresent = artifacts.filter((a) => a.present).length;
        const row: MethodRegisterRow = {
          repo,
          ksi,
          methods: cells,
          automatedMethods,
          methodFloor: floor,
          floorMet: floor === null ? null : automatedMethods >= floor,
          staleMethods,
          historyFloorMonths: historyFloor,
          historyMet:
            historyThreshold === null
              ? null
              : historySince !== undefined && historySince <= historyThreshold,
          artifacts,
          artifactsPresent,
          pointInTimeMethods,
        };
        if (historySince !== undefined) row.historySince = historySince;
        const freshAsOf = cells
          .map((c) => c.freshAsOf)
          .filter((t): t is string => t !== undefined)
          .sort()
          .at(-1);
        if (freshAsOf !== undefined) row.freshAsOf = freshAsOf;
        if (cells.length === 0) row.gap = "G1";
        else if (floor !== null && automatedMethods < floor) row.gap = "G2";
        else if (staleMethods > 0) row.gap = "G3";
        else if (row.historyMet === false) row.gap = "G4";
        else if (artifactsPresent < 5) row.gap = "G5";
        else if (pointInTimeMethods > 0 && processMethods === 0) row.gap = "G6";
        methodRegisters.push(row);
      }
    }
  }

  // The failure→vulnerability feed (Q3.5, G13 — VDR-CSO-FAV): a failed
  // validation is a vulnerability with detection-and-response obligations,
  // so every episode of a cell standing `violated` becomes a record here —
  // never only a drift footnote. An episode opens at the first violated
  // bundle of a violated run (chains hold only evidenced/violated — an
  // unevidenced verdict is never recorded) and resolves at the first later
  // bundle whose verdict is `evidenced`. A violated chain that merely dies
  // (anchor drift, nothing replacing it) stays OPEN: evidence that died
  // unfixed is not a fix, and the record keeps saying so.
  const vulnerabilities: ValidationVulnerability[] = [];
  for (const chain of groups.values()) {
    chain.forEach((entry, i) => {
      const p = entry.bundle.predicate;
      if (p.verdict !== "violated") return;
      const prev = chain[i - 1];
      if (prev !== undefined && prev.bundle.predicate.verdict === "violated") return;
      // the episode's detection — now find its resolution, if one is recorded
      const record: ValidationVulnerability = {
        repo: p.repo,
        recipeId: p.recipe_id,
        ksiIds: p.ksi_ids,
        detectedAt: p.timestamp,
        commit: p.commit,
        bundleDigest: entry.digest,
        status: "open",
      };
      const resolving = chain
        .slice(i + 1)
        .find((e) => e.bundle.predicate.verdict === "evidenced");
      if (resolving !== undefined) {
        const q = resolving.bundle.predicate;
        record.status = "resolved";
        record.resolvedAt = q.timestamp;
        record.resolvingDigest = resolving.digest;
        record.resolvingCommit = q.commit;
      }
      vulnerabilities.push(record);
    });
  }
  vulnerabilities.sort(
    (a, b) => a.detectedAt.localeCompare(b.detectedAt) || a.bundleDigest.localeCompare(b.bundleDigest),
  );

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
    methodRegisters,
    gaps,
    vulnerabilities,
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
      if (options.methods !== undefined) foldOptions.methods = options.methods;
      if (options.ksiIds !== undefined) foldOptions.ksiIds = options.ksiIds;
      if (options.methodFloor !== undefined) foldOptions.methodFloor = options.methodFloor;
      if (options.historyFloorMonths !== undefined)
        foldOptions.historyFloorMonths = options.historyFloorMonths;
      if (options.machineWindow !== undefined) foldOptions.machineWindow = options.machineWindow;
      if (options.nonMachineWindow !== undefined)
        foldOptions.nonMachineWindow = options.nonMachineWindow;
      return foldEntries(await ledger.list(), now().toISOString(), foldOptions);
    },
  };
}
