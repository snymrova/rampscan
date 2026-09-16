import type { ClockWindow, MethodRegisterRow } from "@rampscan/core";
import type { HistoryFloor, KsiCatalog, OfferingClass, ValidationWindow } from "@rampscan/dataset";
import { optionalKsis } from "@rampscan/dataset";
import type { PipelineMethod } from "@rampscan/schema";
import type { FrontierMap } from "./frontier.js";

// `rampscan frontier` v2 — the KSI register (SPEC §12.5, plan Q2.4). The
// output format is DECIDED in the spec before this implementation, because
// this text is the product's headline: the README quotes the command, never
// the spec. The legacy control view stays intact behind `--by-controls`, and
// v2's footer names it on every invocation — the denominator change is
// announced, never slipped (ground rule 1).
//
// Everything here is a join of things other modules computed: the owed side
// (KsiCatalog, Q1), the derived methods (Q2.2), the projector's method
// register (Q2.3), and the control frontier (for the G8 queue and the legacy
// footer's numbers). Nothing probed, nothing typed.

export interface KsiRegisterRowView {
  ksi: string;
  name: string;
  /** derived methods for this KSI */
  methods: number;
  /** the FRC-CSX-VVK numerator */
  automated: number;
  floor: number | null;
  /** null exactly when floor is null */
  floorMet: boolean | null;
  /** freshest live evidence across the KSI's methods; absent when none */
  freshest?: string; // ISO 8601
  /**
   * The owed window of the METHOD that supplied `freshest`, not the row's
   * (§12.5 rule 3: "against the method's window"). Load-bearing from Q4.2,
   * when a row's methods stopped being one clock family: an attestation runs
   * on VDR-TFR-NMV's 3 months, and printing the class's 7-day MVX window
   * beside its age would report a lapse the fold never judged.
   *
   * Absent when no folded cell supplied the instant — then the class's MVX
   * window is the honest label, because every derived method is machine.
   * Null when that method's family owes no window (machine at class d).
   */
  freshestWindow?: ClockWindow | null;
  /**
   * The FOLD's freshness judgment for that same method (Q3.2), carried rather
   * than recomputed here: the fold judges calendar months exactly, and a
   * second approximation in the renderer could print "ok" on a row the gap
   * column calls G3. One computation, quoted twice.
   */
  freshestMet?: boolean | null;
  /** where this KSI's ledger history begins (Q3.1); absent when it holds nothing */
  historySince?: string; // ISO 8601
  /**
   * The FRC-CSX-MOT judgment (#159): reach-back AND no lapse of known status
   * across the span. Null when the class owes no months — or when the fold
   * could not judge persistence (an instant with no owed window, class d).
   */
  historyMet: boolean | null;
  /** when the known status expired unrefreshed (#159); absent unless historyMet is false by lapse */
  historyLapseAt?: string; // ISO 8601
  /**
   * Methods whose owed clock is unmet (Q3.2) — stale OR missing evidence,
   * each judged against its own family's window (machine → VDR-TFR-MVX,
   * non-machine → VDR-TFR-NMV). Zero when the class defines no window.
   */
  staleMethods: number;
  /**
   * Of the five owed artifacts (Q3.3), how many are present — 2 and 5
   * computed by the fold, 1/3/4 by live two-key judgment. Null when no
   * scanned repo exists to measure against: "–/5" is unmeasured, never a
   * fake 0 that implies measurement (§12.5 rule 3).
   */
  artifactsPresent: number | null;
  /**
   * Methods whose live evidence asserts point-in-time (Q3.4) — the G6
   * numerator. Zero without a fold: an unscanned register holds no evidence
   * of either class.
   */
  pointInTimeMethods: number;
  /** worst gap class computable today — G8/G13 land with the gap register */
  worstGap?: "G1" | "G2" | "G3" | "G4" | "G5" | "G6";
  methodIds: string[];
  /**
   * This class does not oblige the indicator (SPEC §13.7) — the rules JSON
   * prefixes its class statement `**Optional:**`. The row STAYS (invariant 4:
   * 46 rows at every class, because a KSI that vanished at one class is a KSI
   * nobody remembers at the class where it returns) and leaves every meter's
   * numerator and denominator, so a provider who evidences one anyway is
   * never shown 42 of 41.
   */
  optional: boolean;
}

export interface G8QueueRow {
  displayId: string;
  family: string;
  leverage?: number;
  ksis: string[];
}

export interface KsiRegisterView {
  offeringClass: OfferingClass;
  datasetVersion: string;
  frontierOverlay: string;
  /**
   * The scanned repo whose ledger the evidence columns read; absent when no
   * scan has been recorded — the register still prints all its rows, with
   * every method unevidenced, because a board that vanishes without a ledger
   * would hide exactly the state it exists to show.
   */
  repo?: string;
  /** one row per owed KSI — 46 at the pin, always */
  rows: KsiRegisterRowView[];
  /** the MVX window for the reporting class; null when the rules define none (class d) */
  window: ValidationWindow | null;
  /** the FRC-CSX-MOT floor for the reporting class — the history meter's rule (Q3.1) */
  history: HistoryFloor;
  summary: {
    floorMet: number;
    atLeastOneAutomated: number;
    noMethod: number;
    /**
     * Rows with methods, all of them inside their owed window (Q3.2); null
     * when the rules define no machine window for the class (d) — today's
     * methods are all machine-clocked, so there is nothing to meter.
     */
    everyMethodFresh: number | null;
    /** rows whose ledger history reaches the MOT floor; null when the class owes none */
    historyMet: number | null;
    /**
     * Rows holding all five owed artifacts (Q3.3); null when no scanned repo
     * exists — the artifacts are measured against a ledger, and without one
     * there is nothing to measure, which is a different fact from zero.
     */
    allArtifacts: number | null;
    /**
     * Rows holding any point-in-time evidence (Q3.4, G6) — rejectable as
     * standalone under FRR-PVA-AA-06 when nothing process-generated stands
     * beside it. Null when no scanned repo exists — the class of evidence
     * that does not exist is not a zero, it is unmeasured.
     */
    pointInTime: number | null;
    /** the denominator: rows this class obliges (§13.7) — 41 of 46 at class b */
    total: number;
    /** rows this class leaves optional, by id, ascending */
    optional: readonly string[];
    /** of those, how many carry at least one method anyway */
    optionalEvidenced: number;
    /**
     * Absent when applicability is stated. Present when NEITHER source could
     * say which indicators the class obliges, naming why — a denominator
     * standing on an assumption has to say so out loud.
     */
    applicabilityUnstated?: string;
  };
  /** the G8 adjudication queue: unreviewed frontier controls, by leverage */
  queue: G8QueueRow[];
  /** the legacy view's own numbers, so the footer can announce the old denominator */
  legacy: { catalogCovered: number; ksiReachedControls: number; reachable: number };
}

export interface KsiRegisterInput {
  catalog: KsiCatalog;
  offeringClass: OfferingClass;
  /** the derived register (Q2.2) */
  methods: PipelineMethod[];
  /** the projector's method register (Q2.3); empty when no scan is recorded */
  methodRegisters: MethodRegisterRow[];
  /** the control frontier — the G8 queue and the legacy footer read it */
  frontier: FrontierMap;
}

export function buildKsiRegister(input: KsiRegisterInput): KsiRegisterView {
  const floor = input.catalog.floors[input.offeringClass].minPerKsi;
  const history = input.catalog.historyFloors[input.offeringClass];

  // The evidence column reads ONE repo's ledger. More than one scanned repo
  // in a local ledger is the daemon-multi-target case the board handles;
  // this register reads the first by name and says which, rather than
  // averaging two repos into a row about neither.
  const repos = [...new Set(input.methodRegisters.map((r) => r.repo))].sort();
  const repo = repos[0];
  const foldedByKsi = new Map(
    input.methodRegisters.filter((r) => r.repo === repo).map((r) => [r.ksi, r]),
  );
  const methodsByKsi = new Map<string, PipelineMethod[]>();
  for (const method of input.methods) {
    (methodsByKsi.get(method.ksi) ?? methodsByKsi.set(method.ksi, []).get(method.ksi)!).push(
      method,
    );
  }

  // Which indicators this class does not oblige (§13.7). Read from the
  // catalog, never derived here: the loader is the only thing that reads the
  // rules JSON's prefix, and a second reading in a renderer is a second
  // answer waiting to disagree with the first.
  const optionalIds = new Set(optionalKsis(input.catalog, input.offeringClass));

  const rows: KsiRegisterRowView[] = input.catalog.ksis.map((entry) => {
    const folded = foldedByKsi.get(entry.id);
    // With a scan recorded, the projector's row is the authority (Q2.3);
    // without one, the register-side facts — which methods exist, G1/G2 —
    // are computed from the derivation directly, because they never depended
    // on the ledger in the first place (plan §4: properties of the register).
    const derived = methodsByKsi.get(entry.id) ?? [];
    const methodIds = (folded?.methods.map((m) => m.methodId) ?? derived.map((m) => m.id)).sort();
    const automated =
      folded?.automatedMethods ?? derived.filter((m) => m.automated).length;
    const total = folded?.methods.length ?? derived.length;
    const row: KsiRegisterRowView = {
      ksi: entry.id,
      name: entry.name,
      optional: optionalIds.has(entry.id),
      methods: total,
      automated,
      floor,
      floorMet: floor === null ? null : automated >= floor,
      // With a fold, the projector's judgment (computed against the ledger
      // and the same reporting class — main.ts folds with it). Without one,
      // the honest number for a ledger that holds nothing: zero months,
      // which meets no floor — never null, because the class still owes.
      historyMet:
        folded !== undefined ? folded.historyMet : history.months === null ? null : false,
      // Same honesty for the clocks (Q3.2): without a fold, every method's
      // evidence is missing, so every method whose family has an owed window
      // is unmet. Derived methods are all machine today (source: pipeline) —
      // judged by the class's MVX window, which class d defines none of.
      staleMethods:
        folded?.staleMethods ??
        (input.catalog.windows[input.offeringClass] === null ? 0 : derived.length),
      // The G5 column (Q3.3): the fold's count when a scan is recorded;
      // without one, unmeasured — the judged artifacts live in the ledger
      // and the computed ones are facts about a repo's evidence, so a
      // register with no repo has nothing to count, not a zero.
      artifactsPresent: folded?.artifactsPresent ?? null,
      // The G6 numerator (Q3.4): the fold's count of methods whose live
      // evidence asserts point-in-time. Without a fold there is no evidence
      // of either class, so zero is the fact, not a placeholder.
      pointInTimeMethods: folded?.pointInTimeMethods ?? 0,
      methodIds,
    };
    if (folded?.freshAsOf !== undefined) {
      row.freshest = folded.freshAsOf;
      // Which method's clock does that instant belong to? The freshest cell —
      // and from Q4.2 a row can hold more than one family, so the window and
      // the verdict travel WITH the instant instead of being re-derived from
      // the class. Ties go to the first by method id, matching the cell order
      // the fold already sorted.
      const source = folded.methods.find((m) => m.freshAsOf === folded.freshAsOf);
      if (source !== undefined) {
        row.freshestWindow = source.window;
        row.freshestMet = source.freshMet;
      }
    }
    if (folded?.historySince !== undefined) row.historySince = folded.historySince;
    if (folded?.historyLapseAt !== undefined) row.historyLapseAt = folded.historyLapseAt;
    if (total === 0) row.worstGap = "G1";
    else if (floor !== null && automated < floor) row.worstGap = "G2";
    else if (row.staleMethods > 0) row.worstGap = "G3";
    else if (row.historyMet === false) row.worstGap = "G4";
    else if (row.artifactsPresent !== null && row.artifactsPresent < 5) row.worstGap = "G5";
    // G6 (Q3.4): the standalone judgment is the fold's — it read each live
    // bundle's signed assertion, which this join deliberately does not
    // re-derive. The chain position is preserved: the fold's own chain only
    // reaches G6 after the same earlier arms declined.
    else if (folded?.gap === "G6") row.worstGap = "G6";
    return row;
  });

  const queue: G8QueueRow[] = input.frontier.rows
    .filter((r) => r.commit === undefined)
    .map((r) => ({
      displayId: r.displayId,
      family: r.family,
      ...(r.leverage !== undefined ? { leverage: r.leverage } : {}),
      ksis: r.ksis,
    }))
    // by leverage descending — the dataset's own field (§12.5 rule 4);
    // unleveraged rows last, then by id so the order is stable
    .sort(
      (a, b) =>
        (b.leverage ?? -1) - (a.leverage ?? -1) || a.displayId.localeCompare(b.displayId),
    );

  const obliged = rows.filter((r) => !r.optional);

  return {
    offeringClass: input.offeringClass,
    datasetVersion: input.catalog.datasetVersion,
    frontierOverlay: "", // set by the caller from the pinned overlay version
    ...(repo !== undefined ? { repo } : {}),
    rows,
    window: input.catalog.windows[input.offeringClass],
    history,
    summary: {
      // Every meter counts the OBLIGED rows only (§13.7). An optional row that
      // is evidenced anyway is real work and is counted on its own line below,
      // never folded into a numerator whose denominator excludes it.
      floorMet: obliged.filter((r) => r.floorMet === true).length,
      atLeastOneAutomated: obliged.filter((r) => r.automated > 0).length,
      noMethod: obliged.filter((r) => r.methods === 0).length,
      everyMethodFresh:
        input.catalog.windows[input.offeringClass] === null
          ? null
          : obliged.filter((r) => r.methods > 0 && r.staleMethods === 0).length,
      historyMet:
        history.months === null ? null : obliged.filter((r) => r.historyMet === true).length,
      allArtifacts:
        repo === undefined ? null : obliged.filter((r) => r.artifactsPresent === 5).length,
      pointInTime:
        repo === undefined ? null : obliged.filter((r) => r.pointInTimeMethods > 0).length,
      total: obliged.length,
      optional: [...optionalIds].sort(),
      optionalEvidenced: rows.filter((r) => r.optional && r.methods > 0).length,
      ...(input.catalog.applicability.stated
        ? {}
        : { applicabilityUnstated: input.catalog.applicability.reason }),
    },
    queue,
    legacy: {
      catalogCovered: input.frontier.rollup.catalogCovered,
      ksiReachedControls: input.frontier.rollup.ksiReachedControls,
      reachable: input.frontier.rollup.reachable,
    },
  };
}

/** a short age: 45m, 11h, 2d — display only, never a stored number */
function shortAge(ms: number): string {
  if (ms < 0) return "0m";
  const minutes = Math.round(ms / 60_000);
  if (minutes < 60) return `${minutes}m`;
  const hours = Math.round(ms / 3_600_000);
  if (hours < 48) return `${hours}h`;
  return `${Math.round(ms / 86_400_000)}d`;
}

function windowMs(window: ClockWindow): number {
  // months as 30 days for the AGE COMPARISON only — the scheduler owns real
  // scheduling; this is a report saying whether evidence is inside its window
  const dayMs = 86_400_000;
  return window.unit === "days" ? window.num * dayMs : window.num * 30 * dayMs;
}

function windowLabel(window: ClockWindow): string {
  return `${window.num}${window.unit === "days" ? "d" : "mo"}`;
}

/**
 * The register as text — the §12.5 format, verbatim in structure. `now` is
 * the render instant for the age column only: ages are display, the ok/not-ok
 * judgment beside them is computed from bundle timestamps × the owed window.
 */
export function renderKsiRegister(view: KsiRegisterView, useColor: boolean, now: Date): string {
  const paint = (code: string, s: string) => (useColor ? `[${code}m${s}[0m` : s);
  const dim = (s: string) => paint("2", s);
  const red = (s: string) => paint("31", s);
  const bold = (s: string) => paint("1", s);
  const lines: string[] = [];

  lines.push(
    bold("rampscan frontier — the KSI register"),
    `class ${view.offeringClass} · dataset ${view.datasetVersion}` +
      (view.frontierOverlay !== "" ? ` · frontier overlay ${view.frontierOverlay}` : "") +
      (view.repo !== undefined ? dim(` · evidence: ${view.repo}`) : dim(" · no scan recorded")),
  );

  // Methods outside the FRC-CSX-VVK numerator — attestations (Q4.2) and
  // ingested assessment packages (S3-1) — are methods the row holds and the
  // floor does not count. Shown as `+N` so a row reading `0/1` over a KSI
  // with three human-read artifacts says so, and only when there is
  // something to say: a register with none renders exactly as it did, column
  // width included.
  const methodsCells = view.rows.map((row) => {
    const floorPart = row.floor === null ? `${row.automated}/—` : `${row.automated}/${row.floor}`;
    const extra = row.methods - row.automated;
    return `${floorPart}${row.floorMet === true ? " ok" : ""}${extra > 0 ? ` +${extra}` : ""}`;
  });
  const methodsWidth = Math.max(9, ...methodsCells.map((c) => c.length));
  const nonAutomatedShown = view.rows.some((row) => row.methods > row.automated);
  lines.push(
    "",
    dim(
      `  ${"KSI".padEnd(16)} ${"methods".padEnd(methodsWidth)}  ${"freshest".padEnd(15)}  ` +
        `${"artifacts".padEnd(10)}  worst gap`,
    ),
  );

  view.rows.forEach((row, i) => {
    const methodsCol = methodsCells[i]!.padEnd(methodsWidth);
    let freshestCol: string;
    if (row.freshest === undefined) {
      freshestCol = "—".padEnd(15);
    } else {
      const age = shortAge(now.getTime() - Date.parse(row.freshest));
      // The window of the METHOD that supplied the instant (§12.5 rule 3),
      // falling back to the class's MVX window only when no fold named one —
      // where every derived method is machine, so MVX is the honest label.
      const owed = row.freshestWindow === undefined ? view.window : row.freshestWindow;
      if (owed === null) {
        freshestCol = `${age} / —`.padEnd(15);
      } else {
        // Prefer the FOLD's verdict; recompute only when there is no fold.
        // The fold judges calendar months exactly, and `windowMs` below
        // approximates a month as 30 days — close enough to label a report,
        // never close enough to contradict the gap column.
        const within =
          row.freshestMet ?? now.getTime() - Date.parse(row.freshest) <= windowMs(owed);
        freshestCol = `${age} / ${windowLabel(owed)}${within ? " ok" : ""}`.padEnd(15);
      }
    }
    // artifacts (Q3.3): the fold's count over the five owed artifacts;
    // "–/5" only when no scanned repo exists to measure against — unmeasured,
    // never a fake 0 that implies measurement (§12.5 rule 3)
    const artifactsCol = (
      row.artifactsPresent === null ? "–/5" : `${row.artifactsPresent}/5`
    ).padEnd(10);
    const gapCol =
      row.worstGap === "G1"
        ? red("G1 coverage")
        : row.worstGap === "G2"
          ? red("G2 methods")
          : row.worstGap === "G3"
            ? red("G3 freshness")
            : row.worstGap === "G4"
              ? red("G4 history")
              : row.worstGap === "G5"
                ? red("G5 artifact")
                : row.worstGap === "G6"
                  ? red("G6 evidence")
                  : dim("—");
    // An optional row keeps its place and is dimmed with the rules' own word:
    // it is not owed at this class, and it is not gone either (§13.7).
    const line = `  ${row.ksi.padEnd(16)} ${methodsCol}  ${freshestCol}  ${artifactsCol}  ${gapCol}`;
    lines.push(row.optional ? dim(`${line}  optional at class ${view.offeringClass}`) : line);
  });

  if (nonAutomatedShown) {
    lines.push(
      dim(
        "  +N beside a methods cell: non-automated methods the row holds (attestations, ingested " +
          "assessment evidence) — outside the FRC-CSX-VVK numerator, judged by VDR-TFR-NMV's clock",
      ),
    );
  }

  const s = view.summary;
  lines.push(
    "",
    bold(
      `  floor met on ${s.floorMet} of ${s.total} KSIs · at least one automated method on ${s.atLeastOneAutomated} · no method on ${s.noMethod}`,
    ),
    dim(
      `  covering all ${s.total} — a row that says "nothing evidences this from a pipeline" is a row`,
    ),
    // The denominator, said out loud (§13.7). A meter that divided by 46 at a
    // class owing 41 would overstate the provider's obligation by five rows.
    s.applicabilityUnstated !== undefined
      ? dim(
          `  applicability: unstated — ${s.applicabilityUnstated}. Every one of the ${view.rows.length} rows is counted as obliged, which is the conservative reading and not a measured one`,
        )
      : s.optional.length === 0
        ? dim(
            `  applicability: class ${view.offeringClass} obliges all ${view.rows.length} indicators — none is optional at this class`,
          )
        : dim(
            `  ${s.optional.length} optional at class ${view.offeringClass}, outside every meter above — ${s.optional.join(", ")} (${s.optionalEvidenced} evidenced anyway)`,
          ),
    // the clock meter (Q3.2): every method judged against its own family's
    // owed window at fold time — the count is the fold's, never this render's
    view.window === null || view.summary.everyMethodFresh === null
      ? dim(
          `  clocks: no machine window at class ${view.offeringClass} — VDR-TFR-MVX defines none (§11 q6)`,
        )
      : dim(
          `  clocks: ${view.summary.everyMethodFresh} of ${view.summary.total} KSIs hold every method inside its owed window — ${view.window.requirementId} (${view.window.force})`,
        ),
    // the history meter (Q3.1, FRC-CSX-MOT): counted from the ledger, so a
    // young ledger prints a young number — never a claim it cannot back
    view.history.months === null
      ? dim(
          `  history: no floor at class ${view.offeringClass} — ${view.history.requirementId} (${view.history.force}, unquantified)`,
        )
      : dim(
          `  history: ${s.historyMet} of ${s.total} KSIs hold ≥${view.history.months}mo of persistent validation — ${view.history.requirementId} (${view.history.force})`,
        ),
    // the artifact meter (Q3.3, default_artifacts.KSI): 2 and 5 computed by
    // the fold, 1/3/4 by signed two-key judgment — never a checkbox
    s.allArtifacts === null
      ? dim(
          `  artifacts: unmeasured — the five owed artifacts are counted against a scanned repo's ledger (default_artifacts.KSI)`,
        )
      : dim(
          `  artifacts: ${s.allArtifacts} of ${s.total} KSIs hold all five owed artifacts — default_artifacts.KSI (2, 5 computed · 1, 3, 4 two-key judged)`,
        ),
    // the evidence-class meter (Q3.4, FRR-PVA-AA-06): every bundle asserts
    // process-generated vs point-in-time at ingestion; point-in-time is
    // rejectable as standalone evidence, and the count here is of asserted
    // labels — the fold never infers a class a signature did not state
    s.pointInTime === null
      ? dim(
          `  evidence class: unmeasured — asserted per bundle at ingestion (process-generated | point-in-time, FRR-PVA-AA-06)`,
        )
      : dim(
          `  evidence class: ${s.pointInTime} of ${s.total} KSIs hold point-in-time evidence, rejectable when standalone — FRR-PVA-AA-06 (pipeline mints assert process-generated)`,
        ),
    "",
  );

  // The G8 queue is its own section (§12.5 rule 4): the unanswered question
  // stays a first-class output, not a residue.
  lines.push(
    bold(`  adjudication queue (G8): ${view.queue.length} unreviewed, sorted by leverage`),
  );
  for (const q of view.queue) {
    lines.push(
      dim(
        `    ${q.displayId.padEnd(12)} ${q.family.padEnd(3)}` +
          (q.leverage !== undefined ? ` lev ${q.leverage}` : " lev —") +
          `  ${q.ksis.join(" ")}`,
      ),
    );
  }

  lines.push(
    "",
    dim(
      `  legacy view: --by-controls   (${view.legacy.catalogCovered} of ${view.legacy.ksiReachedControls} controls · ${view.legacy.reachable} reachable at this pin)`,
    ),
  );

  return lines.join("\n");
}
