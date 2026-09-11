import type { MethodRegisterRow } from "@rampscan/core";
import type { HistoryFloor, KsiCatalog, OfferingClass, ValidationWindow } from "@rampscan/dataset";
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
  /** where this KSI's ledger history begins (Q3.1); absent when it holds nothing */
  historySince?: string; // ISO 8601
  /** the FRC-CSX-MOT judgment; null exactly when the class owes no months */
  historyMet: boolean | null;
  /** worst gap class computable today — G3, G5+ land later in Q3 */
  worstGap?: "G1" | "G2" | "G4";
  methodIds: string[];
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
    /** rows whose ledger history reaches the MOT floor; null when the class owes none */
    historyMet: number | null;
    total: number;
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
      methods: total,
      automated,
      floor,
      floorMet: floor === null ? null : automated >= floor,
      // With a fold, the projector's judgment (computed against the ledger
      // and the same reporting class — main.ts folds with it). Without one,
      // the honest number for a ledger that holds nothing: zero months,
      // which meets no floor — never null, because the class still owes.
      historyMet:
        folded?.historyMet ?? (history.months === null ? null : false),
      methodIds,
    };
    if (folded?.freshAsOf !== undefined) row.freshest = folded.freshAsOf;
    if (folded?.historySince !== undefined) row.historySince = folded.historySince;
    if (total === 0) row.worstGap = "G1";
    else if (floor !== null && automated < floor) row.worstGap = "G2";
    else if (row.historyMet === false) row.worstGap = "G4";
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

  return {
    offeringClass: input.offeringClass,
    datasetVersion: input.catalog.datasetVersion,
    frontierOverlay: "", // set by the caller from the pinned overlay version
    ...(repo !== undefined ? { repo } : {}),
    rows,
    window: input.catalog.windows[input.offeringClass],
    history,
    summary: {
      floorMet: rows.filter((r) => r.floorMet === true).length,
      atLeastOneAutomated: rows.filter((r) => r.automated > 0).length,
      noMethod: rows.filter((r) => r.methods === 0).length,
      historyMet:
        history.months === null ? null : rows.filter((r) => r.historyMet === true).length,
      total: rows.length,
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

function windowMs(window: ValidationWindow): number {
  // months as 30 days for the AGE COMPARISON only — the scheduler owns real
  // scheduling; this is a report saying whether evidence is inside its window
  const dayMs = 86_400_000;
  return window.unit === "days" ? window.num * dayMs : window.num * 30 * dayMs;
}

function windowLabel(window: ValidationWindow): string {
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
    "",
    dim("  KSI              methods    freshest         artifacts   worst gap"),
  );

  for (const row of view.rows) {
    const floorPart = row.floor === null ? `${row.automated}/—` : `${row.automated}/${row.floor}`;
    const methodsCol = `${floorPart}${row.floorMet === true ? " ok" : ""}`.padEnd(9);
    let freshestCol: string;
    if (row.freshest === undefined) {
      freshestCol = "—".padEnd(15);
    } else {
      const age = shortAge(now.getTime() - Date.parse(row.freshest));
      if (view.window === null) {
        freshestCol = `${age} / —`.padEnd(15);
      } else {
        const within = now.getTime() - Date.parse(row.freshest) <= windowMs(view.window);
        freshestCol = `${age} / ${windowLabel(view.window)}${within ? " ok" : ""}`.padEnd(15);
      }
    }
    // artifacts print –/5 until Q3 models them: unmeasured, never a fake 0
    // that implies measurement (§12.5 rule 3)
    const gapCol =
      row.worstGap === "G1"
        ? red("G1 coverage")
        : row.worstGap === "G2"
          ? red("G2 methods")
          : row.worstGap === "G4"
            ? red("G4 history")
            : dim("—");
    lines.push(`  ${row.ksi.padEnd(16)} ${methodsCol}  ${freshestCol}  ${"–/5".padEnd(10)}  ${gapCol}`);
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
    // the history meter (Q3.1, FRC-CSX-MOT): counted from the ledger, so a
    // young ledger prints a young number — never a claim it cannot back
    view.history.months === null
      ? dim(
          `  history: no floor at class ${view.offeringClass} — ${view.history.requirementId} (${view.history.force}, unquantified)`,
        )
      : dim(
          `  history: ${s.historyMet} of ${s.total} KSIs hold ≥${view.history.months}mo of persistent validation — ${view.history.requirementId} (${view.history.force})`,
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
