import { missingRunReason } from "./provenance";
import type { CollectorRunRecord, RegisterRecord, ScanRunRecord } from "./types";

// Guided empty states (plan K1, over J1's run record). An unevidenced cell is
// the honest default, and it is also the least useful thing on the board: it
// says nothing happened without saying why. The reason exists — every scan
// since J1 signs a run record naming each collector it dispatched and, for the
// ones that could not run, the reason in the collector's own words. This
// module turns that into one sentence and one next move.
//
// THE RULE THIS HAD TO STAY INSIDE, and it needed sharpening rather than
// obeying-as-written. J1's standing rule is that the board is folded from
// evidence and scoping ALONE — a run record names a repo too, and letting it
// introduce cells would make the coverage board partly a function of the run
// log. J3 kept that by having the board fetch no run data whatsoever. K1 needs
// run data on the board, so the rule is restated in its precise form:
//
//   which cells exist, and what state each is in, is a function of evidence
//   and scoping only — never of the run log;
//   WHY an already-drawn empty cell is empty is a function of the run log
//   only, because it is recorded nowhere else.
//
// Everything here takes an already-folded row and can only ever return
// sentences: there is no path through this file that produces a state, a
// verdict or a count. The board with every run record removed draws exactly
// the same rows in exactly the same states — pinned by test — and loses only
// its explanations.

export interface SkipClassification {
  actionable: boolean;
  category: "tool-missing" | "collector-failed" | "honest-skip";
  hint?: string;
}

/**
 * Classify one collector skip reason. The wording is pinned by test against
 * the real producers (`absentReason` in collectors, the `failed (exit …)`
 * shape), so a reworded reason breaks the test instead of silently falling off
 * the queue. Anything unrecognized counts as an honest skip — nothing here
 * invents work.
 */
export function classifySkip(reason: string): SkipClassification {
  if (/is not installed/.test(reason)) {
    return {
      actionable: true,
      category: "tool-missing",
      hint: "install the tool or Docker — `pnpm run doctor` lists what's missing and how to get it",
    };
  }
  if (/failed \(exit /.test(reason)) {
    return {
      actionable: true,
      category: "collector-failed",
      hint: "the collector crashed instead of observing — read the reason, fix the cause, re-scan",
    };
  }
  return { actionable: false, category: "honest-skip" };
}

/**
 * Where the sentence came from. Five different facts, kept apart on purpose —
 * "the tool is missing", "the collector was never dispatched" and "no scan of
 * this repo is on file" are three different problems with three different
 * fixes, and a single "not evidenced" message would hide which one applies.
 */
export type EmptyStateSource =
  | "skip-reason" // the run record's own words for why the collector could not run
  | "ran-no-evidence" // the collector ran and this recipe still came out empty
  | "collector-not-dispatched" // the scan never asked this collector to run
  | "no-run-record" // no run of this repo is in the projection
  | "no-collector"; // the catalog names no collector for this recipe

export interface EmptyStateExplanation {
  source: EmptyStateSource;
  /** why this cell is empty — the run record's words wherever it has them */
  reason: string;
  /** the concrete next move; "" when there is honestly nothing to do */
  action: string;
  /** true when a person can fix the cause — an honest skip is not a task */
  actionable: boolean;
  /** the run this was read from, when there was one */
  runId?: string;
  /** the collector the row expected, when the catalog names one */
  collector?: string;
}

export interface EmptyStateInput {
  row: RegisterRecord;
  /** the newest recorded run of THIS row's repo, or null when the projection holds none */
  run: ScanRunRecord | null;
  /** false while the run collection is still loading — silence is not absence (J5's rule) */
  runsLoaded: boolean;
  /** how many runs the projection holds at all, for J3's two different absences */
  runCount: number;
}

/** The newest recorded run of one repo — the scan whose outcome this row reflects. */
export function newestRunOf(runs: ScanRunRecord[], repo: string): ScanRunRecord | null {
  let newest: ScanRunRecord | null = null;
  for (const run of runs) {
    if (run.repo !== repo) continue;
    if (
      !newest ||
      run.run_timestamp > newest.run_timestamp ||
      (run.run_timestamp === newest.run_timestamp && run.run_id > newest.run_id)
    ) {
      newest = run;
    }
  }
  return newest;
}

/**
 * Why this cell is empty. Returns null for a cell that needs no explaining —
 * an evidenced, violated or scoped-out row — and null while the run records
 * are still loading, because a sentence written during the gap would be a
 * claim about data this page has not read yet.
 */
export function explainUnevidenced(input: EmptyStateInput): EmptyStateExplanation | null {
  const { row, run, runsLoaded, runCount } = input;
  if (row.state !== "unevidenced") return null;
  if (!runsLoaded) return null;

  // no collector: the recipe left the catalog, so nothing was ever going to
  // fill this cell. Naming a collector from the ledger's tool names is the
  // shortcut J3 refused for the hop and this refuses for the same reason.
  if (row.collector === "") {
    return {
      source: "no-collector",
      reason:
        "no collector claims this recipe — it is not in the catalog this projection was folded with, so nothing was dispatched to answer it. The row exists because the ledger holds a statement about it.",
      action: "restore the recipe to the catalog, or retire the cell with a scoping decision",
      actionable: true,
    };
  }

  if (!run) {
    return {
      source: "no-run-record",
      reason:
        runCount === 0
          ? "no scan has appended a run record to this projection yet, so nothing on file says what ran against this repository. Run records began with scans made after this feature landed; a re-scan writes one."
          : `no run record for this repository is among the newest ${runCount} run${runCount === 1 ? "" : "s"} this projection keeps. The ledger still holds any older ones.`,
      action: "re-scan the repository: pnpm rampscan scan <repo>",
      actionable: true,
      collector: row.collector,
    };
  }

  const collectorRow: CollectorRunRecord | undefined = run.collectors.find(
    (c) => c.collector === row.collector,
  );

  // dispatched-and-skipped is a different fact from never-dispatched, and the
  // fixes are different too: one is a tool problem, the other is a wiring
  // problem. J5 kept these apart in the provenance chain; the same two facts
  // reach the operator here.
  if (!collectorRow) {
    return {
      source: "collector-not-dispatched",
      reason: `the newest recorded scan of this repository (${run.run_id}) never dispatched "${row.collector}", so it neither ran nor skipped — it was not in that scan's collector set at all.`,
      action: "check the scan's collector selection, then re-scan",
      actionable: true,
      runId: run.run_id,
      collector: row.collector,
    };
  }

  if (collectorRow.skip_reason !== undefined) {
    const classified = classifySkip(collectorRow.skip_reason);
    return {
      source: "skip-reason",
      // the collector's own words, quoted rather than paraphrased: a
      // paraphrase is a second wording of a fact that already has one
      reason: `"${row.collector}" could not run in the newest recorded scan — ${collectorRow.skip_reason}`,
      action: classified.hint ?? "nothing to fix here: the collector had nothing of its kind to look at",
      actionable: classified.actionable,
      runId: run.run_id,
      collector: row.collector,
    };
  }

  // the collector ran and this cell is still empty. Not a skip, so the run
  // record has no reason to offer — and inventing one ("no findings"?) would
  // be a guess at a verdict, which is the one thing this file may not do.
  return {
    source: "ran-no-evidence",
    reason: `"${row.collector}" ran in the newest recorded scan and produced no evidence for this recipe — the collector worked, and this particular check still came out with nothing to state.`,
    action: "open the run and read the collector's row — its artifacts and exit code are recorded there",
    actionable: false,
    runId: run.run_id,
    collector: row.collector,
  };
}
