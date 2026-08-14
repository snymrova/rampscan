import type { RegisterDiff } from "@rampscan/core";
import { createLocalLedger } from "@rampscan/ledger";
import { diffRegisters, foldEntries, resolveBaseline, scanInstants } from "@rampscan/projector";
import { loadRecipes } from "./recipes.js";

// The one hand that computes a "since baseline" diff (I2d), for BOTH surfaces:
// `rampscan board --since` and the console's read-only diff route call this,
// so the terminal and the browser can never disagree about what moved. Two
// as-of folds of the same ledger, then a pure register diff — nothing here
// can write anything.

export interface BoardDiffOptions {
  ledgerDir: string;
  recipesDir: string;
  /** `"previous"` (the scan before the current one) or an explicit ISO instant */
  since: string;
  /** diff the board as of this instant instead of now (rides `--as-of`, I1b) */
  asOf?: string;
}

export interface BoardDiffOutcome {
  /** every scan instant the ledger records, ascending — the baseline picker's choices */
  scans: string[];
  /** the resolved baseline instant the diff is against */
  baseline: string;
  /** true when the baseline is one of the ledger's scan instants */
  baselineIsScan: boolean;
  diff: RegisterDiff;
}

export async function computeBoardDiff(options: BoardDiffOptions): Promise<BoardDiffOutcome> {
  const entries = await createLocalLedger(options.ledgerDir).list();
  const recipes = await loadRecipes(options.recipesDir);
  const baseline = resolveBaseline(entries, options.since, options.asOf);
  if (options.asOf !== undefined && baseline >= options.asOf) {
    throw new Error(
      `the baseline (${baseline}) is not before the board's --as-of instant (${options.asOf}) — nothing sits between them to diff`,
    );
  }
  const projectedAt = new Date().toISOString();
  const current = foldEntries(entries, projectedAt, {
    recipes,
    ...(options.asOf !== undefined ? { asOf: options.asOf } : {}),
  });
  const before = foldEntries(entries, projectedAt, { recipes, asOf: baseline });
  const scans = scanInstants(entries);
  return {
    scans,
    baseline,
    baselineIsScan: scans.includes(baseline),
    diff: diffRegisters(before.registers, current.registers, baseline),
  };
}
