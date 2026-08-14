import type { Projection } from "@rampscan/core";
import { createLocalLedger } from "@rampscan/ledger";
import { foldEntries, scanInstants } from "@rampscan/projector";
import { loadRecipes } from "./recipes.js";

// The one hand that computes an as-of board (I3d), for BOTH surfaces:
// `rampscan board --as-of` and the console's read-only as-of route call this,
// so the terminal and the browser can never disagree about what the world
// looked like at a past instant. One as-of fold of the append-only ledger
// (I1b) — deterministic by construction, and nothing here can write anything.
//
// No MVX window is passed: the as-of board is registers + rollups. The
// cadence-gap history is the LIVE projection's story (the `gaps` collection,
// I1d) — an as-of fold's "ongoing" gap would end at the fold clock, not the
// chosen instant, and quoting that as history would be an invented claim.

export interface BoardAsOfOptions {
  ledgerDir: string;
  recipesDir: string;
  /** the instant to refold at (ISO 8601) — statements at or before it participate */
  asOf: string;
}

export interface BoardAsOfOutcome {
  /** every scan instant the ledger records, ascending — the selector's quick picks */
  scans: string[];
  /** the instant the projection was folded as of */
  asOf: string;
  /** true when the instant is one of the ledger's scan instants */
  asOfIsScan: boolean;
  /** the full as-of fold: registers, rollups, chains, drift */
  projection: Projection;
}

export async function computeBoardAsOf(options: BoardAsOfOptions): Promise<BoardAsOfOutcome> {
  const entries = await createLocalLedger(options.ledgerDir).list();
  const recipes = await loadRecipes(options.recipesDir);
  const projection = foldEntries(entries, new Date().toISOString(), {
    recipes,
    asOf: options.asOf,
  });
  const scans = scanInstants(entries);
  return {
    scans,
    asOf: options.asOf,
    asOfIsScan: scans.includes(options.asOf),
    projection,
  };
}
