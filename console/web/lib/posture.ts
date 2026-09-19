import type { KsiCatalogRecord, MethodRegisterRecord } from "./types";

// The posture fold (L0): one standing per obliged KSI, the themes ordered
// worst first, and the one computed sentence that opens the console
// (docs/PLAN-CONSOLE-DEPTH.md U-R3, U-R4). Every count on the posture block
// comes from here, so the numeral, the sentence and the strata cannot
// disagree. Nothing in it is typed except the sentence's template.

/**
 * Worst first (U-R4). A KSI takes the worst thing true of it:
 * - `violated`: a method's live evidence failed its assertions;
 * - `stale`: a method's owed clock is unmet (its evidence is past its window, or absent);
 * - `none`: no validation method derives to it (G1);
 * - `short`: it has methods but the floor or an owed gap is still open;
 * - `clear`: the method floor is met and nothing above applies.
 */
export type Standing = "violated" | "stale" | "none" | "short" | "clear";

export const STANDING_ORDER: readonly Standing[] = ["violated", "stale", "none", "short", "clear"];

/** the word each standing is printed with: colour is never alone */
export const STANDING_WORD: Record<Standing, string> = {
  violated: "violated",
  stale: "clock unmet",
  none: "no method",
  short: "below floor",
  clear: "clear",
};

export function standingOf(register: MethodRegisterRecord | undefined): Standing {
  const methods = register?.methods ?? [];
  if (methods.length === 0) return "none";
  if (methods.some((m) => m.state === "violated")) return "violated";
  if ((register?.stale_methods ?? 0) > 0 || register?.gap === "G3") return "stale";
  if (register?.floor_met === true) return "clear";
  return "short";
}

export type StandingCounts = Record<Standing, number>;

function zero(): StandingCounts {
  return { violated: 0, stale: 0, none: 0, short: 0, clear: 0 };
}

export interface ThemeStratum {
  key: string;
  name: string;
  counts: StandingCounts;
  total: number;
  /** the stratum's KSIs, worst first, then by id */
  ksis: Array<{ ksi: string; standing: Standing }>;
}

export interface Posture {
  total: number;
  /** floor_met === true — the same count the board's meter has always shown */
  floorMet: number;
  counts: StandingCounts;
  strata: ThemeStratum[];
}

/** worst-first comparison of two count vectors: more of a worse standing ranks first */
function worse(a: StandingCounts, b: StandingCounts): number {
  for (const s of STANDING_ORDER) {
    if (s === "clear") break;
    if (a[s] !== b[s]) return b[s] - a[s];
  }
  return 0;
}

export function foldPosture(
  catalog: KsiCatalogRecord[],
  registers: Map<string, MethodRegisterRecord>,
  isOptional: (k: KsiCatalogRecord) => boolean,
): Posture {
  const obliged = catalog.filter((k) => !isOptional(k));
  const counts = zero();
  let floorMet = 0;
  const byTheme = new Map<string, ThemeStratum>();
  for (const k of obliged) {
    const register = registers.get(k.ksi);
    const standing = standingOf(register);
    counts[standing] += 1;
    if (register?.floor_met === true) floorMet += 1;
    let stratum = byTheme.get(k.theme_key);
    if (!stratum) {
      stratum = { key: k.theme_key, name: k.theme_name, counts: zero(), total: 0, ksis: [] };
      byTheme.set(k.theme_key, stratum);
    }
    stratum.counts[standing] += 1;
    stratum.total += 1;
    stratum.ksis.push({ ksi: k.ksi, standing });
  }
  const rank = (s: Standing) => STANDING_ORDER.indexOf(s);
  const strata = [...byTheme.values()];
  for (const s of strata) {
    s.ksis.sort((a, b) => rank(a.standing) - rank(b.standing) || a.ksi.localeCompare(b.ksi));
  }
  strata.sort((a, b) => worse(a.counts, b.counts) || a.key.localeCompare(b.key));
  return { total: obliged.length, floorMet, counts, strata };
}

/**
 * The one sentence L0 opens with (U-R3). The template is authored; every
 * number is the fold's. A standing with nothing in it is left out rather than
 * printed as a reassuring zero — except "violated", whose absence is news.
 */
export function postureSentence(p: Posture): string {
  const parts = [`${p.floorMet} of ${p.total} obliged indicators meet the method floor`];
  parts.push(
    p.counts.violated === 0
      ? "none has a violated check"
      : `${p.counts.violated} ${p.counts.violated === 1 ? "has" : "have"} a violated check`,
  );
  if (p.counts.stale > 0) parts.push(`${p.counts.stale} ${p.counts.stale === 1 ? "has" : "have"} an unmet clock`);
  if (p.counts.none > 0) parts.push(`${p.counts.none} ${p.counts.none === 1 ? "has" : "have"} no method at all`);
  return `${parts.join(" · ")}.`;
}
