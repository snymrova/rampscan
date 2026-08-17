import type { Collector } from "@rampscan/core";
import type { FrontierControl } from "@rampscan/dataset";
import type { Disposition, PipelineAdjudication, PipelineRecipe } from "@rampscan/schema";

// `rampscan frontier` (plan N1a-T2) — a pure derivation in the shape of
// `rampscan tools`: catalog × adjudications × the pinned frontier → coverage.
// Nothing probed, nothing written, non-zero exit on a broken link.
//
// This command exists BEFORE the recipes it will eventually count, and that
// order is the point. Ground rule 9 says coverage is computed, never typed: no
// coverage number appears in a document, a README or a slide unless a command
// emitted it. After N1a the number is this command's output, and every later
// claim about coverage quotes it.
//
// The frontier holds 121 controls a KSI reaches that no AWS recipe covers,
// adjudicated from exactly one source — every reviewed row reads
// `sourcesConsidered: ["aws"]`. The question here is the other one: which of
// them can evidence committed to a REPOSITORY discharge?

/**
 * Collectors named in `IMPLEMENTATION-PLAN-REMAINING.md` Tier 2 as cheap wins:
 * each an H-phase-shaped single-collector move, scoped upstream, on nobody's
 * critical path. An adjudication may name one of these as its candidate before
 * it is written — that is the whole use of the list — but it may not name
 * something nobody has ever scoped, which is how a disposition turns into a
 * wish.
 */
export const TIER_2_COLLECTORS = ["actionlint", "dockle", "license", "trivy-config", "zizmor"];

export interface FrontierRow {
  controlId: string;
  displayId: string;
  family: string;
  classes: string[];
  ksis: string[];
  leverage?: number;
  /** upstream's pass over this control, mirrored and never edited by us */
  aws: { disposition?: string; rationale?: string };
  /** ours, when `recipes/adjudications/` holds a record for it */
  pipeline?: {
    disposition: Disposition;
    rationale: string;
    recipeIds: string[];
    candidateCollectors: string[];
    remainder?: string;
    reviewed: string;
    datasetVersion: string;
  };
  /**
   * Recipes in the catalog whose `control_ids` name this control — computed
   * from the catalog, not read from the adjudication. A record claiming a
   * recipe the catalog does not carry is a broken link; a catalog recipe the
   * record forgot to claim is one too, and both are only visible because this
   * side is derived independently.
   */
  catalogRecipeIds: string[];
}

export interface FrontierRollup {
  /** the frontier's own size — the uncovered set upstream published */
  frontierTotal: number;
  /** upstream's denominator: controls any KSI reaches at all */
  ksiReachedControls: number;
  /** of the 121, by our disposition */
  automatable: number;
  partial: number;
  narrative: number;
  unreviewed: number;
  /** frontier controls we adjudicated automatable AND already carry a recipe for */
  discharged: number;
  /** controls (of all 209) at least one catalog recipe claims today */
  catalogCovered: number;
  /** catalogCovered ∪ {frontier controls adjudicated automatable or partial} */
  reachable: number;
  /** reachable ÷ ksiReachedControls — the pipeline source's ceiling */
  ceiling: number;
}

export interface FrontierMap {
  datasetVersion: string;
  rows: FrontierRow[];
  rollup: FrontierRollup;
  /** families the pipeline source cannot answer, with the count it cannot answer (N1d) */
  ceilingByFamily: Array<{ family: string; narrative: number; unreviewed: number; total: number }>;
  problems: string[];
}

export interface FrontierInput {
  frontier: FrontierControl[];
  adjudications: PipelineAdjudication[];
  recipes: PipelineRecipe[];
  collectors: Collector[];
  /** the pin every record must have been written against (ground rule 2) */
  datasetVersion: string;
  /** upstream's `rollup.ksiReachedControls` — read, never typed */
  ksiReachedControls: number;
}

/**
 * The derivation. Every list sorted, every number counted from the rows above
 * it, so an independent recount from `rows` always reproduces `rollup` — the
 * same attributability rule the control register holds itself to.
 */
export function buildFrontier(input: FrontierInput): FrontierMap {
  const byControl = new Map(input.adjudications.map((a) => [a.controlId, a]));
  const registered = new Set(input.collectors.map((c) => c.manifest.name));
  const recipeIds = new Set(input.recipes.map((r) => r.id));
  const onFrontier = new Set(input.frontier.map((f) => f.controlId));

  const recipesForControl = new Map<string, string[]>();
  for (const recipe of input.recipes) {
    for (const control of recipe.control_ids) {
      recipesForControl.set(control, [...(recipesForControl.get(control) ?? []), recipe.id].sort());
    }
  }

  const rows: FrontierRow[] = input.frontier
    .map((f) => {
      const record = byControl.get(f.controlId);
      const row: FrontierRow = {
        controlId: f.controlId,
        displayId: f.displayId,
        family: f.family,
        classes: [...f.classes].sort(),
        ksis: [...f.ksis].sort(),
        ...(f.leverage !== undefined ? { leverage: f.leverage } : {}),
        // upstream writes `null` for a control its pass never reached; absent
        // and explicitly-nothing are the same fact, so both land as no key
        aws: {
          ...(f.disposition ? { disposition: f.disposition } : {}),
          ...(f.rationale ? { rationale: f.rationale } : {}),
        },
        catalogRecipeIds: recipesForControl.get(f.controlId) ?? [],
      };
      if (record) {
        row.pipeline = {
          disposition: record.disposition,
          rationale: record.rationale,
          recipeIds: [...record.recipeIds].sort(),
          candidateCollectors: [...record.candidateCollectors].sort(),
          ...(record.remainder !== undefined ? { remainder: record.remainder } : {}),
          reviewed: record.reviewed,
          datasetVersion: record.datasetVersion,
        };
      }
      return row;
    })
    // by displayId, not controlId: the display form is zero-padded ("AC-02",
    // "AC-18 (01)"), so it sorts the way a reader of the control catalogue
    // expects, while the canonical id sorts "ac-18.1" before "ac-2"
    .sort((a, b) => a.displayId.localeCompare(b.displayId));

  const count = (d: Disposition) => rows.filter((r) => r.pipeline?.disposition === d).length;
  const discharged = rows.filter(
    (r) =>
      r.pipeline?.disposition === "automatable" &&
      r.pipeline.recipeIds.length > 0 &&
      r.pipeline.recipeIds.every((id) => recipeIds.has(id)),
  ).length;

  // What the catalog claims today, counted from the catalog itself rather than
  // from any record ABOUT the catalog — the thesis line "17 recipes against N
  // of 209 controls" is this number, and it must be recomputable without
  // reading a document.
  const catalogControls = new Set(input.recipes.flatMap((r) => r.control_ids));
  const reachable = new Set(catalogControls);
  for (const row of rows) {
    if (row.pipeline?.disposition === "automatable" || row.pipeline?.disposition === "partial") {
      reachable.add(row.controlId);
    }
  }

  const families = new Map<string, { narrative: number; unreviewed: number; total: number }>();
  for (const row of rows) {
    const entry = families.get(row.family) ?? { narrative: 0, unreviewed: 0, total: 0 };
    entry.total++;
    if (row.pipeline === undefined) entry.unreviewed++;
    else if (row.pipeline.disposition === "narrative") entry.narrative++;
    families.set(row.family, entry);
  }

  return {
    datasetVersion: input.datasetVersion,
    rows,
    rollup: {
      frontierTotal: rows.length,
      ksiReachedControls: input.ksiReachedControls,
      automatable: count("automatable"),
      partial: count("partial"),
      narrative: count("narrative"),
      unreviewed: rows.filter((r) => r.pipeline === undefined).length,
      discharged,
      catalogCovered: catalogControls.size,
      reachable: reachable.size,
      ceiling: input.ksiReachedControls > 0 ? reachable.size / input.ksiReachedControls : 0,
    },
    ceilingByFamily: [...families.entries()]
      .map(([family, e]) => ({ family, ...e }))
      .sort((a, b) => b.narrative + b.unreviewed - (a.narrative + a.unreviewed) || a.family.localeCompare(b.family)),
    problems: frontierProblems({
      rows,
      adjudications: input.adjudications,
      onFrontier,
      recipeIds,
      claimsControl: new Map(input.recipes.map((r) => [r.id, [...r.control_ids].sort()])),
      registered,
      datasetVersion: input.datasetVersion,
    }),
  };
}

function frontierProblems(input: {
  rows: FrontierRow[];
  adjudications: PipelineAdjudication[];
  onFrontier: Set<string>;
  recipeIds: Set<string>;
  /** recipe id → the controls that recipe claims */
  claimsControl: Map<string, string[]>;
  registered: Set<string>;
  datasetVersion: string;
}): string[] {
  const problems: string[] = [];
  const tier2 = new Set(TIER_2_COLLECTORS);
  for (const record of input.adjudications) {
    // Upstream drift, caught at the record rather than discovered in a number
    // (risk 4): our reasoning is keyed to controlId + datasetVersion, and a
    // re-published frontier must invalidate it loudly.
    if (record.datasetVersion !== input.datasetVersion) {
      problems.push(
        `adjudication "${record.controlId}" was written against dataset ${record.datasetVersion}, ` +
          `but the pinned dataset is ${input.datasetVersion} — re-read the control before trusting the disposition`,
      );
    }
    if (!input.onFrontier.has(record.controlId)) {
      problems.push(
        `adjudication "${record.controlId}" names a control that is not on the frontier — ` +
          "either it was covered upstream since, or the id is wrong",
      );
    }
    for (const id of record.recipeIds) {
      if (!input.recipeIds.has(id)) {
        problems.push(
          `adjudication "${record.controlId}" names recipe "${id}", which the catalog does not hold`,
        );
        continue;
      }
      // A recipe can only discharge a control it CLAIMS: the board, the
      // rollups and every coverage count join on `control_ids`, and
      // `validateRecipeIds` refuses a claim the recipe's own KSIs do not
      // reach. So an adjudication naming a recipe that does not name the
      // control back is a discharge that would never appear on any surface —
      // which usually means the control needs a NEW recipe over that
      // collector rather than a re-labelling of an existing one.
      const claimed = input.claimsControl.get(id) ?? [];
      if (!claimed.includes(record.controlId)) {
        problems.push(
          `adjudication "${record.controlId}" names recipe "${id}", whose control_ids are ` +
            `[${claimed.join(", ")}] — the recipe does not claim this control, so nothing would ever ` +
            "record it as discharged",
        );
      }
    }
    for (const name of record.candidateCollectors) {
      if (!input.registered.has(name) && !tier2.has(name)) {
        problems.push(
          `adjudication "${record.controlId}" names candidate collector "${name}", which is neither ` +
            `registered nor a Tier-2 cheap win (${[...tier2].join(", ")})`,
        );
      }
    }
    // A disposition claiming a repository CAN answer this, naming nothing that
    // would: the shape of an opinion (ground rule 8).
    if (
      (record.disposition === "automatable" || record.disposition === "partial") &&
      record.recipeIds.length === 0 &&
      record.candidateCollectors.length === 0
    ) {
      problems.push(
        `adjudication "${record.controlId}" is "${record.disposition}" but names no recipe and no ` +
          "candidate collector — a claim that a repository can answer it, with nothing that would",
      );
    }
  }
  return problems;
}

/** unreviewed controls, as the strict gate reports them (N0 decision 3) */
export function unreviewedControls(map: FrontierMap): string[] {
  return map.rows.filter((r) => r.pipeline === undefined).map((r) => r.displayId);
}

/**
 * The map as text. Sections in the order a reader asks them: where the pipeline
 * source stands, what it cannot answer, and then the controls themselves.
 */
export function renderFrontier(map: FrontierMap, useColor: boolean): string {
  const paint = (code: string, s: string) => (useColor ? `[${code}m${s}[0m` : s);
  const dim = (s: string) => paint("2", s);
  const red = (s: string) => paint("31", s);
  const bold = (s: string) => paint("1", s);
  const r = map.rollup;
  const pct = (n: number) => `${(n * 100).toFixed(1)}%`;
  const lines: string[] = [];

  lines.push(
    dim(
      "the pipeline source's answer to ramprules' automation frontier — catalog × adjudications × the pinned frontier. " +
        "Nothing was probed and nothing was written; every number here is counted from the rows below it.",
    ),
    "",
    bold(`frontier ${r.frontierTotal} uncovered controls · dataset ${map.datasetVersion}`),
    `  adjudicated  ${r.automatable} automatable · ${r.partial} partial · ${r.narrative} narrative`,
    `  unreviewed   ${r.unreviewed}${r.unreviewed > 0 ? dim("  ← the question nobody has asked yet") : ""}`,
    `  discharged   ${r.discharged}${dim("  (automatable AND a recipe exists today)")}`,
    "",
    bold("the pipeline ceiling"),
    `  catalog covers   ${r.catalogCovered} of ${r.ksiReachedControls} controls a KSI reaches`,
    `  reachable        ${r.reachable} of ${r.ksiReachedControls} — ${pct(r.ceiling)}`,
    dim("  reachable = what the catalog claims today ∪ what the adjudication says a repository could answer"),
    "",
  );

  if (map.ceilingByFamily.length > 0) {
    lines.push(bold("what a repository cannot answer, by family"), "");
    lines.push("  family  narrative  unreviewed  on frontier");
    for (const f of map.ceilingByFamily) {
      lines.push(
        `  ${f.family.padEnd(6)}  ${String(f.narrative).padStart(9)}  ${String(f.unreviewed).padStart(10)}  ${String(f.total).padStart(11)}`,
      );
    }
    lines.push("");
  }

  lines.push(bold("controls"), "");
  for (const row of map.rows) {
    const p = row.pipeline;
    const state = p ? p.disposition : dim("unreviewed");
    lines.push(
      `  ${row.displayId.padEnd(12)} ${row.family.padEnd(3)} ${state}` +
        (row.classes.length > 0 ? dim(` [${row.classes.join("")}]`) : "") +
        (row.leverage !== undefined ? dim(` lev ${row.leverage}`) : ""),
    );
    if (p) {
      lines.push(dim(`      ${p.rationale}`));
      if (p.remainder) lines.push(dim(`      remainder: ${p.remainder}`));
      if (p.recipeIds.length > 0) lines.push(dim(`      recipes: ${p.recipeIds.join(", ")}`));
      else if (p.candidateCollectors.length > 0) {
        lines.push(dim(`      candidates: ${p.candidateCollectors.join(", ")}`));
      }
    }
  }

  if (map.problems.length > 0) {
    lines.push("", red(`${map.problems.length} broken link(s):`));
    for (const p of map.problems) lines.push(red(`  - ${p}`));
  }

  return lines.join("\n");
}
