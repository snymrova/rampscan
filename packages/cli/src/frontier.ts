import type { Collector } from "@rampscan/core";
import type { FrontierControl } from "@rampscan/dataset";
import type { Disposition, CommitAdjudication, PipelineRecipe } from "@rampscan/schema";

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
// The frontier holds the controls a KSI reaches that no AWS recipe covers. When
// this command was written every reviewed row read `sourcesConsidered: ["aws"]`,
// and the question here was the other one: which of them can evidence committed
// to a REPOSITORY discharge?
//
// That premise expired on 2026-08-17 (N1a′-T2). The project that publishes the
// register opened a second evidence plane of its own and named it `pipeline`, so
// upstream's file now carries reviewed rows attributed to a source that is not
// AWS. Upstream's disposition is therefore filed under THE SOURCE THAT WROTE IT
// and never under a default, because the alternative — copying `f.disposition`
// into an `aws` field unconditionally, which is what this file used to do —
// prints upstream's pipeline reasoning in the AWS column on exactly the rows
// where our own column duplicates or disagrees with it. Two planes reasoning
// about one control is the interesting case, and conflating them destroys the
// only thing that makes it readable.
//
// Three plane names appear in this file and they are not interchangeable
// (N1a′-T3): `aws` and `pipeline` are UPSTREAM's two, and `commit` is ours —
// named for the anchor rather than the subject, because the subject is shared
// and the anchor is not. Where this file says "the commit plane" it means our
// adjudications; where it says `pipeline` it means upstream's.

/**
 * Collectors named in `IMPLEMENTATION-PLAN-REMAINING.md` Tier 2 as cheap wins:
 * each an H-phase-shaped single-collector move, scoped upstream, on nobody's
 * critical path. An adjudication may name one of these as its candidate before
 * it is written — that is the whole use of the list — but it may not name
 * something nobody has ever scoped, which is how a disposition turns into a
 * wish.
 */
export const TIER_2_COLLECTORS = ["actionlint", "dockle", "license", "trivy-config", "zizmor"];

/**
 * The key a disposition is filed under when upstream published one and named no
 * source for it. Reserved rather than guessed: dropping the reasoning would lose
 * it, and crediting it to a plane the file did not name is the bug T2 fixes,
 * arriving by a quieter route.
 */
export const UNATTRIBUTED = "unattributed";

/** upstream's own pass over a control, mirrored and never edited by us */
export interface UpstreamDisposition {
  disposition?: string;
  rationale?: string;
}

export interface FrontierRow {
  controlId: string;
  displayId: string;
  family: string;
  classes: string[];
  ksis: string[];
  leverage?: number;
  /**
   * Upstream's adjudications, keyed by the source in `sourcesConsidered` that
   * wrote each one — `aws` for the AWS pass, `pipeline` for upstream's own
   * pipeline plane, `unattributed` when the file names none. Keys sorted on
   * construction so the JSON is stable.
   */
  upstream: Record<string, UpstreamDisposition>;
  /**
   * Ours, when `recipes/adjudications/` holds a record for it. Named `commit`
   * and not `pipeline` because `upstream` above already has a `pipeline` key
   * that means something else — a row where both are populated is the case
   * this whole command was rebuilt to render, and two fields one word apart
   * would have made it unreadable at exactly that moment.
   */
  commit?: {
    disposition: Disposition;
    rationale: string;
    recipeIds: string[];
    candidateCollectors: string[];
    /**
     * Two limbs — the control's own gap, and the boundary gap every claim owes.
     * Taken from the record's own type rather than restated, so the map cannot
     * drift from the schema the records are validated against.
     */
    remainder?: CommitAdjudication["remainder"];
    externalSystem?: string;
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
  /** of the frontier, by our disposition */
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
  /** reachable ÷ ksiReachedControls — the commit plane's ceiling */
  ceiling: number;
  /**
   * How many frontier rows each upstream source adjudicated, counted from the
   * rows rather than read from upstream's own `rollup.bySource`. Two independent
   * counts of one fact is the only way a mis-filing is visible at all: the bug
   * T2 fixed would have shown 61 rows under `aws` where upstream's own rollup
   * said 48, and nothing in the old shape would have noticed.
   */
  upstreamAdjudicatedBySource: Record<string, number>;
}

/**
 * A record whose control has left the frontier. It has no row — rows are built
 * FROM the frontier and the control is no longer on it — so without this it
 * would disappear from every surface the moment upstream answered, taking its
 * reasoning with it. That is the outcome ground rule 10 forbids, and the only
 * thing separating a declared retirement from a quiet delete is that this list
 * prints.
 */
export interface RetiredAdjudication {
  controlId: string;
  displayId: string;
  family: string;
  /** the disposition it held while it was live, unedited */
  disposition: Disposition;
  at: string;
  overlayVersion: string;
  reason: string;
  upstreamRecipeIds: string[];
}

export interface FrontierMap {
  datasetVersion: string;
  rows: FrontierRow[];
  rollup: FrontierRollup;
  /** families the commit plane cannot answer, with the count it cannot answer (N1d) */
  ceilingByFamily: Array<{ family: string; narrative: number; unreviewed: number; total: number }>;
  /** records closed because upstream took the control off the frontier */
  retired: RetiredAdjudication[];
  problems: string[];
}

export interface FrontierInput {
  frontier: FrontierControl[];
  adjudications: CommitAdjudication[];
  recipes: PipelineRecipe[];
  collectors: Collector[];
  /** the pin every record must have been written against (ground rule 2) */
  datasetVersion: string;
  /** upstream's `rollup.ksiReachedControls` — read, never typed */
  ksiReachedControls: number;
}

/**
 * File upstream's disposition under the source that wrote it (N1a′-T2).
 *
 * Upstream publishes one `disposition`/`rationale` pair per row alongside a
 * `sourcesConsidered` list, so a row reviewed by two of upstream's planes
 * carries both names and one paragraph; that paragraph is filed under both,
 * because the file does not say which half of it belongs to which plane and
 * picking one would be us inventing an attribution upstream did not publish.
 *
 * Upstream writes `null` for a control its passes never reached, and "the field
 * is absent" and "the field is explicitly nothing" are the same fact to a
 * reader — both mean unreviewed, and both produce no key at all.
 */
function upstreamDispositions(f: FrontierControl): Record<string, UpstreamDisposition> {
  const claim: UpstreamDisposition = {
    ...(f.disposition ? { disposition: f.disposition } : {}),
    ...(f.rationale ? { rationale: f.rationale } : {}),
  };
  if (claim.disposition === undefined && claim.rationale === undefined) return {};
  const sources = f.sourcesConsidered.length > 0 ? [...f.sourcesConsidered].sort() : [UNATTRIBUTED];
  return Object.fromEntries(sources.map((source) => [source, claim]));
}

/** rows each upstream source adjudicated, keys sorted */
function upstreamCounts(rows: FrontierRow[]): Record<string, number> {
  const counts = new Map<string, number>();
  for (const row of rows) {
    for (const source of Object.keys(row.upstream)) {
      counts.set(source, (counts.get(source) ?? 0) + 1);
    }
  }
  return Object.fromEntries([...counts.entries()].sort(([a], [b]) => a.localeCompare(b)));
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
        upstream: upstreamDispositions(f),
        catalogRecipeIds: recipesForControl.get(f.controlId) ?? [],
      };
      if (record) {
        row.commit = {
          disposition: record.disposition,
          rationale: record.rationale,
          recipeIds: [...record.recipeIds].sort(),
          candidateCollectors: [...record.candidateCollectors].sort(),
          ...(record.remainder !== undefined ? { remainder: record.remainder } : {}),
          ...(record.externalSystem !== undefined
            ? { externalSystem: record.externalSystem }
            : {}),
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

  const count = (d: Disposition) => rows.filter((r) => r.commit?.disposition === d).length;
  const discharged = rows.filter(
    (r) =>
      r.commit?.disposition === "automatable" &&
      r.commit.recipeIds.length > 0 &&
      r.commit.recipeIds.every((id) => recipeIds.has(id)),
  ).length;

  // What the catalog claims today, counted from the catalog itself rather than
  // from any record ABOUT the catalog — the thesis line "17 recipes against N
  // of 209 controls" is this number, and it must be recomputable without
  // reading a document.
  const catalogControls = new Set(input.recipes.flatMap((r) => r.control_ids));
  const reachable = new Set(catalogControls);
  for (const row of rows) {
    if (row.commit?.disposition === "automatable" || row.commit?.disposition === "partial") {
      reachable.add(row.controlId);
    }
  }

  const families = new Map<string, { narrative: number; unreviewed: number; total: number }>();
  for (const row of rows) {
    const entry = families.get(row.family) ?? { narrative: 0, unreviewed: 0, total: 0 };
    entry.total++;
    if (row.commit === undefined) entry.unreviewed++;
    else if (row.commit.disposition === "narrative") entry.narrative++;
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
      unreviewed: rows.filter((r) => r.commit === undefined).length,
      discharged,
      catalogCovered: catalogControls.size,
      reachable: reachable.size,
      ceiling: input.ksiReachedControls > 0 ? reachable.size / input.ksiReachedControls : 0,
      upstreamAdjudicatedBySource: upstreamCounts(rows),
    },
    ceilingByFamily: [...families.entries()]
      .map(([family, e]) => ({ family, ...e }))
      .sort((a, b) => b.narrative + b.unreviewed - (a.narrative + a.unreviewed) || a.family.localeCompare(b.family)),
    retired: input.adjudications
      .flatMap((record) =>
        record.retired === undefined
          ? []
          : [
              {
                controlId: record.controlId,
                displayId: record.displayId,
                family: record.family,
                disposition: record.disposition,
                at: record.retired.at,
                overlayVersion: record.retired.overlayVersion,
                reason: record.retired.reason,
                upstreamRecipeIds: [...record.retired.upstreamRecipeIds].sort(),
              },
            ],
      )
      .sort((a, b) => a.displayId.localeCompare(b.displayId)),
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
  adjudications: CommitAdjudication[];
  onFrontier: Set<string>;
  recipeIds: Set<string>;
  /** recipe id → the controls that recipe claims */
  claimsControl: Map<string, string[]>;
  registered: Set<string>;
  datasetVersion: string;
}): string[] {
  const problems: string[] = [];
  const tier2 = new Set(TIER_2_COLLECTORS);
  // Upstream published reasoning and named nobody who wrote it. Not our record's
  // fault and not silently absorbable either: the whole of T2 is that a
  // disposition belongs to the plane that wrote it, and a claim with no plane
  // cannot be compared with ours, cited under ground rule 10, or argued with.
  for (const row of input.rows) {
    if (row.upstream[UNATTRIBUTED] !== undefined) {
      problems.push(
        `frontier row "${row.displayId}" carries an upstream disposition ` +
          `("${row.upstream[UNATTRIBUTED].disposition ?? "—"}") with an empty sourcesConsidered — ` +
          "it is filed unattributed rather than credited to a plane the file did not name",
      );
    }
  }
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
    // The frontier is the UNCOVERED set and it is upstream's, so it shrinks
    // whenever upstream answers something. A live record pointing off it is
    // either drift nobody read or a typo; a retired one is that drift already
    // read and declared, which is the only difference between the two and the
    // whole reason `retired` exists rather than a delete.
    if (!input.onFrontier.has(record.controlId) && record.retired === undefined) {
      problems.push(
        `adjudication "${record.controlId}" names a control that is not on the frontier — ` +
          "either it was covered upstream since, or the id is wrong",
      );
    }
    // The mirror, and it is the one that catches us rather than upstream:
    // retiring a record whose control upstream STILL lists as uncovered is
    // work dropped under cover of a re-pin.
    if (input.onFrontier.has(record.controlId) && record.retired !== undefined) {
      problems.push(
        `adjudication "${record.controlId}" is retired, but the control is still on the frontier — ` +
          "upstream lists it as uncovered, so the reasoning is still owed rather than closed",
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
  return map.rows.filter((r) => r.commit === undefined).map((r) => r.displayId);
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
      "the commit plane's answer to ramprules' automation frontier — catalog × adjudications × the pinned frontier. " +
        "Nothing was probed and nothing was written; every number here is counted from the rows below it.",
    ),
    "",
    bold(`frontier ${r.frontierTotal} uncovered controls · dataset ${map.datasetVersion}`),
    `  adjudicated  ${r.automatable} automatable · ${r.partial} partial · ${r.narrative} narrative`,
    `  unreviewed   ${r.unreviewed}${r.unreviewed > 0 ? dim("  ← the question nobody has asked yet") : ""}`,
    `  discharged   ${r.discharged}${dim("  (automatable AND a recipe exists today)")}`,
    "",
    bold("the commit plane's ceiling"),
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

  const bySource = Object.entries(r.upstreamAdjudicatedBySource);
  if (bySource.length > 0) {
    lines.push(
      bold("upstream's own passes over the same controls"),
      ...bySource.map(([source, n]) => `  ${source.padEnd(14)} ${String(n).padStart(3)} adjudicated`),
      dim("  filed by the source that wrote each one, never conflated — a control both planes"),
      dim("  reasoned about is the interesting case, and one column would hide it"),
      "",
    );
  }

  if (map.retired.length > 0) {
    lines.push(bold("retired — upstream took the control off the frontier"), "");
    for (const rec of map.retired) {
      lines.push(
        `  ${rec.displayId.padEnd(12)} ${rec.family.padEnd(3)} was ${rec.disposition}` +
          dim(`  · retired ${rec.at} at overlay ${rec.overlayVersion}`),
      );
      lines.push(dim(`      ${rec.reason}`));
      if (rec.upstreamRecipeIds.length > 0) {
        lines.push(dim(`      upstream recipes: ${rec.upstreamRecipeIds.join(", ")}`));
      }
    }
    lines.push(
      dim("  kept rather than deleted — a paragraph that vanishes at a re-pin leaves a reader"),
      dim("  holding two overlays unable to tell agreement from absence (ground rule 10)"),
      "",
    );
  }

  lines.push(bold("controls"), "");
  for (const row of map.rows) {
    const p = row.commit;
    const state = p ? p.disposition : dim("unreviewed");
    lines.push(
      `  ${row.displayId.padEnd(12)} ${row.family.padEnd(3)} ${state}` +
        (row.classes.length > 0 ? dim(` [${row.classes.join("")}]`) : "") +
        (row.leverage !== undefined ? dim(` lev ${row.leverage}`) : ""),
    );
    const upstream = Object.entries(row.upstream);
    if (upstream.length > 0) {
      lines.push(
        dim(
          `      upstream: ${upstream.map(([source, u]) => `${source} ${u.disposition ?? "—"}`).join(" · ")}`,
        ),
      );
    }
    if (p) {
      lines.push(dim(`      ${p.rationale}`));
      // The two limbs print on separate lines and are labelled differently,
      // because they are different kinds of gap: `remainder` is this control's,
      // `boundary` is every claim's. Run together they read as one hedge, and
      // the boundary limb — the one no control asks for — is the half a reader
      // skips first.
      if (p.remainder) {
        lines.push(dim(`      remainder: ${p.remainder.control}`));
        if (p.remainder.boundary) lines.push(dim(`      boundary:  ${p.remainder.boundary}`));
      }
      if (p.externalSystem) lines.push(dim(`      external system: ${p.externalSystem}`));
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
