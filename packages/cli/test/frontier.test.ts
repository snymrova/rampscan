import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { allCollectors } from "@rampscan/collectors";
import type { FrontierControl } from "@rampscan/dataset";
import { DEFAULT_DATASET_PIN, loadLocalDataset } from "@rampscan/dataset";
import type { PipelineAdjudication } from "@rampscan/schema";
import { PipelineAdjudication as AdjudicationSchema } from "@rampscan/schema";
import { loadAdjudications } from "../src/adjudications.js";
import type { FrontierRow } from "../src/frontier.js";
import { UNATTRIBUTED, buildFrontier, renderFrontier, unreviewedControls } from "../src/frontier.js";
import { loadRecipes } from "../src/recipes.js";

// `rampscan frontier` (plan N1a-T2). Two kinds of test, answering different
// questions — the posture tools-map.test.ts established:
//
//   over the REAL overlay: is this repository's adjudication set intact, and
//     does every number it prints recount from its own rows? Ground rule 9
//     says coverage is computed, never typed; a coverage figure that cannot be
//     independently recounted from the rows it summarises is typed with extra
//     steps.
//   over SYNTHETIC records: does the checker notice a broken link? An overlay
//     that has only ever been read healthy proves nothing about the day
//     someone adjudicates a control against a recipe that does not exist.

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "../../..");
const DERIVED = join(REPO_ROOT, "docs/context/ramprules/derived");

async function realMap() {
  const dataset = await loadLocalDataset(DERIVED, DEFAULT_DATASET_PIN);
  return buildFrontier({
    frontier: dataset.frontier(),
    adjudications: await loadAdjudications(join(REPO_ROOT, "recipes/adjudications")),
    recipes: await loadRecipes(join(REPO_ROOT, "recipes/pipeline")),
    collectors: allCollectors,
    datasetVersion: dataset.version(),
    ksiReachedControls: dataset.ksiReachedControls(),
  });
}

function record(over: Partial<PipelineAdjudication> = {}): PipelineAdjudication {
  return AdjudicationSchema.parse({
    controlId: "sa-2",
    displayId: "SA-02",
    family: "SA",
    disposition: "narrative",
    rationale: "a paragraph",
    source: "pipeline",
    recipeIds: [],
    candidateCollectors: [],
    reviewed: "2026-08-16",
    datasetVersion: DEFAULT_DATASET_PIN,
    ...over,
  });
}

async function mapWith(adjudications: PipelineAdjudication[]) {
  const dataset = await loadLocalDataset(DERIVED, DEFAULT_DATASET_PIN);
  return buildFrontier({
    frontier: dataset.frontier(),
    adjudications,
    recipes: await loadRecipes(join(REPO_ROOT, "recipes/pipeline")),
    collectors: allCollectors,
    datasetVersion: dataset.version(),
    ksiReachedControls: dataset.ksiReachedControls(),
  });
}

describe("the overlay as it stands", () => {
  it("reads the frontier under the pin, and it is the 119", async () => {
    // 121 until the re-pin to overlay 0.7.2 (N1a′-T1's second half). Upstream
    // authored two pipeline recipes and `sr-6` and `sr-8` left the uncovered
    // set — the frontier is upstream's file and it shrinks when upstream
    // answers something, which is the whole reason the number is read here
    // rather than typed anywhere.
    const map = await realMap();
    expect(map.rollup.frontierTotal).toBe(119);
    expect(map.datasetVersion).toBe(DEFAULT_DATASET_PIN);
    // upstream's denominator, read rather than typed — every ceiling figure
    // this repository publishes divides by this number
    expect(map.rollup.ksiReachedControls).toBe(209);
  });

  it("names no broken link", async () => {
    const map = await realMap();
    expect(map.problems).toEqual([]);
  });

  it("every number recounts from the rows it summarises", async () => {
    // Ground rule 9, enforced rather than trusted. The rollup is a fold OF the
    // rows; if an independent recount here disagrees with it, the printed
    // coverage figure is an assertion about the overlay rather than a
    // measurement of it.
    const map = await realMap();
    const r = map.rollup;
    const by = (d: string) => map.rows.filter((row) => row.pipeline?.disposition === d).length;
    expect(r.automatable).toBe(by("automatable"));
    expect(r.partial).toBe(by("partial"));
    expect(r.narrative).toBe(by("narrative"));
    expect(r.unreviewed).toBe(map.rows.filter((row) => row.pipeline === undefined).length);
    expect(r.automatable + r.partial + r.narrative + r.unreviewed).toBe(r.frontierTotal);
    expect(r.ceiling).toBeCloseTo(r.reachable / r.ksiReachedControls, 10);
    // the ceiling counts controls, and a control adjudicated automatable or
    // partial is reachable exactly once even when the catalog already claims it
    const reachable = new Set(map.rows.flatMap((row) =>
      row.pipeline?.disposition === "automatable" || row.pipeline?.disposition === "partial"
        ? [row.controlId]
        : [],
    ));
    expect(r.reachable).toBeGreaterThanOrEqual(reachable.size);
    expect(r.reachable).toBeLessThanOrEqual(reachable.size + r.catalogCovered);
    // per-family counts fold from the same rows
    const familyTotal = map.ceilingByFamily.reduce((n, f) => n + f.total, 0);
    expect(familyTotal).toBe(r.frontierTotal);
  });

  it("a partial disposition always names its remainder, on every record we ship", async () => {
    // The schema refuses one at parse time; this is the catalog-level restatement,
    // because `partial` not counting as covered (N0 decision 3) is only honest
    // while the boundary is written down.
    const map = await realMap();
    for (const row of map.rows) {
      if (row.pipeline?.disposition === "partial") {
        expect(row.pipeline.remainder, `${row.displayId} is partial with no remainder`).toBeTruthy();
      }
    }
  });

  it("nothing is discharged yet, and the command says so rather than rounding up", async () => {
    // N1a adjudicates; N1b writes the recipes. A `discharged` figure above zero
    // before wave 1 lands would mean the count is reading intent as delivery.
    const map = await realMap();
    expect(map.rollup.discharged).toBe(0);
    expect(unreviewedControls(map).length).toBe(map.rollup.unreviewed);
  });

  it("renders the same text twice — this is a document people diff", async () => {
    const a = renderFrontier(await realMap(), false);
    const b = renderFrontier(await realMap(), false);
    expect(a).toBe(b);
    expect(a).toContain("frontier 119 uncovered controls");
  });
});

// N1a′-T2. `frontier.ts` used to copy `f.disposition` into `row.aws`
// unconditionally, on an invariant that had already expired: upstream opened a
// second plane, named it `pipeline`, and its reviewed rows carry that name. The
// mis-filing would have printed upstream's pipeline reasoning in the AWS column
// on exactly the rows where our own column disagrees with it.
describe("upstream's dispositions are filed by the source that wrote them", () => {
  function frontierRow(over: Partial<FrontierControl> = {}): FrontierControl {
    return {
      controlId: "sa-8",
      displayId: "SA-08",
      family: "SA",
      ksis: ["KSI-PIY-RSD"],
      classes: ["b"],
      disposition: "partial",
      rationale: "upstream's paragraph",
      sourcesConsidered: ["aws"],
      ...over,
    } as FrontierControl;
  }

  /** the single row these synthetic maps are about, or a loud failure */
  function only(map: { rows: FrontierRow[] }): FrontierRow {
    const [row, ...rest] = map.rows;
    if (row === undefined || rest.length > 0) {
      throw new Error(`expected exactly one row, got ${map.rows.length}`);
    }
    return row;
  }

  async function mapOver(frontier: FrontierControl[]) {
    return buildFrontier({
      frontier,
      adjudications: [],
      recipes: await loadRecipes(join(REPO_ROOT, "recipes/pipeline")),
      collectors: allCollectors,
      datasetVersion: DEFAULT_DATASET_PIN,
      ksiReachedControls: 209,
    });
  }

  it("a row attributed to pipeline does not populate the aws column", async () => {
    const map = await mapOver([frontierRow({ sourcesConsidered: ["pipeline"] })]);
    expect(only(map).upstream.aws).toBeUndefined();
    expect(only(map).upstream.pipeline?.disposition).toBe("partial");
    expect(map.rollup.upstreamAdjudicatedBySource).toEqual({ pipeline: 1 });
  });

  it("a row attributed to aws does", async () => {
    const map = await mapOver([frontierRow()]);
    expect(only(map).upstream.aws?.disposition).toBe("partial");
    expect(only(map).upstream.pipeline).toBeUndefined();
  });

  it("a row attributed to both populates both, and the renderer names them rather than picking one", async () => {
    const map = await mapOver([frontierRow({ sourcesConsidered: ["pipeline", "aws"] })]);
    expect(Object.keys(only(map).upstream)).toEqual(["aws", "pipeline"]);
    expect(map.rollup.upstreamAdjudicatedBySource).toEqual({ aws: 1, pipeline: 1 });
    const text = renderFrontier(map, false);
    expect(text).toContain("upstream: aws partial · pipeline partial");
  });

  it("an unreviewed row populates nothing at all", async () => {
    // upstream writes `null` for a control no pass reached; absent and
    // explicitly-nothing are the same fact, and neither is an adjudication
    const map = await mapOver([
      frontierRow({ disposition: null, rationale: null, sourcesConsidered: [] }),
    ]);
    expect(only(map).upstream).toEqual({});
    expect(map.problems).toEqual([]);
  });

  it("a disposition with no source is filed unattributed and reported, never credited to a plane", async () => {
    const map = await mapOver([frontierRow({ sourcesConsidered: [] })]);
    expect(only(map).upstream.aws).toBeUndefined();
    expect(only(map).upstream[UNATTRIBUTED]?.disposition).toBe("partial");
    expect(map.problems.join(" ")).toContain("filed unattributed");
  });

  it("the aws count recounts against upstream's own rollup.bySource", async () => {
    // Two independent counts of one fact, which is the only way a mis-filing is
    // visible at all: before T2 every reviewed row landed under `aws` whatever
    // the file said, and no number in the system would have disagreed.
    const dataset = await loadLocalDataset(DERIVED, DEFAULT_DATASET_PIN);
    const raw = JSON.parse(
      await readFile(join(DERIVED, "automation-frontier.json"), "utf8"),
    ) as { data: { rollup: { bySource: Record<string, Record<string, number>> } } };
    const map = await realMap();
    for (const [source, upstreamCounts] of Object.entries(raw.data.rollup.bySource)) {
      // covered controls have left the frontier, so what remains adjudicated on
      // it is automatable + partial + narrative
      const expected =
        (upstreamCounts.automatable ?? 0) +
        (upstreamCounts.partial ?? 0) +
        (upstreamCounts.narrative ?? 0);
      expect(map.rollup.upstreamAdjudicatedBySource[source] ?? 0, source).toBe(expected);
    }
    expect(dataset.frontierOverlayVersion()).toBeDefined();
  });
});

// N1a′-T1's second half. The frontier is the UNCOVERED set and it is upstream's
// file, so it shrinks whenever upstream answers something: the re-pin from
// overlay 0.6.0 to 0.7.2 took `sr-6` and `sr-8` off it, and `sr-8` was one of
// the seven records this overlay had already written. Deleting the record would
// have been the silent drop ground rule 10 forbids — a reader holding both
// overlays would find upstream's paragraph standing and ours simply gone, with
// no way to tell whether we agreed, disagreed, or never looked.
describe("a record whose control leaves the frontier is retired, not deleted", () => {
  const retirement = {
    at: "2026-08-17",
    overlayVersion: "0.7.2",
    reason: "upstream answered it and argued the route; conceded",
    upstreamRecipeIds: ["some-upstream-recipe"],
  };

  it("a retired record off the frontier is not a broken link, and it still prints", async () => {
    const map = await mapWith([
      record({ controlId: "not-a-control", displayId: "ZZ-99", retired: retirement }),
    ]);
    expect(map.problems).toEqual([]);
    expect(map.retired.map((r) => r.displayId)).toEqual(["ZZ-99"]);
    // the reasoning survives the retirement — that is the entire point of it
    expect(renderFrontier(map, false)).toContain(retirement.reason);
  });

  it("the same record WITHOUT the retirement is still a broken link", async () => {
    // The pair is the test: `retired` must be the declaration that closes it,
    // never a field whose presence or absence changes nothing.
    const map = await mapWith([record({ controlId: "not-a-control", displayId: "ZZ-99" })]);
    expect(map.problems.join(" ")).toContain("not on the frontier");
    expect(map.retired).toEqual([]);
  });

  it("retiring a record whose control is STILL on the frontier is a broken link", async () => {
    // The mirror, and the one that catches us rather than upstream: closing a
    // record upstream still lists as uncovered is work dropped under cover of
    // a re-pin, and it would otherwise look identical to work finished.
    const map = await mapWith([record({ controlId: "sa-2", retired: retirement })]);
    expect(map.problems.join(" ")).toContain("still on the frontier");
  });

  it("a retired record is counted nowhere — it has no row and moves no number", async () => {
    const live = await mapWith([record({ controlId: "sa-2", disposition: "narrative" })]);
    const dead = await mapWith([
      record({ controlId: "not-a-control", displayId: "ZZ-99", retired: retirement }),
    ]);
    expect(dead.rollup.narrative).toBe(live.rollup.narrative - 1);
    expect(dead.rollup.frontierTotal).toBe(live.rollup.frontierTotal);
  });

  it("sr-8 is the real one, and it cites the upstream recipe that took it", async () => {
    const map = await realMap();
    const [sr8, ...rest] = map.retired;
    expect(rest).toEqual([]);
    expect(sr8?.controlId).toBe("sr-8");
    expect(sr8?.disposition).toBe("partial");
    expect(sr8?.overlayVersion).toBe("0.7.2");
    // ground rule 10: agreement and disagreement are both DECLARED, and this
    // one is a concession, so the reason has to name what upstream authored
    expect(sr8?.upstreamRecipeIds).toEqual(["supply-chain-alert-notification-routing"]);
    // and the record it closes is unedited — a retired claim is a historical
    // claim, and rewriting one to look better in hindsight is how an overlay
    // stops being evidence
    const raw = JSON.parse(
      await readFile(join(REPO_ROOT, "recipes/adjudications/sr-8.json"), "utf8"),
    ) as { disposition: string; remainder: string };
    expect(raw.disposition).toBe("partial");
    expect(raw.remainder).toContain("The agreements.");
  });
});

describe("the checker notices a broken overlay", () => {
  it("an adjudication for a control that is not on the frontier", async () => {
    const map = await mapWith([record({ controlId: "not-a-control", displayId: "ZZ-99" })]);
    expect(map.problems.join(" ")).toContain("not on the frontier");
  });

  it("an adjudication naming a recipe the catalog does not hold", async () => {
    const map = await mapWith([
      record({ disposition: "automatable", recipeIds: ["invented-recipe"] }),
    ]);
    expect(map.problems.join(" ")).toContain("the catalog does not hold");
  });

  it("an adjudication naming a real recipe that does not claim the control", async () => {
    // The subtle one, and the reason it earns a check: the board, the rollups
    // and every coverage count join on the recipe's OWN `control_ids`, and
    // `validateRecipeIds` refuses a claim the recipe's KSIs do not reach. A
    // record naming a recipe that does not name the control back describes a
    // discharge no surface would ever record — it usually means the control
    // needs a new recipe over that collector, which is wave 1's job.
    const map = await mapWith([
      record({ disposition: "automatable", recipeIds: ["dependency-update-automation"] }),
    ]);
    expect(map.problems.join(" ")).toContain("does not claim this control");
  });

  it("an adjudication naming a collector nobody has scoped", async () => {
    const map = await mapWith([
      record({ disposition: "partial", remainder: "r", candidateCollectors: ["wishful"] }),
    ]);
    expect(map.problems.join(" ")).toContain("neither registered nor a Tier-2 cheap win");
    // …while a Tier-2 name is accepted: the whole point of the list is that a
    // disposition may rest on a collector that is scoped but unwritten
    const ok = await mapWith([
      record({ disposition: "partial", remainder: "r", candidateCollectors: ["dockle"] }),
    ]);
    expect(ok.problems).toEqual([]);
  });

  it("an adjudication written against a different dataset version", async () => {
    // Risk 4, caught at the record. Our reasoning is keyed to controlId +
    // datasetVersion; a re-published frontier must invalidate it loudly rather
    // than silently re-basing a disposition onto a control that moved.
    const map = await mapWith([record({ datasetVersion: "2027.01.01.01" })]);
    expect(map.problems.join(" ")).toContain("was written against dataset 2027.01.01.01");
  });

  it("a claim that a repository can answer it, naming nothing that would", async () => {
    const map = await mapWith([record({ disposition: "automatable" })]);
    expect(map.problems.join(" ")).toContain("with nothing that would");
  });

  it("the schema refuses a partial with no remainder, and a remainder without a partial", () => {
    expect(() => record({ disposition: "partial" })).toThrow();
    expect(() => record({ disposition: "narrative", remainder: "half of it" })).toThrow();
    expect(() => record({ disposition: "partial", remainder: "the half a repo cannot see" }))
      .not.toThrow();
  });
});
