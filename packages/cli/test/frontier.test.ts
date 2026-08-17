import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { allCollectors } from "@rampscan/collectors";
import { DEFAULT_DATASET_PIN, loadLocalDataset } from "@rampscan/dataset";
import type { PipelineAdjudication } from "@rampscan/schema";
import { PipelineAdjudication as AdjudicationSchema } from "@rampscan/schema";
import { loadAdjudications } from "../src/adjudications.js";
import { buildFrontier, renderFrontier, unreviewedControls } from "../src/frontier.js";
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
  it("reads the frontier under the pin, and it is the 121", async () => {
    const map = await realMap();
    expect(map.rollup.frontierTotal).toBe(121);
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
    expect(a).toContain("frontier 121 uncovered controls");
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
