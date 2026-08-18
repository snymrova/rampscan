import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { allCollectors } from "@rampscan/collectors";
import type { FrontierControl } from "@rampscan/dataset";
import { DEFAULT_DATASET_PIN, loadLocalDataset } from "@rampscan/dataset";
import type { CommitAdjudication, PipelineRecipe } from "@rampscan/schema";
import {
  CommitAdjudication as AdjudicationSchema,
  PipelineRecipe as RecipeSchema,
} from "@rampscan/schema";
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
    recipes: await loadRecipes(join(REPO_ROOT, "recipes/commit")),
    collectors: allCollectors,
    datasetVersion: dataset.version(),
    ksiReachedControls: dataset.ksiReachedControls(),
    // Wired here exactly as `main.ts` wires it, so "names no broken link" below
    // covers ground rule 10's CATALOG arm on the real catalog rather than only
    // its record arm. Leaving it off would have left the arm passing on an
    // input it never received — the shape of the hole it was built to close.
    upstreamRecipesFor: (controlId) => dataset.upstreamRecipesFor(controlId),
  });
}

function record(over: Partial<CommitAdjudication> = {}): CommitAdjudication {
  return AdjudicationSchema.parse({
    controlId: "sa-2",
    displayId: "SA-02",
    family: "SA",
    disposition: "narrative",
    rationale: "a paragraph",
    source: "commit",
    recipeIds: [],
    candidateCollectors: [],
    externalSystem: "nothing: no network in collectors, local execution, node:crypto signing",
    reviewed: "2026-08-16",
    datasetVersion: DEFAULT_DATASET_PIN,
    ...over,
  });
}

/** a two-limbed remainder, for synthetic records that only need a valid one */
const REMAINDER = { control: "the half a repo cannot see", boundary: "one checkout of unknown many" };

async function mapWith(adjudications: CommitAdjudication[]) {
  const dataset = await loadLocalDataset(DERIVED, DEFAULT_DATASET_PIN);
  return buildFrontier({
    frontier: dataset.frontier(),
    adjudications,
    recipes: await loadRecipes(join(REPO_ROOT, "recipes/commit")),
    collectors: allCollectors,
    datasetVersion: dataset.version(),
    ksiReachedControls: dataset.ksiReachedControls(),
  });
}

describe("the overlay as it stands", () => {
  it("reads the whole frontier under the pin, losing no row to the join", async () => {
    // The number is NOT typed here, and the reason is the same one that
    // reshaped the overlap pin in batch 1: a literal is a snapshot wearing an
    // assertion's clothes. It was 121 at overlay 0.6.0, 119 at 0.7.2 and 112 at
    // 0.7.5 — three values inside two days, every move upstream's to make,
    // because the frontier is the UNCOVERED set and it shrinks whenever
    // upstream answers something. A typed count fails on upstream's work rather
    // than on ours, and it fails second: `DEFAULT_OVERLAY_PINS` already refuses
    // to load a moved overlay at all, so the literal caught nothing the loader
    // had not already caught and cost an edit in a second file every re-pin.
    //
    // What is worth asserting is the property the literal was standing in for —
    // that the map is a lossless fold of the pinned file, so no row is dropped
    // between upstream's frontier and our rollup.
    const dataset = await loadLocalDataset(DERIVED, DEFAULT_DATASET_PIN);
    const map = await realMap();
    expect(map.rollup.frontierTotal).toBe(dataset.frontier().length);
    expect(map.rows.length).toBe(dataset.frontier().length);
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
    const by = (d: string) => map.rows.filter((row) => row.commit?.disposition === d).length;
    expect(r.automatable).toBe(by("automatable"));
    expect(r.partial).toBe(by("partial"));
    expect(r.narrative).toBe(by("narrative"));
    expect(r.unreviewed).toBe(map.rows.filter((row) => row.commit === undefined).length);
    expect(r.automatable + r.partial + r.narrative + r.unreviewed).toBe(r.frontierTotal);
    expect(r.ceiling).toBeCloseTo(r.reachable / r.ksiReachedControls, 10);
    // the ceiling counts controls, and a control adjudicated automatable or
    // partial is reachable exactly once even when the catalog already claims it
    const reachable = new Set(map.rows.flatMap((row) =>
      row.commit?.disposition === "automatable" || row.commit?.disposition === "partial"
        ? [row.controlId]
        : [],
    ));
    expect(r.reachable).toBeGreaterThanOrEqual(reachable.size);
    expect(r.reachable).toBeLessThanOrEqual(reachable.size + r.catalogCovered);
    // per-family counts fold from the same rows
    const familyTotal = map.ceilingByFamily.reduce((n, f) => n + f.total, 0);
    expect(familyTotal).toBe(r.frontierTotal);
  });

  it("a partial disposition always names BOTH remainder limbs, on every record we ship", async () => {
    // The schema refuses one at parse time; this is the catalog-level restatement,
    // because `partial` not counting as covered (N0 decision 3) is only honest
    // while the boundary is written down.
    const map = await realMap();
    for (const row of map.rows) {
      if (row.commit?.disposition === "partial") {
        const r = row.commit.remainder;
        expect(r?.control, `${row.displayId} is partial with no remainder`).toBeTruthy();
        expect(r?.boundary, `${row.displayId} names no boundary limb`).toBeTruthy();
      }
    }
  });

  it("every live record says what this evidence path adds to the boundary", async () => {
    // N1a′-T4. The answer here is always the negative one, and that is the
    // point: a differentiator stated on some records and not others is one
    // nobody can count. Asserted longer than a stub so an empty gesture fails,
    // the same posture the L4b affordance test used on its own reason string.
    const records = await loadAdjudications(join(REPO_ROOT, "recipes/adjudications"));
    const live = records.filter((r) => r.retired === undefined);
    expect(live.length).toBeGreaterThan(0);
    for (const r of live) {
      expect(r.externalSystem, `${r.displayId} states no external-system answer`).toBeTruthy();
      expect(r.externalSystem!.length, `${r.displayId}'s answer is a gesture`).toBeGreaterThan(80);
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
    const map = await realMap();
    const a = renderFrontier(map, false);
    const b = renderFrontier(await realMap(), false);
    expect(a).toBe(b);
    // The header quotes the map's own total rather than a literal, for the
    // reason given on the first test in this file: what is being checked is
    // that the rendered document reports the number it computed, which is
    // ground rule 9 at the point of display. A typed count here would assert
    // upstream's overlay version a second time and nothing else.
    expect(a).toContain(`frontier ${map.rollup.frontierTotal} uncovered controls`);
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
      recipes: await loadRecipes(join(REPO_ROOT, "recipes/commit")),
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
    ) as {
      disposition: string;
      remainder: { control: string; boundary?: string };
      externalSystem?: string;
    };
    expect(raw.disposition).toBe("partial");
    expect(raw.remainder.control).toContain("The agreements.");
    // …and the freeze survived T4, which is the first time it was tested by
    // something other than intent. Splitting `remainder` into two limbs moved
    // this text and did not rewrite it; the limbs the split ADDED are absent,
    // because back-filling them would present today's sentences as what this
    // record said when it was written.
    expect(raw.remainder.boundary).toBeUndefined();
    expect(raw.externalSystem).toBeUndefined();
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

  it("a catalog recipe claiming a control our record does not claim back", async () => {
    // The same link walked the other way, and the direction that had never been
    // checked: `api-spec-lint-clean` has claimed SA-05 since the H phase, and
    // until wave 1 wrote SA-05's first recipeIds nothing compared the two
    // sides. The frontier derives them independently — `catalogRecipeIds` from
    // the catalog, `commit.recipeIds` from the record — which is the only
    // reason a disagreement is visible at all.
    //
    // ac-1 rather than sa-2 for the synthetic: it is a control the catalog now
    // claims (`access-control-policy-present`), so a record that names no
    // recipe for it is exactly the understatement this check is for.
    const map = await mapWith([
      record({
        controlId: "ac-1",
        displayId: "AC-01",
        family: "AC",
        disposition: "partial",
        remainder: REMAINDER,
        candidateCollectors: ["documents"],
        recipeIds: [],
        citesUpstream: {
          source: "aws",
          disposition: "narrative",
          agreement: "diverges",
          note: "a synthetic record, cited so the ground-rule-10 check is not the one that fires here — the divergence being tested lives between our record and our own catalog",
        },
      }),
    ]);
    expect(map.problems.join(" ")).toContain("disagree about what is already answered");
    expect(map.problems.join(" ")).toContain("access-control-policy-present");
  });

  it("an adjudication naming a collector nobody has scoped", async () => {
    const map = await mapWith([
      record({ disposition: "partial", remainder: REMAINDER, candidateCollectors: ["wishful"] }),
    ]);
    expect(map.problems.join(" ")).toContain("neither registered nor a Tier-2 cheap win");
    // …while a Tier-2 name is accepted: the whole point of the list is that a
    // disposition may rest on a collector that is scoped but unwritten
    const ok = await mapWith([
      record({ disposition: "partial", remainder: REMAINDER, candidateCollectors: ["dockle"] }),
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
    expect(() => record({ disposition: "narrative", remainder: REMAINDER })).toThrow();
    expect(() => record({ disposition: "partial", remainder: REMAINDER })).not.toThrow();
  });

  // N1a′-T4. Both limbs of decision 7, enforced by the type rather than by a
  // reviewer noticing a missing sentence.
  it("the schema refuses a live partial that names only the control's own gap", () => {
    // The boundary limb is the one nobody would miss in review: it is the same
    // fact on every record, which is exactly why it is the one that gets
    // dropped in a rewrite and never questioned afterwards.
    expect(() =>
      record({ disposition: "partial", remainder: { control: REMAINDER.control } }),
    ).toThrow();
  });

  it("the schema refuses a live record with no external-system answer", () => {
    expect(() => record({ externalSystem: undefined })).toThrow();
  });

  it("…and requires neither of them on a retired record, which is frozen", () => {
    // One rule, not two exemptions: `retired` already promises the disposition,
    // rationale and remainder stay as written, so a field added afterwards is
    // owed by live records only. Back-filling a closed record would present
    // today's sentence as what it said at the time.
    const retired = {
      at: "2026-08-17",
      overlayVersion: "0.7.2",
      reason: "upstream answered it and argued our route",
      upstreamRecipeIds: ["some-upstream-recipe"],
    };
    expect(() =>
      record({
        disposition: "partial",
        remainder: { control: REMAINDER.control },
        externalSystem: undefined,
        retired,
      }),
    ).not.toThrow();
    // the freeze is not a hole: the rules that predate it still bite
    expect(() => record({ disposition: "partial", remainder: undefined, retired })).toThrow();
  });
});

// N1a′-T3, decision 6 settled as option (b): our plane is `commit`, named for
// the anchor rather than the subject, because the SUBJECT is shared with
// upstream's `pipeline` plane and the anchor is not. Three plane names now
// exist across two projects and the failure this guards is the cheapest one
// available — a record filed under a neighbour's name, which reads as a claim
// about a pass we did not make.
describe("the commit plane is named, and the name is enforced", () => {
  it("every record this repository ships is filed under `commit`", async () => {
    const records = await loadAdjudications(join(REPO_ROOT, "recipes/adjudications"));
    expect(records.length).toBeGreaterThan(0);
    for (const r of records) {
      expect(r.source, `${r.displayId} is filed under a plane that is not ours`).toBe("commit");
    }
  });

  it("the schema refuses upstream's two plane names outright", () => {
    // `pipeline` is the one that would actually have been typed: it is what
    // these records read until 2026-08-17, and it is upstream's name for a
    // plane covering our exact subject matter from the opposite trust model.
    expect(() => record({ source: "pipeline" } as never)).toThrow();
    expect(() => record({ source: "aws" } as never)).toThrow();
  });

  it("a real row carrying both planes keeps them apart", async () => {
    // The case the rename exists for, and it is not hypothetical: SA-08 is one
    // of the three controls both projects adjudicated independently and agreed
    // on. `row.upstream.pipeline` and `row.commit` are one word apart in prose
    // and must never be one field in the map — a control both planes reasoned
    // about is the interesting row, and it is exactly the row a shared name
    // would have flattened.
    const row = (await realMap()).rows.find((r) => r.controlId === "sa-8");
    expect(row, "sa-8 left the frontier — the overlap this test reads is gone").toBeDefined();
    expect(row!.upstream.pipeline?.disposition).toBe("partial"); // theirs
    expect(row!.commit?.disposition).toBe("partial"); // ours, reached another way
    expect(row!.upstream.commit).toBeUndefined(); // and never credited to them
  });
});

// N1a′-T5. Ground rule 10 as a link check. The failure is not disagreement —
// it is UNDECLARED disagreement (risk 7): a reader holding both overlays finds
// two confident paragraphs about one control and no way to choose. Agreement
// left silent fails the same way, because two passes reaching one verdict from
// different evidence is the strongest corroboration either project has and it
// is worth nothing if neither says so.
describe("where upstream has spoken, the record says whether it agrees", () => {
  const CITE = {
    source: "pipeline",
    disposition: "partial",
    agreement: "agrees" as const,
    note: "what a commit adds that their evidence path does not",
  };

  function upstreamRow(over: Partial<FrontierControl> = {}): FrontierControl {
    return {
      controlId: "sa-8",
      displayId: "SA-08",
      family: "SA",
      ksis: ["KSI-PIY-RSD"],
      classes: ["b"],
      disposition: "partial",
      rationale: "upstream's paragraph",
      sourcesConsidered: ["pipeline"],
      ...over,
    } as FrontierControl;
  }

  async function mapOf(frontier: FrontierControl, ours: Partial<CommitAdjudication>) {
    const map = buildFrontier({
      frontier: [frontier],
      adjudications: [record({ controlId: "sa-8", displayId: "SA-08", family: "SA", ...ours })],
      recipes: await loadRecipes(join(REPO_ROOT, "recipes/commit")),
      collectors: allCollectors,
      datasetVersion: DEFAULT_DATASET_PIN,
      ksiReachedControls: 209,
    });
    return map.problems.join(" ");
  }

  const partial = {
    disposition: "partial" as const,
    remainder: REMAINDER,
  };

  it("every shipped record whose control upstream adjudicated cites it", async () => {
    // Over the REAL overlay. This used to pin the overlap set to the three
    // surviving after the 0.7.2 re-pin (SA-08, SA-22, SR-02 (01)) and assert
    // all three agreed — true when three of our seven records met upstream and
    // wrong the moment a batch was written into families the AWS pass had
    // already walked. N1a-T3 batch 1 is nineteen such records, so the list is
    // no longer the fact worth pinning: the PROPERTY is.
    const map = await realMap();
    const overlaps = map.rows.filter(
      (r) => r.commit !== undefined && Object.keys(r.upstream).length > 0,
    );
    for (const row of overlaps) {
      expect(row.commit!.citesUpstream, `${row.displayId} cites nobody`).toBeDefined();
      // the note argues a route rather than restating our own rationale
      expect(row.commit!.citesUpstream!.note.length).toBeGreaterThan(200);
    }
  });

  it("the divergences are declared by name, because a divergence is a claim", async () => {
    // The half of ground rule 10 that cannot be checked mechanically: `agrees`
    // is recounted against upstream's file by the link check, but `diverges` is
    // an ARGUMENT, and an argument is only as good as its being noticed. Pinned
    // by displayId so a record filed as divergence without anyone deciding to
    // fails here rather than shipping — the set is small on purpose and grows
    // only by an edit someone had to make.
    const map = await realMap();
    const diverging = map.rows
      .filter((r) => r.commit?.citesUpstream?.agreement === "diverges")
      .map((r) => r.displayId)
      .sort();
    // SA-03 was the fifth until the batch's independent auditor pass found the
    // artifact its divergence rested on — branch protection — is platform state
    // no collector reads. It concedes upstream's refusal now, and the list is
    // shorter by exactly the record the gate caught.
    //
    // Batch 2 adds five, and it is the first batch whose divergences run in
    // BOTH directions — which is the fact worth recording here, because until
    // now every one of them was this plane reaching further than upstream and
    // the list could be read as a tally of wins.
    //
    //   CP-02, PL-08 — ours `partial` against their `narrative`. Both controls
    //     ask the system to DEVELOP a document (a contingency plan, a security
    //     architecture description), and upstream's refusal is correct about an
    //     estate API and stops being correct for a pass that reads files.
    //   CP-04, MA-02, PS-05 — ours `narrative` against their `partial`, and
    //     here THIS PLANE IS THE WEAKER ONE. All three turn on an execution
    //     record — a restore test that ran, a maintenance window that ran, a
    //     group membership that changed — and an execution record is the class
    //     of evidence a checkout structurally cannot hold. Recorded as
    //     divergences rather than quietly filed as agreement because a reader
    //     comparing the two overlays on these three controls should be sent to
    //     upstream's pass, not reassured by a second refusal.
    expect(diverging).toEqual([
      "AC-01",
      "CP-02",
      "CP-04",
      "IA-06",
      "MA-02",
      "PL-08",
      "PS-05",
      "RA-05 (11)",
      "SR-10",
    ]);
    // and every other overlap agrees — the link check proves the dispositions
    // match, this proves nothing sits in between the two declarations
    const others = map.rows.filter(
      (r) =>
        r.commit !== undefined &&
        Object.keys(r.upstream).length > 0 &&
        !diverging.includes(r.displayId),
    );
    for (const row of others) {
      expect(row.commit!.citesUpstream!.agreement, `${row.displayId}`).toBe("agrees");
    }
  });

  it("a record silent about an upstream disposition is a broken link", async () => {
    expect(await mapOf(upstreamRow(), partial)).toContain("does not say whether it agrees");
  });

  it("a citation whose disposition no longer matches upstream's file", async () => {
    // The one the structure buys that a prose check cannot: upstream moved and
    // the citation did not, which is the silent drift the overlay pin exists
    // to stop, arriving through the reasoning instead of through the bytes.
    const text = await mapOf(upstreamRow({ disposition: "narrative" }), {
      ...partial,
      citesUpstream: CITE,
    });
    expect(text).toContain("but upstream's file now reads");
  });

  it("a divergence filed as agreement", async () => {
    // risk 7 arriving WITH a citation attached, which is the version a reader
    // would never catch by eye
    const text = await mapOf(upstreamRow({ disposition: "narrative" }), {
      ...partial,
      citesUpstream: { ...CITE, disposition: "narrative" },
    });
    expect(text).toContain("a divergence filed as agreement");
  });

  it("agreement filed as a divergence, which throws corroboration away", async () => {
    const text = await mapOf(upstreamRow(), {
      ...partial,
      citesUpstream: { ...CITE, agreement: "diverges" },
    });
    expect(text).toContain("filing it as a disagreement throws it away");
  });

  it("a citation of a plane that said nothing", async () => {
    const cited = await mapOf(upstreamRow({ sourcesConsidered: ["aws"] }), {
      ...partial,
      citesUpstream: CITE,
    });
    expect(cited).toContain("which has no disposition on this control");
    // …and citing upstream where upstream is silent altogether
    const none = await mapOf(upstreamRow({ disposition: null, sourcesConsidered: [] } as never), {
      ...partial,
      citesUpstream: CITE,
    });
    expect(none).toContain("upstream's file carries none on this control");
  });
});

// Ground rule 10's CATALOG arm, added after the 0.7.5 re-pin.
//
// The record arm above is checked against the frontier — the uncovered set —
// which means it is structurally blind to a control upstream has ANSWERED,
// because answering it takes it off the frontier. That is where `ia-5.6`,
// `sa-11` and `si-10` came to be claimed by a recipe on both planes with
// neither project saying so: not a check that failed, a check pointed at the
// one file where the fact cannot appear.
describe("where upstream has authored, the recipe says how the two relate", () => {
  const OVERLAP = {
    control: "sa-11",
    plane: "pipeline" as const,
    recipeId: "static-analysis-coverage-and-flaw-disposition",
    relation: "corroborates" as const,
    note:
      "Upstream proves the analysis ran and what it covered; this proves a result at one commit, " +
      "gated on reachability, which their alert list does not carry. Neither contains the other.",
  };

  function recipe(over: Record<string, unknown> = {}): PipelineRecipe {
    return RecipeSchema.parse({
      id: "a-recipe",
      ksi_ids: ["KSI-SVC-ACM"],
      control_ids: ["sa-11"],
      evidence: "something the repository proves",
      collection: { kind: "pipeline", collector: "repo-facts" },
      expected_output: "one row",
      cadence: "weekly",
      automatable: "full",
      anchor: "commit",
      ...over,
    });
  }

  /** upstream answers sa-11 on the pipeline plane and si-10 on aws */
  const upstream = (controlId: string) =>
    controlId === "sa-11"
      ? [{ plane: "pipeline", recipeId: "static-analysis-coverage-and-flaw-disposition" }]
      : controlId === "si-10"
        ? [{ plane: "aws", recipeId: "config-something" }]
        : [];

  function problemsFor(recipes: PipelineRecipe[], lookup = upstream) {
    return buildFrontier({
      frontier: [],
      adjudications: [],
      recipes,
      collectors: allCollectors,
      datasetVersion: DEFAULT_DATASET_PIN,
      ksiReachedControls: 209,
      upstreamRecipesFor: lookup,
    }).problems;
  }

  it("an undeclared overlap with upstream's pipeline plane is a broken link", () => {
    const problems = problemsFor([recipe()]);
    expect(problems).toHaveLength(1);
    expect(problems[0]).toContain('upstream\'s "pipeline" plane already answers');
    expect(problems[0]).toContain("static-analysis-coverage-and-flaw-disposition");
  });

  it("declaring it clears the link, and the declaration has to match all three fields", () => {
    expect(problemsFor([recipe({ upstream_overlap: [OVERLAP] })])).toEqual([]);
    // a declaration naming a different recipe of theirs does not discharge this one
    const wrongId = problemsFor([
      recipe({ upstream_overlap: [{ ...OVERLAP, recipeId: "some-other-recipe" }] }),
    ]);
    expect(wrongId.some((p) => p.includes("already answers"))).toBe(true);
    expect(wrongId.some((p) => p.includes("does not carry"))).toBe(true);
  });

  it("a declaration pointing at a recipe upstream does not publish is itself a broken link", () => {
    // the same failure `citationProblems` names for a moved disposition: a
    // citation nobody can check reads exactly like one nobody did
    const problems = problemsFor([
      recipe({
        control_ids: ["sa-11", "cm-3.2"],
        upstream_overlap: [OVERLAP, { ...OVERLAP, control: "cm-3.2" }],
      }),
    ]);
    expect(problems).toHaveLength(1);
    expect(problems[0]).toContain("does not carry");
  });

  it("a declaration on a control the recipe does not claim", () => {
    const problems = problemsFor([recipe({ upstream_overlap: [{ ...OVERLAP, control: "ac-1" }] })]);
    expect(problems.some((p) => p.includes("not one of its own control_ids"))).toBe(true);
  });

  it("the AWS plane is deliberately out of scope, and that is a decision not an oversight", () => {
    // Unscoped this check reports 25 overlaps with `aws` on the real catalog,
    // every one of them the product's own thesis rather than a finding: an API
    // over a running estate and a file in a checkout are different evidence by
    // construction. A gate red on its first run for reasons nobody acts on is
    // the gate N2a was held back to avoid becoming.
    expect(problemsFor([recipe({ control_ids: ["si-10"] })])).toEqual([]);
  });

  it("without the lookup the arm does not run, rather than passing everything silently", () => {
    // the absence is visible in the test above it: same recipe, lookup wired,
    // one problem. Here there is no upstream file to read at all.
    const problems = buildFrontier({
      frontier: [],
      adjudications: [],
      recipes: [recipe()],
      collectors: allCollectors,
      datasetVersion: DEFAULT_DATASET_PIN,
      ksiReachedControls: 209,
    }).problems;
    expect(problems).toEqual([]);
  });

  it("the three real overlaps are declared by name, because a corroboration is a claim too", async () => {
    // The mirror of the divergence pin: `agrees` is recounted mechanically, but
    // WHICH controls both projects answer is a fact about upstream's file that
    // only a human decided to look at. Pinning the set by name means a fourth
    // one arriving cannot land without someone noticing it did.
    const recipes = await loadRecipes(join(REPO_ROOT, "recipes/commit"));
    const declared = recipes
      .flatMap((r) => (r.upstream_overlap ?? []).map((o) => `${r.id} → ${o.control}`))
      .sort();
    expect(declared).toEqual([
      "no-reachable-dangerous-code → sa-11",
      "no-reachable-dangerous-code → si-10",
      "no-secrets-in-history → ia-5.6",
      "tests-in-ci → sa-11",
    ]);
    for (const r of recipes) {
      for (const o of r.upstream_overlap ?? []) {
        expect(o.relation).toBe("corroborates");
        expect(o.note.length).toBeGreaterThan(200);
      }
    }
  });
});

// A refusal that names who CAN answer the limb it refuses (added with the
// catalog arm). The pointer is the most useful thing this overlay can do with a
// `narrative` — it turns N1d's ceiling from a list of apologies into a division
// of labour — and it is only worth anything if it is checked, which is
// N1a′-T5's finding applied one file over.
describe("a refusal points somewhere, and the pointer is recounted", () => {
  const REF = {
    plane: "pipeline" as const,
    recipeId: "developer-change-control-and-integrity",
    control: "sa-10",
    note:
      "Upstream's SA-10 recipe reads the branch rules this record refuses for not being a file, so the " +
      "unreadable half is unreadable from a checkout rather than unreadable in general.",
  };

  const lookup = (controlId: string) =>
    controlId === "sa-10"
      ? [{ plane: "pipeline", recipeId: "developer-change-control-and-integrity" }]
      : [];

  async function problemsFor(over: Partial<CommitAdjudication>) {
    const dataset = await loadLocalDataset(DERIVED, DEFAULT_DATASET_PIN);
    return buildFrontier({
      frontier: dataset.frontier(),
      adjudications: [record({ controlId: "sa-2", displayId: "SA-02", ...over })],
      recipes: [],
      collectors: allCollectors,
      datasetVersion: DEFAULT_DATASET_PIN,
      ksiReachedControls: dataset.ksiReachedControls(),
      upstreamRecipesFor: lookup,
    }).problems;
  }

  it("a pointer upstream's plan carries is clean", async () => {
    expect(await problemsFor({ remainderAnsweredBy: [REF] })).toEqual([]);
  });

  it("a pointer at a recipe upstream does not publish fails", async () => {
    const problems = await problemsFor({
      remainderAnsweredBy: [{ ...REF, recipeId: "a-recipe-they-withdrew" }],
    });
    expect(problems.some((p) => p.includes("does not carry"))).toBe(true);
    expect(problems.some((p) => p.includes("stopped being checkable"))).toBe(true);
  });

  it("…and so does a pointer filed under the wrong control of theirs", async () => {
    // the recipe id is real; the control it is filed under is not the one
    // upstream files it under, so the reference resolves to nothing
    const problems = await problemsFor({ remainderAnsweredBy: [{ ...REF, control: "cm-4.2" }] });
    expect(problems.some((p) => p.includes("does not carry"))).toBe(true);
  });

  it("an automatable record has no remainder to hand over", async () => {
    const problems = await problemsFor({
      disposition: "automatable",
      recipeIds: [],
      candidateCollectors: ["repo-facts"],
      remainderAnsweredBy: [REF],
    });
    expect(problems.some((p) => p.includes("no remainder to hand over"))).toBe(true);
  });

  it("the real pointers resolve against upstream's pinned plan, by name", async () => {
    const records = await loadAdjudications(join(REPO_ROOT, "recipes/adjudications"));
    const pointers = records
      .flatMap((r) => (r.remainderAnsweredBy ?? []).map((p) => `${r.controlId} → ${p.control}`))
      .sort();
    // Pinned by name for the reason the divergence list is: which of our
    // refusals hands a limb to upstream is a claim somebody decided to make,
    // and a mechanical recount of the recipe ids cannot tell that a new one
    // was added without anyone arguing for it.
    expect(pointers).toEqual(["sa-3 → cm-4.2", "sa-3 → sa-10", "sr-10 → si-7.7"]);
  });
});
