import { execSync } from "node:child_process";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import { allCollectors } from "@rampscan/collectors";
import { joinRecipeResults } from "@rampscan/core";
import type { RunResult, Workspace } from "@rampscan/core";
import { DEFAULT_DATASET_PIN } from "@rampscan/dataset";
import type { PipelineRecipe, RecipeResult, ScanResult } from "@rampscan/schema";
import { scan } from "../src/index.js";
import { loadRecipes } from "../src/recipes.js";

// N0-T4 — the catalog's honesty test, DYNAMIC half, and the real teeth.
//
// The static half (catalog.test.ts) checks that every recipe declares what an
// empty observation set means. This one checks that the declaration is true:
// the full collector set is run against `fixtures/bare-app` — a library with
// no pipeline, no container, no API surface and no contract — and every recipe
// that declared "an empty set means there was nothing to search" is held to it.
//
// bare-app rather than vulnerable-app because it is the only fixture that can
// reach this at all: the flagship is fully tooled, so every collector finds
// something of its kind and no recipe on that board is ever evaluated over an
// empty domain. That is the third time this repository has met the same
// property from a different direction (J3's empty-cell hop, K1's guided empty
// states, L4b's proposal drawer), so it is stated here as what it is —
// ANYTHING REACHABLE ONLY FROM AN EMPTY ROW IS TESTABLE ONLY ON `bare-app`.
//
// Tool-dependent assertions are gated on the tool being installed, the same
// posture scan.e2e.test.ts holds: a missing binary makes its collector skip,
// which moves rows from evidenced to unevidenced. That direction is safe for
// the two checks that matter — a skipped collector cannot produce a vacuous
// pass — so only the pinned verdict SPLIT needs the gate.

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "../../..");
const fixtureRoot = join(repoRoot, "fixtures/bare-app");
const recipesDir = join(repoRoot, "recipes/commit");

function installed(tool: string): boolean {
  try {
    execSync(`command -v ${tool}`, { stdio: "pipe" });
    return true;
  } catch {
    return false;
  }
}

/**
 * The vacuous-pass check itself (ground rule 7), as a function rather than a
 * chain of expects, because it has to run twice: over the REAL scan below, and
 * over SYNTHETIC wiring that is deliberately broken. A checker that has only
 * ever seen a healthy catalog is not a checker.
 *
 * Each problem names the recipe AND the pattern it should have used, because
 * the person who trips this wrote a recipe an hour ago and does not yet know
 * that `[]` + `count_eq 0` is a thing this codebase has a word for.
 */
const REMEDY =
  "use one of the five empty-set patterns — Guard (omit the observation key), " +
  "Skip (return a stated reason), Witness (emit one row carrying the existence boolean), " +
  "Counter (emit one summary row of counts), or Negative witness (a row per " +
  "declared-but-unmatched rule) — or declare empty_means:clean and say in `notes` " +
  "what domain the collector searched exhaustively";

function vacuousPasses(recipes: PipelineRecipe[], results: RecipeResult[]): string[] {
  const byId = new Map(recipes.map((r) => [r.id, r]));
  const problems: string[] = [];
  for (const row of results) {
    if (row.verdict !== "evidenced") continue;
    const recipe = byId.get(row.recipe_id);
    if (!recipe) continue;
    // 1. the declaration, enforced: a recipe that said an empty set means
    //    nothing was searched may not report evidence
    const population = row.assertions.find((a) => a.population !== undefined)?.population;
    if (recipe.empty_means === "unevidenced" && population === 0) {
      problems.push(
        `${row.recipe_id}: declared empty_means:unevidenced and reached "evidenced" over 0 rows — ${REMEDY}`,
      );
      continue;
    }
    // 2. and the undeclared pass over an empty domain, which is the same
    //    failure wearing the other value: `clean` is a claim that the
    //    collector went and looked, so a pass over zero rows that is NOT
    //    `clean` is a pass over a domain nobody established exists
    if (recipe.empty_means !== "clean" && (population === undefined || population === 0)) {
      problems.push(
        `${row.recipe_id}: reached "evidenced" over ${population ?? "an unstated number of"} ` +
          `observation rows without declaring empty_means:clean — ${REMEDY}`,
      );
    }
  }
  return problems;
}

let result: ScanResult;
let recipes: PipelineRecipe[];

beforeAll(async () => {
  recipes = await loadRecipes(recipesDir);
  const outcome = await scan({
    path: fixtureRoot,
    outDir: await mkdtemp(join(tmpdir(), "rampscan-bare-")),
    datasetDir: join(repoRoot, "docs/context/ramprules/derived"),
    datasetPin: DEFAULT_DATASET_PIN,
    recipesDir,
    collectors: allCollectors,
  });
  result = outcome.result;
}, 600_000);

describe("no recipe passes vacuously on the barren fixture (N0-T4)", () => {
  it("no recipe declaring empty_means:unevidenced reaches evidenced", () => {
    const declared = new Set(
      recipes.filter((r) => r.empty_means === "unevidenced").map((r) => r.id),
    );
    expect(declared.size, "the fixture proves nothing if nothing declares it").toBeGreaterThan(0);
    const passing = result.recipes
      .filter((r) => r.verdict === "evidenced" && declared.has(r.recipe_id))
      .map((r) => {
        const pop = r.assertions.find((a) => a.population !== undefined)?.population;
        return `${r.recipe_id} (over ${pop ?? "?"} row(s))`;
      });
    // an `unevidenced`-declaring recipe MAY still be evidenced here — on a real
    // domain. lockfile-pinned-deps is: bare-app has a package.json and a
    // lockfile, so its witness row is a real observation. What may not happen
    // is that pass arriving over ZERO rows, which is what vacuousPasses reads.
    expect(vacuousPasses(recipes, result.recipes), passing.join(", ")).toEqual([]);
  });

  it("every evidenced row is either empty_means:clean or counted over a non-empty domain", () => {
    const evidenced = result.recipes.filter((r) => r.verdict === "evidenced");
    expect(evidenced.length, "bare-app should still evidence something").toBeGreaterThan(0);
    for (const row of evidenced) {
      const recipe = recipes.find((r) => r.id === row.recipe_id)!;
      const population = row.assertions.find((a) => a.population !== undefined)?.population;
      expect(population, `${row.recipe_id} evidenced with no population stated`).toBeDefined();
      expect(
        recipe.empty_means === "clean" || population! > 0,
        `${row.recipe_id} passed over ${population} rows without claiming an exhaustive search`,
      ).toBe(true);
    }
  });

  it("the empty-domain passes are visible as empty — 0 of 412 and 0 of 0 do not look alike", () => {
    // The finding N0 was written to act on: on a repository with no
    // dependencies, `no-critical-reachable-advisories` counts zero and reports
    // evidence against ra-5 and si-2. That is honest — the collector really ran
    // — and it is much weaker than the badge suggests. The population is the
    // sentence that says so, and it is only worth anything if it is actually
    // on the row.
    for (const row of result.recipes) {
      if (row.verdict === "unevidenced") continue;
      for (const assertion of row.assertions) {
        expect(
          assertion.population,
          `${row.recipe_id}: "${assertion.description}" states no population`,
        ).toBeDefined();
        expect(assertion.population).toBeGreaterThanOrEqual(0);
      }
    }
    // and every assertion of one recipe agrees on the number, because the
    // population is a property of the OBSERVATION, not of the clause
    for (const row of result.recipes) {
      const populations = new Set(row.assertions.map((a) => a.population));
      expect(populations.size, `${row.recipe_id} disagrees with itself about its domain`)
        .toBeLessThanOrEqual(1);
    }
  });

  it.skipIf(!installed("gitleaks") || !installed("syft") || !installed("osv-scanner"))(
    "the verdict split is pinned against the recorded baseline",
    () => {
      // 5 evidenced · 4 violated · 8 unevidenced, recorded 2026-08-16 from
      // e2e/.smoke/out-bare/scan-result.json. Pinned so that movement is
      // deliberate and reviewed rather than discovered: a recipe added under
      // N1 that changes what the barren repo says has to come here and say so.
      expect({
        evidenced: result.summary.evidenced,
        violated: result.summary.violated,
        unevidenced: result.summary.unevidenced,
      }).toEqual({ evidenced: 5, violated: 4, unevidenced: 8 });
    },
  );
});

describe("the checker notices when the catalog is broken", () => {
  // Synthetic wiring, the posture tools-map.test.ts uses: over the real
  // catalog these tests only ever prove the repo is currently healthy. The
  // exit criterion for N0 is that a DELIBERATELY vacuous recipe fails CI with
  // a message naming the recipe and the pattern it should have used, and that
  // cannot be shown by a catalog that contains no such recipe.

  const vacuousRecipe: PipelineRecipe = {
    id: "repo-has-a-security-policy",
    ksi_ids: ["KSI-SCR-MIT"],
    control_ids: ["sa-11"],
    evidence: "a SECURITY.md exists",
    collection: { kind: "pipeline", collector: "made-up" },
    expected_output: "one row per missing policy file",
    assertions: [
      {
        field: "file",
        op: "count_eq",
        value: 0,
        where: [{ field: "missing", op: "eq", value: true }],
        description: "No missing security policy.",
      },
    ],
    cadence: "weekly",
    automatable: "full",
    empty_means: "unevidenced",
    anchor: "commit",
  };

  const emptyRun: RunResult = {
    findings: [],
    artifacts: [],
    // the anti-pattern in one line: emit [], assert count_eq 0, report evidenced
    observations: { "repo-has-a-security-policy": [] },
    anchors: {},
    toolVersion: "0",
    exitCode: 0,
  };

  const workspace: Workspace = { root: "/nowhere", repo: "nowhere", commit: "0".repeat(40) };

  function joinOne(recipe: PipelineRecipe, run: RunResult): RecipeResult[] {
    return joinRecipeResults({
      recipes: [recipe],
      runs: new Map([[recipe.collection.collector, run]]),
      workspace,
      datasetVersion: DEFAULT_DATASET_PIN,
      runId: "synthetic",
      now: new Date("2026-08-16T00:00:00Z"),
    });
  }

  it("a recipe that emits [] and asserts count_eq 0 does reach evidenced — that is the bug", () => {
    // Stated as a test rather than a comment because it is the premise of the
    // whole phase: the join and the evaluator are working exactly as designed,
    // and the design passes an empty set. Nothing here is a bug to fix in
    // assert.ts — the discrimination has to live in the catalog.
    const rows = joinOne(vacuousRecipe, emptyRun);
    expect(rows[0]!.verdict).toBe("evidenced");
    expect(rows[0]!.assertions[0]!.detail).toBe("count 0");
    expect(rows[0]!.assertions[0]!.population).toBe(0);
  });

  it("and the catalog check catches it, naming the recipe and the pattern it should have used", () => {
    const problems = vacuousPasses([vacuousRecipe], joinOne(vacuousRecipe, emptyRun));
    expect(problems).toHaveLength(1);
    expect(problems[0]).toContain("repo-has-a-security-policy");
    expect(problems[0]).toContain("Guard");
    expect(problems[0]).toContain("Witness");
    expect(problems[0]).toContain("empty_means:clean");
  });

  it("the same recipe over a real domain is not flagged — the check is about emptiness, not counting", () => {
    const populated: RunResult = {
      ...emptyRun,
      observations: { "repo-has-a-security-policy": [{ missing: false, file: "SECURITY.md" }] },
    };
    const rows = joinOne(vacuousRecipe, populated);
    // the same "count 0" verdict — over a domain of one. That is the whole
    // distinction N0-T1 exists to make readable: this row counted 0 of 1, the
    // one above counted 0 of 0, and only one of them is evidence.
    expect(rows[0]!.verdict).toBe("evidenced");
    expect(rows[0]!.assertions[0]!.detail).toBe("count 0");
    expect(rows[0]!.assertions[0]!.population).toBe(1);
    expect(vacuousPasses([vacuousRecipe], rows)).toEqual([]);
  });

  it("declaring clean is a claim, not an escape hatch — it passes here and answers to catalog.test.ts", () => {
    // The other value is not a way out of the check: `clean` moves the burden
    // to a sentence in `notes` naming the domain searched, which the static
    // half refuses to accept as absent. Both halves are needed; neither alone
    // holds the line.
    const clean = { ...vacuousRecipe, empty_means: "clean" as const };
    expect(vacuousPasses([clean], joinOne(clean, emptyRun))).toEqual([]);
    expect(clean.notes).toBeUndefined(); // …and catalog.test.ts fails it for exactly that
  });
});
