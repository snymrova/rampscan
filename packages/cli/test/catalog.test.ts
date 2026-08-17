import { readFile, readdir } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import { allCollectors } from "@rampscan/collectors";
import { PipelineRecipe } from "@rampscan/schema";
import { loadRecipes } from "../src/recipes.js";

// N0-T3 — the catalog's honesty test, static half. Modelled on plain.test.ts,
// which is the house precedent for "policy lives in a test that fails CI, not
// in a convention someone remembers."
//
// The rule it enforces is ground rule 7: a recipe may never report `evidenced`
// from the ABSENCE of something to check. That rule has been real and unwritten
// since M1 — held by hand, in four different patterns, verified per collector,
// with no catalog-wide check anywhere. N1 is about to triple the catalog.
//
// What makes it enforceable is one declaration no static analysis can infer:
// what an EMPTY observation set means for this recipe. `assert.ts` passes an
// empty filtered set vacuously by design, and that is correct for "every
// active key is rotated" and catastrophic for "the repo has a security
// policy" — the difference is not in the assertion, the collector or the rows.
// It is in what the recipe is asking. So the recipe says, and this file
// refuses a recipe that stays silent.
//
// The dynamic half — no recipe declaring `unevidenced` may actually REACH
// `evidenced` — lives in catalog-bare.e2e.test.ts, over a real scan of the
// barren fixture.

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "../../..");
const recipesDir = join(repoRoot, "recipes/pipeline");

/**
 * The five empty-set patterns the catalog already used before any of them had
 * a name (plan §1.2). Naming them is most of the work of testing them: a
 * recipe that cannot say which one it uses has not decided how it behaves on a
 * repository that lacks the thing it checks, and undecided is what the vacuous
 * pass looks like in production.
 */
const PATTERNS = ["Guard", "Skip", "Witness", "Counter", "Negative witness"];

/** the sentence every recipe's `notes` carries, and the names it may use */
const DISCIPLINE = /Empty-set discipline — ([^:]+):/;

/** a claim of exhaustive search reads as a totalizing quantifier, or it is not one */
const EXHAUSTIVE = /\b(every|all|entire|full|whole|each)\b/i;

let recipes: Awaited<ReturnType<typeof loadRecipes>>;

beforeAll(async () => {
  recipes = await loadRecipes(recipesDir);
});

describe("the catalog declares what an empty observation set means (N0-T3)", () => {
  it("every recipe in recipes/pipeline declares empty_means", () => {
    const missing = recipes.filter((r) => r.empty_means === undefined).map((r) => r.id);
    expect(missing, "recipes with no `empty_means` declaration").toEqual([]);
    // the whole catalog, not a sample — a count here would pass while a new
    // recipe slipped in undeclared
    expect(recipes.length).toBeGreaterThanOrEqual(17);
  });

  it("no recipe that can pass over zero rows inherits a default — there is no default", async () => {
    // Every assertion op in the language is either a count op or a row-wise
    // op, and BOTH pass over an empty filtered set (assert.ts says so in its
    // own doc comment). So every recipe carrying assertions at all is a recipe
    // that can pass over zero rows, and none of them may be silent.
    const canPassEmpty = recipes.filter((r) => (r.assertions?.length ?? 0) > 0);
    expect(canPassEmpty.length).toBe(recipes.length);
    for (const recipe of canPassEmpty) {
      expect(recipe.empty_means, `${recipe.id} can pass over zero rows and says nothing about it`)
        .toBeDefined();
    }
    // and the loader supplies nothing: a recipe file with no `empty_means` on
    // disk parses to a recipe with no `empty_means`, so the check above is
    // reading the catalog rather than a default someone added later
    const raw = JSON.parse(
      await readFile(join(recipesDir, "codeowners-defined.json"), "utf8"),
    ) as Record<string, unknown>;
    delete raw["empty_means"];
    expect(PipelineRecipe.parse(raw).empty_means).toBeUndefined();
  });

  it("every recipe names which of the five patterns it uses", () => {
    for (const recipe of recipes) {
      const notes = recipe.notes ?? "";
      const named = DISCIPLINE.exec(notes);
      expect(named, `${recipe.id} states no empty-set discipline in its notes`).not.toBeNull();
      const claimed = named![1]!;
      const matched = PATTERNS.filter((p) => new RegExp(`\\b${p}\\b`, "i").test(claimed));
      expect(
        matched.length,
        `${recipe.id} names "${claimed}", which is none of: ${PATTERNS.join(", ")}`,
      ).toBeGreaterThan(0);
    }
  });

  it("every empty_means:clean recipe says in its notes what domain it searched exhaustively", () => {
    // The load-bearing half of the declaration. `clean` is the recipe claiming
    // that an empty result is a real result — that the collector went and
    // looked. A clean claim that cannot say what it searched is not a clean
    // claim, and this is the check that stops `clean` becoming the value
    // people write to make the other test go away.
    //
    // What it can verify is that the claim was STATED, not that it is true:
    // no test can walk gitleaks' history traversal. Stating it is still worth
    // enforcing, because the sentence is what a reviewer disagrees with.
    const clean = recipes.filter((r) => r.empty_means === "clean");
    expect(clean.length, "no clean recipes at all would make this test vacuous").toBeGreaterThan(0);
    for (const recipe of clean) {
      const notes = recipe.notes ?? "";
      expect(notes.length, `${recipe.id} is empty_means:clean with no notes`).toBeGreaterThan(80);
      expect(
        EXHAUSTIVE.test(notes),
        `${recipe.id} claims an empty set is clean without naming the domain it searched: ${notes}`,
      ).toBe(true);
    }
  });

  it("every recipe names a collector that exists and whose manifest declares it", () => {
    // The `tools`-map link, closed at CATALOG level. `tools-map.test.ts`
    // asserts the same wiring through buildToolMap, which is the command's
    // derivation; this asserts it from the catalog side with nothing in
    // between, so a recipe added under N1 pointing at a collector nobody
    // registers fails here whether or not the map is consulted.
    const byName = new Map(allCollectors.map((c) => [c.manifest.name, c]));
    for (const recipe of recipes) {
      const name = recipe.collection.collector;
      const collector = byName.get(name);
      expect(collector, `${recipe.id} names collector "${name}", which is not registered`)
        .toBeDefined();
      expect(
        collector!.manifest.recipes,
        `collector "${name}" does not declare ${recipe.id} in its manifest`,
      ).toContain(recipe.id);
    }
  });

  it("the schema accepts a recipe with no empty_means — shape is not policy", async () => {
    // Same split `plain` already lives under: the recipe shape mirrors
    // aws-evidence.json, which carries no such field, so an imported recipe
    // must still parse. This repository's catalog is held to the higher bar by
    // the first test in this file, not by the type.
    const raw = JSON.parse(
      await readFile(join(recipesDir, "codeowners-defined.json"), "utf8"),
    ) as Record<string, unknown>;
    delete raw["empty_means"];
    expect(() => PipelineRecipe.parse(raw)).not.toThrow();
    // but only the two values exist — a third kind of emptiness is a decision,
    // not a typo (N0 decision 1: a partially-searched domain is a `population`
    // fact, not a second kind of empty)
    expect(() => PipelineRecipe.parse({ ...raw, empty_means: "partial" })).toThrow();
  });

  it("the declaration lives in the recipe file, so it travels with the check", async () => {
    const files = (await readdir(recipesDir)).filter((f) => f.endsWith(".json"));
    expect(files.length).toBe(recipes.length);
    for (const file of files) {
      const raw = JSON.parse(await readFile(join(recipesDir, file), "utf8")) as Record<
        string,
        unknown
      >;
      expect(raw["empty_means"], `${file} has no empty_means on disk`).toBeTruthy();
    }
  });
});
