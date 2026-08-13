import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import { allCollectors } from "@rampscan/collectors";
import { DEFAULT_DATASET_PIN, loadLocalDataset } from "@rampscan/dataset";
import type { DatasetClient } from "@rampscan/dataset";
import type { PipelineRecipe } from "@rampscan/schema";
import { loadRecipes, validateRecipeIds } from "../src/index.js";

// C3's exit condition, as a test: every recipe parses, and every KSI/control
// ID it cites resolves against the pinned dataset. A verdict citing an ID the
// catalog doesn't know is worse than no verdict.

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "../../..");
const recipesDir = join(repoRoot, "recipes/pipeline");
const derivedDir = join(repoRoot, "docs/context/ramprules/derived");

let recipes: PipelineRecipe[];
let dataset: DatasetClient;

beforeAll(async () => {
  recipes = await loadRecipes(recipesDir);
  dataset = await loadLocalDataset(derivedDir, DEFAULT_DATASET_PIN);
});

describe("the starter recipe set", () => {
  it("has roughly a dozen recipes, all schema-valid", () => {
    expect(recipes.length).toBeGreaterThanOrEqual(10);
  });

  it("every KSI and control ID resolves against the pinned dataset", () => {
    expect(validateRecipeIds(recipes, dataset)).toEqual([]);
  });

  it("validation actually bites: a made-up control is rejected", () => {
    const bad: PipelineRecipe = {
      ...recipes[0]!,
      id: "bad",
      control_ids: ["zz-99"],
    };
    expect(validateRecipeIds([bad], dataset)).toHaveLength(1);
  });

  it("collector manifests and recipes agree on who evidences what", () => {
    const recipeIds = new Set(recipes.map((r) => r.id));
    const byCollector = new Map(allCollectors.map((c) => [c.manifest.name, c]));
    for (const recipe of recipes) {
      const collector = byCollector.get(recipe.collection.collector);
      // as of M4 every recipe's collector exists, and it claims the recipe
      expect(collector, `no collector named "${recipe.collection.collector}" (recipe ${recipe.id})`).toBeDefined();
      expect(collector!.manifest.recipes, `${recipe.collection.collector} manifest`).toContain(recipe.id);
    }
    // and every recipe a manifest claims must exist as a recipe file
    for (const collector of allCollectors) {
      for (const id of collector.manifest.recipes) {
        expect(recipeIds, `${collector.manifest.name} claims ${id}`).toContain(id);
      }
    }
  });
});
