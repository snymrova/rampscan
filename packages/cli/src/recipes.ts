import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import { PipelineRecipe } from "@rampscan/schema";
import type { DatasetClient } from "@rampscan/dataset";

// Recipe loading and dataset validation (plan C3): every recipe's KSI and
// control IDs must resolve against the pinned dataset — a verdict citing an
// ID the catalog doesn't know is worse than no verdict.

export async function loadRecipes(dir: string): Promise<PipelineRecipe[]> {
  const files = (await readdir(dir)).filter((f) => f.endsWith(".json")).sort();
  const recipes: PipelineRecipe[] = [];
  for (const file of files) {
    const raw = JSON.parse(await readFile(join(dir, file), "utf8")) as unknown;
    try {
      recipes.push(PipelineRecipe.parse(raw));
    } catch (cause) {
      throw new Error(`recipe file ${file} does not match the PipelineRecipe schema`, { cause });
    }
  }
  const ids = new Set<string>();
  for (const r of recipes) {
    if (ids.has(r.id)) throw new Error(`duplicate recipe id "${r.id}"`);
    ids.add(r.id);
  }
  return recipes;
}

/** every KSI resolves in the crosswalk, and every control is reachable from the recipe's KSIs */
export function validateRecipeIds(recipes: PipelineRecipe[], dataset: DatasetClient): string[] {
  const problems: string[] = [];
  for (const recipe of recipes) {
    const reachable = new Set<string>();
    for (const ksi of recipe.ksi_ids) {
      const controls = dataset.controlsFor(ksi);
      if (controls.length === 0) {
        problems.push(`${recipe.id}: KSI "${ksi}" does not resolve in dataset ${dataset.version()}`);
      }
      for (const c of controls) reachable.add(c);
    }
    for (const control of recipe.control_ids) {
      if (!reachable.has(control)) {
        problems.push(
          `${recipe.id}: control "${control}" is not reachable from its KSIs [${recipe.ksi_ids.join(", ")}]`,
        );
      }
    }
  }
  return problems;
}
