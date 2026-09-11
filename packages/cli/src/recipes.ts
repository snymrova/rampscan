import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import { PipelineRecipe, methodsOfRecipe } from "@rampscan/schema";
import type { CollectorManifest, PipelineMethod } from "@rampscan/schema";
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

/**
 * The register's derivation (SPEC §12.2, plan Q2.2): every recipe in the
 * catalog becomes its pipeline methods — one per claimed KSI, `ksi_ids` as
 * the primary key of the join — with each method's scope inherited from the
 * manifest of the collector the recipe names. Pure over two reviewed
 * artifacts (the recipe files, the collector manifests); there is no methods
 * table anyone edits.
 *
 * Three refusals, all the same failure class: a recipe naming a collector no
 * manifest declares, a manifest with no scope block (§12.6 — a method whose
 * provenance cannot say what was walked is not interrogable), and a duplicate
 * method id (a recipe listing one KSI twice would mint two identical rows
 * that count once everywhere but read as two).
 */
export function deriveCatalogMethods(
  recipes: PipelineRecipe[],
  manifests: CollectorManifest[],
): PipelineMethod[] {
  const byName = new Map(manifests.map((m) => [m.name, m]));
  const methods: PipelineMethod[] = [];
  const seen = new Set<string>();
  for (const recipe of recipes) {
    const manifest = byName.get(recipe.collection.collector);
    if (manifest === undefined) {
      throw new Error(
        `recipe ${recipe.id} names collector "${recipe.collection.collector}", which no manifest declares`,
      );
    }
    if (manifest.scope === undefined) {
      throw new Error(
        `collector "${manifest.name}" declares no scope block (SPEC §12.6) — ` +
          `its methods cannot say what was walked, so none can be derived`,
      );
    }
    for (const method of methodsOfRecipe(recipe, manifest.scope)) {
      if (seen.has(method.id)) throw new Error(`duplicate method id "${method.id}"`);
      seen.add(method.id);
      methods.push(method);
    }
  }
  return methods;
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
