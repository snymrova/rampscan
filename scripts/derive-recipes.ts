#!/usr/bin/env tsx
// Regenerate the crosswalk-derived recipes in recipes/commit/ (docs/PLAN-REACH.md
// N2-1). Computed, never typed: a derived recipe file is the output of
// `deriveCheckovRecipes` over the crosswalk and its base recipe, and
// `packages/cli/test/checkov-crosswalk.test.ts` fails the build when a file on
// disk stops equalling that output. Edit the crosswalk, run this, commit both.
//
//   pnpm exec tsx scripts/derive-recipes.ts          # write
//   pnpm exec tsx scripts/derive-recipes.ts --check  # exit 1 on drift, write nothing
import { readFile, readdir, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { CheckovCrosswalk, PipelineRecipe, deriveCheckovRecipes } from "../packages/schema/src/index.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const CROSSWALKS = join(REPO_ROOT, "recipes/crosswalks");
const RECIPES = join(REPO_ROOT, "recipes/commit");
const check = process.argv.includes("--check");

/** every checkov crosswalk in the directory, by its file's name */
export async function loadCheckovCrosswalks(dir: string): Promise<CheckovCrosswalk[]> {
  const files = (await readdir(dir)).filter((f) => /^checkov-\d+\.\d+\.\d+-to-.+\.json$/.test(f)).sort();
  const out: CheckovCrosswalk[] = [];
  for (const file of files) {
    const parsed = CheckovCrosswalk.parse(JSON.parse(await readFile(join(dir, file), "utf8")));
    out.push(parsed);
  }
  return out;
}

let drift = 0;
for (const crosswalk of await loadCheckovCrosswalks(CROSSWALKS)) {
  const base = PipelineRecipe.parse(
    JSON.parse(await readFile(join(RECIPES, `${crosswalk.derived_from}.json`), "utf8")),
  );
  for (const recipe of deriveCheckovRecipes(crosswalk, base)) {
    const path = join(RECIPES, `${recipe.id}.json`);
    const next = `${JSON.stringify(recipe, null, 2)}\n`;
    const current = await readFile(path, "utf8").catch(() => undefined);
    if (current === next) continue;
    drift++;
    if (check) {
      console.error(`${recipe.id}.json ${current === undefined ? "is missing" : "differs from its derivation"}`);
    } else {
      await writeFile(path, next);
      console.log(`wrote ${recipe.id}.json`);
    }
  }
}
if (check && drift > 0) {
  console.error(`${drift} derived recipe(s) drifted — run \`pnpm exec tsx scripts/derive-recipes.ts\` and commit`);
  process.exit(1);
}
if (drift === 0) console.log("every derived recipe equals its derivation");
