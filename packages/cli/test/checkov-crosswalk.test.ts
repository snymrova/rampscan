import { readFile, readdir } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import { CHECKOV_DERIVED_RECIPES, loadToolManifest } from "@rampscan/collectors";
import { DEFAULT_DATASET_PIN, loadKsiCatalog, loadLocalDataset } from "@rampscan/dataset";
import type { CheckovCrosswalk, PipelineRecipe } from "@rampscan/schema";
import { CheckovCrosswalk as CrosswalkSchema, deriveCheckovRecipes } from "@rampscan/schema";
import { loadRecipes, validateRecipeIds } from "../src/recipes.js";

// The checkov crosswalk over the real pins (docs/PLAN-REACH.md N2-1). Four
// things that must stay true of this checkout, each of which rots quietly
// without a test:
//
//   - every rule id the crosswalk admits exists in the PINNED checkov's rule
//     list, for the framework it names (rule ids move between versions);
//   - the crosswalk, the vendored rule list and tools.json pin ONE checkov
//     version — a re-pin that forgets any of the three is drift, not a bump;
//   - every derived recipe file in recipes/commit/ equals its derivation
//     (computed, never typed — the file is output, the crosswalk is input);
//   - the checkov collector's manifest declares exactly the derived recipes.

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const CROSSWALKS = join(REPO_ROOT, "recipes/crosswalks");
const RECIPES = join(REPO_ROOT, "recipes/commit");

interface RuleList {
  tool: string;
  version: string;
  checks: Array<{ id: string; framework: string; name: string }>;
}

let crosswalk: CheckovCrosswalk;
let rules: RuleList;
let recipes: PipelineRecipe[];

beforeAll(async () => {
  const files = (await readdir(CROSSWALKS)).filter((f) => /^checkov-\d+\.\d+\.\d+-to-.+\.json$/.test(f));
  expect(files, "exactly one checkov crosswalk at a time").toHaveLength(1);
  crosswalk = CrosswalkSchema.parse(JSON.parse(await readFile(join(CROSSWALKS, files[0]!), "utf8")));
  rules = JSON.parse(
    await readFile(join(CROSSWALKS, `checkov-${crosswalk.version}-checks.json`), "utf8"),
  ) as RuleList;
  recipes = await loadRecipes(RECIPES);
});

describe("the checkov crosswalk over the real pins", () => {
  it("is pinned to the checkov version tools.json runs, and the vendored rule list is that version's", async () => {
    const manifest = await loadToolManifest();
    expect(crosswalk.version).toBe(manifest["checkov"]?.version);
    expect(rules.version).toBe(crosswalk.version);
    expect(rules.tool).toBe("checkov");
    expect(crosswalk.to).toBe(DEFAULT_DATASET_PIN);
  });

  it("every admitted rule id exists in the pinned rule list, for the framework the entry names", () => {
    const known = new Set(rules.checks.map((c) => `${c.framework}:${c.id}`));
    const unknown = crosswalk.entries
      .filter((e) => !known.has(`${e.framework}:${e.check}`))
      .map((e) => `${e.framework}:${e.check}`);
    expect(unknown, "rule ids the pinned checkov does not carry").toEqual([]);
  });

  it("every KSI it files under is in the catalog, and every control it claims is reachable from that KSI", async () => {
    const catalog = await loadKsiCatalog({
      derivedDir: join(REPO_ROOT, "docs/context/ramprules/derived"),
      rulesFile: join(REPO_ROOT, "docs/context/fedramp-rules/fedramp-consolidated-rules.json"),
      pin: DEFAULT_DATASET_PIN,
    });
    const ids = new Set(catalog.ksis.map((k) => k.id));
    for (const row of crosswalk.rows) expect(ids.has(row.ksi), row.ksi).toBe(true);
    for (const entry of crosswalk.entries) expect(ids.has(entry.ksi), entry.check).toBe(true);
    const dataset = await loadLocalDataset(join(REPO_ROOT, "docs/context/ramprules/derived"), DEFAULT_DATASET_PIN);
    const base = recipes.find((r) => r.id === crosswalk.derived_from)!;
    expect(validateRecipeIds(deriveCheckovRecipes(crosswalk, base), dataset)).toEqual([]);
  });

  it("every derived recipe file equals its derivation — the file is output, the crosswalk is input", async () => {
    const base = recipes.find((r) => r.id === crosswalk.derived_from);
    expect(base, `base recipe ${crosswalk.derived_from}`).toBeDefined();
    for (const derived of deriveCheckovRecipes(crosswalk, base!)) {
      const onDisk = JSON.parse(await readFile(join(RECIPES, `${derived.id}.json`), "utf8"));
      expect(onDisk, `${derived.id}.json — run scripts/derive-recipes.ts`).toEqual(derived);
    }
  });

  it("the collector's manifest declares exactly the derived recipes, and nothing else derives from checkov", () => {
    const rows = crosswalk.rows.map((r) => r.recipe).sort();
    expect([...CHECKOV_DERIVED_RECIPES].sort()).toEqual(rows);
    const derivedOnDisk = recipes.filter((r) => r.derived_from !== undefined).map((r) => r.id).sort();
    expect(derivedOnDisk).toEqual(rows);
    for (const recipe of recipes) {
      if (recipe.derived_from === undefined) continue;
      expect(recipe.derived_from.recipe).toBe(crosswalk.derived_from);
      expect(recipe.collection.collector).toBe("checkov");
    }
  });

  it("moves at least four KSIs beyond SVC-ACM onto the commit plane — the phase's exit gate, counted", () => {
    const ksis = new Set(crosswalk.rows.map((r) => r.ksi));
    ksis.delete("KSI-SVC-ACM");
    expect(ksis.size).toBeGreaterThanOrEqual(4);
  });
});
