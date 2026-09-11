import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import { allCollectors } from "@rampscan/collectors";
import type { CollectorManifest } from "@rampscan/schema";
import { deriveCatalogMethods, loadRecipes } from "../src/recipes.js";

// Q2.2 — the migration's enforcement. The register's unit is now the
// (recipe × KSI) pair, derived per SPEC §12.2 over the real catalog and the
// real manifests: this file is what makes `ksi_ids` the primary key of the
// join in fact rather than in prose. The scope rule is §12.6's enforcement
// arm, same pattern as `empty_means` in catalog.test.ts — shape is schema's
// job (`scope` is optional there), completeness is policy's, and policy
// lives in a test that fails CI.

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "../../..");
const recipesDir = join(repoRoot, "recipes/commit");

const manifests = allCollectors.map((c) => c.manifest);

let recipes: Awaited<ReturnType<typeof loadRecipes>>;

beforeAll(async () => {
  recipes = await loadRecipes(recipesDir);
});

describe("every collector manifest declares its scan scope (SPEC §12.6)", () => {
  it("no manifest is silent about what it walked", () => {
    const silent = manifests.filter((m) => m.scope === undefined).map((m) => m.name);
    expect(silent, "collector manifests with no `scope` declaration").toEqual([]);
    // the whole collector set, not a sample — same reasoning as empty_means
    expect(manifests.length).toBeGreaterThanOrEqual(13);
  });

  it("only gitleaks reads git history", () => {
    // a new collector that reads history must say so HERE, deliberately —
    // history is the widest population a walk can claim
    const historians = manifests.filter((m) => m.scope?.history).map((m) => m.name);
    expect(historians).toEqual(["gitleaks"]);
  });
});

describe("the catalog derives its methods (SPEC §12.2, Q2.2)", () => {
  it("one method per (recipe × KSI), over the whole catalog", () => {
    const methods = deriveCatalogMethods(recipes, manifests);
    const expected = recipes.flatMap((r) => r.ksi_ids.map((ksi) => `pipeline:${r.id}#${ksi}`));
    expect(methods.map((m) => m.id)).toEqual(expected);
    expect(methods.length).toBeGreaterThanOrEqual(recipes.length);
  });

  it("every derived method is a pipeline method with interrogable provenance", () => {
    const byRecipe = new Map(recipes.map((r) => [r.id, r]));
    const byCollector = new Map(manifests.map((m) => [m.name, m]));
    for (const method of deriveCatalogMethods(recipes, manifests)) {
      expect(method.source).toBe("pipeline");
      expect(method.automated).toBe(true);
      expect(method.clock).toBe("machine");
      const recipe = byRecipe.get(method.provenance.recipe_id)!;
      expect(recipe.ksi_ids).toContain(method.ksi);
      expect(method.provenance.collector).toBe(recipe.collection.collector);
      // the scope on the method IS the scope the collector declared
      expect(method.provenance.scope).toEqual(byCollector.get(method.provenance.collector)!.scope);
    }
  });

  it("refuses a recipe naming a collector no manifest declares", () => {
    expect(() => deriveCatalogMethods(recipes, manifests.filter((m) => m.name !== "gitleaks"))).toThrow(
      /no-secrets-in-history.*"gitleaks"/,
    );
  });

  it("refuses a manifest with no scope block", () => {
    const stripped: CollectorManifest[] = manifests.map((m) =>
      m.name === "gitleaks" ? { ...m, scope: undefined } : m,
    );
    expect(() => deriveCatalogMethods(recipes, stripped)).toThrow(/scope.*12\.6/);
  });

  it("refuses a duplicate (recipe × KSI) pair", () => {
    const doubled = recipes.map((r) =>
      r.id === "no-secrets-in-history" ? { ...r, ksi_ids: [...r.ksi_ids, r.ksi_ids[0]!] } : r,
    );
    expect(() => deriveCatalogMethods(doubled, manifests)).toThrow(/duplicate method id/);
  });
});
