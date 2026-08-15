import { readFile, readdir } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import { PipelineRecipe } from "@rampscan/schema";
import { loadRecipes } from "../src/recipes.js";

// K1 — the plain-language layer's COMPLETENESS test, and the thing it is here
// to stop is a recipe shipping without one.
//
// `plain` is optional in the schema on purpose (the recipe shape mirrors the
// AWS dataset's, which has no such field, so an imported recipe must still
// parse) and REQUIRED in this repository's catalog. That split is exactly what
// this file enforces: shape is the schema's job, completeness is policy's, and
// policy lives in a test that fails CI rather than in a convention someone
// remembers.
//
// The checks past "is it there" all exist because of a specific way this rots:
// a stub that says nothing, a paragraph copied out of the auditor-facing
// `evidence` line, an explanation that only answers one of the three
// questions, or jargon explained with more jargon.

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "../../..");
const recipesDir = join(repoRoot, "recipes/pipeline");
const glossaryLib = join(repoRoot, "console/web/lib/glossary.ts");

interface GlossaryModule {
  lookupTerm(raw: string): { term: string; definition: string } | null;
  glossaryEntries(): Array<{ term: string; definition: string }>;
  normalizeTerm(raw: string): string;
}

let recipes: Awaited<ReturnType<typeof loadRecipes>>;
let glossary: GlossaryModule;

beforeAll(async () => {
  recipes = await loadRecipes(recipesDir);
  // the console's own copy, loaded by path — the twin posture every console
  // library is tested through here (I3e's lesson about compiled duplicates)
  glossary = (await import(glossaryLib)) as GlossaryModule;
});

describe("the catalog's plain-language layer is complete (K1)", () => {
  it("every recipe in the catalog carries all three paragraphs", () => {
    const missing = recipes.filter((r) => r.plain === undefined).map((r) => r.id);
    expect(missing, "recipes with no `plain` block").toEqual([]);
    // the whole catalog, not a sample: a count here would pass while a new
    // recipe slipped in unexplained
    expect(recipes.length).toBeGreaterThanOrEqual(15);
    for (const recipe of recipes) {
      expect(Object.keys(recipe.plain!).sort(), recipe.id).toEqual(["checks", "fix", "violation"]);
    }
  });

  it("each paragraph is written prose, not a stub", () => {
    for (const recipe of recipes) {
      for (const [field, text] of Object.entries(recipe.plain!)) {
        const where = `${recipe.id}.${field}`;
        // long enough to have said something, short enough that nobody skims
        // past it — a screenful of prose on a board row is the same as none
        expect(text.length, `${where} too short`).toBeGreaterThan(80);
        expect(text.length, `${where} too long`).toBeLessThan(560);
        expect(text.trim(), where).toBe(text);
        expect(text, `${where} should end as a sentence`).toMatch(/[.?]$/);
        expect(text, `${where} looks like a placeholder`).not.toMatch(/\bTODO\b|\bTBD\b|\bXXX\b/i);
      }
    }
  });

  it("the operator paragraph is not the auditor sentence recycled", () => {
    // `evidence` is one clause aimed at someone reading a signed statement;
    // `plain.checks` is aimed at someone who has never seen one. If they are
    // the same string, K1 did not happen for that recipe.
    for (const recipe of recipes) {
      expect(recipe.plain!.checks, recipe.id).not.toBe(recipe.evidence);
      expect(recipe.plain!.checks, recipe.id).not.toBe(recipe.notes);
      expect(recipe.plain!.fix, recipe.id).not.toBe(recipe.plain!.violation);
      expect(recipe.plain!.fix, recipe.id).not.toBe(recipe.plain!.checks);
    }
  });

  it("no paragraph states a verdict, a count, or a condition of any repository", () => {
    // The computed-never-typed rule. Authored prose may say what a violation
    // MEANS ("a violation means the container runs as root"); it may not
    // assert that anything IS violated, evidenced or counted — the moment it
    // does, a sentence on screen is claiming something no scan produced.
    const forbidden = [
      /\b\d+\s+(findings?|violations?|advisories|secrets|components?|failures?)\b/i,
      /\bis (currently )?(violated|evidenced|unevidenced)\b/i,
      /\bthis (repository|repo) (is|has|does)\b/i,
      /\bzero (findings|violations)\b/i,
    ];
    for (const recipe of recipes) {
      for (const [field, text] of Object.entries(recipe.plain!)) {
        for (const pattern of forbidden) {
          expect(pattern.test(text), `${recipe.id}.${field} states a computed fact: ${text}`).toBe(
            false,
          );
        }
      }
    }
  });

  it("every rampscan term the prose uses has a glossary entry", () => {
    // The tie between K1's two halves: prose is only plain if its vocabulary
    // is defined somewhere the reader can reach. A term used here with no
    // entry renders as bare text under the Term component — silently
    // unexplained, which is the failure this catches.
    const jargon = [
      "KSI",
      "DSSE",
      "MVX",
      "anchor",
      "notApplicable",
      "not_affected",
      "two-key",
      "projection",
      "ledger",
      "cadence",
      "collector",
      "recipe",
      "bundle",
      // L1's vocabulary: the architecture contract is a word the repository
      // being scanned writes, so an operator meets it first on a board row
      "contract",
      "boundary",
    ];
    for (const recipe of recipes) {
      const prose = Object.values(recipe.plain!).join(" ");
      for (const term of jargon) {
        if (!new RegExp(`\\b${term}\\b`, "i").test(prose)) continue;
        expect(glossary.lookupTerm(term), `${recipe.id} uses "${term}" with no glossary entry`)
          .not.toBeNull();
      }
    }
  });

  it("the glossary defines every term K1 committed to defining", () => {
    // The plan's own list, kept as a list: a term dropped from glossary.ts
    // fails here rather than degrading quietly into plain text on the page.
    const committed = [
      "KSI",
      "control",
      "recipe",
      "DSSE",
      "anchor",
      "anchor-drift",
      "evidenced",
      "violated",
      "unevidenced",
      "notApplicable",
      "MVX window",
      "not_affected",
      "two-key write",
      "projection",
      "ledger",
      "architecture contract",
      "contract rule",
      "boundary",
    ];
    for (const term of committed) {
      expect(glossary.lookupTerm(term), `no glossary entry for "${term}"`).not.toBeNull();
    }
  });

  it("the schema accepts a recipe with no plain block — shape is not policy", async () => {
    // An AWS-dataset recipe carries no `plain`, and must still parse: if the
    // schema required it, this repository could not read the dataset its
    // recipe shape mirrors. The catalog is held to the higher bar by the first
    // test in this file, not by the type.
    const raw = JSON.parse(
      await readFile(join(recipesDir, "codeowners-defined.json"), "utf8"),
    ) as Record<string, unknown>;
    delete raw["plain"];
    expect(() => PipelineRecipe.parse(raw)).not.toThrow();
    // but a half-written one is refused outright — three fields or none
    expect(() =>
      PipelineRecipe.parse({ ...raw, plain: { checks: "only this one" } }),
    ).toThrow();
    expect(() =>
      PipelineRecipe.parse({ ...raw, plain: { checks: "", violation: "a", fix: "b" } }),
    ).toThrow();
  });

  it("the prose lives in the recipe file, so it travels with the check", async () => {
    // Not a style point: a paragraph kept in the console would describe a
    // recipe the console does not own, and would go stale the moment the
    // recipe changed collector, assertion or meaning. Reading the raw JSON
    // proves it is on disk in the catalog rather than merged in at load time.
    const files = (await readdir(recipesDir)).filter((f) => f.endsWith(".json"));
    expect(files.length).toBe(recipes.length);
    for (const file of files) {
      const raw = JSON.parse(await readFile(join(recipesDir, file), "utf8")) as Record<
        string,
        unknown
      >;
      expect(raw["plain"], `${file} has no plain block on disk`).toBeTruthy();
    }
  });
});
