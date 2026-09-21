import { describe, expect, it } from "vitest";
import type { CheckovCrosswalk, PipelineRecipe } from "../src/index.js";
import { CheckovCrosswalk as Schema, deriveCheckovRecipes, methodsOfRecipe } from "../src/index.js";

// The checkov crosswalk's derivation (docs/PLAN-REACH.md N2-1): one recipe
// per KSI over the base recipe's artifact, and the four refusals that keep a
// crosswalk from deriving something quietly wrong.

const base: PipelineRecipe = {
  id: "iac-baseline-clean",
  ksi_ids: ["KSI-SVC-ACM"],
  control_ids: ["cm-2", "cm-6"],
  evidence: "the baseline",
  collection: { kind: "pipeline", collector: "checkov" },
  expected_output: "checkov-results.json",
  assertions: [{ field: "check_id", op: "count_eq", value: 0, description: "zero" }],
  cadence: "daily",
  automatable: "full",
  anchor: "commit",
};

const prose = {
  checks: "Reads the network rules written into the committed infrastructure and counts the ones that open a port to everyone.",
  violation: "Some definition admits the whole internet to a port that should be reachable from one place, before anything is deployed.",
  fix: "Narrow the rule to the sources and ports the service needs, or remove it; each failed check names the file and the rule.",
};

function crosswalk(overrides: Partial<CheckovCrosswalk> = {}): CheckovCrosswalk {
  return Schema.parse({
    _type: "https://rampscan.dev/checkov-crosswalk/v1",
    tool: "checkov",
    version: "3.3.11",
    to: "2026.09.13.02",
    reviewed: "2026-09-21",
    derived_from: "iac-baseline-clean",
    rule: "x".repeat(200),
    rows: [
      {
        ksi: "KSI-CNA-RNT",
        recipe: "iac-traffic-restricted-declared",
        controls: ["sc-7.5"],
        evidence: "The committed definitions declare no security group that admits unrestricted inbound traffic",
        plain: prose,
        caveats: "Declared state only: what the committed definitions say, never what the account runs today.",
      },
    ],
    entries: [
      {
        check: "CKV_AWS_24",
        framework: "terraform",
        ksi: "KSI-CNA-RNT",
        basis: "Ensure no security groups allow ingress from 0.0.0.0:0 to port 22 — an open administrative port is inbound traffic the definition does not limit",
        proves: "declared-state",
      },
      {
        check: "CKV_AWS_25",
        framework: "terraform",
        ksi: "KSI-CNA-RNT",
        basis: "Ensure no security groups allow ingress from 0.0.0.0:0 to port 3389 — the same, for remote desktop",
        proves: "declared-state",
      },
    ],
    ...overrides,
  });
}

describe("deriveCheckovRecipes", () => {
  it("derives one recipe per row, asserting zero failures among the row's rules, over the base's collector", () => {
    const [recipe] = deriveCheckovRecipes(crosswalk(), base);
    expect(recipe!.id).toBe("iac-traffic-restricted-declared");
    expect(recipe!.ksi_ids).toEqual(["KSI-CNA-RNT"]);
    expect(recipe!.collection).toEqual(base.collection);
    expect(recipe!.cadence).toBe(base.cadence);
    expect(recipe!.assertions).toEqual([
      expect.objectContaining({
        field: "check_id",
        op: "count_eq",
        value: 0,
        where: [{ field: "check_id", op: "in", value: ["CKV_AWS_24", "CKV_AWS_25"] }],
      }),
    ]);
    expect(recipe!.derived_from).toEqual({
      recipe: "iac-baseline-clean",
      crosswalk: "checkov-3.3.11-to-2026.09.13.02",
      proves: "declared-state",
      checks: ["CKV_AWS_24", "CKV_AWS_25"],
    });
    // the catalog's obligations, met by construction
    expect(recipe!.empty_means).toBe("clean");
    expect(recipe!.notes).toMatch(/Empty-set discipline — Guard:/);
    expect(recipe!.notes).toMatch(/\b(every|all|entire|full|whole|each)\b/i);
    expect(recipe!.plain).toEqual(prose);
    expect(recipe!.caveats).toContain("Declared state only");
  });

  it("the derived recipe's methods carry derived_from in their provenance, so the register can print declared", () => {
    const [recipe] = deriveCheckovRecipes(crosswalk(), base);
    const [method] = methodsOfRecipe(recipe!, { population: "checkout", history: false, gitignored: "excluded" });
    expect(method!.provenance.derived_from).toEqual({
      recipe: "iac-baseline-clean",
      crosswalk: "checkov-3.3.11-to-2026.09.13.02",
      proves: "declared-state",
    });
    // and a hand-written recipe's method carries none
    const [plain] = methodsOfRecipe(base, { population: "checkout", history: false, gitignored: "excluded" });
    expect(plain!.provenance.derived_from).toBeUndefined();
  });

  it("refuses an entry filed under a KSI with no row", () => {
    const cw = crosswalk();
    cw.entries.push({ ...cw.entries[0]!, check: "CKV_AWS_26", ksi: "KSI-SVC-SIN" });
    expect(() => deriveCheckovRecipes(cw, base)).toThrow(/KSI-SVC-SIN, which has no row/);
  });

  it("refuses a row with no entries — a recipe over no rules passes vacuously", () => {
    const cw = crosswalk();
    cw.rows.push({ ...cw.rows[0]!, ksi: "KSI-CNA-MAT", recipe: "iac-attack-surface-declared" });
    expect(() => deriveCheckovRecipes(cw, base)).toThrow(/has no entries/);
  });

  it("refuses a rule filed under two KSIs — one observation would count twice", () => {
    const cw = crosswalk();
    cw.rows.push({ ...cw.rows[0]!, ksi: "KSI-CNA-MAT", recipe: "iac-attack-surface-declared" });
    cw.entries.push({ ...cw.entries[0]!, ksi: "KSI-CNA-MAT" });
    expect(() => deriveCheckovRecipes(cw, base)).toThrow(/filed under both/);
  });

  it("refuses a base recipe that is not the crosswalk's derived_from, or that runs another collector", () => {
    expect(() => deriveCheckovRecipes(crosswalk(), { ...base, id: "other" })).toThrow(/derives from "iac-baseline-clean"/);
    expect(() =>
      deriveCheckovRecipes(crosswalk(), { ...base, collection: { kind: "pipeline", collector: "spectral" } }),
    ).toThrow(/not checkov/);
  });

  it("the schema is strict: an entry that proves anything but declared state, or a misspelled field, is refused", () => {
    expect(() => crosswalk({ entries: [{ ...crosswalk().entries[0]!, proves: "account-state" as never }] })).toThrow();
    expect(() => Schema.parse({ ...crosswalk(), extra: true })).toThrow();
  });
});
