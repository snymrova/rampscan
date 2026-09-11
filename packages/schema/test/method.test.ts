import { describe, expect, it } from "vitest";
import {
  MethodScope,
  PipelineRecipe,
  ValidationMethod,
  methodId,
  methodsOfRecipe,
} from "../src/index.js";

// The Q2.1 derivation (SPEC §12.2): a recipe claiming N KSIs derives N
// pipeline methods, one per KSI, with deterministic ids — the register is a
// derivation over reviewed artifacts, never a table anyone edits.

const scope: MethodScope = {
  population: "checkout",
  history: false,
  gitignored: "excluded",
};

const recipe = PipelineRecipe.parse({
  id: "lockfile-pinned-deps",
  ksi_ids: ["KSI-SCR-MIT", "KSI-CMT-CHG"],
  control_ids: ["cm-2"],
  evidence: "Lockfile pins every dependency at the scanned commit",
  collection: { kind: "pipeline", collector: "repo-facts" },
  expected_output: "lockfile inventory",
  cadence: "continuous",
  automatable: "full",
  anchor: "commit",
});

describe("methodsOfRecipe", () => {
  it("derives one method per claimed KSI, source pipeline", () => {
    const methods = methodsOfRecipe(recipe, scope);
    expect(methods).toHaveLength(2);
    expect(methods.map((m) => m.ksi)).toEqual(["KSI-SCR-MIT", "KSI-CMT-CHG"]);
    for (const m of methods) {
      expect(m.source).toBe("pipeline");
      expect(m.automated).toBe(true);
      expect(m.clock).toBe("machine");
      expect(m.provenance).toEqual({
        recipe_id: "lockfile-pinned-deps",
        collector: "repo-facts",
        scope,
      });
      // every derived method parses against the schema it claims to be
      expect(ValidationMethod.parse(m)).toEqual(m);
    }
  });

  it("mints the deterministic id: `${source}:${source_ref}#${ksi}`", () => {
    const [first] = methodsOfRecipe(recipe, scope);
    expect(first!.id).toBe("pipeline:lockfile-pinned-deps#KSI-SCR-MIT");
    expect(methodId("pipeline", "lockfile-pinned-deps", "KSI-SCR-MIT")).toBe(first!.id);
  });

  it("standing inherits the recipe's automatable uniformly", () => {
    for (const m of methodsOfRecipe(recipe, scope)) {
      expect(m.standing).toBe("full");
    }
  });

  it("a per_ksi override changes standing for exactly its KSI", () => {
    const overridden = PipelineRecipe.parse({
      ...recipe,
      per_ksi: { "KSI-CMT-CHG": { automatable: "partial", notes: "gestures only" } },
    });
    const byKsi = new Map(methodsOfRecipe(overridden, scope).map((m) => [m.ksi, m]));
    expect(byKsi.get("KSI-SCR-MIT")!.standing).toBe("full");
    expect(byKsi.get("KSI-CMT-CHG")!.standing).toBe("partial");
  });

  it("refuses a per_ksi override naming a KSI the recipe does not claim", () => {
    const stray = PipelineRecipe.parse({
      ...recipe,
      per_ksi: { "KSI-CNA-NET": { automatable: "partial" } },
    });
    expect(() => methodsOfRecipe(stray, scope)).toThrow(/KSI-CNA-NET/);
  });
});

describe("ValidationMethod hard edges", () => {
  const pipelineMethod = methodsOfRecipe(recipe, scope)[0]!;

  it("the source union is closed — an unknown source refuses to parse", () => {
    expect(
      ValidationMethod.safeParse({ ...pipelineMethod, source: "gcp-ingested" }).success,
    ).toBe(false);
  });

  it("a misspelled method field refuses instead of stripping", () => {
    const { standing, ...rest } = pipelineMethod;
    expect(ValidationMethod.safeParse({ ...rest, standings: standing }).success).toBe(false);
  });

  it("a misspelled scope field refuses instead of stripping", () => {
    expect(
      MethodScope.safeParse({ population: "checkout", history: false, gitignore: "excluded" })
        .success,
    ).toBe(false);
  });

  it("provenance is per-source: pipeline provenance under attestation refuses", () => {
    expect(
      ValidationMethod.safeParse({
        ...pipelineMethod,
        source: "attestation",
        automated: false,
        clock: "non-machine",
      }).success,
    ).toBe(false);
  });
});
