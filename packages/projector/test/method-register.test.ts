import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import type { LedgerEntry } from "@rampscan/core";
import type { EvidenceBundle, MethodScope, PipelineRecipe } from "@rampscan/schema";
import { methodsOfRecipe } from "@rampscan/schema";
import { foldEntries, readProjectionSqlite, writeProjectionSqlite } from "../src/index.js";

// Q2.3 — the projector folds per-KSI (SPEC §12.1 invariant 4′, plan §4).
// G1 and G2 are properties of the REGISTER: computed from which methods
// exist, not from what the ledger holds. The ledger join supplies each
// method's evidence state through its recipe cell — one bundle evidences
// every method its recipe derives (§1.1 decision (b) at fold time).

let counter = 0;

function evidenceEntry(opts: {
  recipe: string;
  timestamp: string;
  ksiIds?: string[];
  verdict?: "evidenced" | "violated";
  repo?: string;
}): LedgerEntry {
  const bundle: EvidenceBundle = {
    _type: "https://in-toto.io/Statement/v1",
    subject: [{ name: "x", digest: { sha256: "e".repeat(64) } }],
    predicateType: "https://rampscan.dev/evidence/v1",
    predicate: {
      recipe_id: opts.recipe,
      ksi_ids: opts.ksiIds ?? ["KSI-SCR-MIT"],
      control_ids: ["si-7.1"],
      verdict: opts.verdict ?? "evidenced",
      repo: opts.repo ?? "fixtures/app",
      commit: "1".repeat(40),
      anchor_paths: [{ path: "f", contentHash: "a".repeat(64) }],
      dataset_version: "2026.07.14.01",
      tool_versions: { "repo-facts": "0.1.0" },
      assertions: [
        { description: "check", passed: (opts.verdict ?? "evidenced") === "evidenced" },
      ],
      cadence: "continuous",
      run_id: `run-${opts.timestamp}`,
      timestamp: opts.timestamp,
    },
  };
  return { digest: `digest-${counter++}`, bundle, appendedAt: opts.timestamp };
}

function recipe(id: string, ksiIds: string[]): PipelineRecipe {
  return {
    id,
    ksi_ids: ksiIds,
    control_ids: ["si-7.1"],
    evidence: "test recipe",
    collection: { kind: "pipeline", collector: "repo-facts" },
    expected_output: "rows",
    cadence: "weekly",
    automatable: "full",
    anchor: "commit",
  };
}

const scope: MethodScope = { population: "checkout", history: false, gitignored: "excluded" };
const T1 = "2026-08-01T00:00:00.000Z";
const T2 = "2026-08-08T00:00:00.000Z";

const covered = recipe("covered", ["KSI-SCR-MIT"]);
const twoKsis = recipe("two-ksis", ["KSI-SCR-MIT", "KSI-CMT-CHG"]);
const neverScanned = recipe("never-scanned", ["KSI-CMT-CHG"]);
const recipes = [covered, twoKsis, neverScanned];
const methods = recipes.flatMap((r) => methodsOfRecipe(r, scope));
const KSI_IDS = ["KSI-CMT-CHG", "KSI-CNA-CIC", "KSI-SCR-MIT"];

function foldWith(entries: LedgerEntry[], floor?: number | null) {
  return foldEntries(entries, T2, {
    recipes,
    methods,
    ksiIds: KSI_IDS,
    ...(floor === undefined ? {} : { methodFloor: floor }),
  });
}

describe("the method register (Q2.3)", () => {
  it("folds without methods exactly as before — methodRegisters is empty, never absent", () => {
    const projection = foldEntries([evidenceEntry({ recipe: "covered", timestamp: T1 })], T2, {
      recipes,
    });
    expect(projection.methodRegisters).toEqual([]);
  });

  it("a KSI with zero methods is a G1 row, never an absent row", () => {
    const projection = foldWith([evidenceEntry({ recipe: "covered", timestamp: T1 })], 1);
    const row = projection.methodRegisters.find((r) => r.ksi === "KSI-CNA-CIC")!;
    expect(row.methods).toEqual([]);
    expect(row.automatedMethods).toBe(0);
    expect(row.floorMet).toBe(false);
    expect(row.gap).toBe("G1");
    // every owed KSI appears for the scanned repo, sorted
    expect(projection.methodRegisters.map((r) => r.ksi)).toEqual(KSI_IDS);
  });

  it("counts automated methods against the floor — G2 exactly when below it", () => {
    const met = foldWith([evidenceEntry({ recipe: "covered", timestamp: T1 })], 2);
    const scr = met.methodRegisters.find((r) => r.ksi === "KSI-SCR-MIT")!;
    expect(scr.automatedMethods).toBe(2); // covered + two-ksis both claim it
    expect(scr.floorMet).toBe(true);
    expect(scr.gap).toBeUndefined();

    const unmet = foldWith([evidenceEntry({ recipe: "covered", timestamp: T1 })], 3);
    const short = unmet.methodRegisters.find((r) => r.ksi === "KSI-SCR-MIT")!;
    expect(short.automatedMethods).toBe(2);
    expect(short.floorMet).toBe(false);
    expect(short.gap).toBe("G2");
  });

  it("a null floor (the class owes no number) checks nothing: floorMet null, no G2", () => {
    const projection = foldWith([evidenceEntry({ recipe: "covered", timestamp: T1 })], null);
    const row = projection.methodRegisters.find((r) => r.ksi === "KSI-SCR-MIT")!;
    expect(row.methodFloor).toBeNull();
    expect(row.floorMet).toBeNull();
    expect(row.gap).toBeUndefined();
    // G1 still fires — it needs no floor
    expect(projection.methodRegisters.find((r) => r.ksi === "KSI-CNA-CIC")!.gap).toBe("G1");
  });

  it("a pipeline method's state is its recipe cell's state, and one bundle evidences every method its recipe derives", () => {
    const projection = foldWith(
      [evidenceEntry({ recipe: "two-ksis", timestamp: T1, ksiIds: twoKsis.ksi_ids })],
      1,
    );
    for (const ksi of twoKsis.ksi_ids) {
      const row = projection.methodRegisters.find((r) => r.ksi === ksi)!;
      const cell = row.methods.find((m) => m.recipeId === "two-ksis")!;
      expect(cell.state).toBe("evidenced");
      expect(cell.bundleDigest).toBeDefined();
      expect(cell.freshAsOf).toBe(T1);
      expect(cell.collector).toBe("repo-facts");
    }
    // a method whose recipe was never scanned reads unevidenced — the honest default
    const idle = projection.methodRegisters
      .find((r) => r.ksi === "KSI-CMT-CHG")!
      .methods.find((m) => m.recipeId === "never-scanned")!;
    expect(idle.state).toBe("unevidenced");
    expect(idle.bundleDigest).toBeUndefined();
  });

  it("freshAsOf is the freshest live evidence across the KSI's methods", () => {
    const projection = foldWith(
      [
        evidenceEntry({ recipe: "covered", timestamp: T1 }),
        evidenceEntry({ recipe: "two-ksis", timestamp: T2, ksiIds: twoKsis.ksi_ids }),
      ],
      1,
    );
    expect(projection.methodRegisters.find((r) => r.ksi === "KSI-SCR-MIT")!.freshAsOf).toBe(T2);
  });

  it("survives the sqlite round trip byte-for-byte, nulls included", async () => {
    const projection = foldWith([evidenceEntry({ recipe: "covered", timestamp: T1 })], null);
    const dir = await mkdtemp(join(tmpdir(), "rampscan-methods-"));
    const dbPath = join(dir, "projection.db");
    await writeProjectionSqlite(projection, dbPath);
    expect(readProjectionSqlite(dbPath)).toEqual(projection);
  });
});
