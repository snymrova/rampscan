import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import type { ClockWindow, LedgerEntry } from "@rampscan/core";
import type {
  EvidenceBundle,
  MethodScope,
  PipelineRecipe,
  ScopingEvent,
  ValidationMethod,
} from "@rampscan/schema";
import { methodsOfRecipe } from "@rampscan/schema";
import {
  foldEntries,
  monthsBefore,
  readProjectionSqlite,
  windowThreshold,
  writeProjectionSqlite,
} from "../src/index.js";

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

function foldWith(
  entries: LedgerEntry[],
  floor?: number | null,
  historyFloorMonths?: number | null,
  windows?: {
    machineWindow?: ClockWindow | null;
    nonMachineWindow?: ClockWindow | null;
    methods?: ValidationMethod[];
  },
) {
  return foldEntries(entries, T2, {
    recipes,
    methods: windows?.methods ?? methods,
    ksiIds: KSI_IDS,
    ...(floor === undefined ? {} : { methodFloor: floor }),
    ...(historyFloorMonths === undefined ? {} : { historyFloorMonths }),
    ...(windows?.machineWindow === undefined ? {} : { machineWindow: windows.machineWindow }),
    ...(windows?.nonMachineWindow === undefined
      ? {}
      : { nonMachineWindow: windows.nonMachineWindow }),
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

function scopingEntry(opts: { recipe: string; timestamp: string; repo?: string }): LedgerEntry {
  const bundle: ScopingEvent = {
    _type: "https://in-toto.io/Statement/v1",
    subject: [{ name: "justification.txt", digest: { sha256: "f".repeat(64) } }],
    predicateType: "https://rampscan.dev/scoping/v1",
    predicate: {
      action: "notApplicable",
      recipe_id: opts.recipe,
      ksi_ids: ["KSI-SCR-MIT"],
      control_ids: ["si-7.1"],
      repo: opts.repo ?? "fixtures/app",
      justification: "does not apply here",
      proposed_by: "viewer@rampscan.local (pb:u1)",
      approved_by: "approver@rampscan.local (pb:u2)",
      dataset_version: "2026.07.14.01",
      timestamp: opts.timestamp,
    },
  };
  return { digest: `digest-${counter++}`, bundle, appendedAt: opts.timestamp };
}

// Q3.2 — G3 freshness: every method judged against its own clock family's
// owed window (machine → VDR-TFR-MVX, non-machine → VDR-TFR-NMV), handed to
// the fold as data. Missing evidence judges false — a method nothing
// re-validates is G3 exactly as a stale one is; null is reserved for "no
// window owed" (class d machine) and a live two-key scoping.
describe("G3 freshness (Q3.2)", () => {
  // T2 (the fold instant) is 2026-08-08; seven days before it is T1 exactly —
  // evidence at T1 is on the boundary and inside; STALE is not.
  const MVX7: ClockWindow = { num: 7, unit: "days" };
  const NMV3: ClockWindow = { num: 3, unit: "months" };
  const STALE = "2026-07-25T00:00:00.000Z";

  const attestation: ValidationMethod = {
    id: "attestation:incident-review#KSI-CNA-CIC",
    ksi: "KSI-CNA-CIC",
    automated: false,
    clock: "non-machine",
    standing: "narrative",
    source: "attestation",
    provenance: { attestor_role: "ciso", statement_ref: "st-1" },
  };

  it("evidence inside the window: freshMet true, window echoed on the cell, no G3", () => {
    const projection = foldWith([evidenceEntry({ recipe: "covered", timestamp: T1 })], 1, null, {
      machineWindow: MVX7,
      nonMachineWindow: NMV3,
    });
    const row = projection.methodRegisters.find((r) => r.ksi === "KSI-SCR-MIT")!;
    const cell = row.methods.find((m) => m.recipeId === "covered")!;
    expect(cell.clock).toBe("machine");
    expect(cell.window).toEqual(MVX7);
    expect(cell.freshMet).toBe(true);
    // the sibling method (two-ksis) was never scanned — missing is false
    expect(row.methods.find((m) => m.recipeId === "two-ksis")!.freshMet).toBe(false);
    expect(row.staleMethods).toBe(1);
    expect(row.gap).toBe("G3");
  });

  it("stale evidence: freshMet false, G3 on the row", () => {
    const projection = foldWith(
      [evidenceEntry({ recipe: "covered", timestamp: STALE })],
      null,
      null,
      { machineWindow: MVX7 },
    );
    const row = projection.methodRegisters.find((r) => r.ksi === "KSI-SCR-MIT")!;
    expect(row.methods.find((m) => m.recipeId === "covered")!.freshMet).toBe(false);
    expect(row.staleMethods).toBe(2); // stale + the never-scanned sibling
    expect(row.gap).toBe("G3");
  });

  it("no machine window (class d — the rules define none): freshMet null, never a borrowed judgment", () => {
    const projection = foldWith([evidenceEntry({ recipe: "covered", timestamp: STALE })], null, null, {
      machineWindow: null,
      nonMachineWindow: NMV3,
    });
    const row = projection.methodRegisters.find((r) => r.ksi === "KSI-SCR-MIT")!;
    for (const cell of row.methods) {
      expect(cell.window).toBeNull();
      expect(cell.freshMet).toBeNull();
    }
    expect(row.staleMethods).toBe(0);
    expect(row.gap).toBeUndefined();
  });

  it("a fold given no windows judges nothing — Q2 folds are unchanged", () => {
    const projection = foldWith([evidenceEntry({ recipe: "covered", timestamp: STALE })], 1);
    const row = projection.methodRegisters.find((r) => r.ksi === "KSI-SCR-MIT")!;
    for (const cell of row.methods) expect(cell.freshMet).toBeNull();
    expect(row.staleMethods).toBe(0);
  });

  it("a non-machine method runs on the NMV clock: no evidence yet (Q4) judges false", () => {
    const projection = foldWith([evidenceEntry({ recipe: "covered", timestamp: T1 })], null, null, {
      machineWindow: MVX7,
      nonMachineWindow: NMV3,
      methods: [...methods, attestation],
    });
    const row = projection.methodRegisters.find((r) => r.ksi === "KSI-CNA-CIC")!;
    const cell = row.methods.find((m) => m.methodId === attestation.id)!;
    expect(cell.clock).toBe("non-machine");
    expect(cell.window).toEqual(NMV3);
    expect(cell.freshMet).toBe(false);
    expect(row.gap).toBe("G3");
  });

  it("a live two-key scoping is not a lapsed clock: the scoped cell judges null", () => {
    const projection = foldWith(
      [
        evidenceEntry({ recipe: "two-ksis", timestamp: T1, ksiIds: twoKsis.ksi_ids }),
        scopingEntry({ recipe: "covered", timestamp: T1 }),
      ],
      null,
      null,
      { machineWindow: MVX7 },
    );
    const row = projection.methodRegisters.find((r) => r.ksi === "KSI-SCR-MIT")!;
    const scoped = row.methods.find((m) => m.recipeId === "covered")!;
    expect(scoped.state).toBe("notApplicable");
    expect(scoped.freshMet).toBeNull();
    expect(row.staleMethods).toBe(0);
    expect(row.gap).toBeUndefined();
  });

  it("the worst gap outranks: G1 and G2 beat G3; G3 beats G4", () => {
    const stale = [evidenceEntry({ recipe: "covered", timestamp: STALE })];
    // below the method floor AND stale → G2
    expect(
      foldWith(stale, 3, 6, { machineWindow: MVX7 }).methodRegisters.find(
        (r) => r.ksi === "KSI-SCR-MIT",
      )!.gap,
    ).toBe("G2");
    // floor met, stale, history short → G3, not G4
    expect(
      foldWith(stale, 1, 6, { machineWindow: MVX7 }).methodRegisters.find(
        (r) => r.ksi === "KSI-SCR-MIT",
      )!.gap,
    ).toBe("G3");
    // no methods at all stays G1
    expect(
      foldWith(stale, 1, 6, { machineWindow: MVX7 }).methodRegisters.find(
        (r) => r.ksi === "KSI-CNA-CIC",
      )!.gap,
    ).toBe("G1");
  });

  it("the catalog's richer window object is stripped to number + unit in the projection", () => {
    const projection = foldWith([evidenceEntry({ recipe: "covered", timestamp: T1 })], null, null, {
      machineWindow: {
        num: 7,
        unit: "days",
        requirementId: "VDR-TFR-MVX",
        force: "MUST",
      } as ClockWindow,
    });
    const cell = projection.methodRegisters
      .find((r) => r.ksi === "KSI-SCR-MIT")!
      .methods.find((m) => m.recipeId === "covered")!;
    expect(cell.window).toEqual({ num: 7, unit: "days" });
  });

  it("survives the sqlite round trip, windows and judgments included", async () => {
    const projection = foldWith([evidenceEntry({ recipe: "covered", timestamp: STALE })], 1, 6, {
      machineWindow: MVX7,
      nonMachineWindow: NMV3,
      methods: [...methods, attestation],
    });
    const dir = await mkdtemp(join(tmpdir(), "rampscan-g3-"));
    const dbPath = join(dir, "projection.db");
    await writeProjectionSqlite(projection, dbPath);
    expect(readProjectionSqlite(dbPath)).toEqual(projection);
  });
});

describe("windowThreshold — days exact, months calendar", () => {
  it("days are exact ms arithmetic", () => {
    expect(windowThreshold("2026-08-08T00:00:00.000Z", { num: 7, unit: "days" })).toBe(
      "2026-08-01T00:00:00.000Z",
    );
    expect(windowThreshold("2026-08-08T12:30:00.000Z", { num: 3, unit: "days" })).toBe(
      "2026-08-05T12:30:00.000Z",
    );
  });

  it("months go through monthsBefore — calendar months, day clamped", () => {
    expect(windowThreshold("2026-08-08T00:00:00.000Z", { num: 3, unit: "months" })).toBe(
      "2026-05-08T00:00:00.000Z",
    );
    expect(windowThreshold("2026-05-31T00:00:00.000Z", { num: 3, unit: "months" })).toBe(
      "2026-02-28T00:00:00.000Z",
    );
  });
});

describe("monthsBefore — calendar months, day clamped", () => {
  it("subtracts calendar months", () => {
    expect(monthsBefore("2026-08-08T12:00:00.000Z", 6)).toBe("2026-02-08T12:00:00.000Z");
    expect(monthsBefore("2026-08-08T12:00:00.000Z", 18)).toBe("2025-02-08T12:00:00.000Z");
  });

  it("clamps the day instead of rolling into the adjacent month", () => {
    expect(monthsBefore("2026-03-31T00:00:00.000Z", 1)).toBe("2026-02-28T00:00:00.000Z");
    expect(monthsBefore("2024-03-31T00:00:00.000Z", 1)).toBe("2024-02-29T00:00:00.000Z"); // leap
    expect(monthsBefore("2026-07-31T00:00:00.000Z", 1)).toBe("2026-06-30T00:00:00.000Z");
  });

  it("crosses year boundaries", () => {
    expect(monthsBefore("2026-01-15T00:00:00.000Z", 6)).toBe("2025-07-15T00:00:00.000Z");
  });
});

// Q3.1 — G4 history (FRC-CSX-MOT): persistent-validation history per KSI,
// counted from the ledger's chains against the class's months floor. The
// data was always there; these tests pin the counting — and the honesty:
// a young ledger states a young number, never a met floor it cannot back.
describe("G4 history (Q3.1)", () => {
  // T2 (the fold instant) is 2026-08-08; six calendar months before it is
  // 2026-02-08 — OLD reaches past that, T1 (2026-08-01) does not.
  const OLD = "2026-01-01T00:00:00.000Z";

  it("a young ledger shows a young number: history since first evidence, floor unmet, G4", () => {
    const projection = foldWith([evidenceEntry({ recipe: "covered", timestamp: T1 })], 1, 6);
    const row = projection.methodRegisters.find((r) => r.ksi === "KSI-SCR-MIT")!;
    expect(row.historySince).toBe(T1);
    expect(row.historyFloorMonths).toBe(6);
    expect(row.historyMet).toBe(false);
    expect(row.gap).toBe("G4"); // method floor met, history floor not
  });

  it("history reaching past the floor meets it — dead bundles included, they ARE the history", () => {
    const projection = foldWith(
      [
        evidenceEntry({ recipe: "covered", timestamp: OLD }), // superseded below
        evidenceEntry({ recipe: "covered", timestamp: T1 }),
      ],
      1,
      6,
    );
    const row = projection.methodRegisters.find((r) => r.ksi === "KSI-SCR-MIT")!;
    expect(row.historySince).toBe(OLD);
    expect(row.historyMet).toBe(true);
    expect(row.gap).toBeUndefined();
  });

  it("history spans the KSI's methods: any method's chain extends it", () => {
    const projection = foldWith(
      [
        evidenceEntry({ recipe: "two-ksis", timestamp: OLD, ksiIds: twoKsis.ksi_ids }),
        evidenceEntry({ recipe: "covered", timestamp: T1 }),
      ],
      1,
      6,
    );
    const row = projection.methodRegisters.find((r) => r.ksi === "KSI-SCR-MIT")!;
    expect(row.historySince).toBe(OLD);
    expect(row.historyMet).toBe(true);
  });

  it("the worst gap outranks G4: below the method floor stays G2, no methods stays G1", () => {
    const projection = foldWith([evidenceEntry({ recipe: "covered", timestamp: T1 })], 3, 6);
    expect(projection.methodRegisters.find((r) => r.ksi === "KSI-SCR-MIT")!.gap).toBe("G2");
    expect(projection.methodRegisters.find((r) => r.ksi === "KSI-CNA-CIC")!.gap).toBe("G1");
  });

  it("a null history floor (a and b: unquantified) checks nothing: historyMet null, no G4", () => {
    const projection = foldWith([evidenceEntry({ recipe: "covered", timestamp: T1 })], 1, null);
    const row = projection.methodRegisters.find((r) => r.ksi === "KSI-SCR-MIT")!;
    expect(row.historySince).toBe(T1); // the fact is still stated
    expect(row.historyFloorMonths).toBeNull();
    expect(row.historyMet).toBeNull();
    expect(row.gap).toBeUndefined();
  });

  it("a fold given no history floor behaves as null — nothing to check against", () => {
    const projection = foldWith([evidenceEntry({ recipe: "covered", timestamp: T1 })], 1);
    const row = projection.methodRegisters.find((r) => r.ksi === "KSI-SCR-MIT")!;
    expect(row.historyFloorMonths).toBeNull();
    expect(row.historyMet).toBeNull();
  });

  it("survives the sqlite round trip, history fields and nulls included", async () => {
    const projection = foldWith(
      [
        evidenceEntry({ recipe: "covered", timestamp: OLD }),
        evidenceEntry({ recipe: "covered", timestamp: T1 }),
      ],
      1,
      6,
    );
    const dir = await mkdtemp(join(tmpdir(), "rampscan-g4-"));
    const dbPath = join(dir, "projection.db");
    await writeProjectionSqlite(projection, dbPath);
    expect(readProjectionSqlite(dbPath)).toEqual(projection);
  });
});
