import { createHash } from "node:crypto";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import type { ClockWindow, LedgerEntry } from "@rampscan/core";
import type {
  Artifact,
  ArtifactJudgment,
  ArtifactSlot,
  ArtifactSource,
  Attestation,
  EvidenceBundle,
  JudgedArtifact,
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
  /** the Q3.4 assertion; omitted = a pre-Q3.4 bundle that asserted nothing */
  evidenceClass?: "process-generated" | "point-in-time";
}): LedgerEntry {
  const bundle: EvidenceBundle = {
    _type: "https://in-toto.io/Statement/v1",
    subject: [{ name: "x", digest: { sha256: "e".repeat(64) } }],
    predicateType: "https://rampscan.dev/evidence/v1",
    predicate: {
      recipe_id: opts.recipe,
      ...(opts.evidenceClass !== undefined ? { evidence_class: opts.evidenceClass } : {}),
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
    expect(scr.gap).toBe("G5"); // no G2 — the unjudged artifacts are the worst remaining gap (Q3.3)

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
    expect(row.gap).toBe("G5"); // no G2 — the unjudged artifacts remain (Q3.3)
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
    expect(row.gap).toBe("G5"); // no G3 — the unjudged artifacts remain (Q3.3)
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
    expect(row.gap).toBe("G5"); // no G3 — the unjudged artifacts remain (Q3.3)
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

  // the 7-day machine window every history test below judges against
  const W7: ClockWindow = { num: 7, unit: "days" };
  // one instant every 7 days from OLD (day 0) to day 217 — the fold at T2 is
  // day 219, inside the last tick's window, so the status never lapsed
  const weekly = (recipe: string, ksiIds?: string[]) =>
    Array.from({ length: 32 }, (_, i) =>
      evidenceEntry({
        recipe,
        timestamp: new Date(Date.parse(OLD) + i * 7 * 86_400_000).toISOString(),
        ...(ksiIds !== undefined ? { ksiIds } : {}),
      }),
    );

  it("history reaching past the floor, refreshed on the clock, meets it — dead bundles included, they ARE the history", () => {
    const projection = foldWith(weekly("covered"), 1, 6, { machineWindow: W7 });
    const row = projection.methodRegisters.find((r) => r.ksi === "KSI-SCR-MIT")!;
    expect(row.historySince).toBe(OLD);
    expect(row.historyMet).toBe(true);
    expect(row.historyLapseAt).toBeUndefined();
    expect(row.gap).toBe("G3"); // not G4 — `two-ksis` never ran, and its stale cell outranks
  });

  it("history spans the KSI's methods: any method's chain extends it, and together they keep the status known", () => {
    // `two-ksis` carried the status for the first half, `covered` for the second
    const first = weekly("two-ksis", twoKsis.ksi_ids).slice(0, 16);
    const second = weekly("covered").slice(15);
    const projection = foldWith([...first, ...second], 1, 6, { machineWindow: W7 });
    const row = projection.methodRegisters.find((r) => r.ksi === "KSI-SCR-MIT")!;
    expect(row.historySince).toBe(OLD);
    expect(row.historyMet).toBe(true);
  });

  // #159 — the meter measured reach-back alone, and reach-back is satisfied
  // by one old bundle. FRC-CSX-MOT wants "status from persistent validation
  // over at least the past N months", and `Persistently` (FRD-PER) says the
  // status of a persistent activity "will always be known": history is the
  // sequence of instants on the owed clock, not the age of the oldest one.
  it("one stale capture is not six months of persistent validation (#159): the status lapsed", () => {
    // a single bundle, seven months before the fold, on a 7-day machine window
    const projection = foldWith([evidenceEntry({ recipe: "covered", timestamp: OLD })], 1, 6, {
      machineWindow: W7,
    });
    const row = projection.methodRegisters.find((r) => r.ksi === "KSI-SCR-MIT")!;
    expect(row.historySince).toBe(OLD); // the reach-back is still a fact
    expect(row.historyMet).toBe(false); // but the status was known for seven days of the six months
    expect(row.historyLapseAt).toBe("2026-01-08T00:00:00.000Z"); // OLD + 7 days
    expect(row.gap).toBe("G3"); // stale evidence outranks G4; the history verdict stands beside it
  });

  it("a lapse in the middle of the span is a lapse: the first expiry that went unrefreshed is named", () => {
    // both of the KSI's recipes run weekly, both skip tick 10
    const entries = [...weekly("covered"), ...weekly("two-ksis", twoKsis.ksi_ids)].filter(
      (e) => e.bundle.predicate.timestamp !== new Date(Date.parse(OLD) + 70 * 86_400_000).toISOString(),
    );
    const projection = foldWith(entries, 1, 6, { machineWindow: W7 });
    const row = projection.methodRegisters.find((r) => r.ksi === "KSI-SCR-MIT")!;
    expect(row.historyMet).toBe(false);
    // tick 9 at OLD + 63d expired at OLD + 70d; tick 11 landed at OLD + 77d
    expect(row.historyLapseAt).toBe(new Date(Date.parse(OLD) + 70 * 86_400_000).toISOString());
    expect(row.gap).toBe("G4"); // fresh at the fold, floor met — history is the worst gap
  });

  it("the tail counts: history that stopped before the fold instant lapsed, however long it ran", () => {
    const entries = weekly("covered").slice(0, 28); // last tick OLD + 189d, fold at OLD + 219d
    const projection = foldWith(entries, 1, 6, { machineWindow: W7 });
    const row = projection.methodRegisters.find((r) => r.ksi === "KSI-SCR-MIT")!;
    expect(row.historyMet).toBe(false);
    expect(row.historyLapseAt).toBe(new Date(Date.parse(OLD) + 196 * 86_400_000).toISOString());
  });

  it("instants before the span are not walked: a lapse older than the floor does not count against it", () => {
    // a lone capture a year before, then the clean weekly run — the status
    // standing when the six-month span opens is the weekly run's
    const entries = [
      evidenceEntry({ recipe: "covered", timestamp: "2025-01-01T00:00:00.000Z" }),
      ...weekly("covered"),
    ];
    const projection = foldWith(entries, 1, 6, { machineWindow: W7 });
    const row = projection.methodRegisters.find((r) => r.ksi === "KSI-SCR-MIT")!;
    expect(row.historySince).toBe("2025-01-01T00:00:00.000Z");
    expect(row.historyMet).toBe(true);
  });

  it("no owed window on the clock (class d's machine clock): reach-back holds, persistence is unjudged — null, never met", () => {
    const projection = foldWith(weekly("covered"), 1, 6, { machineWindow: null });
    const row = projection.methodRegisters.find((r) => r.ksi === "KSI-SCR-MIT")!;
    expect(row.historySince).toBe(OLD);
    expect(row.historyMet).toBeNull();
    expect(row.historyLapseAt).toBeUndefined();
    expect(row.gap).toBe("G5"); // not G4: unjudged is not unmet
  });

  it("no owed window, and history that never reached back at all: false, not null", () => {
    const projection = foldWith([evidenceEntry({ recipe: "covered", timestamp: T1 })], 1, 6, {
      machineWindow: null,
    });
    const row = projection.methodRegisters.find((r) => r.ksi === "KSI-SCR-MIT")!;
    expect(row.historyMet).toBe(false);
    expect(row.gap).toBe("G4");
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
    expect(row.gap).toBe("G5"); // no G4 — the unjudged artifacts remain (Q3.3)
  });

  it("a fold given no history floor behaves as null — nothing to check against", () => {
    const projection = foldWith([evidenceEntry({ recipe: "covered", timestamp: T1 })], 1);
    const row = projection.methodRegisters.find((r) => r.ksi === "KSI-SCR-MIT")!;
    expect(row.historyFloorMonths).toBeNull();
    expect(row.historyMet).toBeNull();
  });

  it("survives the sqlite round trip, history fields, the lapse instant and nulls included", async () => {
    const projection = foldWith(
      [
        evidenceEntry({ recipe: "covered", timestamp: OLD }),
        evidenceEntry({ recipe: "covered", timestamp: T1 }),
      ],
      1,
      6,
      { machineWindow: W7 },
    );
    expect(projection.methodRegisters.some((r) => r.historyLapseAt !== undefined)).toBe(true);
    const dir = await mkdtemp(join(tmpdir(), "rampscan-g4-"));
    const dbPath = join(dir, "projection.db");
    await writeProjectionSqlite(projection, dbPath);
    expect(readProjectionSqlite(dbPath)).toEqual(projection);
  });
});

function judgmentEntry(opts: {
  ksi: string;
  artifact: JudgedArtifact;
  action?: "sufficient" | "insufficient";
  timestamp: string;
  repo?: string;
  /** the body these two keys approved (§13.6) — omitted = a pre-R1.1 judgment */
  judgedBody?: string;
}): LedgerEntry {
  const judgedDigest =
    opts.judgedBody === undefined
      ? undefined
      : createHash("sha256").update(opts.judgedBody, "utf8").digest("hex");
  const bundle: ArtifactJudgment = {
    _type: "https://in-toto.io/Statement/v1",
    subject: [
      { name: "justification.txt", digest: { sha256: "b".repeat(64) } },
      ...(judgedDigest !== undefined
        ? [{ name: "artifact.md", digest: { sha256: judgedDigest } }]
        : []),
    ],
    predicateType: "https://rampscan.dev/artifact-judgment/v1",
    predicate: {
      action: opts.action ?? "sufficient",
      ksi_id: opts.ksi,
      artifact: opts.artifact,
      repo: opts.repo ?? "fixtures/app",
      ...(judgedDigest !== undefined ? { body_digest: judgedDigest } : {}),
      justification: "reviewed against the pinned statement",
      proposed_by: "viewer@rampscan.local (pb:u1)",
      approved_by: "approver@rampscan.local (pb:u2)",
      dataset_version: "2026.07.14.01",
      timestamp: opts.timestamp,
    },
  };
  return { digest: `digest-${counter++}`, bundle, appendedAt: opts.timestamp };
}

/** an artifact body filling a slot (R1.1, SPEC §13.2) — the plane's own object */
function artifactEntry(opts: {
  ksi: string;
  artifact: ArtifactSlot;
  timestamp: string;
  source?: ArtifactSource;
  body?: string;
  repo?: string;
  validFrom?: string;
  anchor?: { commit: string; path: string };
}): LedgerEntry {
  const source = opts.source ?? "authored";
  const body = opts.body ?? `## ${opts.ksi} artifact ${opts.artifact}\n\nthe measures, summarised.`;
  const bundle: Artifact = {
    _type: "https://in-toto.io/Statement/v1",
    subject: [
      { name: "artifact.md", digest: { sha256: createHash("sha256").update(body, "utf8").digest("hex") } },
    ],
    predicateType: "https://rampscan.dev/artifact/v1",
    predicate: {
      ksi_id: opts.ksi,
      artifact: opts.artifact,
      repo: opts.repo ?? "fixtures/app",
      source,
      body,
      body_digest: createHash("sha256").update(body, "utf8").digest("hex"),
      ...(source === "authored"
        ? { anchor: opts.anchor ?? { commit: "1".repeat(40), path: `docs/ksi/${opts.ksi}-${opts.artifact}.md` } }
        : {}),
      ...(source === "computed"
        ? { generator: { pins: { dataset: "2026.07.14.01" }, tool_versions: {} } }
        : {}),
      valid_from: opts.validFrom ?? opts.timestamp,
      dataset_version: "2026.07.14.01",
      timestamp: opts.timestamp,
    },
  };
  return { digest: `digest-${counter++}`, bundle, appendedAt: opts.timestamp };
}

/** the five bodies that clear G5, so a chain can reach the arms below it */
function filled(ksi: string, timestamp: string): LedgerEntry[] {
  return ([1, 2, 3, 4, 5] as ArtifactSlot[]).map((n) =>
    artifactEntry({ ksi, artifact: n, timestamp }),
  );
}

// Q3.3 + R1.1 — G5 artifacts (default_artifacts.KSI): five cells per
// (repo, KSI), ascending, and PRESENCE IS A BODY. A slot is present when a
// signed `Artifact` fills it and no live judgment calls those bytes
// insufficient. What the fold can DERIVE for artifacts 2 and 5 is carried as
// `derivable` — a work queue, never a substitute for the bytes — and the
// two-key judgment on 1, 3 and 4 now judges bytes that exist (§13.6).
describe("G5 artifacts (Q3.3, R1.1)", () => {
  it("five cells always, and an evidenced KSI with no bodies holds none of them", () => {
    const projection = foldWith([evidenceEntry({ recipe: "covered", timestamp: T1 })], 1);
    const row = projection.methodRegisters.find((r) => r.ksi === "KSI-SCR-MIT")!;
    expect(row.artifacts.map((a) => a.artifact)).toEqual([1, 2, 3, 4, 5]);
    expect(row.artifacts.map((a) => a.basis)).toEqual([
      "judged",
      "computed",
      "judged",
      "judged",
      "computed",
    ]);
    // Evidence is the MATERIAL for artifacts 2 and 5, not the artifacts: the
    // test recipe declares cadence "weekly", so the scheduler's cycle record
    // (2) and the register itself (5) are derivable — and nobody has minted
    // either body, so the row holds nothing and says so.
    expect(row.artifacts.map((a) => a.present)).toEqual([false, false, false, false, false]);
    expect(row.artifacts.map((a) => a.derivable)).toEqual([
      undefined,
      true,
      undefined,
      undefined,
      true,
    ]);
    expect(row.artifactsPresent).toBe(0);
    expect(row.gap).toBe("G5");
  });

  it("methods without evidence are not even derivable — never green because empty", () => {
    const projection = foldWith([evidenceEntry({ recipe: "covered", timestamp: T1 })], 1);
    const row = projection.methodRegisters.find((r) => r.ksi === "KSI-CMT-CHG")!;
    expect(row.methods.length).toBeGreaterThan(0); // two-ksis + never-scanned derive here
    expect(row.artifacts.find((a) => a.artifact === 2)!.derivable).toBe(false);
    expect(row.artifacts.find((a) => a.artifact === 5)!.derivable).toBe(false);
    expect(row.artifactsPresent).toBe(0);
  });

  it("a body fills its slot, carrying its source, its clock and its anchor", () => {
    const projection = foldWith(
      [
        evidenceEntry({ recipe: "covered", timestamp: T1 }),
        artifactEntry({ ksi: "KSI-SCR-MIT", artifact: 1, timestamp: T1 }),
      ],
      1,
    );
    const cell = projection.methodRegisters
      .find((r) => r.ksi === "KSI-SCR-MIT")!
      .artifacts.find((a) => a.artifact === 1)!;
    expect(cell.present).toBe(true);
    expect(cell.body?.source).toBe("authored");
    expect(cell.body?.anchor?.path).toBe("docs/ksi/KSI-SCR-MIT-1.md");
    expect(cell.body?.bodyDigest).toHaveLength(64);
    expect(cell.body?.bodyBytes).toBeGreaterThan(0);
    expect(cell.body?.validFrom).toBe(T1);
    expect(cell.body?.freshMet).toBeNull(); // no non-machine window given
    expect(cell.body?.reviewed).toBeUndefined(); // nobody asked the forge (R4)
  });

  it("a body that a computed slot holds stops being derivable — the bytes replace the queue", () => {
    const projection = foldWith(
      [
        evidenceEntry({ recipe: "covered", timestamp: T1 }),
        artifactEntry({ ksi: "KSI-SCR-MIT", artifact: 5, source: "computed", timestamp: T1 }),
      ],
      1,
    );
    const cell = projection.methodRegisters
      .find((r) => r.ksi === "KSI-SCR-MIT")!
      .artifacts.find((a) => a.artifact === 5)!;
    expect(cell.present).toBe(true);
    expect(cell.derivable).toBeUndefined();
    expect(cell.body?.source).toBe("computed");
  });

  it("all five bodies clear G5", () => {
    const projection = foldWith(
      [evidenceEntry({ recipe: "covered", timestamp: T1 }), ...filled("KSI-SCR-MIT", T1)],
      1,
    );
    const row = projection.methodRegisters.find((r) => r.ksi === "KSI-SCR-MIT")!;
    expect(row.artifacts.every((a) => a.present)).toBe(true);
    expect(row.artifactsPresent).toBe(5);
    expect(row.gap).toBeUndefined();
  });

  it("a judgment without a body presents nothing — the checklist no longer approves the unwritten", () => {
    const projection = foldWith(
      [
        evidenceEntry({ recipe: "covered", timestamp: T1 }),
        judgmentEntry({ ksi: "KSI-SCR-MIT", artifact: 1, timestamp: T1 }),
        judgmentEntry({ ksi: "KSI-SCR-MIT", artifact: 3, timestamp: T1 }),
        judgmentEntry({ ksi: "KSI-SCR-MIT", artifact: 4, timestamp: T1 }),
      ],
      1,
    );
    const row = projection.methodRegisters.find((r) => r.ksi === "KSI-SCR-MIT")!;
    expect(row.artifactsPresent).toBe(0);
    expect(row.gap).toBe("G5");
    // the decision is still a fact the board states — it simply no longer
    // stands in for the prose it was a decision ABOUT
    const judged = row.artifacts.find((a) => a.artifact === 4)!;
    expect(judged.judgment?.action).toBe("sufficient");
    expect(judged.judgment?.approvedBy).toBe("approver@rampscan.local (pb:u2)");
    expect(judged.judgment?.digest).toBeDefined();
  });

  it("the latest body wins: a supersession replaces the bytes, never edits them", () => {
    const projection = foldWith(
      [
        evidenceEntry({ recipe: "covered", timestamp: T1 }),
        artifactEntry({ ksi: "KSI-SCR-MIT", artifact: 1, body: "first", timestamp: T1 }),
        artifactEntry({ ksi: "KSI-SCR-MIT", artifact: 1, body: "revised", timestamp: T2 }),
      ],
      1,
    );
    const cell = projection.methodRegisters
      .find((r) => r.ksi === "KSI-SCR-MIT")!
      .artifacts.find((a) => a.artifact === 1)!;
    expect(cell.body?.bodyDigest).toBe(
      createHash("sha256").update("revised", "utf8").digest("hex"),
    );
    expect(cell.body?.validFrom).toBe(T2);
  });

  it("the artifact clock is VDR-TFR-NMV, judged against the non-machine window", () => {
    const stale = foldWith(
      [
        evidenceEntry({ recipe: "covered", timestamp: T1 }),
        artifactEntry({ ksi: "KSI-SCR-MIT", artifact: 1, timestamp: T1, validFrom: "2026-01-01T00:00:00.000Z" }),
        artifactEntry({ ksi: "KSI-SCR-MIT", artifact: 3, timestamp: T1 }),
      ],
      1,
      undefined,
      { nonMachineWindow: { num: 3, unit: "months" } },
    );
    const row = stale.methodRegisters.find((r) => r.ksi === "KSI-SCR-MIT")!;
    // an aged artifact still EXISTS — the clock is a second question, and the
    // presence meter is not allowed to answer it
    expect(row.artifacts.find((a) => a.artifact === 1)!.body?.freshMet).toBe(false);
    expect(row.artifacts.find((a) => a.artifact === 1)!.present).toBe(true);
    expect(row.artifacts.find((a) => a.artifact === 3)!.body?.freshMet).toBe(true);
  });

  it("a signed insufficient withdraws a body's presence, and the record still shows both", () => {
    const body = "the measures, as written";
    const projection = foldWith(
      [
        evidenceEntry({ recipe: "covered", timestamp: T1 }),
        artifactEntry({ ksi: "KSI-SCR-MIT", artifact: 4, body, timestamp: T1 }),
        judgmentEntry({ ksi: "KSI-SCR-MIT", artifact: 4, judgedBody: body, timestamp: T1 }),
        judgmentEntry({
          ksi: "KSI-SCR-MIT",
          artifact: 4,
          action: "insufficient",
          judgedBody: body,
          timestamp: T2,
        }),
      ],
      1,
    );
    const cell = projection.methodRegisters
      .find((r) => r.ksi === "KSI-SCR-MIT")!
      .artifacts.find((a) => a.artifact === 4)!;
    expect(cell.present).toBe(false);
    expect(cell.judgment?.action).toBe("insufficient"); // a recorded withdrawal, not an absence
    expect(cell.judgment?.appliesToLiveBody).toBe(true);
    expect(cell.body).toBeDefined(); // the bytes it judged are still there to read
  });

  it("a judgment does not reach bytes it never read — a revision is unjudged until judged again", () => {
    const first = "the measures, as first written";
    const projection = foldWith(
      [
        evidenceEntry({ recipe: "covered", timestamp: T1 }),
        artifactEntry({ ksi: "KSI-SCR-MIT", artifact: 4, body: first, timestamp: T1 }),
        judgmentEntry({
          ksi: "KSI-SCR-MIT",
          artifact: 4,
          action: "insufficient",
          judgedBody: first,
          timestamp: T1,
        }),
        artifactEntry({ ksi: "KSI-SCR-MIT", artifact: 4, body: "rewritten after review", timestamp: T2 }),
      ],
      1,
    );
    const cell = projection.methodRegisters
      .find((r) => r.ksi === "KSI-SCR-MIT")!
      .artifacts.find((a) => a.artifact === 4)!;
    // the withdrawal stands in the record and is printed — it simply decides
    // nothing about prose it never read
    expect(cell.judgment?.action).toBe("insufficient");
    expect(cell.judgment?.appliesToLiveBody).toBe(false);
    expect(cell.present).toBe(true);
  });

  it("a pre-R1.1 judgment names no bytes, so it applies to none", () => {
    const projection = foldWith(
      [
        evidenceEntry({ recipe: "covered", timestamp: T1 }),
        artifactEntry({ ksi: "KSI-SCR-MIT", artifact: 4, timestamp: T1 }),
        judgmentEntry({ ksi: "KSI-SCR-MIT", artifact: 4, timestamp: T1 }),
      ],
      1,
    );
    const cell = projection.methodRegisters
      .find((r) => r.ksi === "KSI-SCR-MIT")!
      .artifacts.find((a) => a.artifact === 4)!;
    expect(cell.judgment?.bodyDigest).toBeUndefined();
    expect(cell.judgment?.appliesToLiveBody).toBe(false);
  });

  it("a body lands per (KSI, artifact): the same index on another KSI stays absent", () => {
    const projection = foldWith(
      [
        evidenceEntry({ recipe: "covered", timestamp: T1 }),
        artifactEntry({ ksi: "KSI-SCR-MIT", artifact: 1, timestamp: T1 }),
      ],
      1,
    );
    const other = projection.methodRegisters.find((r) => r.ksi === "KSI-CMT-CHG")!;
    expect(other.artifacts.find((a) => a.artifact === 1)!.present).toBe(false);
  });

  it("a body can stand on a zero-method KSI — G1 still outranks G5", () => {
    // artifact 1's own text allows "an explanation of the reason ... for not
    // having measures", so the body is meaningful where nothing derives
    const projection = foldWith(
      [
        evidenceEntry({ recipe: "covered", timestamp: T1 }),
        artifactEntry({ ksi: "KSI-CNA-CIC", artifact: 1, timestamp: T1 }),
      ],
      1,
    );
    const row = projection.methodRegisters.find((r) => r.ksi === "KSI-CNA-CIC")!;
    expect(row.artifacts.find((a) => a.artifact === 1)!.present).toBe(true);
    expect(row.gap).toBe("G1");
  });

  it("the worst gap outranks G5: an unmet history floor stays G4", () => {
    const projection = foldWith(
      [evidenceEntry({ recipe: "covered", timestamp: T1 })],
      1,
      6, // T1 is ~1 week before the fold instant — history floor unmet
    );
    expect(projection.methodRegisters.find((r) => r.ksi === "KSI-SCR-MIT")!.gap).toBe("G4");
  });

  it("a judgment-only ledger introduces its repo — the signed decision is never invisible", () => {
    const projection = foldWith(
      [judgmentEntry({ ksi: "KSI-SCR-MIT", artifact: 1, timestamp: T1, repo: "fixtures/other" })],
      1,
    );
    const row = projection.methodRegisters.find(
      (r) => r.repo === "fixtures/other" && r.ksi === "KSI-SCR-MIT",
    )!;
    expect(row).toBeDefined();
    // the decision is visible; what it decided about is not there to present
    expect(row.artifacts.find((a) => a.artifact === 1)!.judgment?.action).toBe("sufficient");
    expect(row.artifacts.find((a) => a.artifact === 1)!.present).toBe(false);
  });

  it("an artifact-only ledger introduces its repo — a body is never invisible either", () => {
    const projection = foldWith(
      [artifactEntry({ ksi: "KSI-SCR-MIT", artifact: 1, timestamp: T1, repo: "fixtures/other" })],
      1,
    );
    const row = projection.methodRegisters.find(
      (r) => r.repo === "fixtures/other" && r.ksi === "KSI-SCR-MIT",
    )!;
    expect(row).toBeDefined();
    expect(row.artifacts.find((a) => a.artifact === 1)!.present).toBe(true);
  });

  it("survives the sqlite round trip, bodies and judgments included", async () => {
    const projection = foldWith(
      [
        evidenceEntry({ recipe: "covered", timestamp: T1 }),
        artifactEntry({ ksi: "KSI-SCR-MIT", artifact: 1, timestamp: T1 }),
        artifactEntry({ ksi: "KSI-SCR-MIT", artifact: 4, source: "attested", timestamp: T1 }),
        judgmentEntry({ ksi: "KSI-SCR-MIT", artifact: 1, timestamp: T1 }),
        judgmentEntry({ ksi: "KSI-SCR-MIT", artifact: 4, action: "insufficient", timestamp: T2 }),
      ],
      1,
    );
    const dir = await mkdtemp(join(tmpdir(), "rampscan-g5-"));
    const dbPath = join(dir, "projection.db");
    await writeProjectionSqlite(projection, dbPath);
    expect(readProjectionSqlite(dbPath)).toEqual(projection);
  });
});

// Q3.4 — G6 evidence class (FRR-PVA-AA-06): every bundle asserts
// process-generated vs point-in-time at ingestion, and the fold lifts the
// SIGNED assertion onto the cell — never a convention. The gap is
// standing-alone: point-in-time evidence with nothing process-generated
// beside it, because that is exactly what the rule tells assessors to
// reject. Unlabeled (pre-Q3.4) evidence neither triggers nor defends.
describe("G6 evidence class (Q3.4)", () => {
  /** the five bodies that clear G5, so the chain can reach the G6 arm */
  const judged = (ksi: string) => filled(ksi, T1);

  it("lifts the signed assertion onto the cell; a pre-Q3.4 bundle leaves it absent", () => {
    const projection = foldWith(
      [
        evidenceEntry({ recipe: "covered", timestamp: T1, evidenceClass: "process-generated" }),
        evidenceEntry({ recipe: "never-scanned", timestamp: T1, ksiIds: ["KSI-CMT-CHG"] }),
      ],
      1,
    );
    const scr = projection.methodRegisters.find((r) => r.ksi === "KSI-SCR-MIT")!;
    expect(scr.methods.find((m) => m.recipeId === "covered")!.evidenceClass).toBe(
      "process-generated",
    );
    const cmt = projection.methodRegisters.find((r) => r.ksi === "KSI-CMT-CHG")!;
    expect(cmt.methods.find((m) => m.recipeId === "never-scanned")!.evidenceClass).toBeUndefined();
    expect(scr.pointInTimeMethods).toBe(0);
    expect(cmt.pointInTimeMethods).toBe(0);
  });

  it("point-in-time standing alone is G6 once every earlier arm has declined", () => {
    const projection = foldWith(
      [
        evidenceEntry({ recipe: "covered", timestamp: T1, evidenceClass: "point-in-time" }),
        ...judged("KSI-SCR-MIT"),
      ],
      1,
    );
    const row = projection.methodRegisters.find((r) => r.ksi === "KSI-SCR-MIT")!;
    expect(row.artifactsPresent).toBe(5); // G5 cleared — the gap is the class
    expect(row.pointInTimeMethods).toBe(1);
    expect(row.gap).toBe("G6");
  });

  it("process-generated evidence beside it defends: corroborated, not standalone", () => {
    const projection = foldWith(
      [
        evidenceEntry({ recipe: "covered", timestamp: T1, evidenceClass: "point-in-time" }),
        evidenceEntry({ recipe: "two-ksis", timestamp: T1, evidenceClass: "process-generated" }),
        ...judged("KSI-SCR-MIT"),
      ],
      1,
    );
    const row = projection.methodRegisters.find((r) => r.ksi === "KSI-SCR-MIT")!;
    expect(row.pointInTimeMethods).toBe(1); // the numerator still counts it
    expect(row.gap).toBeUndefined(); // but nothing stands alone
  });

  it("an unlabeled bundle defends nothing — an unsigned assertion cannot be relied on", () => {
    const projection = foldWith(
      [
        evidenceEntry({ recipe: "covered", timestamp: T1 }), // pre-Q3.4: no assertion
        evidenceEntry({ recipe: "two-ksis", timestamp: T1, evidenceClass: "point-in-time" }),
        ...judged("KSI-SCR-MIT"),
      ],
      1,
    );
    expect(projection.methodRegisters.find((r) => r.ksi === "KSI-SCR-MIT")!.gap).toBe("G6");
  });

  it("an unlabeled bundle triggers nothing either — no point-in-time assertion, no G6", () => {
    const projection = foldWith(
      [evidenceEntry({ recipe: "covered", timestamp: T1 }), ...judged("KSI-SCR-MIT")],
      1,
    );
    const row = projection.methodRegisters.find((r) => r.ksi === "KSI-SCR-MIT")!;
    expect(row.pointInTimeMethods).toBe(0);
    expect(row.gap).toBeUndefined();
  });

  it("the worst gap outranks G6: unjudged artifacts stay G5, the numerator still counted", () => {
    const projection = foldWith(
      [evidenceEntry({ recipe: "covered", timestamp: T1, evidenceClass: "point-in-time" })],
      1,
    );
    const row = projection.methodRegisters.find((r) => r.ksi === "KSI-SCR-MIT")!;
    expect(row.gap).toBe("G5");
    expect(row.pointInTimeMethods).toBe(1);
  });

  it("survives the sqlite round trip, the cell's class and the numerator included", async () => {
    const projection = foldWith(
      [
        evidenceEntry({ recipe: "covered", timestamp: T1, evidenceClass: "point-in-time" }),
        ...judged("KSI-SCR-MIT"),
      ],
      1,
    );
    const dir = await mkdtemp(join(tmpdir(), "rampscan-g6-"));
    const dbPath = join(dir, "projection.db");
    await writeProjectionSqlite(projection, dbPath);
    expect(readProjectionSqlite(dbPath)).toEqual(projection);
  });
});

// Q4.2 — the attestation leg (SPEC §12.9). Unlike pipeline methods, these are
// not handed to the fold: the catalog cannot carry a human attestation, so the
// fold DERIVES them from the signed events it already reads. The cell's
// freshness comes from the event's own timestamp, because an attestation has
// no evidence chain — the event IS the evidence.
describe("attestation methods (Q4.2)", () => {
  const NMV3: ClockWindow = { num: 3, unit: "months" };
  // T2 is 2026-08-08; NMV's threshold is three calendar months before it
  const FRESH = "2026-07-01T00:00:00.000Z";
  const LAPSED = "2026-01-01T00:00:00.000Z";

  function attestationEntry(opts: {
    statementId: string;
    ksiId: string;
    timestamp: string;
    action?: "attested" | "withdrawn";
    repo?: string;
    role?: string;
    statementRef?: string;
  }): LedgerEntry {
    const bundle: Attestation = {
      _type: "https://in-toto.io/Statement/v1",
      subject: [
        { name: "attestation.txt", digest: { sha256: (opts.statementRef ?? "b").repeat(64) } },
      ],
      predicateType: "https://rampscan.dev/attestation/v1",
      predicate: {
        action: opts.action ?? "attested",
        statement_id: opts.statementId,
        ksi_id: opts.ksiId,
        attestor_role: opts.role ?? "ciso",
        statement: "the programme ran and its effectiveness was reviewed",
        repo: opts.repo ?? "fixtures/app",
        proposed_by: "viewer@rampscan.local (pb:u1)",
        approved_by: "approver@rampscan.local (pb:u2)",
        dataset_version: "2026.07.14.01",
        timestamp: opts.timestamp,
      },
    };
    return { digest: `att-${counter++}`, bundle, appendedAt: opts.timestamp };
  }

  it("derives a method from the ledger event and judges it on the NMV clock", () => {
    const projection = foldWith(
      [
        evidenceEntry({ recipe: "covered", timestamp: T1 }),
        attestationEntry({
          statementId: "incident-review",
          ksiId: "KSI-CNA-CIC",
          timestamp: FRESH,
        }),
      ],
      null,
      null,
      { nonMachineWindow: NMV3 },
    );
    const row = projection.methodRegisters.find(
      (r) => r.repo === "fixtures/app" && r.ksi === "KSI-CNA-CIC",
    )!;
    expect(row.methods).toHaveLength(1);
    const cell = row.methods[0]!;
    expect(cell.methodId).toBe("attestation:incident-review#KSI-CNA-CIC");
    expect(cell.source).toBe("attestation");
    expect(cell.automated).toBe(false);
    expect(cell.clock).toBe("non-machine");
    expect(cell.standing).toBe("narrative");
    expect(cell.state).toBe("evidenced");
    expect(cell.freshAsOf).toBe(FRESH);
    expect(cell.window).toEqual(NMV3);
    expect(cell.freshMet).toBe(true);
    // no pipeline join fields, and no G6 label: a human statement asserts none
    expect(cell.recipeId).toBeUndefined();
    expect(cell.evidenceClass).toBeUndefined();
    expect(row.gap).not.toBe("G1");
  });

  it("a lapsed attestation is stale on its own clock", () => {
    const projection = foldWith(
      [attestationEntry({ statementId: "incident-review", ksiId: "KSI-CNA-CIC", timestamp: LAPSED })],
      null,
      null,
      { nonMachineWindow: NMV3 },
    );
    const row = projection.methodRegisters.find((r) => r.ksi === "KSI-CNA-CIC")!;
    expect(row.methods[0]!.freshMet).toBe(false);
    expect(row.staleMethods).toBe(1);
    expect(row.gap).toBe("G3");
  });

  it("a signed withdrawal supersedes the claim, and the method goes with it", () => {
    const projection = foldWith(
      [
        attestationEntry({ statementId: "incident-review", ksiId: "KSI-CNA-CIC", timestamp: FRESH }),
        attestationEntry({
          statementId: "incident-review",
          ksiId: "KSI-CNA-CIC",
          timestamp: "2026-08-02T00:00:00.000Z",
          action: "withdrawn",
        }),
      ],
      null,
      null,
      { nonMachineWindow: NMV3 },
    );
    const row = projection.methodRegisters.find((r) => r.ksi === "KSI-CNA-CIC")!;
    expect(row.methods).toHaveLength(0);
    expect(row.gap).toBe("G1");
  });

  it("a renewal satisfies the same method — one mechanism, not two", () => {
    const projection = foldWith(
      [
        attestationEntry({
          statementId: "incident-review",
          ksiId: "KSI-CNA-CIC",
          timestamp: LAPSED,
          statementRef: "a",
        }),
        attestationEntry({
          statementId: "incident-review",
          ksiId: "KSI-CNA-CIC",
          timestamp: FRESH,
          statementRef: "c",
        }),
      ],
      null,
      null,
      { nonMachineWindow: NMV3 },
    );
    const row = projection.methodRegisters.find((r) => r.ksi === "KSI-CNA-CIC")!;
    expect(row.methods).toHaveLength(1);
    expect(row.methods[0]!.freshMet).toBe(true);
  });

  it("is scoped to its own repo — an attestation is about one offering", () => {
    const projection = foldWith(
      [
        evidenceEntry({ recipe: "covered", timestamp: T1, repo: "fixtures/other" }),
        attestationEntry({
          statementId: "incident-review",
          ksiId: "KSI-CNA-CIC",
          timestamp: FRESH,
          repo: "fixtures/app",
        }),
      ],
      null,
      null,
      { nonMachineWindow: NMV3 },
    );
    const mine = projection.methodRegisters.find(
      (r) => r.repo === "fixtures/app" && r.ksi === "KSI-CNA-CIC",
    )!;
    const theirs = projection.methodRegisters.find(
      (r) => r.repo === "fixtures/other" && r.ksi === "KSI-CNA-CIC",
    )!;
    expect(mine.methods).toHaveLength(1);
    expect(theirs.methods).toHaveLength(0);
  });

  it("no number of attestations reaches an automated floor — cover is not automate", () => {
    const projection = foldWith(
      ["ir", "training", "access", "vendor"].map((statementId) =>
        attestationEntry({ statementId, ksiId: "KSI-CNA-CIC", timestamp: FRESH }),
      ),
      1,
      null,
      { nonMachineWindow: NMV3 },
    );
    const row = projection.methodRegisters.find((r) => r.ksi === "KSI-CNA-CIC")!;
    expect(row.methods).toHaveLength(4);
    expect(row.automatedMethods).toBe(0);
    expect(row.floorMet).toBe(false);
    expect(row.gap).toBe("G2");
  });

  it("survives the sqlite round trip", async () => {
    const projection = foldWith(
      [attestationEntry({ statementId: "incident-review", ksiId: "KSI-CNA-CIC", timestamp: FRESH })],
      1,
      null,
      { nonMachineWindow: NMV3 },
    );
    const dir = await mkdtemp(join(tmpdir(), "rampscan-q42-"));
    const dbPath = join(dir, "projection.db");
    await writeProjectionSqlite(projection, dbPath);
    expect(readProjectionSqlite(dbPath)).toEqual(projection);
  });
});

// Q4.3 — the aws-ingested leg (SPEC §12.8/§12.10). Also ledger-derived: the
// catalog holds OUR recipes, and an ingested result names the client's. The
// join is to the live submission by METHOD identity, not through the recipe
// cell, because one upstream recipe can evidence two KSIs and neither result
// may stand in for the other.
describe("aws-ingested methods (Q4.3)", () => {
  const MVX7: ClockWindow = { num: 7, unit: "days" };

  function ingestedEntry(opts: {
    recipeId: string;
    ksiId: string;
    timestamp: string;
    verdict?: "evidenced" | "violated";
    repo?: string;
    evidenceClass?: "process-generated" | "point-in-time";
    signer?: string;
    ingestDigest?: string;
  }): LedgerEntry {
    const bundle: EvidenceBundle = {
      _type: "https://in-toto.io/Statement/v1",
      subject: [{ name: "out.json", digest: { sha256: "f".repeat(64) } }],
      predicateType: "https://rampscan.dev/evidence/v1",
      predicate: {
        recipe_id: opts.recipeId,
        method_id: `aws-ingested:${opts.recipeId}#${opts.ksiId}`,
        evidence_class: opts.evidenceClass ?? "process-generated",
        ingest: {
          signer_identity: opts.signer ?? "ops@client.example",
          ingest_digest: (opts.ingestDigest ?? "a").repeat(64),
        },
        ksi_ids: [opts.ksiId],
        control_ids: [],
        verdict: opts.verdict ?? "evidenced",
        repo: opts.repo ?? "fixtures/app",
        // no commit anchor: ingested evidence dies superseded or goes stale,
        // never by anchor drift (SPEC §12.8)
        commit: "",
        anchor_paths: [],
        dataset_version: "2026.07.14.01",
        tool_versions: {},
        assertions: [
          { description: "check", passed: (opts.verdict ?? "evidenced") === "evidenced" },
        ],
        cadence: "monthly",
        run_id: `ingest:${opts.timestamp}`,
        timestamp: opts.timestamp,
      },
    };
    return { digest: `ing-${counter++}`, bundle, appendedAt: opts.timestamp };
  }

  it("an ingested result becomes a counted automated method on its KSI", () => {
    const projection = foldWith(
      [ingestedEntry({ recipeId: "KSI-CNA-CIC.sh", ksiId: "KSI-CNA-CIC", timestamp: T1 })],
      1,
      null,
      { machineWindow: MVX7 },
    );
    const row = projection.methodRegisters.find(
      (r) => r.repo === "fixtures/app" && r.ksi === "KSI-CNA-CIC",
    )!;
    expect(row.methods).toHaveLength(1);
    const cell = row.methods[0]!;
    expect(cell.methodId).toBe("aws-ingested:KSI-CNA-CIC.sh#KSI-CNA-CIC");
    expect(cell.source).toBe("aws-ingested");
    expect(cell.recipeId).toBe("KSI-CNA-CIC.sh"); // the UPSTREAM id, named
    // nothing of ours walked anything, so there is no collector and no scope
    expect(cell.collector).toBeUndefined();
    expect(cell.scope).toBeUndefined();
    expect(cell.state).toBe("evidenced");
    expect(cell.freshAsOf).toBe(T1);
    expect(cell.clock).toBe("machine");
    expect(cell.freshMet).toBe(true);
    // the point of Q4.3: it counts toward the FRC-CSX-VVK numerator
    expect(cell.automated).toBe(true);
    expect(row.automatedMethods).toBe(1);
    expect(row.floorMet).toBe(true);
    expect(row.gap).not.toBe("G1");
    expect(row.gap).not.toBe("G2");
  });

  it("a violated ingested result still counts as a method — the record exists (G13 owns what it says)", () => {
    const projection = foldWith(
      [
        ingestedEntry({
          recipeId: "KSI-CNA-CIC.sh",
          ksiId: "KSI-CNA-CIC",
          timestamp: T1,
          verdict: "violated",
        }),
      ],
      1,
      null,
      { machineWindow: MVX7 },
    );
    const row = projection.methodRegisters.find((r) => r.ksi === "KSI-CNA-CIC")!;
    expect(row.methods[0]!.state).toBe("violated");
    expect(row.automatedMethods).toBe(1);
    expect(row.floorMet).toBe(true);
  });

  it("quotes the submitter's evidence-class assertion — the one fact the appliance cannot compute", () => {
    const projection = foldWith(
      [
        ingestedEntry({
          recipeId: "KSI-CNA-CIC.sh",
          ksiId: "KSI-CNA-CIC",
          timestamp: T1,
          evidenceClass: "point-in-time",
        }),
      ],
      1,
      null,
      { machineWindow: MVX7 },
    );
    const row = projection.methodRegisters.find((r) => r.ksi === "KSI-CNA-CIC")!;
    expect(row.methods[0]!.evidenceClass).toBe("point-in-time");
    expect(row.pointInTimeMethods).toBe(1);
    // standing alone, so G6 is the row's gap once nothing worse outranks it
    expect(row.gap).toBe("G5"); // artifacts 1/3/4 unjudged outrank G6
  });

  it("one upstream recipe evidencing two KSIs mints two methods, neither standing in for the other", () => {
    const projection = foldWith(
      [
        ingestedEntry({ recipeId: "shared.sh", ksiId: "KSI-CNA-CIC", timestamp: T1 }),
        ingestedEntry({
          recipeId: "shared.sh",
          ksiId: "KSI-CMT-CHG",
          timestamp: T1,
          verdict: "violated",
        }),
      ],
      1,
      null,
      { machineWindow: MVX7 },
    );
    const cic = projection.methodRegisters.find((r) => r.ksi === "KSI-CNA-CIC")!;
    const chg = projection.methodRegisters.find((r) => r.ksi === "KSI-CMT-CHG")!;
    const cicCell = cic.methods.find((m) => m.source === "aws-ingested")!;
    const chgCell = chg.methods.find((m) => m.source === "aws-ingested")!;
    expect(cicCell.methodId).toBe("aws-ingested:shared.sh#KSI-CNA-CIC");
    expect(chgCell.methodId).toBe("aws-ingested:shared.sh#KSI-CMT-CHG");
    // the distinct verdicts prove the join did not collapse through the shared
    // recipe id — each KSI reads its own submission
    expect(cicCell.state).toBe("evidenced");
    expect(chgCell.state).toBe("violated");
  });

  it("a re-ingestion satisfies the same method and its provenance cites the live submission", () => {
    const stale = "2026-07-20T00:00:00.000Z";
    const projection = foldWith(
      [
        ingestedEntry({
          recipeId: "KSI-CNA-CIC.sh",
          ksiId: "KSI-CNA-CIC",
          timestamp: stale,
          ingestDigest: "a",
        }),
        ingestedEntry({
          recipeId: "KSI-CNA-CIC.sh",
          ksiId: "KSI-CNA-CIC",
          timestamp: T1,
          ingestDigest: "b",
        }),
      ],
      1,
      null,
      { machineWindow: MVX7 },
    );
    const row = projection.methodRegisters.find((r) => r.ksi === "KSI-CNA-CIC")!;
    expect(row.methods).toHaveLength(1);
    expect(row.methods[0]!.freshAsOf).toBe(T1);
    expect(row.methods[0]!.freshMet).toBe(true);
  });

  it("is scoped to its own repo — an ingested result is about one offering", () => {
    const projection = foldWith(
      [
        ingestedEntry({
          recipeId: "KSI-CNA-CIC.sh",
          ksiId: "KSI-CNA-CIC",
          timestamp: T1,
          repo: "fixtures/app",
        }),
        evidenceEntry({ recipe: "covered", timestamp: T1, repo: "fixtures/other" }),
      ],
      1,
      null,
      { machineWindow: MVX7 },
    );
    const mine = projection.methodRegisters.find(
      (r) => r.repo === "fixtures/app" && r.ksi === "KSI-CNA-CIC",
    )!;
    const theirs = projection.methodRegisters.find(
      (r) => r.repo === "fixtures/other" && r.ksi === "KSI-CNA-CIC",
    )!;
    expect(mine.methods).toHaveLength(1);
    expect(theirs.methods).toHaveLength(0);
  });

  it("all three sources count on one KSI — the register spans them (the Q4.3 point)", () => {
    const projection = foldEntries(
      [
        evidenceEntry({ recipe: "covered", timestamp: T1, ksiIds: ["KSI-CNA-CIC"] }),
        ingestedEntry({ recipeId: "KSI-CNA-CIC.sh", ksiId: "KSI-CNA-CIC", timestamp: T1 }),
        {
          digest: "att-q43",
          appendedAt: T1,
          bundle: {
            _type: "https://in-toto.io/Statement/v1",
            subject: [{ name: "attestation.txt", digest: { sha256: "b".repeat(64) } }],
            predicateType: "https://rampscan.dev/attestation/v1",
            predicate: {
              action: "attested",
              statement_id: "incident-review",
              ksi_id: "KSI-CNA-CIC",
              attestor_role: "ciso",
              statement: "reviewed",
              repo: "fixtures/app",
              proposed_by: "v",
              approved_by: "a",
              dataset_version: "2026.07.14.01",
              timestamp: T1,
            },
          } as Attestation,
        },
      ],
      T2,
      {
        recipes,
        // a pipeline method for this KSI, so all three legs are present
        methods: [...methods, ...methodsOfRecipe(recipe("cic", ["KSI-CNA-CIC"]), scope)],
        ksiIds: KSI_IDS,
        methodFloor: 2,
        machineWindow: MVX7,
        nonMachineWindow: { num: 3, unit: "months" },
      },
    );
    const row = projection.methodRegisters.find(
      (r) => r.repo === "fixtures/app" && r.ksi === "KSI-CNA-CIC",
    )!;
    expect([...new Set(row.methods.map((m) => m.source))].sort()).toEqual([
      "attestation",
      "aws-ingested",
      "pipeline",
    ]);
    expect(row.methods).toHaveLength(3);
    // two automated (pipeline + ingested); the attestation is not, so a floor
    // of 2 is met by the automated pair and the attestation adds coverage only
    expect(row.automatedMethods).toBe(2);
    expect(row.floorMet).toBe(true);
  });

  it("survives the sqlite round trip", async () => {
    const projection = foldWith(
      [ingestedEntry({ recipeId: "KSI-CNA-CIC.sh", ksiId: "KSI-CNA-CIC", timestamp: T1 })],
      1,
      null,
      { machineWindow: MVX7 },
    );
    const dir = await mkdtemp(join(tmpdir(), "rampscan-q43-"));
    const dbPath = join(dir, "projection.db");
    await writeProjectionSqlite(projection, dbPath);
    expect(readProjectionSqlite(dbPath)).toEqual(projection);
  });
});
