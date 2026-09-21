import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import type { ClockWindow, LedgerEntry } from "@rampscan/core";
import type { EvidenceBundle, MethodScope, PipelineRecipe, ReachPin } from "@rampscan/schema";
import { REACH_RUNGS, methodsOfRecipe } from "@rampscan/schema";
import { foldEntries, reachOf, readProjectionSqlite, writeProjectionSqlite } from "../src/index.js";

// The reach ladder (docs/PLAN-REACH.md N0-1). One fixture ledger, one KSI
// sitting on each rung, and the sentence beneath each rung naming what
// earns the next one. The number this ladder feeds is the plan's north
// star, so every rung here is earned by the ledger and the pins and never by
// the catalog: `wired` is the most a recipe confers by existing.

let counter = 0;
const T1 = "2026-08-01T00:00:00.000Z"; // seven days before the fold: on the boundary, inside
const STALE = "2026-07-20T00:00:00.000Z";
const T2 = "2026-08-08T00:00:00.000Z"; // the fold instant
const MVX7: ClockWindow = { num: 7, unit: "days" };
const scope: MethodScope = { population: "checkout", history: false, gitignored: "excluded" };

function evidenceEntry(opts: {
  recipe: string;
  ksi: string;
  timestamp: string;
  ingest?: boolean;
}): LedgerEntry {
  const bundle: EvidenceBundle = {
    _type: "https://in-toto.io/Statement/v1",
    subject: [{ name: "x", digest: { sha256: "e".repeat(64) } }],
    predicateType: "https://rampscan.dev/evidence/v1",
    predicate: {
      recipe_id: opts.recipe,
      ksi_ids: [opts.ksi],
      control_ids: ["si-7.1"],
      verdict: "evidenced",
      repo: "fixtures/app",
      commit: opts.ingest ? "" : "1".repeat(40),
      anchor_paths: opts.ingest ? [] : [{ path: "f", contentHash: "a".repeat(64) }],
      dataset_version: "2026.07.14.01",
      tool_versions: { "repo-facts": "0.1.0" },
      assertions: [{ description: "check", passed: true }],
      cadence: "continuous",
      run_id: `run-${opts.timestamp}`,
      timestamp: opts.timestamp,
      ...(opts.ingest
        ? { ingest: { signer_identity: "client", ingest_digest: "d".repeat(64) } }
        : {}),
    },
  };
  return { digest: `digest-${counter++}`, bundle, appendedAt: opts.timestamp };
}

function recipe(id: string, ksi: string): PipelineRecipe {
  return {
    id,
    ksi_ids: [ksi],
    control_ids: ["si-7.1"],
    evidence: "test recipe",
    collection: { kind: "pipeline", collector: "repo-facts" },
    expected_output: "rows",
    cadence: "weekly",
    automatable: "full",
    anchor: "commit",
  };
}

// one KSI per rung, named for the rung it is built to sit on
const KSI = {
  unreachable: "KSI-CED-RAT",
  reachable: "KSI-INR-AAR",
  wired: "KSI-CMT-LMC",
  run: "KSI-CMT-VTD",
  fresh: "KSI-SCR-MIT",
  floor: "KSI-SCR-MON",
  distinct: "KSI-IAM-APM",
} as const;

const recipes = [
  recipe("wired-never-ran", KSI.wired),
  recipe("ran-stale", KSI.run),
  recipe("fresh-one", KSI.fresh),
  recipe("floor-one", KSI.floor),
  recipe("floor-two", KSI.floor),
  recipe("distinct-pipeline", KSI.distinct),
];
const methods = recipes.flatMap((r) => methodsOfRecipe(r, scope));
const pin = (plane: ReachPin["plane"], observes: string[], wired: string[] = observes): ReachPin => ({
  plane,
  observes,
  wired,
});
const pins: Record<string, ReachPin[]> = {
  // nothing on any plane — the three pins are the reason
  [KSI.unreachable]: [pin("pipeline", []), pin("aws", []), pin("prowler", [])],
  // an upstream recipe exists and is not runnable; Prowler maps no check
  [KSI.reachable]: [pin("pipeline", []), pin("aws", ["incident-tracker-export"], []), pin("prowler", [])],
  [KSI.wired]: [pin("pipeline", ["wired-never-ran"]), pin("aws", []), pin("prowler", ["iam_x"])],
  [KSI.run]: [pin("pipeline", ["ran-stale"]), pin("aws", []), pin("prowler", [])],
  [KSI.fresh]: [pin("pipeline", ["fresh-one"]), pin("aws", []), pin("prowler", [])],
  [KSI.floor]: [pin("pipeline", ["floor-one", "floor-two"]), pin("aws", []), pin("prowler", [])],
  [KSI.distinct]: [
    pin("pipeline", ["distinct-pipeline"]),
    pin("aws", ["iam-credential-report"]),
    pin("prowler", []),
  ],
};
const entries = [
  evidenceEntry({ recipe: "ran-stale", ksi: KSI.run, timestamp: STALE }),
  evidenceEntry({ recipe: "fresh-one", ksi: KSI.fresh, timestamp: T1 }),
  evidenceEntry({ recipe: "floor-one", ksi: KSI.floor, timestamp: T1 }),
  evidenceEntry({ recipe: "floor-two", ksi: KSI.floor, timestamp: T1 }),
  evidenceEntry({ recipe: "distinct-pipeline", ksi: KSI.distinct, timestamp: T1 }),
  evidenceEntry({ recipe: "iam-credential-report", ksi: KSI.distinct, timestamp: T1, ingest: true }),
];

function fold(floor: number | null, withPins = true) {
  return foldEntries(entries, T2, {
    recipes,
    methods,
    ksiIds: Object.values(KSI),
    methodFloor: floor,
    machineWindow: MVX7,
    ...(withPins ? { reach: pins } : {}),
  });
}
const rowOf = (projection: ReturnType<typeof fold>, ksi: string) =>
  projection.methodRegisters.find((r) => r.ksi === ksi)!;

describe("the reach ladder (N0-1): one KSI per rung", () => {
  // class c: floor 2, so `fresh` and `floor` are different rungs
  const projection = fold(2);

  it("KSI-CED-RAT is unreachable, and the three pins are the reason", () => {
    const reach = rowOf(projection, KSI.unreachable).reach!;
    expect(reach.rung).toBe("unreachable");
    expect(reach.next).toContain("recipes/commit/");
    expect(reach.next).toContain("aws-evidence.json");
    expect(reach.next).toContain("docs/context/prowler/");
    expect(reach.next).toContain("attestation");
  });

  it("reachable: a tool exists somewhere, nothing of ours turns its output into a method", () => {
    const reach = rowOf(projection, KSI.reachable).reach!;
    expect(reach.rung).toBe("reachable");
    expect(reach.next).toContain("aws (incident-tracker-export)");
    expect(reach.next).toContain("earns wired");
  });

  it("wired: a recipe exists and no signed bundle does — the catalog confers nothing higher", () => {
    const reach = rowOf(projection, KSI.wired).reach!;
    expect(reach.rung).toBe("wired");
    expect(reach.next).toContain("pipeline (wired-never-ran)");
    expect(reach.next).toContain("prowler (iam_x)");
    expect(reach.next).toContain("no signed bundle");
  });

  it("run: a bundle stands in the ledger and is outside its window", () => {
    const reach = rowOf(projection, KSI.run).reach!;
    expect(reach.rung).toBe("run");
    expect(reach.next).toContain("1 automated method(s) have run and none is inside its owed window");
  });

  it("fresh: one automated method inside its window, short of a floor of 2", () => {
    const reach = rowOf(projection, KSI.fresh).reach!;
    expect(reach.rung).toBe("fresh");
    expect(reach.next).toContain("1 automated method(s) inside their window against a floor of 2");
    expect(reach.distinctPlanes).toBe(1);
  });

  it("floor: the floor is met from one plane, and the sentence names it", () => {
    const reach = rowOf(projection, KSI.floor).reach!;
    expect(reach.rung).toBe("floor");
    expect(reach.next).toContain("one plane (pipeline)");
    expect(reach.distinctPlanes).toBe(1);
  });

  it("distinct: the floor is met from two planes — the top rung has no next", () => {
    const reach = rowOf(projection, KSI.distinct).reach!;
    expect(reach.rung).toBe("distinct");
    expect(reach.next).toBeNull();
    expect(reach.distinctPlanes).toBe(2);
  });

  it("every rung in the fixture is a rung of the ladder, in the ladder's order", () => {
    const rungs = Object.values(KSI).map((ksi) => rowOf(projection, ksi).reach!.rung);
    expect(rungs).toEqual([...REACH_RUNGS]);
  });
});

describe("the ladder is earned by the ledger, never by the catalog", () => {
  it("floor is judged over FRESH automated methods, not G2's count: a stale second method leaves the row at fresh", () => {
    const projection = foldEntries(
      [
        evidenceEntry({ recipe: "floor-one", ksi: KSI.floor, timestamp: T1 }),
        evidenceEntry({ recipe: "floor-two", ksi: KSI.floor, timestamp: STALE }),
      ],
      T2,
      { recipes, methods, ksiIds: [KSI.floor], methodFloor: 2, machineWindow: MVX7, reach: pins },
    );
    const row = rowOf(projection, KSI.floor);
    expect(row.floorMet).toBe(true); // G2 counts methods that exist
    expect(row.reach!.rung).toBe("fresh"); // the ladder counts methods inside their window
    expect(row.reach!.next).toContain("1 automated method(s) inside their window against a floor of 2");
  });

  it("at class b (floor 1) fresh and floor coincide, and one plane stops short of distinct", () => {
    const reach = rowOf(fold(1), KSI.fresh).reach!;
    expect(reach.rung).toBe("floor");
    expect(reach.next).toContain("a second plane observing a different thing earns distinct");
  });

  it("a class that owes no floor stops at fresh and says the floor is unjudged", () => {
    const reach = rowOf(fold(null), KSI.fresh).reach!;
    expect(reach.rung).toBe("fresh");
    expect(reach.next).toContain("the class owes no method floor");
  });

  it("a class with no machine window (d) stops at run and says freshness is unjudged", () => {
    const projection = foldEntries(entries, T2, {
      recipes,
      methods,
      ksiIds: [KSI.fresh],
      methodFloor: 4,
      machineWindow: null,
      reach: pins,
    });
    const reach = rowOf(projection, KSI.fresh).reach!;
    expect(reach.rung).toBe("run");
    expect(reach.next).toContain("the class owes no machine window");
  });

  it("an attestation ends G1 and does not climb the ladder: non-automated methods are not counted", () => {
    // the same shape `reachOf` sees for a KSI whose only method is a signed
    // human statement inside its three-month window
    const reach = reachOf(
      {
        methods: [
          {
            automated: false,
            source: "attestation",
            bundleDigest: "d",
            freshMet: true,
            window: { num: 3, unit: "months" },
          },
        ],
        methodFloor: 1,
      },
      pins[KSI.unreachable]!,
    );
    expect(reach.rung).toBe("unreachable");
    expect(reach.distinctPlanes).toBe(0);
  });

  it("a KSI the pins do not name is observed by nothing — the fold reads silence as silence", () => {
    const projection = foldEntries(entries, T2, {
      recipes,
      methods,
      ksiIds: [KSI.fresh],
      methodFloor: 1,
      machineWindow: MVX7,
      reach: {},
    });
    expect(rowOf(projection, KSI.fresh).reach!.rung).toBe("unreachable");
  });

  it("a fold given no pins carries no rung — absent, never a rung computed from nothing", () => {
    const projection = fold(1, false);
    for (const row of projection.methodRegisters) expect(row.reach).toBeUndefined();
  });

  it("survives the sqlite round trip, rungs and their absence included", async () => {
    const dir = await mkdtemp(join(tmpdir(), "rampscan-reach-"));
    for (const projection of [fold(2), fold(1, false)]) {
      const dbPath = join(dir, `projection-${counter++}.db`);
      await writeProjectionSqlite(projection, dbPath);
      expect(readProjectionSqlite(dbPath)).toEqual(projection);
    }
  });
});
