import { describe, expect, it } from "vitest";
import type { LedgerEntry, RegisterRow } from "@rampscan/core";
import type { EvidenceBundle, PipelineRecipe, ScopingEvent } from "@rampscan/schema";
import { foldEntries } from "../src/index.js";

// Phase I1 substrate: the control/KSI rollup registers (I1a), the as-of fold
// (I1b), and the cadence-adherence history (I1d). All pure — synthetic
// entries here; the CLI e2e closes the loop over a real ledger.

let counter = 0;

function evidenceEntry(opts: {
  recipe: string;
  timestamp: string;
  commit?: string;
  verdict?: "evidenced" | "violated";
  repo?: string;
  anchors?: Array<{ path: string; contentHash: string }>;
}): LedgerEntry {
  const bundle: EvidenceBundle = {
    _type: "https://in-toto.io/Statement/v1",
    subject: [{ name: "x", digest: { sha256: "e".repeat(64) } }],
    predicateType: "https://rampscan.dev/evidence/v1",
    predicate: {
      recipe_id: opts.recipe,
      ksi_ids: ["KSI-SCR-MIT"],
      control_ids: ["si-7.1"],
      verdict: opts.verdict ?? "evidenced",
      repo: opts.repo ?? "fixtures/app",
      commit: opts.commit ?? "1".repeat(40),
      anchor_paths: opts.anchors ?? [{ path: `f-${opts.recipe}`, contentHash: "a".repeat(64) }],
      dataset_version: "2026.07.14.01",
      tool_versions: { "repo-facts": "0.1.0" },
      assertions: [{ description: "check", passed: (opts.verdict ?? "evidenced") === "evidenced" }],
      cadence: "continuous",
      run_id: `run-${opts.timestamp}`,
      timestamp: opts.timestamp,
    },
  };
  return { digest: `digest-${counter++}`, bundle, appendedAt: opts.timestamp };
}

function scopingEntry(opts: { recipe: string; timestamp: string; repo?: string }): LedgerEntry {
  const bundle: ScopingEvent = {
    _type: "https://in-toto.io/Statement/v1",
    subject: [{ name: "justification.txt", digest: { sha256: "f".repeat(64) } }],
    predicateType: "https://rampscan.dev/scoping/v1",
    predicate: {
      action: "notApplicable",
      recipe_id: opts.recipe,
      ksi_ids: ["KSI-CNA-CIC"],
      control_ids: ["cm-2.2"],
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

function recipe(id: string, opts: { controls?: string[]; ksis?: string[] } = {}): PipelineRecipe {
  return {
    id,
    ksi_ids: opts.ksis ?? ["KSI-SVC-CLS"],
    control_ids: opts.controls ?? ["sc-8.1"],
    evidence: "test recipe",
    collection: { kind: "pipeline", collector: "repo-facts" },
    expected_output: "rows",
    cadence: "weekly",
    automatable: "full",
    anchor: "commit",
  };
}

const T1 = "2026-08-01T00:00:00.000Z";
const T2 = "2026-08-05T00:00:00.000Z";
const T3 = "2026-08-10T00:00:00.000Z";

describe("I1a — control register rollup", () => {
  const catalog = [
    recipe("r-evidenced", { controls: ["ac-2.1"], ksis: ["KSI-A"] }),
    recipe("r-violated", { controls: ["ac-2.1", "si-4.1"], ksis: ["KSI-A"] }),
    recipe("r-unevidenced", { controls: ["ac-2.1", "cm-8.1"], ksis: ["KSI-B"] }),
  ];
  const entries = [
    evidenceEntry({ recipe: "r-evidenced", timestamp: T1 }),
    evidenceEntry({ recipe: "r-violated", timestamp: T1, verdict: "violated" }),
  ];

  it("violated beats unevidenced beats evidenced, with attributable coverage counts", () => {
    const projection = foldEntries(entries, T2, { recipes: catalog });
    const control = projection.controls.find((c) => c.id === "ac-2.1")!;
    expect(control.state).toBe("violated");
    expect(control.recipeIds).toEqual(["r-evidenced", "r-unevidenced", "r-violated"]);
    expect(control.counts).toEqual({
      evidenced: 1,
      violated: 1,
      unevidenced: 1,
      notApplicable: 0,
      total: 3,
    });

    // no violation on cm-8.1: its one mapped recipe is unevidenced
    expect(projection.controls.find((c) => c.id === "cm-8.1")!.state).toBe("unevidenced");
    // si-4.1 maps only the violated recipe
    expect(projection.controls.find((c) => c.id === "si-4.1")!.state).toBe("violated");
  });

  it("all mapped recipes evidenced → evidenced", () => {
    const projection = foldEntries(
      [evidenceEntry({ recipe: "solo", timestamp: T1 })],
      T2,
      { recipes: [recipe("solo", { controls: ["au-2.1"] })] },
    );
    expect(projection.controls.find((c) => c.id === "au-2.1")!.state).toBe("evidenced");
  });

  it("a scoped-out recipe never drags the rollup down; all scoped → notApplicable", () => {
    const projection = foldEntries(
      [
        evidenceEntry({ recipe: "live", timestamp: T1 }),
        scopingEntry({ recipe: "na-shared", timestamp: T1 }),
        scopingEntry({ recipe: "na-lone", timestamp: T1 }),
      ],
      T2,
      {
        recipes: [
          recipe("live", { controls: ["shared-ctl"] }),
          recipe("na-shared", { controls: ["shared-ctl"] }),
          recipe("na-lone", { controls: ["lone-ctl"] }),
        ],
      },
    );
    const shared = projection.controls.find((c) => c.id === "shared-ctl")!;
    expect(shared.state).toBe("evidenced");
    expect(shared.counts.notApplicable).toBe(1);
    expect(projection.controls.find((c) => c.id === "lone-ctl")!.state).toBe("notApplicable");
  });

  it("the KSI register folds the same way, keyed by KSI id", () => {
    const projection = foldEntries(entries, T2, { recipes: catalog });
    expect(projection.ksis.find((k) => k.id === "KSI-A")!.state).toBe("violated");
    expect(projection.ksis.find((k) => k.id === "KSI-B")!.state).toBe("unevidenced");
  });

  it("counts always match an independent recount from the register rows", () => {
    const projection = foldEntries(
      [...entries, scopingEntry({ recipe: "r-unevidenced", timestamp: T2 })],
      T3,
      { recipes: catalog },
    );
    for (const rollup of [...projection.controls, ...projection.ksis]) {
      const idsOf = (row: RegisterRow) =>
        projection.controls.includes(rollup) ? row.controlIds : row.ksiIds;
      const mapped = projection.registers.filter(
        (row) => row.repo === rollup.repo && idsOf(row).includes(rollup.id),
      );
      expect(rollup.counts.total).toBe(mapped.length);
      for (const state of ["evidenced", "violated", "unevidenced", "notApplicable"] as const) {
        expect(rollup.counts[state]).toBe(mapped.filter((r) => r.state === state).length);
      }
    }
  });
});

describe("I1b — as-of fold", () => {
  it("folding as-of an instant between two entries reproduces the earlier projection exactly", () => {
    const first = [evidenceEntry({ recipe: "r", timestamp: T1, verdict: "evidenced" })];
    const later = evidenceEntry({ recipe: "r", timestamp: T3, verdict: "violated" });
    const options = { recipes: [recipe("r")], windowMs: 7 * 24 * 3600 * 1000 };

    const atFirstScan = foldEntries(first, T2, options);
    const asOf = foldEntries([...first, later], T2, { ...options, asOf: T2 });
    expect(asOf).toEqual(atFirstScan);
  });

  it("a scoping after the as-of instant does not reach back", () => {
    const projection = foldEntries(
      [
        evidenceEntry({ recipe: "r", timestamp: T1 }),
        scopingEntry({ recipe: "later-na", timestamp: T3 }),
      ],
      T3,
      { recipes: [recipe("r"), recipe("later-na")], asOf: T2 },
    );
    expect(projection.registers.find((r) => r.recipeId === "later-na")!.state).toBe("unevidenced");
    expect(projection.drift.some((d) => d.kind === "scoped")).toBe(false);
  });
});

describe("I1d — cadence-adherence history", () => {
  const WINDOW = 24 * 3600 * 1000; // 1 day
  const at = (dayOffset: number) =>
    new Date(Date.parse("2026-08-01T00:00:00.000Z") + dayOffset * WINDOW).toISOString();

  it("a refresh that landed after the window closed is a closed gap with exact bounds", () => {
    const projection = foldEntries(
      [
        evidenceEntry({ recipe: "r", timestamp: at(0) }),
        evidenceEntry({ recipe: "r", timestamp: at(2.5) }),
      ],
      at(3),
      { windowMs: WINDOW },
    );
    expect(projection.gaps).toEqual([
      {
        repo: "fixtures/app",
        recipeId: "r",
        bundleDigest: projection.rows[0]!.bundleDigest,
        start: at(1),
        end: at(2.5),
        durationMs: 1.5 * WINDOW,
        ongoing: false,
      },
    ]);
  });

  it("an unrefreshed tail past its window is an ongoing gap ending at projectedAt", () => {
    const projection = foldEntries(
      [evidenceEntry({ recipe: "r", timestamp: at(0) })],
      at(4),
      { windowMs: WINDOW },
    );
    expect(projection.gaps).toEqual([
      expect.objectContaining({ start: at(1), end: at(4), durationMs: 3 * WINDOW, ongoing: true }),
    ]);
  });

  it("refreshes inside the window leave no gap; no window given leaves the history empty", () => {
    const chain = [
      evidenceEntry({ recipe: "r", timestamp: at(0) }),
      evidenceEntry({ recipe: "r", timestamp: at(0.5) }),
      evidenceEntry({ recipe: "r", timestamp: at(1.2) }),
    ];
    expect(foldEntries(chain, at(1.5), { windowMs: WINDOW }).gaps).toEqual([]);
    expect(foldEntries(chain, at(9), {}).gaps).toEqual([]);
  });
});
