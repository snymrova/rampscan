import { describe, expect, it } from "vitest";
import type { MethodRegisterRow } from "@rampscan/core";
import type { KsiCatalog } from "@rampscan/dataset";
import type { MethodScope, PipelineRecipe } from "@rampscan/schema";
import { methodsOfRecipe } from "@rampscan/schema";
import type { FrontierMap } from "../src/frontier.js";
import { buildKsiRegister, renderKsiRegister } from "../src/ksi-register.js";

// Q2.4 — frontier v2, the KSI register (SPEC §12.5). The format is DECIDED
// in the spec; these tests pin the derivation and the format rules that
// carry ground rules 1 and 2: both denominators printable, cover ≠ automate
// stated structurally, artifacts –/5 (unmeasured) rather than a fake 0.

const scope: MethodScope = { population: "checkout", history: false, gitignored: "excluded" };

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

const catalog: KsiCatalog = {
  datasetVersion: "2026.07.14.01",
  themes: [{ key: "SCR", name: "Supply Chain Risk" }],
  ksis: [
    { id: "KSI-CMT-CHG", themeKey: "CMT", name: "Change management", statement: "s", controls: ["cm-2"] },
    { id: "KSI-CNA-CIC", themeKey: "CNA", name: "Untouched", statement: "s", controls: ["cm-3"] },
    { id: "KSI-SCR-MIT", themeKey: "SCR", name: "Mitigation", statement: "s", controls: ["si-7.1"] },
  ],
  defaultArtifacts: ["a1", "a2", "a3", "a4", "a5"],
  floors: {
    a: { requirementId: "FRC-CSX-VVK", force: "MAY", minPerKsi: null },
    b: { requirementId: "FRC-CSX-VVK", force: "SHOULD", minPerKsi: 1 },
    c: { requirementId: "FRC-CSX-VVK", force: "MUST", minPerKsi: 2 },
    d: { requirementId: "FRC-CSX-VVK", force: "MUST", minPerKsi: 4 },
  },
  historyFloors: {
    a: { requirementId: "FRC-CSX-MOT", force: "MAY", months: null },
    b: { requirementId: "FRC-CSX-MOT", force: "SHOULD", months: null },
    c: { requirementId: "FRC-CSX-MOT", force: "MUST", months: 6 },
    d: { requirementId: "FRC-CSX-MOT", force: "MUST", months: 18 },
  },
  windows: {
    a: { requirementId: "VDR-TFR-MVX", force: "SHOULD", num: 1, unit: "months" },
    b: { requirementId: "VDR-TFR-MVX", force: "MUST", num: 7, unit: "days" },
    c: { requirementId: "VDR-TFR-MVX", force: "MUST", num: 3, unit: "days" },
    d: null,
  },
  nonMachineWindow: { requirementId: "VDR-TFR-NMV", force: "MUST", num: 3, unit: "months" },
};

const recipes = [recipe("covered", ["KSI-SCR-MIT"]), recipe("both", ["KSI-SCR-MIT", "KSI-CMT-CHG"])];
const methods = recipes.flatMap((r) => methodsOfRecipe(r, scope));

const frontier: FrontierMap = {
  datasetVersion: "2026.07.14.01",
  rows: [
    {
      controlId: "sc-8",
      displayId: "SC-08",
      family: "SC",
      classes: [],
      ksis: ["KSI-CNA-CIC"],
      leverage: 3,
      upstream: {},
      catalogRecipeIds: [],
    },
    {
      controlId: "cm-3",
      displayId: "CM-03",
      family: "CM",
      classes: [],
      ksis: ["KSI-CNA-CIC"],
      leverage: 9,
      upstream: {},
      catalogRecipeIds: [],
    },
    {
      controlId: "si-7.1",
      displayId: "SI-07 (01)",
      family: "SI",
      classes: [],
      ksis: ["KSI-SCR-MIT"],
      upstream: {},
      commit: {
        disposition: "automatable",
        rationale: "answered",
        recipeIds: ["covered"],
        candidateCollectors: [],
        reviewed: "2026-09-01",
        datasetVersion: "2026.07.14.01",
      },
      catalogRecipeIds: ["covered"],
    },
  ],
  rollup: {
    frontierTotal: 3,
    ksiReachedControls: 209,
    automatable: 1,
    partial: 0,
    narrative: 0,
    unreviewed: 2,
    discharged: 1,
    catalogCovered: 23,
    reachable: 38,
    ceiling: 38 / 209,
    upstreamAdjudicatedBySource: {},
  },
  ceilingByFamily: [],
  retired: [],
  problems: [],
};

const T1 = "2026-09-10T00:00:00.000Z";
const foldedRegisters: MethodRegisterRow[] = [
  {
    repo: "/repo/app",
    ksi: "KSI-SCR-MIT",
    methods: [
      {
        methodId: "pipeline:covered#KSI-SCR-MIT",
        source: "pipeline",
        automated: true,
        standing: "full",
        recipeId: "covered",
        collector: "repo-facts",
        state: "evidenced",
        bundleDigest: "d1",
        freshAsOf: T1,
      },
      {
        methodId: "pipeline:both#KSI-SCR-MIT",
        source: "pipeline",
        automated: true,
        standing: "full",
        recipeId: "both",
        collector: "repo-facts",
        state: "unevidenced",
      },
    ],
    automatedMethods: 2,
    methodFloor: 1,
    floorMet: true,
    freshAsOf: T1,
    historySince: T1,
    historyFloorMonths: null,
    historyMet: null,
  },
  {
    repo: "/repo/app",
    ksi: "KSI-CMT-CHG",
    methods: [
      {
        methodId: "pipeline:both#KSI-CMT-CHG",
        source: "pipeline",
        automated: true,
        standing: "full",
        recipeId: "both",
        collector: "repo-facts",
        state: "unevidenced",
      },
    ],
    automatedMethods: 1,
    methodFloor: 1,
    floorMet: true,
    historyFloorMonths: null,
    historyMet: null,
  },
  {
    repo: "/repo/app",
    ksi: "KSI-CNA-CIC",
    methods: [],
    automatedMethods: 0,
    methodFloor: 1,
    floorMet: false,
    historyFloorMonths: null,
    historyMet: null,
    gap: "G1",
  },
];

describe("buildKsiRegister (Q2.4)", () => {
  it("one row per owed KSI, always — a KSI nothing evidences is a G1 row", () => {
    const view = buildKsiRegister({
      catalog,
      offeringClass: "b",
      methods,
      methodRegisters: foldedRegisters,
      frontier,
    });
    expect(view.rows.map((r) => r.ksi)).toEqual(["KSI-CMT-CHG", "KSI-CNA-CIC", "KSI-SCR-MIT"]);
    const untouched = view.rows.find((r) => r.ksi === "KSI-CNA-CIC")!;
    expect(untouched.methods).toBe(0);
    expect(untouched.worstGap).toBe("G1");
    expect(view.repo).toBe("/repo/app");
    expect(view.rows.find((r) => r.ksi === "KSI-SCR-MIT")!.freshest).toBe(T1);
  });

  it("summary: floor met · at least one automated · no method, counted from the rows", () => {
    const view = buildKsiRegister({
      catalog,
      offeringClass: "b",
      methods,
      methodRegisters: foldedRegisters,
      frontier,
    });
    expect(view.summary).toEqual({
      floorMet: 2,
      atLeastOneAutomated: 2,
      noMethod: 1,
      historyMet: null, // class b owes no months (Q3.1)
      total: 3,
    });
  });

  it("the class floor is a what-if: class c's floor of 2 turns a one-method KSI into G2", () => {
    const view = buildKsiRegister({
      catalog,
      offeringClass: "c",
      methods,
      methodRegisters: [],
      frontier,
    });
    const one = view.rows.find((r) => r.ksi === "KSI-CMT-CHG")!;
    expect(one.floor).toBe(2);
    expect(one.floorMet).toBe(false);
    expect(one.worstGap).toBe("G2");
    // class a owes no number: nothing to check, floorMet null
    const a = buildKsiRegister({
      catalog,
      offeringClass: "a",
      methods,
      methodRegisters: [],
      frontier,
    });
    expect(a.rows.find((r) => r.ksi === "KSI-CMT-CHG")!.floorMet).toBeNull();
  });

  it("the history meter (Q3.1): class b owes no months — historyMet null, no G4, summary null", () => {
    const view = buildKsiRegister({
      catalog,
      offeringClass: "b",
      methods,
      methodRegisters: foldedRegisters,
      frontier,
    });
    expect(view.history.months).toBeNull();
    expect(view.summary.historyMet).toBeNull();
    expect(view.rows.every((r) => r.historyMet === null)).toBe(true);
    expect(view.rows.some((r) => r.worstGap === "G4")).toBe(false);
  });

  it("class c owes 6 months: a KSI past its method floor but short of history is G4", () => {
    // SCR-MIT derives two methods (floor 2 met at class c); the fold judged
    // its history short — the projector's judgment rides through untouched
    const folded: MethodRegisterRow[] = [
      {
        ...foldedRegisters[0]!,
        floorMet: true,
        historySince: T1,
        historyFloorMonths: 6,
        historyMet: false,
      },
    ];
    const view = buildKsiRegister({
      catalog,
      offeringClass: "c",
      methods,
      methodRegisters: folded,
      frontier,
    });
    const row = view.rows.find((r) => r.ksi === "KSI-SCR-MIT")!;
    expect(row.historySince).toBe(T1);
    expect(row.historyMet).toBe(false);
    expect(row.worstGap).toBe("G4");
    expect(view.history.months).toBe(6);
  });

  it("without a fold the history meter starts honest: zero months meets no floor, never null", () => {
    const view = buildKsiRegister({
      catalog,
      offeringClass: "c",
      methods,
      methodRegisters: [],
      frontier,
    });
    // every row owes 6 months and the ledger holds nothing — met on none
    expect(view.summary.historyMet).toBe(0);
    expect(view.rows.every((r) => r.historyMet === false)).toBe(true);
    // but the WORST gap still outranks: one-method KSIs are G2 at class c
    expect(view.rows.find((r) => r.ksi === "KSI-CMT-CHG")!.worstGap).toBe("G2");
    expect(view.rows.find((r) => r.ksi === "KSI-SCR-MIT")!.worstGap).toBe("G4");
  });

  it("renders without a ledger: every row present, no repo named", () => {
    const view = buildKsiRegister({
      catalog,
      offeringClass: "b",
      methods,
      methodRegisters: [],
      frontier,
    });
    expect(view.repo).toBeUndefined();
    expect(view.rows).toHaveLength(3);
    expect(view.rows.find((r) => r.ksi === "KSI-SCR-MIT")!.methods).toBe(2);
    expect(view.rows.find((r) => r.ksi === "KSI-SCR-MIT")!.freshest).toBeUndefined();
  });

  it("the G8 queue is unreviewed controls sorted by leverage, descending", () => {
    const view = buildKsiRegister({
      catalog,
      offeringClass: "b",
      methods,
      methodRegisters: [],
      frontier,
    });
    expect(view.queue.map((q) => q.displayId)).toEqual(["CM-03", "SC-08"]);
    expect(view.queue[0]!.leverage).toBe(9);
  });
});

describe("renderKsiRegister — the §12.5 format rules", () => {
  const now = new Date("2026-09-10T11:00:00.000Z"); // 11h after T1
  const view = buildKsiRegister({
    catalog,
    offeringClass: "b",
    methods,
    methodRegisters: foldedRegisters,
    frontier,
  });
  view.frontierOverlay = "0.7.5";
  const text = renderKsiRegister(view, false, now);

  it("the headline sentence and the covering line print in the same breath (ground rules 1+2)", () => {
    expect(text).toContain("floor met on 2 of 3 KSIs · at least one automated method on 2 · no method on 1");
    expect(text).toContain('covering all 3 — a row that says "nothing evidences this from a pipeline" is a row');
  });

  it("row anatomy: methods n/floor · age vs window · artifacts –/5 · worst gap", () => {
    expect(text).toMatch(/KSI-SCR-MIT\s+2\/1 ok\s+11h \/ 7d ok\s+–\/5/);
    expect(text).toMatch(/KSI-CNA-CIC\s+0\/1\s+—\s+–\/5\s+G1 coverage/);
    // –/5, never a fake 0/5 that implies measurement
    expect(text).not.toContain("0/5");
  });

  it("the history meter line names the rule even when the class owes no months (Q3.1)", () => {
    expect(text).toContain("history: no floor at class b — FRC-CSX-MOT (SHOULD, unquantified)");
    const cView = buildKsiRegister({
      catalog,
      offeringClass: "c",
      methods,
      methodRegisters: [],
      frontier,
    });
    const cText = renderKsiRegister(cView, false, now);
    expect(cText).toContain(
      "history: 0 of 3 KSIs hold ≥6mo of persistent validation — FRC-CSX-MOT (MUST)",
    );
    expect(cText).toContain("G4 history");
  });

  it("the footer names the legacy view and its numbers on every invocation", () => {
    expect(text).toContain("legacy view: --by-controls   (23 of 209 controls · 38 reachable at this pin)");
  });

  it("the G8 queue prints as its own section, by leverage", () => {
    const queueAt = text.indexOf("adjudication queue (G8): 2 unreviewed, sorted by leverage");
    expect(queueAt).toBeGreaterThan(-1);
    expect(text.indexOf("CM-03")).toBeLessThan(text.indexOf("SC-08"));
  });

  it("the header names class, dataset and overlay — the pins a reader checks numbers against", () => {
    expect(text).toContain("class b · dataset 2026.07.14.01 · frontier overlay 0.7.5");
  });
});
