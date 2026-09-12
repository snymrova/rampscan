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
const MVX_B = { num: 7, unit: "days" } as const;
const foldedRegisters: MethodRegisterRow[] = [
  {
    repo: "/repo/app",
    ksi: "KSI-SCR-MIT",
    methods: [
      {
        methodId: "pipeline:covered#KSI-SCR-MIT",
        source: "pipeline",
        automated: true,
        clock: "machine",
        standing: "full",
        recipeId: "covered",
        collector: "repo-facts",
        state: "evidenced",
        bundleDigest: "d1",
        freshAsOf: T1,
        window: MVX_B,
        freshMet: true,
      },
      {
        methodId: "pipeline:both#KSI-SCR-MIT",
        source: "pipeline",
        automated: true,
        clock: "machine",
        standing: "full",
        recipeId: "both",
        collector: "repo-facts",
        state: "unevidenced",
        window: MVX_B,
        freshMet: false, // missing evidence — G3's other half (Q3.2)
      },
    ],
    automatedMethods: 2,
    methodFloor: 1,
    floorMet: true,
    freshAsOf: T1,
    staleMethods: 1,
    historySince: T1,
    historyFloorMonths: null,
    historyMet: null,
    artifacts: [
      { artifact: 1, basis: "judged", present: false },
      { artifact: 2, basis: "computed", present: true },
      { artifact: 3, basis: "judged", present: false },
      { artifact: 4, basis: "judged", present: false },
      { artifact: 5, basis: "computed", present: true },
    ],
    artifactsPresent: 2,
    pointInTimeMethods: 0,
    gap: "G3",
  },
  {
    repo: "/repo/app",
    ksi: "KSI-CMT-CHG",
    methods: [
      {
        methodId: "pipeline:both#KSI-CMT-CHG",
        source: "pipeline",
        automated: true,
        clock: "machine",
        standing: "full",
        recipeId: "both",
        collector: "repo-facts",
        state: "unevidenced",
        window: MVX_B,
        freshMet: false,
      },
    ],
    automatedMethods: 1,
    methodFloor: 1,
    floorMet: true,
    staleMethods: 1,
    historyFloorMonths: null,
    historyMet: null,
    artifacts: [
      { artifact: 1, basis: "judged", present: false },
      { artifact: 2, basis: "computed", present: false },
      { artifact: 3, basis: "judged", present: false },
      { artifact: 4, basis: "judged", present: false },
      { artifact: 5, basis: "computed", present: false },
    ],
    artifactsPresent: 0,
    pointInTimeMethods: 0,
    gap: "G3",
  },
  {
    repo: "/repo/app",
    ksi: "KSI-CNA-CIC",
    methods: [],
    automatedMethods: 0,
    methodFloor: 1,
    floorMet: false,
    staleMethods: 0,
    historyFloorMonths: null,
    historyMet: null,
    artifacts: [
      { artifact: 1, basis: "judged", present: false },
      { artifact: 2, basis: "computed", present: false },
      { artifact: 3, basis: "judged", present: false },
      { artifact: 4, basis: "judged", present: false },
      { artifact: 5, basis: "computed", present: false },
    ],
    artifactsPresent: 0,
    pointInTimeMethods: 0,
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
      everyMethodFresh: 0, // both method-bearing rows carry an unmet clock (Q3.2)
      historyMet: null, // class b owes no months (Q3.1)
      allArtifacts: 0, // no row holds all five owed artifacts (Q3.3)
      pointInTime: 0, // nothing asserted point-in-time — the pipeline mints process-generated (Q3.4)
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
        staleMethods: 0, // every clock met — G3 must not mask the history gap
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
    // but the WORST gap still outranks: one-method KSIs are G2 at class c,
    // and a floor-met KSI with no evidence is G3 (nothing runs its clocks —
    // Q3.2), which outranks the history it also lacks
    expect(view.rows.find((r) => r.ksi === "KSI-CMT-CHG")!.worstGap).toBe("G2");
    expect(view.rows.find((r) => r.ksi === "KSI-SCR-MIT")!.worstGap).toBe("G3");
  });

  it("G3 freshness (Q3.2): the fold's per-method judgment rides through, floor met or not", () => {
    const view = buildKsiRegister({
      catalog,
      offeringClass: "b",
      methods,
      methodRegisters: foldedRegisters,
      frontier,
    });
    const scr = view.rows.find((r) => r.ksi === "KSI-SCR-MIT")!;
    expect(scr.staleMethods).toBe(1); // "both" has no evidence — missing counts
    expect(scr.floorMet).toBe(true);
    expect(scr.worstGap).toBe("G3");
    expect(view.summary.everyMethodFresh).toBe(0);
  });

  it("class d defines no machine window: no clock judgment, no G3, meter null", () => {
    const view = buildKsiRegister({
      catalog,
      offeringClass: "d",
      methods,
      methodRegisters: [],
      frontier,
    });
    expect(view.window).toBeNull();
    expect(view.summary.everyMethodFresh).toBeNull();
    expect(view.rows.every((r) => r.staleMethods === 0)).toBe(true);
    expect(view.rows.some((r) => r.worstGap === "G3")).toBe(false);
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

  it("row anatomy: methods n/floor · age vs window · artifacts k/5 · worst gap", () => {
    // the fold measured: 2 of 5 artifacts on SCR-MIT (Q3.3), a real 0/5 on
    // the G1 row — measured zeros, not placeholders, because a ledger exists
    expect(text).toMatch(/KSI-SCR-MIT\s+2\/1 ok\s+11h \/ 7d ok\s+2\/5/);
    expect(text).toMatch(/KSI-CNA-CIC\s+0\/1\s+—\s+0\/5\s+G1 coverage/);
  });

  it("artifacts print –/5 only when no scanned repo exists — unmeasured, never a fake 0 (§12.5 rule 3)", () => {
    const bare = buildKsiRegister({
      catalog,
      offeringClass: "b",
      methods,
      methodRegisters: [],
      frontier,
    });
    const bareText = renderKsiRegister(bare, false, now);
    expect(bareText).toMatch(/KSI-SCR-MIT\s+2\/1 ok\s+—\s+–\/5/);
    expect(bareText).not.toContain("0/5");
    expect(bareText).toContain(
      "artifacts: unmeasured — the five owed artifacts are counted against a scanned repo's ledger",
    );
    expect(bare.summary.allArtifacts).toBeNull();
  });

  it("the artifact meter (Q3.3) counts rows holding all five, and names the owed source", () => {
    expect(text).toContain(
      "artifacts: 0 of 3 KSIs hold all five owed artifacts — default_artifacts.KSI (2, 5 computed · 1, 3, 4 two-key judged)",
    );
  });

  it("G5 renders when everything else is met and an artifact alone is missing (Q3.3)", () => {
    const folded: MethodRegisterRow[] = [
      {
        ...foldedRegisters[0]!,
        staleMethods: 0, // clocks met — G3 must not mask the artifact gap
        artifactsPresent: 4,
      },
    ];
    const view = buildKsiRegister({
      catalog,
      offeringClass: "b",
      methods,
      methodRegisters: folded,
      frontier,
    });
    const row = view.rows.find((r) => r.ksi === "KSI-SCR-MIT")!;
    expect(row.artifactsPresent).toBe(4);
    expect(row.worstGap).toBe("G5");
    expect(renderKsiRegister(view, false, now)).toContain("G5 artifact");
  });

  it("the evidence-class meter (Q3.4) counts asserted point-in-time rows, and unmeasured without a repo", () => {
    expect(text).toContain(
      "evidence class: 0 of 3 KSIs hold point-in-time evidence, rejectable when standalone — FRR-PVA-AA-06 (pipeline mints assert process-generated)",
    );
    expect(view.summary.pointInTime).toBe(0);
    const bare = buildKsiRegister({
      catalog,
      offeringClass: "b",
      methods,
      methodRegisters: [],
      frontier,
    });
    expect(bare.summary.pointInTime).toBeNull();
    expect(renderKsiRegister(bare, false, now)).toContain(
      "evidence class: unmeasured — asserted per bundle at ingestion (process-generated | point-in-time, FRR-PVA-AA-06)",
    );
  });

  it("G6 renders when the fold judged point-in-time standing alone and every earlier arm declined (Q3.4)", () => {
    const folded: MethodRegisterRow[] = [
      {
        ...foldedRegisters[0]!,
        staleMethods: 0, // clocks met — G3 must not mask the class gap
        artifactsPresent: 5, // artifacts judged — G5 must not either
        pointInTimeMethods: 1,
        gap: "G6", // the fold's judgment: it read the signed assertions, this join does not
      },
    ];
    const view = buildKsiRegister({
      catalog,
      offeringClass: "b",
      methods,
      methodRegisters: folded,
      frontier,
    });
    const row = view.rows.find((r) => r.ksi === "KSI-SCR-MIT")!;
    expect(row.pointInTimeMethods).toBe(1);
    expect(row.worstGap).toBe("G6");
    const rendered = renderKsiRegister(view, false, now);
    expect(rendered).toContain("G6 evidence");
    expect(rendered).toContain(
      "evidence class: 1 of 3 KSIs hold point-in-time evidence, rejectable when standalone",
    );
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
    // no scan → nothing runs the clocks: G3 outranks the history gap (Q3.2)
    expect(cText).toContain("G3 freshness");
  });

  it("the clock meter (Q3.2): counted at the fold, named by rule; class d prints its missing window", () => {
    expect(text).toContain(
      "clocks: 0 of 3 KSIs hold every method inside its owed window — VDR-TFR-MVX (MUST)",
    );
    expect(text).toContain("G3 freshness");
    const dView = buildKsiRegister({
      catalog,
      offeringClass: "d",
      methods,
      methodRegisters: [],
      frontier,
    });
    const dText = renderKsiRegister(dView, false, now);
    expect(dText).toContain("clocks: no machine window at class d — VDR-TFR-MVX defines none");
    expect(dText).not.toContain("G3 freshness");
  });

  it("G4 renders when the clocks are met and history alone is short", () => {
    const folded: MethodRegisterRow[] = [
      {
        ...foldedRegisters[0]!,
        staleMethods: 0,
        historyFloorMonths: 6,
        historyMet: false,
      },
    ];
    const view4 = buildKsiRegister({
      catalog,
      offeringClass: "c",
      methods,
      methodRegisters: folded,
      frontier,
    });
    expect(renderKsiRegister(view4, false, now)).toContain("G4 history");
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

  // Q4.2: a row's methods stopped being one clock family. The freshest column
  // prints the window of the METHOD that supplied the instant (§12.5 rule 3),
  // never the class's MVX window borrowed across families — an attestation
  // 20 days old is inside VDR-TFR-NMV's 3 months and would read as a lapse
  // against VDR-TFR-MVX's 7 days.
  const NMV3 = { num: 3, unit: "months" } as const;
  const attested = (freshAsOf: string, freshMet: boolean): MethodRegisterRow => ({
    repo: "/repo/app",
    ksi: "KSI-CNA-CIC",
    methods: [
      {
        methodId: "attestation:incident-review#KSI-CNA-CIC",
        source: "attestation",
        automated: false,
        clock: "non-machine",
        standing: "narrative",
        state: "evidenced",
        bundleDigest: "att-1",
        freshAsOf,
        window: NMV3,
        freshMet,
      },
    ],
    automatedMethods: 0,
    methodFloor: 1,
    floorMet: false,
    freshAsOf,
    staleMethods: freshMet ? 0 : 1,
    historyFloorMonths: null,
    historyMet: null,
    artifacts: [
      { artifact: 1, basis: "judged", present: false },
      { artifact: 2, basis: "computed", present: false },
      { artifact: 3, basis: "judged", present: false },
      { artifact: 4, basis: "judged", present: false },
      { artifact: 5, basis: "computed", present: true },
    ],
    artifactsPresent: 1,
    pointInTimeMethods: 0,
    gap: "G2",
  });

  it("a non-machine method is judged against VDR-TFR-NMV, not the class MVX window", () => {
    // 20 days old: outside MVX's 7 days, comfortably inside NMV's 3 months
    const twentyDaysAgo = "2026-08-21T11:00:00.000Z";
    const nmvView = buildKsiRegister({
      catalog,
      offeringClass: "b",
      methods,
      methodRegisters: [attested(twentyDaysAgo, true)],
      frontier,
    });
    const row = nmvView.rows.find((r) => r.ksi === "KSI-CNA-CIC")!;
    expect(row.freshestWindow).toEqual(NMV3);
    expect(row.freshestMet).toBe(true);
    const nmvText = renderKsiRegister(nmvView, false, now);
    // the label is the method's own window, and "ok" is the fold's verdict —
    // against the 7-day window this same row would have read as lapsed
    expect(nmvText).toMatch(/KSI-CNA-CIC\s+0\/1\s+20d \/ 3mo ok/);
    expect(nmvText).not.toMatch(/KSI-CNA-CIC.*7d/);
  });

  it("the fold's verdict wins over the renderer's approximation — no row says ok beside its own G3", () => {
    const lapsed = attested("2026-06-01T00:00:00.000Z", false);
    lapsed.gap = "G3";
    lapsed.methodFloor = null;
    lapsed.floorMet = null;
    const lapsedView = buildKsiRegister({
      catalog,
      offeringClass: "a", // class a owes no automated floor, so G3 is the row's worst
      methods,
      methodRegisters: [lapsed],
      frontier,
    });
    const lapsedText = renderKsiRegister(lapsedView, false, now);
    const line = lapsedText.split("\n").find((l) => l.includes("KSI-CNA-CIC"))!;
    expect(line).toContain("3mo");
    expect(line).not.toContain("ok");
    expect(line).toContain("G3 freshness");
  });
});
