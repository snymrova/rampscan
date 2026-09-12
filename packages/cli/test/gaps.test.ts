import { describe, expect, it } from "vitest";
import type { MethodRegisterRow, ValidationVulnerability } from "@rampscan/core";
import type { KsiCatalog } from "@rampscan/dataset";
import type { MethodScope, PipelineRecipe } from "@rampscan/schema";
import { methodsOfRecipe } from "@rampscan/schema";
import type { FrontierMap } from "../src/frontier.js";
import { buildGapRegister, renderGapRegister } from "../src/gaps.js";

// Q3 exit gate — `rampscan gaps`, the gap register as a computation: every
// G1–G6, G8, G13 row, each citing its rule id and the evidence digest where
// evidence exists to cite. These tests pin the join, not the judgments: the
// fold and the frontier judged; this register only lists.

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

const artifacts = (present: boolean[]) =>
  present.map((p, i) => ({
    artifact: (i + 1) as 1 | 2 | 3 | 4 | 5,
    basis: (i === 1 || i === 4 ? "computed" : "judged") as "computed" | "judged",
    present: p,
  }));

/** one evidenced KSI: fresh method + a stale one; one point-in-time method */
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
        evidenceClass: "point-in-time",
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
        freshMet: false,
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
    artifacts: artifacts([false, true, false, false, true]),
    artifactsPresent: 2,
    pointInTimeMethods: 1,
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
    artifacts: artifacts([false, false, false, false, false]),
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
    artifacts: artifacts([false, false, false, false, false]),
    artifactsPresent: 0,
    pointInTimeMethods: 0,
    gap: "G1",
  },
];

const vulnerabilities: ValidationVulnerability[] = [
  {
    repo: "/repo/app",
    recipeId: "covered",
    ksiIds: ["KSI-SCR-MIT"],
    detectedAt: "2026-09-01T00:00:00.000Z",
    commit: "1".repeat(40),
    bundleDigest: "vd1",
    status: "open",
  },
  {
    repo: "/repo/app",
    recipeId: "both",
    ksiIds: ["KSI-CMT-CHG"],
    detectedAt: "2026-08-01T00:00:00.000Z",
    commit: "2".repeat(40),
    bundleDigest: "vd2",
    status: "resolved",
    resolvedAt: "2026-08-08T00:00:00.000Z",
    resolvingDigest: "vd3",
    resolvingCommit: "3".repeat(40),
  },
];

const view = buildGapRegister({
  catalog,
  offeringClass: "b",
  methods,
  methodRegisters: foldedRegisters,
  vulnerabilities,
  frontier,
});

describe("buildGapRegister — the Q3 exit gate", () => {
  it("lists every taxonomy class the register computes, in order", () => {
    expect(view.sections.map((s) => s.gapClass)).toEqual([
      "G1",
      "G2",
      "G3",
      "G4",
      "G5",
      "G6",
      "G8",
      "G13",
    ]);
  });

  it("every section cites its rule id — owed-side data where the catalog carries it", () => {
    const rules = Object.fromEntries(view.sections.map((s) => [s.gapClass, s.ruleId]));
    expect(rules).toEqual({
      G1: "FRC-CSX-VVK",
      G2: "FRC-CSX-VVK",
      G3: "VDR-TFR-MVX",
      G4: "FRC-CSX-MOT",
      G5: "default_artifacts.KSI",
      G6: "FRR-PVA-AA-06",
      G8: null, // product-level — the unasked question has no FedRAMP rule
      G13: "VDR-CSO-FAV",
    });
  });

  it("G1: the untouched KSI is a row; evidenced ones are not", () => {
    const g1 = view.sections.find((s) => s.gapClass === "G1")!;
    expect(g1.rows.map((r) => r.subject)).toEqual(["KSI-CNA-CIC"]);
  });

  it("G3: one row per unmet clock, digest exactly when evidence exists", () => {
    const g3 = view.sections.find((s) => s.gapClass === "G3")!;
    expect(g3.rows.map((r) => r.subject)).toEqual([
      "KSI-SCR-MIT · pipeline:both#KSI-SCR-MIT",
      "KSI-CMT-CHG · pipeline:both#KSI-CMT-CHG",
    ]);
    // both are missing-evidence cells: nothing to cite IS the gap
    expect(g3.rows.every((r) => r.digest === undefined)).toBe(true);
  });

  it("G5: absent artifacts named per KSI; unjudged rows carry no digest", () => {
    const g5 = view.sections.find((s) => s.gapClass === "G5")!;
    expect(g5.rows.map((r) => r.subject)).toContain("KSI-SCR-MIT · artifact 1");
    expect(g5.rows.map((r) => r.subject)).toContain("KSI-CMT-CHG · artifact 5");
  });

  it("G6: the asserted point-in-time cell is a row citing its bundle, corroboration stated", () => {
    const g6 = view.sections.find((s) => s.gapClass === "G6")!;
    // Nothing on this row asserts process-generated — the sibling method holds
    // no live evidence at all — so the point-in-time evidence STANDS ALONE.
    // It reads that way even though the row's worst gap is G3: corroboration
    // is the G6 predicate, not the row's headline (the two part whenever
    // something outranks G6 under precedence).
    const row = view.sections.find((s) => s.gapClass === "G3")!;
    expect(row.rows.length).toBeGreaterThan(0);
    expect(g6.rows).toEqual([
      {
        subject: "KSI-SCR-MIT · pipeline:covered#KSI-SCR-MIT",
        detail: "point-in-time evidence STANDING ALONE — rejectable as standalone evidence",
        digest: "d1",
      },
    ]);
  });

  it("G6: a process-generated method beside it reads as corroborated, whatever the row's worst gap", () => {
    const corroborated: MethodRegisterRow[] = foldedRegisters.map((r) =>
      r.ksi !== "KSI-SCR-MIT"
        ? r
        : {
            ...r,
            methods: r.methods.map((m) =>
              m.methodId === "pipeline:both#KSI-SCR-MIT"
                ? { ...m, state: "evidenced" as const, evidenceClass: "process-generated" as const }
                : m,
            ),
          },
    );
    const withBoth = buildGapRegister({
      catalog,
      offeringClass: "b",
      methods,
      methodRegisters: corroborated,
      vulnerabilities: [],
      frontier,
    });
    const g6 = withBoth.sections.find((s) => s.gapClass === "G6")!;
    expect(g6.rows).toHaveLength(1);
    expect(g6.rows[0]!.detail).toBe(
      "point-in-time evidence, corroborated by a process-generated method",
    );
  });

  it("G8: the unreviewed controls, sorted — the unasked question stays a first-class row", () => {
    const g8 = view.sections.find((s) => s.gapClass === "G8")!;
    expect(g8.rows.map((r) => r.subject)).toEqual(["CM-03", "SC-08"]);
  });

  it("G13: open episodes are rows with their violating digest; resolved ones are history", () => {
    const g13 = view.sections.find((s) => s.gapClass === "G13")!;
    expect(g13.rows).toHaveLength(1);
    expect(g13.rows[0]!.subject).toBe("KSI-SCR-MIT · covered");
    expect(g13.rows[0]!.digest).toBe("vd1");
  });

  it("class a: G2 says the class owes no number instead of judging against one", () => {
    const a = buildGapRegister({
      catalog,
      offeringClass: "a",
      methods,
      methodRegisters: foldedRegisters,
      vulnerabilities,
      frontier,
    });
    const g2 = a.sections.find((s) => s.gapClass === "G2")!;
    expect(g2.unmeasured).toContain("owes no number");
    expect(g2.rows).toEqual([]);
  });

  it("without a scan, the evidence-side sections say unmeasured, never a fake zero", () => {
    const bare = buildGapRegister({
      catalog,
      offeringClass: "b",
      methods,
      methodRegisters: [],
      vulnerabilities: [],
      frontier,
    });
    expect(bare.repo).toBeUndefined();
    expect(bare.sections.find((s) => s.gapClass === "G5")!.unmeasured).toBeDefined();
    expect(bare.sections.find((s) => s.gapClass === "G6")!.unmeasured).toBeDefined();
    // G1/G2 never depended on the ledger: still computed, from the derivation
    expect(bare.sections.find((s) => s.gapClass === "G1")!.rows.map((r) => r.subject)).toEqual([
      "KSI-CNA-CIC",
    ]);
  });
});

describe("renderGapRegister", () => {
  const text = renderGapRegister(view, false);

  it("prints the header, every section with its rule, and the digest column", () => {
    expect(text).toContain("rampscan gaps — the gap register");
    expect(text).toContain("class b · dataset 2026.07.14.01");
    expect(text).toContain("G1 coverage — FRC-CSX-VVK (SHOULD)");
    expect(text).toContain("G6 evidence class — FRR-PVA-AA-06");
    expect(text).toContain("G8 adjudication — product-level, not a rule");
    expect(text).toContain("G13 failure handling — VDR-CSO-FAV");
    expect(text).toContain("vd1"); // the open episode's violating digest, truncated for display
  });

  // Q4.2: G3 now spans two clock families, so the section's single rule id
  // stopped covering every row. A non-machine row cites VDR-TFR-NMV beside a
  // section headed by the machine window — the gap register's promise is that
  // every row cites the rule that makes IT a gap.
  it("a lapsed non-machine method cites VDR-TFR-NMV, not the section's machine rule", () => {
    const withAttestation: MethodRegisterRow = {
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
          freshAsOf: "2026-05-01T00:00:00.000Z",
          window: { num: 3, unit: "months" },
          freshMet: false,
        },
      ],
      automatedMethods: 0,
      methodFloor: 1,
      floorMet: false,
      freshAsOf: "2026-05-01T00:00:00.000Z",
      staleMethods: 1,
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
    };
    const mixed = buildGapRegister({
      catalog,
      offeringClass: "b",
      methods,
      methodRegisters: [...foldedRegisters, withAttestation],
      vulnerabilities: [],
      frontier,
    });
    const g3 = mixed.sections.find((sec) => sec.gapClass === "G3")!;
    // the section still heads with the machine rule, since most rows are machine
    expect(g3.ruleId).toBe("VDR-TFR-MVX");
    const attestationRow = g3.rows.find((r) => r.subject.includes("attestation:"))!;
    expect(attestationRow.ruleId).toBe("VDR-TFR-NMV");
    expect(attestationRow.detail).toContain("outside the owed 3mo window");
    // machine rows stay silent: their rule is the section's, so repeating it
    // on every row would be noise
    const machineRow = g3.rows.find((r) => r.subject.includes("pipeline:"))!;
    expect(machineRow.ruleId).toBeUndefined();
    // and the renderer prints the divergent rule where it applies
    expect(renderGapRegister(mixed, false)).toContain("VDR-TFR-NMV");
  });

  it("an empty section prints none — measured emptiness, said out loud", () => {
    const noVulns = buildGapRegister({
      catalog,
      offeringClass: "b",
      methods,
      methodRegisters: foldedRegisters,
      vulnerabilities: [],
      frontier,
    });
    const rendered = renderGapRegister(noVulns, false);
    expect(rendered).toMatch(/G13 failure handling[^\n]*\n    none/);
  });
});
