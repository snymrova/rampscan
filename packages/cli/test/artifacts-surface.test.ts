import { mkdtemp, readFile, writeFile, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import type { ArtifactCell, MethodRegisterRow } from "@rampscan/core";
import type { KsiCatalog } from "@rampscan/dataset";
import {
  buildArtifactsView,
  checkArtifacts,
  renderArtifact,
  renderArtifactCheck,
  renderArtifacts,
} from "../src/artifacts-view.js";
import { scaffoldArtifact, scaffoldBody, scaffoldPath } from "../src/artifacts-scaffold.js";

// R1.5 — `rampscan artifacts`. Two behaviours carry the phase's ground rules
// into a surface a person actually uses, and both are pinned here:
//
//   1. THE EMPTY CELLS ARE A WORK QUEUE WITH A COMMAND ATTACHED, and which
//      command it is follows §13.4 exactly: scaffold for 1 and 3, generate for
//      2, 4 and 5. A slot that is the provider's own claim never offers to
//      write itself.
//   2. THE SCAFFOLD FILLS THE COMPUTED HALF AND LEAVES THE CLAIM BLANK. That
//      refusal is the single most tempting thing in this plan to ship the other
//      way, so it is a property of a pure function with a test on it.

const NOW = new Date("2026-09-13T12:00:00.000Z");

const catalog = {
  datasetVersion: "2026.07.14.01",
  ksis: [
    {
      id: "KSI-SVC-SIN",
      themeKey: "svc",
      name: "Securing Information",
      statement: "Information is encrypted or otherwise secured.",
      controls: ["sc-13"],
    },
    {
      id: "KSI-SVC-RUD",
      themeKey: "svc",
      name: "Redundancy",
      statement: "Redundancy is in place.",
      controls: ["cp-9"],
    },
  ],
  themes: [{ key: "svc", name: "Service Configuration" }],
  defaultArtifacts: [
    "Explanation of measures…",
    "Explanation of the cycle…",
    "Verification that the measures demonstrate…",
    "Verification that the automation in place is accurate…",
    "Validation that the measures are accurately produced…",
  ],
  floors: {
    a: { minPerKsi: null, requirementId: "FRC-CSX-VVK", force: "SHOULD" },
    b: { minPerKsi: 1, requirementId: "FRC-CSX-VVK", force: "MUST" },
    c: { minPerKsi: 2, requirementId: "FRC-CSX-VVK", force: "MUST" },
    d: { minPerKsi: null, requirementId: "FRC-CSX-VVK", force: "MUST" },
  },
  historyFloors: {
    a: { months: null, requirementId: "FRC-CSX-MOT", force: "SHOULD" },
    b: { months: null, requirementId: "FRC-CSX-MOT", force: "MUST" },
    c: { months: 3, requirementId: "FRC-CSX-MOT", force: "MUST" },
    d: { months: null, requirementId: "FRC-CSX-MOT", force: "MUST" },
  },
  windows: { a: null, b: null, c: null, d: null },
  nonMachineWindow: { requirementId: "VDR-TFR-NMV", force: "MUST", num: 3, unit: "months" },
  applicability: {
    stated: true,
    optionalAt: { a: [], b: ["KSI-SVC-RUD"], c: [], d: [] },
    source: "fixture",
  },
} as unknown as KsiCatalog;

function cell(artifact: 1 | 2 | 3 | 4 | 5, overrides: Partial<ArtifactCell> = {}): ArtifactCell {
  return {
    artifact,
    basis: artifact === 2 || artifact === 5 ? "computed" : "judged",
    present: false,
    ...overrides,
  };
}

function register(artifacts: ArtifactCell[]): MethodRegisterRow {
  return {
    repo: "fixtures/app",
    ksi: "KSI-SVC-SIN",
    methods: [],
    automatedMethods: 0,
    methodFloor: 1,
    floorMet: false,
    staleMethods: 0,
    historyFloorMonths: null,
    historyMet: null,
    artifacts,
    artifactsPresent: artifacts.filter((a) => a.present).length,
    pointInTimeMethods: 0,
  };
}

function viewWith(artifacts: ArtifactCell[]) {
  return buildArtifactsView({
    catalog,
    offeringClass: "b",
    repo: "fixtures/app",
    methodRegisters: [register(artifacts)],
  });
}

const body = (overrides: Record<string, unknown> = {}) => ({
  digest: "d".repeat(64),
  bodyDigest: "b".repeat(64),
  source: "authored" as const,
  validFrom: "2026-09-10T00:00:00.000Z",
  freshMet: true,
  bodyBytes: 420,
  ...overrides,
});

describe("the artifacts view (R1.5)", () => {
  it("attaches the scaffold command to the two slots that are the provider's", () => {
    const view = viewWith([cell(1), cell(2), cell(3), cell(4), cell(5)]);
    const row = view.rows.find((r) => r.ksi === "KSI-SVC-SIN")!;
    expect(row.slots[0]!.next).toBe("rampscan artifacts scaffold KSI-SVC-SIN --artifact 1");
    expect(row.slots[2]!.next).toBe("rampscan artifacts scaffold KSI-SVC-SIN --artifact 3");
    // 2, 4 and 5 offer nothing while the fold has nothing to compute from —
    // a command that would only fail is not a work queue
    expect(row.slots[1]!.next).toBeUndefined();
    expect(row.slots[4]!.next).toBeUndefined();
  });

  it("attaches generate to a computed slot the fold can fill now", () => {
    const view = viewWith([cell(2, { derivable: true }), cell(5, { derivable: true })]);
    const row = view.rows.find((r) => r.ksi === "KSI-SVC-SIN")!;
    expect(row.slots[1]!.next).toBe("rampscan artifacts generate KSI-SVC-SIN --artifact 2");
    expect(row.slots[4]!.next).toBe("rampscan artifacts generate KSI-SVC-SIN --artifact 5");
  });

  it("never offers to generate artifacts 1 or 3, whatever the fold holds", () => {
    // a cell claiming derivability for a provider's own claim must not turn
    // into a command that would write it (§13.4)
    const view = viewWith([cell(1, { derivable: true }), cell(3, { derivable: true })]);
    const row = view.rows.find((r) => r.ksi === "KSI-SVC-SIN")!;
    expect(row.slots[0]!.next).toContain("scaffold");
    expect(row.slots[2]!.next).toContain("scaffold");
    expect(view.rows.flatMap((r) => r.slots).filter((s) => s.next?.includes("generate"))).toEqual(
      [],
    );
  });

  it("divides by the obliged KSIs only — an optional one keeps its row and leaves the meter", () => {
    const view = viewWith([cell(1, { present: true, body: body() })]);
    expect(view.rows.map((r) => r.ksi)).toEqual(["KSI-SVC-SIN", "KSI-SVC-RUD"]);
    expect(view.summary.owed).toBe(5); // one obliged KSI × five slots
    expect(view.summary.optional).toEqual(["KSI-SVC-RUD"]);
    expect(view.summary.filled).toBe(1);
  });

  it("counts the lost, the stale and what is still yours", () => {
    const view = viewWith([
      cell(1, { present: true, body: body({ freshMet: false }) }),
      cell(2, { absent: { reason: "no file at the declared path", at: "2026-09-12T00:00:00.000Z", path: "a.md" } }),
      cell(3),
      cell(4),
      cell(5),
    ]);
    expect(view.summary.stale).toBe(1);
    expect(view.summary.lost).toBe(1);
    expect(view.summary.yours).toBe(1); // 3 is empty; 1 is filled
  });

  it("renders a cell's source and age, marking a body past its clock", () => {
    const view = viewWith([
      cell(1, { present: true, body: body() }),
      cell(2, { present: true, body: body({ source: "computed", freshMet: false }) }),
      cell(3),
      cell(4, { derivable: true }),
      cell(5, {
        absent: { reason: "the declared file is empty", at: "2026-09-12T00:00:00.000Z", path: "a.md" },
      }),
    ]);
    const out = renderArtifacts(view, NOW);
    expect(out).toContain("auth 3d");
    expect(out).toContain("comp 3d!");
    expect(out).toContain("deriv");
    expect(out).toContain("gone");
    expect(out).toContain("optional at this class");
  });

  it("prints the rule's own text for every slot in the long view", () => {
    const view = viewWith([cell(1, { present: true, body: body() })]);
    const out = renderArtifact(view, view.rows[0]!, NOW);
    expect(out).toContain("Explanation of measures…");
    expect(out).toContain("Verification that the automation in place is accurate…");
    expect(out).toContain("review none on record"); // §13.2: absence is printed
    expect(out).toContain("This one is yours to write");
  });
});

describe("artifacts check (R1.5)", () => {
  it("passes on an empty plane — how much is owed is not this command's question", () => {
    const view = viewWith([cell(1), cell(2), cell(3), cell(4), cell(5)]);
    expect(checkArtifacts(view)).toEqual([]);
    expect(renderArtifactCheck(view, [])).toContain("whether what EXISTS is sound");
  });

  it("fails on a declaration that stopped resolving", () => {
    const view = viewWith([
      cell(1, { absent: { reason: "no file at the declared path", at: "2026-09-12T00:00:00.000Z", path: "a.md" } }),
    ]);
    const problems = checkArtifacts(view);
    expect(problems).toHaveLength(1);
    expect(problems[0]!.problem).toContain("no file at the declared path");
  });

  it("fails on a body past its three-month window", () => {
    const view = viewWith([cell(1, { present: true, body: body({ freshMet: false }) })]);
    expect(checkArtifacts(view)[0]!.problem).toContain("VDR-TFR-NMV");
  });

  it("fails on a judgment about bytes that were revised out from under it", () => {
    const view = viewWith([
      cell(1, {
        present: true,
        body: body(),
        judgment: {
          digest: "j".repeat(64),
          action: "sufficient",
          justification: "reviewed",
          proposedBy: "a",
          approvedBy: "b",
          timestamp: "2026-09-01T00:00:00.000Z",
          appliesToLiveBody: false,
        },
      }),
    ]);
    expect(checkArtifacts(view)[0]!.problem).toContain("unjudged until it is judged again");
  });
});

describe("artifacts scaffold (R1.5)", () => {
  it("fills what was measured and leaves the claim blank — it does not draft", () => {
    const text = scaffoldBody({ catalog, ksiId: "KSI-SVC-SIN", artifact: 1 });
    expect(text).toContain("Explanation of measures…"); // the rule's own words
    expect(text).toContain("Information is encrypted or otherwise secured."); // the indicator
    expect(text).toContain("## Your statement");
    expect(text).toContain("rampscan will not draft it");
    // the reason-for-absence path is offered as an equal, not as a failure
    expect(text).toContain("…or the reason there are no measures");
    expect(text).toContain("First-class alternative, not a failure");
    // and nothing resembling a claim has been written under either heading
    const claim = text.split("## Your statement")[1]!.split("---")[0]!;
    expect(claim.replace(/<!--[\s\S]*?-->/g, "").trim()).toBe("## …or the reason there are no measures");
  });

  it("carries the register's own numbers into the computed half", () => {
    const text = scaffoldBody({
      catalog,
      ksiId: "KSI-SVC-SIN",
      artifact: 1,
      register: {
        ...register([]),
        methods: [
          {
            methodId: "pipeline:secrets@history",
            source: "pipeline",
            automated: true,
            clock: "machine",
            standing: "full",
            state: "evidenced",
            bundleDigest: "b".repeat(64),
            freshAsOf: "2026-09-10T00:00:00.000Z",
            window: { num: 7, unit: "days" },
            freshMet: true,
          },
        ],
        automatedMethods: 1,
        floorMet: true,
      },
    });
    expect(text).toContain("1 validation method(s)");
    expect(text).toContain("meets");
    expect(text).toContain("`pipeline:secrets@history`");
    expect(text).toContain("nothing in this section is signed by writing it here");
  });

  it("says so plainly when the ledger has nothing folded for the indicator", () => {
    expect(scaffoldBody({ catalog, ksiId: "KSI-SVC-SIN", artifact: 3 })).toContain(
      "Nothing is folded for this indicator yet",
    );
  });

  it("writes the stub and hands back a paste-ready declaration", async () => {
    const root = await mkdtemp(join(tmpdir(), "rampscan-r15-"));
    const result = await scaffoldArtifact({ catalog, ksiId: "KSI-SVC-SIN", artifact: 1, root });
    expect(result.path).toBe(scaffoldPath("KSI-SVC-SIN", 1));
    expect(await readFile(join(root, result.path), "utf8")).toBe(result.body);
    expect(result.declaration).toMatchObject({ ksi: "KSI-SVC-SIN", artifact: 1 });
  });

  it("REFUSES to overwrite a written artifact", async () => {
    const root = await mkdtemp(join(tmpdir(), "rampscan-r15-over-"));
    await mkdir(join(root, "docs", "ksi"), { recursive: true });
    await writeFile(join(root, scaffoldPath("KSI-SVC-SIN", 1)), "# the real thing\n");
    await expect(
      scaffoldArtifact({ catalog, ksiId: "KSI-SVC-SIN", artifact: 1, root }),
    ).rejects.toThrow(/will not overwrite/);
    // and the written artifact is untouched
    expect(await readFile(join(root, scaffoldPath("KSI-SVC-SIN", 1)), "utf8")).toBe(
      "# the real thing\n",
    );
  });

  it("refuses a KSI outside the pinned catalog", async () => {
    const root = await mkdtemp(join(tmpdir(), "rampscan-r15-bad-"));
    await expect(
      scaffoldArtifact({ catalog, ksiId: "KSI-NOPE", artifact: 1, root }),
    ).rejects.toThrow(/unknown KSI/);
  });
});
