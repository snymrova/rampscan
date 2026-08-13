import { describe, expect, it } from "vitest";
import type { PipelineRecipe, RecipeAssertion } from "@rampscan/schema";
import { buildScanResult, evaluateAssertion, joinRecipeResults } from "../src/index.js";
import type { JoinInput, RunResult } from "../src/index.js";

const NOW = new Date("2026-08-13T00:00:00Z");

function recipe(over: Partial<PipelineRecipe> = {}): PipelineRecipe {
  return {
    id: "r-test",
    ksi_ids: ["KSI-SCR-MIT"],
    control_ids: ["si-7.1"],
    evidence: "test evidence",
    collection: { kind: "pipeline", collector: "c1" },
    expected_output: "rows",
    cadence: "weekly",
    automatable: "full",
    anchor: "commit",
    ...over,
  };
}

function run(over: Partial<RunResult> = {}): RunResult {
  return {
    findings: [],
    artifacts: [],
    observations: {},
    anchors: {},
    toolVersion: "1.0.0",
    exitCode: 0,
    ...over,
  };
}

function join(recipes: PipelineRecipe[], runs: Map<string, RunResult>) {
  const input: JoinInput = {
    recipes,
    runs,
    workspace: { root: "/x", repo: "x", commit: "a".repeat(40) },
    datasetVersion: "2026.07.14.01",
    runId: "run-1",
    now: NOW,
  };
  return joinRecipeResults(input);
}

describe("assertion evaluation", () => {
  const rows = [
    { name: "a", pinned: true, count: 3, when: "2026-08-10T00:00:00Z", sev: "HIGH" },
    { name: "b", pinned: false, count: 9, when: "2026-01-01T00:00:00Z", sev: "LOW" },
  ];
  const assert = (a: Partial<RecipeAssertion>) =>
    evaluateAssertion({ field: "x", op: "eq", description: "d", ...a } as RecipeAssertion, rows, NOW);

  it("row-wise eq fails when any row misses, and names an offender", () => {
    const r = assert({ field: "pinned", op: "eq", value: true });
    expect(r.passed).toBe(false);
    expect(r.detail).toContain('"name":"b"');
  });

  it("where filters before evaluating", () => {
    const r = assert({
      field: "pinned",
      op: "eq",
      value: true,
      where: [{ field: "name", op: "eq", value: "a" }],
    });
    expect(r.passed).toBe(true);
  });

  it("row-wise ops pass vacuously on an empty filtered set", () => {
    const r = assert({
      field: "pinned",
      op: "eq",
      value: true,
      where: [{ field: "name", op: "eq", value: "zzz" }],
    });
    expect(r.passed).toBe(true);
  });

  it("count_eq counts the where-filtered set", () => {
    const r = assert({
      op: "count_eq",
      value: 0,
      where: [{ field: "sev", op: "in", value: ["CRITICAL", "HIGH"] }],
    });
    expect(r.passed).toBe(false);
    expect(r.detail).toContain("got 1");
  });

  it("count_lte compares filtered count against the bound", () => {
    expect(assert({ op: "count_lte", value: 2 }).passed).toBe(true);
    expect(assert({ op: "count_lte", value: 1 }).passed).toBe(false);
  });

  it("exists / not_exists check field presence", () => {
    expect(assert({ field: "name", op: "exists" }).passed).toBe(true);
    expect(assert({ field: "ghost", op: "not_exists" }).passed).toBe(true);
    expect(assert({ field: "ghost", op: "exists" }).passed).toBe(false);
  });

  it("lte / gte are numeric", () => {
    expect(assert({ field: "count", op: "lte", value: 9 }).passed).toBe(true);
    expect(assert({ field: "count", op: "gte", value: 4 }).passed).toBe(false);
  });

  it("max_age_days measures against the run clock", () => {
    const fresh = assert({
      field: "when",
      op: "max_age_days",
      value: 7,
      where: [{ field: "name", op: "eq", value: "a" }],
    });
    expect(fresh.passed).toBe(true);
    const stale = assert({ field: "when", op: "max_age_days", value: 7 });
    expect(stale.passed).toBe(false);
  });

  it("dotted field paths traverse nested objects", () => {
    const r = evaluateAssertion(
      { field: "meta.deep", op: "eq", value: 1, description: "d" },
      [{ meta: { deep: 1 } }],
      NOW,
    );
    expect(r.passed).toBe(true);
  });
});

describe("the join (C4)", () => {
  const passing: RecipeAssertion[] = [
    { field: "ok", op: "eq", value: true, description: "everything ok" },
  ];

  it("evidenced when every assertion passes", () => {
    const [r] = join(
      [recipe({ assertions: passing })],
      new Map([["c1", run({ observations: { "r-test": [{ ok: true }] } })]]),
    );
    expect(r!.verdict).toBe("evidenced");
  });

  it("violated when any assertion fails", () => {
    const [r] = join(
      [recipe({ assertions: passing })],
      new Map([["c1", run({ observations: { "r-test": [{ ok: false }] } })]]),
    );
    expect(r!.verdict).toBe("violated");
    expect(r!.assertions[0]!.passed).toBe(false);
  });

  it("unevidenced when the collector is not registered", () => {
    const [r] = join([recipe({ assertions: passing })], new Map());
    expect(r!.verdict).toBe("unevidenced");
    expect(r!.reason).toContain("not registered");
  });

  it("unevidenced when the collector skipped, carrying the skip reason", () => {
    const [r] = join(
      [recipe({ assertions: passing })],
      new Map([["c1", run({ skipped: { reason: "no Dockerfile" } })]]),
    );
    expect(r!.verdict).toBe("unevidenced");
    expect(r!.reason).toContain("no Dockerfile");
  });

  it("unevidenced when the collector ran but observed nothing for the recipe", () => {
    const [r] = join(
      [recipe({ assertions: passing })],
      new Map([["c1", run({ observations: { other: [] } })]]),
    );
    expect(r!.verdict).toBe("unevidenced");
    expect(r!.reason).toContain("no observation");
  });

  it("unevidenced when the recipe has no machine assertions yet (route-auth until M4)", () => {
    const [r] = join(
      [recipe()],
      new Map([["c1", run({ observations: { "r-test": [{ ok: true }] } })]]),
    );
    expect(r!.verdict).toBe("unevidenced");
    expect(r!.reason).toContain("no machine assertions");
  });

  it("an empty observation with a count_eq 0 assertion is evidenced — absence proven, not assumed", () => {
    const [r] = join(
      [recipe({ assertions: [{ field: "leak", op: "count_eq", value: 0, description: "no leaks" }] })],
      new Map([["c1", run({ observations: { "r-test": [] } })]]),
    );
    expect(r!.verdict).toBe("evidenced");
  });

  it("buildScanResult totals the three registers and records skips + tool versions", () => {
    const input: JoinInput = {
      recipes: [
        recipe({ id: "a", assertions: passing }),
        recipe({ id: "b", assertions: passing, collection: { kind: "pipeline", collector: "c2" } }),
        recipe({ id: "c" }),
      ],
      runs: new Map([
        ["c1", run({ observations: { a: [{ ok: true }], c: [] } })],
        ["c2", run({ skipped: { reason: "tool missing" }, toolVersion: "absent" })],
      ]),
      workspace: { root: "/x", repo: "x", commit: "a".repeat(40) },
      datasetVersion: "2026.07.14.01",
      runId: "run-1",
      now: NOW,
    };
    const result = buildScanResult(input);
    expect(result.summary).toEqual({ evidenced: 1, violated: 0, unevidenced: 2 });
    expect(result.skipped_collectors).toEqual([{ collector: "c2", reason: "tool missing" }]);
    expect(result.tool_versions).toEqual({ c1: "1.0.0", c2: "absent" });
    expect(result.commit).toBe("a".repeat(40));
  });
});
