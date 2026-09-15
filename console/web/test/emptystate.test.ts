import { describe, expect, it } from "vitest";
import { absentReason } from "@rampscan/collectors";
import { classifySkip, explainUnevidenced, newestRunOf } from "../lib/emptystate";
import type { CollectorRunRecord, RegisterRecord, ScanRunRecord } from "../lib/types";

// The console test floor (docs/PLAN-SOUNDNESS.md S4-3, #141). Not a coverage
// push: `console/web` is 13,000 lines with one Playwright smoke, and a test
// count is as easy a vacuous pass as a recipe count (ground rule 7). The
// floor is the pure functions the board's correctness rests on, starting with
// the one whose header already said "pinned by test" and had none:
// `classifySkip` reads the collectors' skip reasons by regex, so a reworded
// reason in `packages/collectors` would silently fall off the queue. The
// pin below imports the real producer, `absentReason`, instead of retyping
// its sentence.

const run = (over: Partial<ScanRunRecord> & { collectors?: CollectorRunRecord[] }): ScanRunRecord => ({
  id: "r1",
  digest: "sha256:run",
  run_id: "run-1",
  repo: "acme",
  commit_sha: "a".repeat(40),
  trigger_kind: "manual",
  started_at: "2026-09-15T10:00:00.000Z",
  run_timestamp: "2026-09-15T10:00:00.000Z",
  duration_ms: 1,
  dataset_version: "2026.07.14.01",
  collectors: [],
  ...over,
});

const collector = (over: Partial<CollectorRunRecord>): CollectorRunRecord => ({
  collector: "osv-scanner",
  tool_version: "1",
  duration_ms: 1,
  exit_code: 0,
  findings: 0,
  tools: [],
  invocations: [],
  artifacts: [],
  cache: { state: "miss" },
  ...over,
});

const row = (over: Partial<RegisterRecord>): RegisterRecord => ({
  id: "row",
  repo: "acme",
  recipe_id: "no-critical-reachable-advisories",
  ksi_ids: ["KSI-SVC-VRI"],
  control_ids: [],
  state: "unevidenced",
  cadence: "daily",
  collector: "osv-scanner",
  plain: null,
  run_id: "",
  bundle_digest: "",
  fresh_as_of: "",
  commit_sha: "",
  pointers: null,
  population: null,
  introduced_at: "",
  introducing_commit: "",
  scoping: null,
  ...over,
});

describe("classifySkip — pinned to the collectors' own wording", () => {
  it("the real absent-tool sentence is a tool-missing skip, and actionable", () => {
    const c = classifySkip(absentReason("osv-scanner"));
    expect(c).toEqual({
      actionable: true,
      category: "tool-missing",
      hint: "install the tool or Docker — `pnpm run doctor` lists what's missing and how to get it",
    });
  });

  it("the collectors' failed-run shape is a collector failure, and actionable", () => {
    // the shape six collectors write: `${name} failed (exit ${code}, via ${runtime}): ${stderr}`
    // (checkov, gitleaks, osv-scanner, semgrep, spectral, syft)
    const c = classifySkip("semgrep failed (exit 2, via docker): rule parse error");
    expect(c.category).toBe("collector-failed");
    expect(c.actionable).toBe(true);
    expect(c.hint).toContain("re-scan");
  });

  it("anything else is an honest skip — no hint, no task", () => {
    expect(classifySkip("no Dockerfile in this repository")).toEqual({ actionable: false, category: "honest-skip" });
    expect(classifySkip("")).toEqual({ actionable: false, category: "honest-skip" });
  });
});

describe("newestRunOf — the run whose outcome a row reflects", () => {
  it("picks the newest timestamp for the row's repo, breaking ties on run_id, and ignores other repos", () => {
    const runs = [
      run({ id: "a", run_id: "run-a", run_timestamp: "2026-09-14T00:00:00.000Z" }),
      run({ id: "b", run_id: "run-b", run_timestamp: "2026-09-15T00:00:00.000Z" }),
      run({ id: "c", run_id: "run-c", run_timestamp: "2026-09-15T00:00:00.000Z" }),
      run({ id: "z", run_id: "run-z", repo: "other", run_timestamp: "2026-09-16T00:00:00.000Z" }),
    ];
    expect(newestRunOf(runs, "acme")?.run_id).toBe("run-c");
    expect(newestRunOf(runs, "nobody")).toBeNull();
    expect(newestRunOf([], "acme")).toBeNull();
  });
});

describe("explainUnevidenced — sentences only, never a state", () => {
  const loaded = { runsLoaded: true, runCount: 1 };

  it("is silent for a row that needs no explaining, and silent while runs are loading", () => {
    for (const state of ["evidenced", "violated", "notApplicable"] as const) {
      expect(explainUnevidenced({ row: row({ state }), run: run({}), ...loaded })).toBeNull();
    }
    expect(explainUnevidenced({ row: row({}), run: null, runsLoaded: false, runCount: 0 })).toBeNull();
  });

  it("no collector: the recipe left the catalog", () => {
    const e = explainUnevidenced({ row: row({ collector: "" }), run: run({}), ...loaded })!;
    expect(e.source).toBe("no-collector");
    expect(e.actionable).toBe(true);
    expect(e.runId).toBeUndefined();
  });

  it("no run record: two different absences, told apart by how many runs exist", () => {
    const none = explainUnevidenced({ row: row({}), run: null, runsLoaded: true, runCount: 0 })!;
    expect(none.source).toBe("no-run-record");
    expect(none.reason).toContain("no scan has appended a run record");
    const older = explainUnevidenced({ row: row({}), run: null, runsLoaded: true, runCount: 3 })!;
    expect(older.source).toBe("no-run-record");
    expect(older.reason).toContain("newest 3 runs");
    expect(older.action).toContain("pnpm rampscan scan");
    expect(older.collector).toBe("osv-scanner");
  });

  it("dispatched-and-skipped and never-dispatched are different facts with different fixes", () => {
    const skipped = explainUnevidenced({
      row: row({}),
      run: run({ collectors: [collector({ skip_reason: absentReason("osv-scanner") })] }),
      ...loaded,
    })!;
    expect(skipped.source).toBe("skip-reason");
    expect(skipped.actionable).toBe(true);
    expect(skipped.reason).toContain(absentReason("osv-scanner")); // quoted, not paraphrased
    expect(skipped.runId).toBe("run-1");

    const notDispatched = explainUnevidenced({
      row: row({}),
      run: run({ collectors: [collector({ collector: "syft" })] }),
      ...loaded,
    })!;
    expect(notDispatched.source).toBe("collector-not-dispatched");
    expect(notDispatched.reason).toContain('never dispatched "osv-scanner"');
    expect(notDispatched.actionable).toBe(true);
  });

  it("an honest skip is explained and is not a task", () => {
    const e = explainUnevidenced({
      row: row({}),
      run: run({ collectors: [collector({ skip_reason: "no container image is built by this repository" })] }),
      ...loaded,
    })!;
    expect(e.source).toBe("skip-reason");
    expect(e.actionable).toBe(false);
    expect(e.action).toContain("nothing to fix");
  });

  it("the collector ran and the cell is still empty: no reason is invented", () => {
    const e = explainUnevidenced({ row: row({}), run: run({ collectors: [collector({})] }), ...loaded })!;
    expect(e.source).toBe("ran-no-evidence");
    expect(e.actionable).toBe(false);
    expect(e.reason).not.toMatch(/no findings|passed|clean/i);
  });

  it("no path through the module produces a state, a verdict or a count", () => {
    const inputs = [
      { row: row({ collector: "" }), run: run({}), ...loaded },
      { row: row({}), run: null, runsLoaded: true, runCount: 0 },
      { row: row({}), run: run({ collectors: [collector({ skip_reason: "x failed (exit 1, via path): y" })] }), ...loaded },
      { row: row({}), run: run({ collectors: [collector({})] }), ...loaded },
    ];
    for (const input of inputs) {
      const e = explainUnevidenced(input)!;
      expect(Object.keys(e).sort()).toEqual(
        expect.arrayContaining(["source", "reason", "action", "actionable"]),
      );
      for (const key of Object.keys(e)) {
        expect(["source", "reason", "action", "actionable", "runId", "collector"]).toContain(key);
      }
    }
  });
});
