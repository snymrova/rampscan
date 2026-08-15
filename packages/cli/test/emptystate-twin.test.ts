import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import { absentReason } from "@rampscan/collectors";

// K1 — guided empty states, tested through the console's own copy (the twin
// posture used by every console library here).
//
// This module exists in the narrow gap J1 left open, and the gap is worth
// stating precisely, because K1 needed the standing rule SHARPENED rather than
// obeyed as written. J1: the board is folded from evidence and scoping alone —
// a run record names a repo too, and letting it introduce cells would make the
// coverage board partly a function of the run log. J3 honoured that by having
// the board fetch no run data at all.
//
// The precise rule, and the one this file pins:
//
//   which cells exist and what state each is in — evidence and scoping ONLY;
//   why an already-drawn empty cell is empty — the run log only, because it is
//   recorded nowhere else.
//
// So the tests below check two different things: that each of the five
// absences is told apart from the other four, and that no output of this
// module can carry a state.

interface EmptyStateExplanation {
  source: string;
  reason: string;
  action: string;
  actionable: boolean;
  runId?: string;
  collector?: string;
}

interface EmptyStateModule {
  explainUnevidenced(input: {
    row: Record<string, unknown>;
    run: unknown;
    runsLoaded: boolean;
    runCount: number;
  }): EmptyStateExplanation | null;
  newestRunOf(runs: unknown[], repo: string): unknown;
  classifySkip(reason: string): { actionable: boolean; category: string; hint?: string };
}

const consoleLib = join(
  dirname(fileURLToPath(import.meta.url)),
  "../../../console/web/lib/emptystate.ts",
);

let M: EmptyStateModule;

beforeAll(async () => {
  M = (await import(consoleLib)) as EmptyStateModule;
});

const REPO = "fixtures/app";

function row(overrides: Record<string, unknown> = {}) {
  return {
    repo: REPO,
    recipe_id: "iac-baseline-clean",
    state: "unevidenced",
    collector: "checkov",
    run_id: "",
    fresh_as_of: "",
    plain: null,
    ...overrides,
  };
}

function collector(overrides: Record<string, unknown> = {}) {
  return {
    collector: "checkov",
    tool_version: "checkov 3.2.0",
    duration_ms: 100,
    exit_code: 0,
    findings: 0,
    tools: [],
    invocations: [],
    artifacts: [],
    cache: { state: "miss" },
    ...overrides,
  };
}

function run(overrides: Record<string, unknown> = {}) {
  return {
    id: "r1",
    digest: "d".repeat(64),
    run_id: "run-2026-08-15T10:00:00.000Z",
    repo: REPO,
    commit_sha: "c".repeat(40),
    trigger_kind: "manual",
    started_at: "2026-08-15T09:59:00.000Z",
    run_timestamp: "2026-08-15T10:00:00.000Z",
    duration_ms: 60_000,
    dataset_version: "2026.07.14.01",
    collectors: [collector()],
    ...overrides,
  };
}

describe("explainUnevidenced: only empty cells, and only once they can be explained", () => {
  it("says nothing about a cell that is not empty", () => {
    for (const state of ["evidenced", "violated", "notApplicable"]) {
      expect(
        M.explainUnevidenced({ row: row({ state }), run: run(), runsLoaded: true, runCount: 1 }),
        state,
      ).toBeNull();
    }
  });

  it("says nothing while the run records are still loading — silence is not absence", () => {
    // the J5 rule, repeated here because the failure mode is the same: a
    // sentence written during the gap would be a claim about data this page
    // has not read yet, and it would flicker into a different one on arrival
    expect(
      M.explainUnevidenced({ row: row(), run: null, runsLoaded: false, runCount: 0 }),
    ).toBeNull();
  });
});

describe("explainUnevidenced: five absences, told apart", () => {
  it("a recipe that left the catalog names no collector and says so", () => {
    const why = M.explainUnevidenced({
      row: row({ collector: "" }),
      run: run(),
      runsLoaded: true,
      runCount: 1,
    })!;
    expect(why.source).toBe("no-collector");
    expect(why.reason).toContain("no collector claims this recipe");
    // and never a collector guessed from the run's tool names (J3's refusal)
    expect(why.collector).toBeUndefined();
    expect(why.reason).not.toContain("checkov");
  });

  it("no run record at all reads differently from one aged out of the cap", () => {
    const none = M.explainUnevidenced({ row: row(), run: null, runsLoaded: true, runCount: 0 })!;
    expect(none.source).toBe("no-run-record");
    expect(none.reason).toContain("no scan has appended a run record");

    const capped = M.explainUnevidenced({ row: row(), run: null, runsLoaded: true, runCount: 200 })!;
    expect(capped.source).toBe("no-run-record");
    expect(capped.reason).toContain("newest 200 runs");
    expect(capped.reason).toContain("The ledger still holds any older ones.");
    // two different facts, never one message covering both
    expect(capped.reason).not.toBe(none.reason);
  });

  it("a collector the run never dispatched is not a collector that ran and skipped", () => {
    const why = M.explainUnevidenced({
      row: row({ collector: "grype" }),
      run: run(),
      runsLoaded: true,
      runCount: 1,
    })!;
    expect(why.source).toBe("collector-not-dispatched");
    expect(why.reason).toContain("never dispatched");
    expect(why.reason).toContain("neither ran nor skipped");
    expect(why.runId).toBe("run-2026-08-15T10:00:00.000Z");
  });

  it("a skip quotes the collector's own words and turns them into a move", () => {
    // pinned against the REAL producer: absentReason is what a collector
    // actually writes, so a reworded reason breaks this test rather than
    // silently rendering as an unactionable shrug
    const reason = absentReason("checkov");
    const why = M.explainUnevidenced({
      row: row(),
      run: run({ collectors: [collector({ skip_reason: reason })] }),
      runsLoaded: true,
      runCount: 1,
    })!;
    expect(why.source).toBe("skip-reason");
    expect(why.reason).toContain(reason);
    expect(why.actionable).toBe(true);
    expect(why.action).toContain("pnpm doctor");
  });

  it("an honest skip is explained and is NOT dressed up as a task", () => {
    const why = M.explainUnevidenced({
      row: row(),
      run: run({
        collectors: [collector({ skip_reason: "no IaC files in the committed tree" })],
      }),
      runsLoaded: true,
      runCount: 1,
    })!;
    expect(why.source).toBe("skip-reason");
    expect(why.reason).toContain("no IaC files in the committed tree");
    expect(why.actionable).toBe(false);
    expect(why.action).toContain("nothing to fix here");
  });

  it("a collector that ran and produced nothing says exactly that, and guesses no reason", () => {
    const why = M.explainUnevidenced({
      row: row(),
      run: run({ collectors: [collector()] }),
      runsLoaded: true,
      runCount: 1,
    })!;
    expect(why.source).toBe("ran-no-evidence");
    expect(why.reason).toContain("ran in the newest recorded scan");
    // the run record has no reason to offer for this one, and inventing
    // "no findings" would be guessing at a verdict
    expect(why.reason).not.toMatch(/no findings|passed|clean/i);
    expect(why.actionable).toBe(false);
  });

  it("every source is distinct — five absences, five sentences", () => {
    const sources = new Set(
      [
        M.explainUnevidenced({ row: row({ collector: "" }), run: run(), runsLoaded: true, runCount: 1 }),
        M.explainUnevidenced({ row: row(), run: null, runsLoaded: true, runCount: 0 }),
        M.explainUnevidenced({ row: row({ collector: "grype" }), run: run(), runsLoaded: true, runCount: 1 }),
        M.explainUnevidenced({
          row: row(),
          run: run({ collectors: [collector({ skip_reason: absentReason("checkov") })] }),
          runsLoaded: true,
          runCount: 1,
        }),
        M.explainUnevidenced({ row: row(), run: run(), runsLoaded: true, runCount: 1 }),
      ].map((why) => why!.source),
    );
    expect(sources.size).toBe(5);
  });
});

describe("the rule this module had to stay inside", () => {
  it("no explanation states a register state — it explains a cell, it never moves one", () => {
    // J1's precedent, same shape: that test greps a run record's canonical
    // bytes for all four state words. Here the same four words are banned from
    // every sentence this module can produce, so a future edit that started
    // narrating verdicts fails rather than quietly making the board's
    // explanations into a second opinion about it.
    const outputs = [
      M.explainUnevidenced({ row: row({ collector: "" }), run: run(), runsLoaded: true, runCount: 1 }),
      M.explainUnevidenced({ row: row(), run: null, runsLoaded: true, runCount: 0 }),
      M.explainUnevidenced({ row: row(), run: null, runsLoaded: true, runCount: 12 }),
      M.explainUnevidenced({ row: row({ collector: "grype" }), run: run(), runsLoaded: true, runCount: 1 }),
      M.explainUnevidenced({
        row: row(),
        run: run({ collectors: [collector({ skip_reason: absentReason("checkov") })] }),
        runsLoaded: true,
        runCount: 1,
      }),
      M.explainUnevidenced({ row: row(), run: run(), runsLoaded: true, runCount: 1 }),
    ];
    for (const why of outputs) {
      const text = JSON.stringify(why);
      for (const word of ["evidenced", "violated", "unevidenced", "notApplicable"]) {
        expect(new RegExp(`\\b${word}\\b`).test(text), `${word} in ${text}`).toBe(false);
      }
    }
  });

  it("returns sentences and flags only — there is no field here that could carry a verdict", () => {
    const why = M.explainUnevidenced({ row: row(), run: run(), runsLoaded: true, runCount: 1 })!;
    expect(Object.keys(why).sort()).toEqual(
      ["action", "actionable", "collector", "reason", "runId", "source"].sort(),
    );
    expect(typeof why.actionable).toBe("boolean");
    for (const key of ["reason", "action", "source"] as const) {
      expect(typeof why[key], key).toBe("string");
    }
  });
});

describe("newestRunOf: which scan an empty row is explained against", () => {
  it("picks the newest run of THIS repo and ignores every other repo's", () => {
    const mine = run({ run_id: "run-b", run_timestamp: "2026-08-15T12:00:00.000Z" });
    const older = run({ run_id: "run-a", run_timestamp: "2026-08-15T10:00:00.000Z" });
    const theirs = run({
      run_id: "run-c",
      repo: "other/repo",
      run_timestamp: "2026-08-15T23:00:00.000Z",
    });
    expect((M.newestRunOf([older, mine, theirs], REPO) as { run_id: string }).run_id).toBe("run-b");
  });

  it("breaks a timestamp tie on the run id, so the choice is total and stable", () => {
    const a = run({ run_id: "run-a" });
    const b = run({ run_id: "run-b" });
    expect((M.newestRunOf([a, b], REPO) as { run_id: string }).run_id).toBe("run-b");
    expect((M.newestRunOf([b, a], REPO) as { run_id: string }).run_id).toBe("run-b");
  });

  it("returns null when the projection holds no run of this repo", () => {
    expect(M.newestRunOf([], REPO)).toBeNull();
    expect(M.newestRunOf([run({ repo: "other/repo" })], REPO)).toBeNull();
  });
});
