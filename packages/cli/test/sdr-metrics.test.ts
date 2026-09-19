import { describe, expect, it } from "vitest";
import type { LedgerEntry } from "@rampscan/core";
import type { EvidenceBundle, MethodScope, PipelineRecipe } from "@rampscan/schema";
import { methodsOfRecipe } from "@rampscan/schema";
import {
  completedDays,
  dailyOwed,
  dailyRuns,
  daySeries,
  dayEnd,
  expandRuns,
  metricSummaries,
  reachDays,
  summarize,
  type MetricsInput,
} from "../src/sdr-metrics.js";

// R3.1 (#106, docs/PLAN-HISTORY.md): a KSI's metric for a day is its D6
// status and counts, refolded at the day's last millisecond (H1, H2). A day
// before the first scan is absent, never zero (H3).

let counter = 0;
function evidence(timestamp: string, verdict: "evidenced" | "violated" = "evidenced"): LedgerEntry {
  const bundle: EvidenceBundle = {
    _type: "https://in-toto.io/Statement/v1",
    subject: [{ name: "x", digest: { sha256: "e".repeat(64) } }],
    predicateType: "https://rampscan.dev/evidence/v1",
    predicate: {
      recipe_id: "covered",
      ksi_ids: ["KSI-SCR-MIT"],
      control_ids: ["si-7.1"],
      verdict,
      repo: "fixtures/app",
      commit: "1".repeat(40),
      anchor_paths: [{ path: "f", contentHash: "a".repeat(64) }],
      dataset_version: "2026.07.14.01",
      tool_versions: { "repo-facts": "0.1.0" },
      assertions: [{ description: "check", passed: verdict === "evidenced" }],
      cadence: "continuous",
      run_id: `run-${timestamp}`,
      timestamp,
    },
  };
  return { digest: `digest-${counter++}`, bundle, appendedAt: timestamp };
}

const recipe: PipelineRecipe = {
  id: "covered",
  ksi_ids: ["KSI-SCR-MIT"],
  control_ids: ["si-7.1"],
  evidence: "test recipe",
  collection: { kind: "pipeline", collector: "repo-facts" },
  expected_output: "rows",
  cadence: "weekly",
  automatable: "full",
  anchor: "commit",
};
const scope: MethodScope = { population: "checkout", history: false, gitignored: "excluded" };

function input(entries: LedgerEntry[], asOf: string): MetricsInput {
  return {
    entries,
    fold: {
      recipes: [recipe],
      methods: methodsOfRecipe(recipe, scope),
      ksiIds: ["KSI-CMT-CHG", "KSI-SCR-MIT"],
      methodFloor: 1,
      historyFloorMonths: null,
      machineWindow: { num: 7, unit: "days" },
      nonMachineWindow: { num: 3, unit: "months" },
    },
    repo: "fixtures/app",
    ksiIds: ["KSI-CMT-CHG", "KSI-SCR-MIT"],
    asOf,
  };
}

const AS_OF = "2026-08-20T12:00:00.000Z";
const LEDGER = [evidence("2026-08-01T00:00:00.000Z"), evidence("2026-08-15T00:00:00.000Z", "violated")];

describe("the day series (R3.1, H2/H3)", () => {
  it("holds only completed UTC days, the last one ending before the instant", () => {
    const days = completedDays(AS_OF, 3);
    expect(days).toEqual(["2026-08-17", "2026-08-18", "2026-08-19"]);
    // an instant on a day's last millisecond completes that day
    expect(completedDays(dayEnd("2026-08-19"), 1)).toEqual(["2026-08-19"]);
    expect(completedDays("2026-08-20T00:00:00.000Z", 1)).toEqual(["2026-08-19"]);
  });

  it("reads a day before the first scan as absent, never as zero", () => {
    const series = daySeries(input(LEDGER, AS_OF));
    expect(series.days).toHaveLength(365);
    expect(series.coveredFrom).toBe("2026-08-01");
    const mit = series.byKsi.get("KSI-SCR-MIT")!;
    const at = (day: string) => mit[series.days.indexOf(day)];
    expect(at("2026-07-31")).toBeUndefined();
    expect(at("2026-08-01")).toBeDefined();
    // a KSI no method reaches is still covered from the first scan: its status is a fact
    expect(series.byKsi.get("KSI-CMT-CHG")![series.days.indexOf("2026-08-01")]?.status).toBe(
      "Not Implemented",
    );
  });

  it("moves a count on the day time makes evidence stale, with no new statement", () => {
    const series = daySeries(input(LEDGER, AS_OF));
    const mit = series.byKsi.get("KSI-SCR-MIT")!;
    const at = (day: string) => mit[series.days.indexOf(day)]!;
    expect(at("2026-08-07").staleMethods).toBe(0);
    expect(at("2026-08-08").staleMethods).toBe(1);
    expect(at("2026-08-07").status).toBe("Partially Implemented");
  });

  it("changes the status on the day a violation lands", () => {
    const series = daySeries(input(LEDGER, AS_OF));
    const mit = series.byKsi.get("KSI-SCR-MIT")!;
    const at = (day: string) => mit[series.days.indexOf(day)]!;
    expect(at("2026-08-14").status).toBe("Partially Implemented");
    expect(at("2026-08-15").status).toBe("Not Implemented");
    expect(at("2026-08-15").violatedMethods).toBe(1);
  });

  it("is deterministic: the same ledger at the same instant gives the same bytes", () => {
    const a = JSON.stringify(metricSummaries(daySeries(input(LEDGER, AS_OF))));
    const b = JSON.stringify(metricSummaries(daySeries(input([...LEDGER].reverse(), AS_OF))));
    expect(a).toBe(b);
  });

  it("ignores statements after the instant", () => {
    const later = [...LEDGER, evidence("2026-08-21T00:00:00.000Z")];
    expect(JSON.stringify(metricSummaries(daySeries(input(later, AS_OF))))).toBe(
      JSON.stringify(metricSummaries(daySeries(input(LEDGER, AS_OF)))),
    );
  });

  it("covers nothing when the ledger never scanned the offering", () => {
    const series = daySeries({ ...input(LEDGER, AS_OF), repo: "elsewhere" });
    expect(series.coveredFrom).toBeUndefined();
    const s = metricSummaries(series)["KSI-SCR-MIT"]!;
    expect(s.pastYear).toMatchObject({ daysInWindow: 365, daysCovered: 0, daysAbsent: 365 });
    expect(s.pastYear.lastStatus).toBeUndefined();
    expect(s.pastYear.counts).toBeUndefined();
  });
});

describe("the summaries (R3.1, H7)", () => {
  it("states the window, coverage, days per status, and each count's range", () => {
    const s = metricSummaries(daySeries(input(LEDGER, AS_OF)))["KSI-SCR-MIT"]!;
    expect(s.past30Days).toMatchObject({
      from: "2026-07-21",
      to: "2026-08-19",
      daysInWindow: 30,
      daysCovered: 19,
      daysAbsent: 11,
      statusDays: { Implemented: 0, "Partially Implemented": 14, "Not Implemented": 5 },
      firstStatus: "Partially Implemented",
      lastStatus: "Not Implemented",
    });
    expect(s.past30Days.counts?.staleMethods).toEqual({ min: 0, max: 1, last: 0 });
    expect(s.past30Days.counts?.violatedMethods).toEqual({ min: 0, max: 1, last: 1 });
    expect(s.pastYear).toMatchObject({ daysInWindow: 365, daysCovered: 19, daysAbsent: 346 });
  });

  it("summarizes a window shorter than the series from its tail", () => {
    const days = ["d1", "d2", "d3"];
    const m = (status: "Implemented" | "Not Implemented") => ({
      status,
      methodsInScope: 1,
      methodsPassing: status === "Implemented" ? 1 : 0,
      violatedMethods: 0,
      staleMethods: 0,
      automatedWithEvidence: 1,
      artifactsPresent: 5,
    });
    const s = summarize(days, [m("Not Implemented"), m("Implemented"), undefined], 2);
    expect(s).toMatchObject({ from: "d2", to: "d3", daysCovered: 1, daysAbsent: 1, lastStatus: "Implemented" });
  });
});

describe("the daily data (R3.2, H4/H5)", () => {
  it("is owed at class c and d only", () => {
    expect(["a", "b", "c", "d"].map(dailyOwed)).toEqual([false, false, true, true]);
  });

  it("runs expand to exactly one entry per covered day, in order, with the day's own metric", () => {
    const series = daySeries(input(LEDGER, AS_OF));
    const mit = series.byKsi.get("KSI-SCR-MIT")!;
    const runs = dailyRuns(series.days, mit);
    const covered = series.days
      .map((day, i) => ({ day, metric: mit[i] }))
      .filter((d) => d.metric !== undefined);
    expect(expandRuns(runs)).toEqual(covered);
    // 08-01..08-07 fresh, 08-08..08-14 stale, 08-15..08-19 violated
    expect(runs.map((r) => [r.from, r.to, r.days, r.status])).toEqual([
      ["2026-08-01", "2026-08-07", 7, "Partially Implemented"],
      ["2026-08-08", "2026-08-14", 7, "Partially Implemented"],
      ["2026-08-15", "2026-08-19", 5, "Not Implemented"],
    ]);
  });

  it("keeps a gap in coverage as a gap between runs", () => {
    const m = {
      status: "Implemented" as const,
      methodsInScope: 1,
      methodsPassing: 1,
      violatedMethods: 0,
      staleMethods: 0,
      automatedWithEvidence: 1,
      artifactsPresent: 5,
    };
    const days = ["2026-01-01", "2026-01-02", "2026-01-03"];
    const runs = dailyRuns(days, [m, undefined, m]);
    expect(runs.map((r) => [r.from, r.to])).toEqual([
      ["2026-01-01", "2026-01-01"],
      ["2026-01-03", "2026-01-03"],
    ]);
  });

  it("reaches back a year, or FRC-CSX-MOT's floor where that is longer", () => {
    expect(reachDays(AS_OF, null)).toBe(365);
    expect(reachDays(AS_OF, 6)).toBe(365);
    // 18 months back from the last completed day, 2026-08-19, opens on 2025-02-19
    const d = reachDays(AS_OF, 18);
    expect(d).toBe((Date.parse("2026-08-19") - Date.parse("2025-02-19")) / 86_400_000 + 1);
    expect(d).toBe(547);
    const series = daySeries({ ...input(LEDGER, AS_OF), reachDays: d });
    expect(series.days[0]).toBe("2025-02-19");
    // the summaries still speak for their own windows
    expect(metricSummaries(series)["KSI-SCR-MIT"]!.pastYear.daysInWindow).toBe(365);
  });
});
