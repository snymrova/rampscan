import { describe, expect, it } from "vitest";
import type { LedgerEntry, RegisterState } from "@rampscan/core";
import type { EvidenceBundle, PipelineRecipe, ScanRun, ScopingEvent } from "@rampscan/schema";
import {
  classifyChange,
  diffRegisters,
  foldEntries,
  resolveBaseline,
  scanInstants,
} from "../src/index.js";

// I2d: the "since baseline" diff. Both sides are as-of folds of the same
// append-only ledger, so these tests build one ledger and diff its folds —
// the exact computation `rampscan board --since` and the console route run.

let counter = 0;

function evidenceEntry(opts: {
  recipe: string;
  timestamp: string;
  commit: string;
  anchors: Array<{ path: string; contentHash: string }>;
  verdict?: "evidenced" | "violated";
  repo?: string;
  assertions?: EvidenceBundle["predicate"]["assertions"];
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
      commit: opts.commit,
      anchor_paths: opts.anchors,
      dataset_version: "2026.07.14.01",
      tool_versions: { "repo-facts": "0.1.0" },
      assertions: opts.assertions ?? [
        { description: "check", passed: (opts.verdict ?? "evidenced") === "evidenced" },
      ],
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

/** A scan that recorded how it went (J1) — with or without evidence beside it. */
function scanRunEntry(opts: { timestamp: string; commit: string; repo?: string }): LedgerEntry {
  const bundle: ScanRun = {
    _type: "https://in-toto.io/Statement/v1",
    subject: [{ name: "scan-result.json", digest: { sha256: "c".repeat(64) } }],
    predicateType: "https://rampscan.dev/scan-run/v1",
    predicate: {
      run_id: `run-${counter++}`,
      repo: opts.repo ?? "fixtures/app",
      commit: opts.commit,
      trigger: "manual",
      started_at: opts.timestamp,
      duration_ms: 1200,
      dataset_version: "2026.07.14.01",
      collectors: [],
      timestamp: opts.timestamp,
    },
  };
  return { digest: `digest-${counter++}`, bundle, appendedAt: opts.timestamp };
}

function recipe(id: string): PipelineRecipe {
  return {
    id,
    ksi_ids: ["KSI-SVC-CLS"],
    control_ids: ["sc-8.1"],
    evidence: "test recipe",
    collection: { kind: "pipeline", collector: "repo-facts" },
    expected_output: "rows",
    cadence: "weekly",
    automatable: "full",
    anchor: "commit",
  };
}

const C1 = "1".repeat(40);
const C2 = "2".repeat(40);
const HASH_A = "a".repeat(64);
const HASH_B = "b".repeat(64);
const T1 = "2026-08-01T00:00:00.000Z";
const T15 = "2026-08-04T00:00:00.000Z"; // a scoping between the scans
const T2 = "2026-08-08T00:00:00.000Z";
const T3 = "2026-08-10T00:00:00.000Z";

describe("classifyChange: total over every state transition", () => {
  const states: Array<RegisterState | undefined> = [
    "evidenced",
    "violated",
    "unevidenced",
    "notApplicable",
    undefined,
  ];

  // the pinned matrix: EVERY (from, to) pair with from ≠ to has exactly one
  // name. A new kind or a re-mapped pair must change this table on purpose.
  const pinned: Record<string, string> = {
    "evidenced→violated": "newly-violated",
    "evidenced→unevidenced": "evidence-lapsed",
    "evidenced→notApplicable": "scoped",
    "evidenced→(gone)": "removed",
    "violated→evidenced": "resolved",
    "violated→unevidenced": "evidence-lapsed",
    "violated→notApplicable": "scoped",
    "violated→(gone)": "removed",
    "unevidenced→evidenced": "newly-evidenced",
    "unevidenced→violated": "newly-violated",
    "unevidenced→notApplicable": "scoped",
    "unevidenced→(gone)": "removed",
    "notApplicable→evidenced": "newly-evidenced",
    "notApplicable→violated": "newly-violated",
    "notApplicable→unevidenced": "unscoped",
    "notApplicable→(gone)": "removed",
    "(new)→evidenced": "appeared",
    "(new)→violated": "newly-violated",
    "(new)→unevidenced": "appeared",
    "(new)→notApplicable": "appeared",
  };

  it("classifies every pair exactly as pinned — nothing falls through unnamed", () => {
    const seen: Record<string, string> = {};
    for (const from of states) {
      for (const to of states) {
        if (from === to) continue;
        if (from === undefined && to === undefined) continue;
        const key = `${from ?? "(new)"}→${to ?? "(gone)"}`;
        seen[key] = classifyChange(from, to);
      }
    }
    expect(seen).toEqual(pinned);
  });
});

describe("scanInstants: the ledger's scans, from the join's single clock", () => {
  it("dedups bundles of one scan, ignores scoping events, sorts ascending", () => {
    const entries = [
      evidenceEntry({ recipe: "b", timestamp: T2, commit: C2, anchors: [] }),
      evidenceEntry({ recipe: "a", timestamp: T1, commit: C1, anchors: [] }),
      evidenceEntry({ recipe: "b", timestamp: T1, commit: C1, anchors: [] }),
      scopingEntry({ recipe: "c", timestamp: T15 }),
    ];
    expect(scanInstants(entries)).toEqual([T1, T2]);
  });

  // J2's deliberate redefinition of what "a scan" is. A run record carries the
  // same clock as the bundles it produced, so an evidence-moving scan is
  // unchanged — the instant was already in the set.
  it("a run record beside its own evidence adds no second instant", () => {
    const entries = [
      evidenceEntry({ recipe: "a", timestamp: T1, commit: C1, anchors: [] }),
      scanRunEntry({ timestamp: T1, commit: C1 }),
    ];
    expect(scanInstants(entries)).toEqual([T1]);
  });

  // ...and this is what it buys: the scan that moved nothing used to leave no
  // trace, so "the previous scan" silently meant "the previous scan that moved
  // evidence". Now it means what it says.
  it("a scan that produced no evidence is still a scan", () => {
    const entries = [
      evidenceEntry({ recipe: "a", timestamp: T1, commit: C1, anchors: [] }),
      scanRunEntry({ timestamp: T2, commit: C2 }),
    ];
    expect(scanInstants(entries)).toEqual([T1, T2]);
    expect(resolveBaseline(entries, "previous")).toBe(T1);
  });
});

describe("resolveBaseline", () => {
  const entries = [
    evidenceEntry({ recipe: "a", timestamp: T1, commit: C1, anchors: [] }),
    evidenceEntry({ recipe: "a", timestamp: T2, commit: C2, anchors: [] }),
    evidenceEntry({ recipe: "a", timestamp: T3, commit: C2, anchors: [] }),
  ];

  it("`previous` is the second-newest scan", () => {
    expect(resolveBaseline(entries, "previous")).toBe(T2);
  });

  it("`previous` under an as-of cap is the second-newest scan at or before it", () => {
    expect(resolveBaseline(entries, "previous", T2)).toBe(T1);
  });

  it("an explicit instant passes through untouched", () => {
    expect(resolveBaseline(entries, T15)).toBe(T15);
  });

  it("refuses honestly when the ledger records one scan or none", () => {
    expect(() => resolveBaseline(entries.slice(0, 1), "previous")).toThrow(/no previous scan/);
    expect(() => resolveBaseline([], "previous")).toThrow(/no scans/);
  });
});

describe("diffRegisters over as-of folds — the I2d computation", () => {
  // one ledger, two scans, one scoping in between:
  //   fixed      violated @T1 → evidenced @T2                  = resolved
  //   steady     evidenced @T1, refreshed @T2 (state held)     = unchanged
  //   lapsing    evidenced @T1; its anchor drifts @T2 with no
  //              successor bundle                              = evidence-lapsed
  //   arrived    first evidence @T2, violated, with offenders  = newly-violated
  //   scoped-out unevidenced @T1, scoped notApplicable @T15    = scoped
  //   never      in the catalog, never scanned                 = unchanged (unevidenced)
  const entries = [
    evidenceEntry({
      recipe: "fixed",
      timestamp: T1,
      commit: C1,
      verdict: "violated",
      anchors: [{ path: "src/fixed.ts", contentHash: HASH_A }],
    }),
    evidenceEntry({
      recipe: "steady",
      timestamp: T1,
      commit: C1,
      anchors: [{ path: "src/steady.ts", contentHash: HASH_A }],
    }),
    evidenceEntry({
      recipe: "lapsing",
      timestamp: T1,
      commit: C1,
      anchors: [{ path: "src/lapsing.ts", contentHash: HASH_A }],
    }),
    scopingEntry({ recipe: "scoped-out", timestamp: T15 }),
    evidenceEntry({
      recipe: "fixed",
      timestamp: T2,
      commit: C2,
      anchors: [{ path: "src/fixed.ts", contentHash: HASH_A }],
    }),
    evidenceEntry({
      recipe: "steady",
      timestamp: T2,
      commit: C2,
      anchors: [{ path: "src/steady.ts", contentHash: HASH_A }],
    }),
    // `arrived` observed lapsing's anchor at a new hash — the cross-recipe
    // kill that drops `lapsing` back to unevidenced
    evidenceEntry({
      recipe: "arrived",
      timestamp: T2,
      commit: C2,
      verdict: "violated",
      anchors: [{ path: "src/lapsing.ts", contentHash: HASH_B }],
      assertions: [
        {
          description: "no secrets",
          passed: false,
          offenders: [{ file: "src/lapsing.ts", line: 12, check: "aws-access-token" }],
        },
      ],
    }),
  ];
  const recipes = ["fixed", "steady", "lapsing", "arrived", "scoped-out", "never"].map(recipe);

  function computeDiff() {
    const before = foldEntries(entries, T3, { recipes, asOf: T1 });
    const current = foldEntries(entries, T3, { recipes });
    return diffRegisters(before.registers, current.registers, T1);
  }

  it("classifies every movement and counts the held cells", () => {
    const diff = computeDiff();
    const byRecipe = new Map(diff.changes.map((c) => [c.recipeId, c]));
    expect(byRecipe.get("fixed")?.kind).toBe("resolved");
    expect(byRecipe.get("lapsing")?.kind).toBe("evidence-lapsed");
    expect(byRecipe.get("arrived")?.kind).toBe("newly-violated");
    expect(byRecipe.get("scoped-out")?.kind).toBe("scoped");
    expect(byRecipe.has("steady")).toBe(false);
    expect(byRecipe.has("never")).toBe(false);
    expect(diff.unchanged).toBe(2); // steady + never
    expect(diff.counts["newly-violated"]).toBe(1);
    expect(diff.counts.resolved).toBe(1);
    expect(diff.changes.length).toBe(4);
  });

  it("orders bad news first and carries both sides' digests", () => {
    const diff = computeDiff();
    expect(diff.changes[0]!.kind).toBe("newly-violated");
    expect(diff.changes.at(-1)!.kind).toBe("resolved");
    const fixed = diff.changes.find((c) => c.recipeId === "fixed")!;
    expect(fixed.from).toBe("violated");
    expect(fixed.to).toBe("evidenced");
    expect(fixed.baselineDigest).toBeDefined();
    expect(fixed.bundleDigest).toBeDefined();
    expect(fixed.baselineDigest).not.toBe(fixed.bundleDigest);
  });

  it("newly-violated changes carry the current row's fix pointers (I2c rides I2d)", () => {
    const arrived = computeDiff().changes.find((c) => c.recipeId === "arrived")!;
    expect(arrived.pointers).toEqual([
      { file: "src/lapsing.ts", line: 12, check: "aws-access-token" },
    ]);
    expect(arrived.introducedAt).toBe(T2);
    expect(arrived.introducingCommit).toBe(C2);
  });

  it("is deterministic: the same ledger and baseline always diff identically", () => {
    expect(computeDiff()).toEqual(computeDiff());
  });

  it("a cell newly in scope since the baseline appears — a new repo's rows", () => {
    const withNewRepo = [
      ...entries,
      evidenceEntry({
        recipe: "steady",
        repo: "fixtures/other",
        timestamp: T2,
        commit: C2,
        anchors: [],
      }),
    ];
    const before = foldEntries(withNewRepo, T3, { recipes, asOf: T1 });
    const current = foldEntries(withNewRepo, T3, { recipes });
    const diff = diffRegisters(before.registers, current.registers, T1);
    const other = diff.changes.filter((c) => c.repo === "fixtures/other");
    // the scanned recipe is newly evidenced-from-nothing; the rest of the
    // catalog appears as honest unevidenced rows
    expect(other.find((c) => c.recipeId === "steady")?.kind).toBe("appeared");
    expect(other.filter((c) => c.kind === "appeared").length).toBe(recipes.length);
  });
});
