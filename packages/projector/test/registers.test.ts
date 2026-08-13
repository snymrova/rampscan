import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import type { LedgerEntry } from "@rampscan/core";
import type { EvidenceBundle, PipelineRecipe, ScopingEvent } from "@rampscan/schema";
import { foldEntries, readProjectionSqlite, writeProjectionSqlite } from "../src/index.js";

// M3: the projection joins the recipe catalog (unevidenced becomes VISIBLE),
// folds notApplicable scopings, and computes drift. All pure — synthetic
// entries here, the CLI e2e proves the loop end to end.

let counter = 0;

function evidenceEntry(opts: {
  recipe: string;
  timestamp: string;
  commit: string;
  anchors: Array<{ path: string; contentHash: string }>;
  verdict?: "evidenced" | "violated";
  repo?: string;
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
      assertions: [{ description: "check", passed: (opts.verdict ?? "evidenced") === "evidenced" }],
      cadence: "continuous",
      run_id: `run-${opts.timestamp}`,
      timestamp: opts.timestamp,
    },
  };
  return { digest: `digest-${counter++}`, bundle, appendedAt: opts.timestamp };
}

function scopingEntry(opts: {
  recipe: string;
  timestamp: string;
  repo?: string;
  justification?: string;
}): LedgerEntry {
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
      justification: opts.justification ?? "does not apply here",
      proposed_by: "viewer@rampscan.local (pb:u1)",
      approved_by: "approver@rampscan.local (pb:u2)",
      dataset_version: "2026.07.14.01",
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
const T2 = "2026-08-08T00:00:00.000Z";
const T3 = "2026-08-10T00:00:00.000Z";

describe("registers: projection × recipe set", () => {
  it("a catalog recipe nobody evidenced shows as unevidenced — the honest default", () => {
    const projection = foldEntries(
      [evidenceEntry({ recipe: "covered", timestamp: T1, commit: C1, anchors: [{ path: "f", contentHash: HASH_A }] })],
      T2,
      { recipes: [recipe("covered"), recipe("never-scanned")] },
    );
    const states = new Map(projection.registers.map((r) => [r.recipeId, r.state]));
    expect(states.get("covered")).toBe("evidenced");
    expect(states.get("never-scanned")).toBe("unevidenced");
  });

  it("evidence that died with no successor drops back to unevidenced, not to its old verdict", () => {
    const projection = foldEntries(
      [
        evidenceEntry({ recipe: "r", timestamp: T1, commit: C1, anchors: [{ path: "f", contentHash: HASH_A }] }),
        // another recipe's later bundle saw the anchor change — cross-recipe kill
        evidenceEntry({ recipe: "other", timestamp: T2, commit: C2, anchors: [{ path: "f", contentHash: HASH_B }] }),
      ],
      T2,
      { recipes: [recipe("r"), recipe("other")] },
    );
    const r = projection.registers.find((x) => x.recipeId === "r")!;
    expect(r.state).toBe("unevidenced");
    expect(r.bundleDigest).toBeUndefined();
  });

  it("a ledger recipe missing from the catalog still appears — nothing recorded ever hides", () => {
    const projection = foldEntries(
      [evidenceEntry({ recipe: "legacy", timestamp: T1, commit: C1, anchors: [{ path: "f", contentHash: HASH_A }] })],
      T2,
      { recipes: [] },
    );
    expect(projection.registers.map((r) => r.recipeId)).toContain("legacy");
  });

  it("a live scoping moves an unevidenced row to notApplicable, with the signed identities attached", () => {
    const projection = foldEntries(
      [scopingEntry({ recipe: "na-recipe", timestamp: T1, justification: "no container here" })],
      T2,
      { recipes: [recipe("na-recipe")] },
    );
    const row = projection.registers.find((r) => r.recipeId === "na-recipe")!;
    expect(row.state).toBe("notApplicable");
    expect(row.scoping?.justification).toBe("no container here");
    expect(row.scoping?.approvedBy).toContain("approver@");
  });

  it("live evidence outranks a scoping — a recipe producing verdicts is not N/A", () => {
    const projection = foldEntries(
      [
        scopingEntry({ recipe: "r", timestamp: T1 }),
        evidenceEntry({ recipe: "r", timestamp: T2, commit: C1, anchors: [{ path: "f", contentHash: HASH_A }], verdict: "violated" }),
      ],
      T3,
      { recipes: [recipe("r")] },
    );
    const row = projection.registers.find((r) => r.recipeId === "r")!;
    expect(row.state).toBe("violated");
    expect(row.scoping).toBeDefined(); // the conflict stays visible
  });
});

describe("drift events", () => {
  it("born, then verdict-flipped with cause; a scoping is a scoped event", () => {
    const anchors = [{ path: "f", contentHash: HASH_A }];
    const projection = foldEntries(
      [
        evidenceEntry({ recipe: "r", timestamp: T1, commit: C1, anchors, verdict: "evidenced" }),
        evidenceEntry({ recipe: "r", timestamp: T2, commit: C1, anchors, verdict: "violated" }),
        scopingEntry({ recipe: "other", timestamp: T3 }),
      ],
      T3,
      {},
    );
    const kinds = projection.drift.map((d) => d.kind);
    expect(kinds).toEqual(["born", "verdict-flipped", "scoped"]);
    const flip = projection.drift[1]!;
    expect(flip.from).toBe("evidenced");
    expect(flip.to).toBe("violated");
    expect(flip.cause).toBe("superseded");
  });

  it("anchor drift with the same verdict is a died event naming the killing commit", () => {
    const projection = foldEntries(
      [
        evidenceEntry({ recipe: "r", timestamp: T1, commit: C1, anchors: [{ path: "f", contentHash: HASH_A }] }),
        evidenceEntry({ recipe: "r", timestamp: T2, commit: C2, anchors: [{ path: "f", contentHash: HASH_B }] }),
      ],
      T2,
      {},
    );
    const died = projection.drift.find((d) => d.kind === "died")!;
    expect(died.cause).toBe("anchor-drift");
    expect(died.killingCommit).toBe(C2);
  });
});

describe("sqlite round trip", () => {
  it("write → read returns the identical projection — the rebuild proof's mechanism", async () => {
    const dbPath = join(await mkdtemp(join(tmpdir(), "rampscan-proj-")), "projection.db");
    const projection = foldEntries(
      [
        evidenceEntry({ recipe: "r", timestamp: T1, commit: C1, anchors: [{ path: "f", contentHash: HASH_A }] }),
        evidenceEntry({ recipe: "r", timestamp: T2, commit: C2, anchors: [{ path: "f", contentHash: HASH_B }] }),
        scopingEntry({ recipe: "na-recipe", timestamp: T3 }),
      ],
      T3,
      { recipes: [recipe("r"), recipe("na-recipe"), recipe("never-scanned")] },
    );
    await writeProjectionSqlite(projection, dbPath);
    expect(readProjectionSqlite(dbPath)).toEqual(projection);
  });
});
