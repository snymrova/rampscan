import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { describe, expect, it } from "vitest";
import type { LedgerEntry } from "@rampscan/core";
import type { EvidenceBundle } from "@rampscan/schema";
import { foldEntries, writeProjectionSqlite } from "../src/index.js";

// Anchor death is the point of M2: nothing "expires" by human memory — the
// fold computes it. Synthetic entries here; the CLI e2e proves it end to end.

let counter = 0;

function entry(opts: {
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

const C1 = "1".repeat(40);
const C2 = "2".repeat(40);
const HASH_A = "a".repeat(64);
const HASH_B = "b".repeat(64);

const T1 = "2026-08-01T00:00:00.000Z";
const T2 = "2026-08-08T00:00:00.000Z";

describe("projector fold", () => {
  it("a lone bundle is live, fresh as of its own timestamp", () => {
    const projection = foldEntries(
      [entry({ recipe: "r", timestamp: T1, commit: C1, anchors: [{ path: "f", contentHash: HASH_A }] })],
      T2,
    );
    expect(projection.rows).toHaveLength(1);
    expect(projection.rows[0]!.status).toEqual({ state: "live" });
    expect(projection.rows[0]!.freshAsOf).toBe(T1);
    expect(projection.projectedAt).toBe(T2);
  });

  it("a successor with changed anchors kills its predecessor: anchor-drift, killing commit recorded", () => {
    const projection = foldEntries(
      [
        entry({ recipe: "r", timestamp: T1, commit: C1, anchors: [{ path: "f", contentHash: HASH_A }] }),
        entry({ recipe: "r", timestamp: T2, commit: C2, anchors: [{ path: "f", contentHash: HASH_B }] }),
      ],
      T2,
    );
    const dead = projection.rows.find((r) => r.status.state === "dead")!;
    expect(dead.freshAsOf).toBe(T1);
    expect(dead.status).toEqual({ state: "dead", cause: "anchor-drift", killingCommit: C2 });
    const live = projection.rows.find((r) => r.status.state === "live")!;
    expect(live.freshAsOf).toBe(T2);
  });

  it("a successor with identical anchors supersedes (verdict flip, not code change)", () => {
    const anchors = [{ path: "f", contentHash: HASH_A }];
    const projection = foldEntries(
      [
        entry({ recipe: "r", timestamp: T1, commit: C1, anchors, verdict: "evidenced" }),
        entry({ recipe: "r", timestamp: T2, commit: C1, anchors, verdict: "violated" }),
      ],
      T2,
    );
    const dead = projection.rows.find((r) => r.status.state === "dead")!;
    expect(dead.status).toEqual({ state: "dead", cause: "superseded", killingCommit: C1 });
  });

  it("cross-recipe anchor death: evidence dies when ANOTHER recipe's later bundle saw its anchor change", () => {
    const projection = foldEntries(
      [
        // recipe-a evidences package.json at T1 and never re-runs
        entry({ recipe: "recipe-a", timestamp: T1, commit: C1, anchors: [{ path: "package.json", contentHash: HASH_A }] }),
        // recipe-b's T2 bundle observed package.json with a different hash
        entry({ recipe: "recipe-b", timestamp: T2, commit: C2, anchors: [{ path: "package.json", contentHash: HASH_B }] }),
      ],
      T2,
    );
    const a = projection.rows.find((r) => r.recipeId === "recipe-a")!;
    expect(a.status).toEqual({ state: "dead", cause: "anchor-drift", killingCommit: C2 });
    const b = projection.rows.find((r) => r.recipeId === "recipe-b")!;
    expect(b.status).toEqual({ state: "live" });
  });

  it("untouched anchors survive a later scan — same hash observed later is not death", () => {
    const projection = foldEntries(
      [
        entry({ recipe: "recipe-a", timestamp: T1, commit: C1, anchors: [{ path: "package.json", contentHash: HASH_A }] }),
        entry({ recipe: "recipe-b", timestamp: T2, commit: C2, anchors: [{ path: "package.json", contentHash: HASH_A }] }),
      ],
      T2,
    );
    const a = projection.rows.find((r) => r.recipeId === "recipe-a")!;
    expect(a.status).toEqual({ state: "live" });
  });

  it("repos do not cross-contaminate: the same path in another repo is a different anchor", () => {
    const projection = foldEntries(
      [
        entry({ recipe: "r", repo: "repo-one", timestamp: T1, commit: C1, anchors: [{ path: "package.json", contentHash: HASH_A }] }),
        entry({ recipe: "r", repo: "repo-two", timestamp: T2, commit: C2, anchors: [{ path: "package.json", contentHash: HASH_B }] }),
      ],
      T2,
    );
    expect(projection.rows.every((r) => r.status.state === "live")).toBe(true);
  });
});

describe("sqlite projection", () => {
  it("writes a queryable coverage table and is rebuildable (second write replaces)", async () => {
    const dbPath = join(await mkdtemp(join(tmpdir(), "rampscan-proj-")), "projection.db");
    const projection = foldEntries(
      [
        entry({ recipe: "r", timestamp: T1, commit: C1, anchors: [{ path: "f", contentHash: HASH_A }] }),
        entry({ recipe: "r", timestamp: T2, commit: C2, anchors: [{ path: "f", contentHash: HASH_B }] }),
      ],
      T2,
    );
    await writeProjectionSqlite(projection, dbPath);
    await writeProjectionSqlite(projection, dbPath); // idempotent rebuild

    const db = new DatabaseSync(dbPath);
    const rows = db.prepare("SELECT * FROM coverage ORDER BY fresh_as_of").all() as Array<Record<string, unknown>>;
    expect(rows).toHaveLength(2);
    expect(rows[0]!["state"]).toBe("dead");
    expect(rows[0]!["cause"]).toBe("anchor-drift");
    expect(rows[0]!["killing_commit"]).toBe(C2);
    expect(rows[1]!["state"]).toBe("live");
    const meta = db.prepare("SELECT * FROM meta").all() as Array<Record<string, unknown>>;
    expect(meta[0]!["dataset_version"]).toBe("2026.07.14.01");
    db.close();
  });
});
