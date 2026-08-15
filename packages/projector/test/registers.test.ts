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

function recipe(id: string, collector = "repo-facts"): PipelineRecipe {
  return {
    id,
    ksi_ids: ["KSI-SVC-CLS"],
    control_ids: ["sc-8.1"],
    evidence: "test recipe",
    collection: { kind: "pipeline", collector },
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

describe("fix pointers on violated register rows (I2c)", () => {
  const anchors = [{ path: "f", contentHash: HASH_A }];
  const failing = (offenders: Array<Record<string, unknown>>, count: number) => [
    {
      description: "every hit unreachable",
      passed: false,
      detail: "some fail",
      offenders,
      offender_count: count,
    },
  ];

  it("a violated row carries its evidence's offenders, deduped across assertions", () => {
    const projection = foldEntries(
      [
        evidenceEntry({
          recipe: "r",
          timestamp: T1,
          commit: C1,
          anchors,
          verdict: "violated",
          assertions: [
            ...failing([{ file: "bad.ts", line: 2, check: "b" }], 1),
            // a second failing assertion pointing at the same row, plus a new one
            {
              description: "and zero criticals",
              passed: false,
              offenders: [
                { file: "bad.ts", line: 2, check: "b" },
                { file: "worse.ts", line: 9 },
              ],
              offender_count: 2,
            },
            { description: "passing", passed: true },
          ],
        }),
      ],
      T2,
      { recipes: [recipe("r")] },
    );
    const row = projection.registers.find((x) => x.recipeId === "r")!;
    expect(row.state).toBe("violated");
    expect(row.pointers).toEqual([
      { file: "bad.ts", line: 2, check: "b" },
      { file: "worse.ts", line: 9 },
    ]);
  });

  it("pre-I2c evidence (no offenders) yields a violated row without pointers — never invented", () => {
    const projection = foldEntries(
      [evidenceEntry({ recipe: "r", timestamp: T1, commit: C1, anchors, verdict: "violated" })],
      T2,
      { recipes: [recipe("r")] },
    );
    const row = projection.registers.find((x) => x.recipeId === "r")!;
    expect(row.pointers).toBeUndefined();
    // …but the streak is still computed: it needs only the chain
    expect(row.introducedAt).toBe(T1);
    expect(row.introducingCommit).toBe(C1);
  });

  it("the violated streak walks back past consecutive violated bundles to the first", () => {
    const projection = foldEntries(
      [
        evidenceEntry({ recipe: "r", timestamp: T1, commit: C1, anchors, verdict: "evidenced" }),
        evidenceEntry({ recipe: "r", timestamp: T2, commit: C2, anchors, verdict: "violated" }),
        evidenceEntry({ recipe: "r", timestamp: T3, commit: "3".repeat(40), anchors, verdict: "violated" }),
      ],
      T3,
      { recipes: [recipe("r")] },
    );
    const row = projection.registers.find((x) => x.recipeId === "r")!;
    // introduced when it FLIPPED (T2/C2), not when the recipe was first evidenced
    expect(row.introducedAt).toBe(T2);
    expect(row.introducingCommit).toBe(C2);
  });

  it("a clean bundle breaks the streak — only the current run of violations counts", () => {
    const T4 = "2026-08-12T00:00:00.000Z";
    const projection = foldEntries(
      [
        evidenceEntry({ recipe: "r", timestamp: T1, commit: C1, anchors, verdict: "violated" }),
        evidenceEntry({ recipe: "r", timestamp: T2, commit: C2, anchors, verdict: "evidenced" }),
        evidenceEntry({ recipe: "r", timestamp: T3, commit: "3".repeat(40), anchors, verdict: "violated" }),
        evidenceEntry({ recipe: "r", timestamp: T4, commit: "4".repeat(40), anchors, verdict: "violated" }),
      ],
      T4,
      { recipes: [recipe("r")] },
    );
    const row = projection.registers.find((x) => x.recipeId === "r")!;
    expect(row.introducedAt).toBe(T3);
    expect(row.introducingCommit).toBe("3".repeat(40));
  });

  it("evidenced and unevidenced rows never carry pointers or a streak", () => {
    const projection = foldEntries(
      [evidenceEntry({ recipe: "r", timestamp: T1, commit: C1, anchors, verdict: "evidenced" })],
      T2,
      { recipes: [recipe("r"), recipe("never-scanned")] },
    );
    for (const row of projection.registers) {
      expect(row.pointers).toBeUndefined();
      expect(row.introducedAt).toBeUndefined();
      expect(row.introducingCommit).toBeUndefined();
    }
  });
});

// J3: the board hop needs two facts on the row that the fold already has in
// hand — which collector is SUPPOSED to evidence this recipe (the catalog
// join, same as ksi_ids/control_ids) and which run DID (the live predicate's
// own run_id). Both are joins, neither is a computation: the board must not
// become a function of the run log, so nothing here may read a run record.
describe("the run hop's two fields (J3)", () => {
  const anchors = [{ path: "f", contentHash: HASH_A }];

  it("the collector comes from the catalog and is carried per row, not per repo", () => {
    const projection = foldEntries(
      [evidenceEntry({ recipe: "sbom", timestamp: T1, commit: C1, anchors })],
      T2,
      { recipes: [recipe("sbom", "sbom"), recipe("secrets", "gitleaks")] },
    );
    const byId = new Map(projection.registers.map((r) => [r.recipeId, r]));
    expect(byId.get("sbom")!.collector).toBe("sbom");
    // the unevidenced row is exactly the one that needs the hop most, and it
    // gets its collector from the catalog with no evidence in sight
    expect(byId.get("secrets")!.state).toBe("unevidenced");
    expect(byId.get("secrets")!.collector).toBe("gitleaks");
  });

  it("a recipe that fell out of the catalog names no collector — never a guess", () => {
    const projection = foldEntries(
      [evidenceEntry({ recipe: "legacy", timestamp: T1, commit: C1, anchors })],
      T2,
      { recipes: [] },
    );
    const row = projection.registers.find((r) => r.recipeId === "legacy")!;
    expect(row.state).toBe("evidenced"); // still visible — nothing recorded hides
    expect(row.collector).toBeUndefined();
    // it still knows which run produced it: that fact lives in the bundle
    expect(row.runId).toBe(`run-${T1}`);
  });

  it("runId is the LIVE bundle's own run — a superseded run never lingers on the row", () => {
    const projection = foldEntries(
      [
        evidenceEntry({ recipe: "r", timestamp: T1, commit: C1, anchors }),
        evidenceEntry({ recipe: "r", timestamp: T2, commit: C2, anchors }),
      ],
      T3,
      { recipes: [recipe("r")] },
    );
    const row = projection.registers.find((x) => x.recipeId === "r")!;
    expect(row.runId).toBe(`run-${T2}`);
  });

  it("an unevidenced cell carries NO run id — no run produced it, and the row says so", () => {
    const projection = foldEntries(
      [
        evidenceEntry({ recipe: "r", timestamp: T1, commit: C1, anchors }),
        // a later bundle saw the anchor change: r's evidence dies with no successor
        evidenceEntry({ recipe: "other", timestamp: T2, commit: C2, anchors: [{ path: "f", contentHash: HASH_B }] }),
      ],
      T3,
      { recipes: [recipe("r"), recipe("other"), recipe("never-scanned")] },
    );
    const byId = new Map(projection.registers.map((r) => [r.recipeId, r]));
    expect(byId.get("r")!.state).toBe("unevidenced");
    expect(byId.get("r")!.runId).toBeUndefined();
    expect(byId.get("never-scanned")!.runId).toBeUndefined();
  });

  it("a scoped-out cell carries no run id either — a scoping is not a run", () => {
    const projection = foldEntries([scopingEntry({ recipe: "na-recipe", timestamp: T1 })], T2, {
      recipes: [recipe("na-recipe", "kubescape")],
    });
    const row = projection.registers.find((r) => r.recipeId === "na-recipe")!;
    expect(row.state).toBe("notApplicable");
    expect(row.runId).toBeUndefined();
    expect(row.collector).toBe("kubescape"); // the catalog still knows who owns it
  });

  it("run records still introduce no register cell — the hop's fields changed nothing", () => {
    // The standing J1 rule, re-pinned here because J3 is the first thing to
    // put run identity on a board row: the id RIDES on evidence, it does not
    // let the run log create or move a cell.
    const projection = foldEntries(
      [evidenceEntry({ recipe: "r", timestamp: T1, commit: C1, anchors })],
      T2,
      { recipes: [recipe("r")] },
    );
    expect(projection.registers).toHaveLength(1);
    expect(projection.registers[0]!.runId).toBe(`run-${T1}`);
  });
});

describe("sqlite round trip", () => {
  it("write → read returns the identical projection — the rebuild proof's mechanism", async () => {
    const dbPath = join(await mkdtemp(join(tmpdir(), "rampscan-proj-")), "projection.db");
    const projection = foldEntries(
      [
        evidenceEntry({ recipe: "r", timestamp: T1, commit: C1, anchors: [{ path: "f", contentHash: HASH_A }] }),
        evidenceEntry({ recipe: "r", timestamp: T2, commit: C2, anchors: [{ path: "f", contentHash: HASH_B }] }),
        // a violated row carrying fix pointers — the I2c register columns must survive the trip
        evidenceEntry({
          recipe: "viol",
          timestamp: T2,
          commit: C2,
          anchors: [{ path: "g", contentHash: HASH_A }],
          verdict: "violated",
          assertions: [
            {
              description: "check",
              passed: false,
              detail: "1 of 1 row(s) fail",
              offenders: [{ file: "bad.ts", line: 2, check: "b" }],
              offender_count: 1,
            },
          ],
        }),
        scopingEntry({ recipe: "na-recipe", timestamp: T3 }),
      ],
      T3,
      {
        recipes: [
          recipe("r", "sbom"),
          recipe("viol", "semgrep"),
          recipe("na-recipe", "kubescape"),
          recipe("never-scanned", "gitleaks"),
        ],
      },
    );
    expect(projection.registers.find((x) => x.recipeId === "viol")!.pointers).toBeDefined();
    // the J3 columns must survive the trip too — a distinct collector per row
    // so a column that dropped or smeared would show
    // rows sort by cell key: na-recipe, never-scanned, r, viol
    expect(projection.registers.map((x) => x.collector)).toEqual([
      "kubescape",
      "gitleaks",
      "sbom",
      "semgrep",
    ]);
    expect(projection.registers.find((x) => x.recipeId === "r")!.runId).toBe(`run-${T2}`);
    await writeProjectionSqlite(projection, dbPath);
    expect(readProjectionSqlite(dbPath)).toEqual(projection);
  });
});

// K1: the plain-language paragraphs ride the SAME catalog join as ksi_ids,
// control_ids, cadence and collector. They are authored prose about the check
// — never about the cell — so the fold's only job is to carry them, and its
// only refusal is the one it already makes for the collector: a recipe that
// left the catalog gets nothing rather than something invented.
describe("the plain-language join (K1)", () => {
  const anchors = [{ path: "f", contentHash: HASH_A }];

  function withPlain(id: string, collector: string, fix: string): PipelineRecipe {
    return {
      ...recipe(id, collector),
      plain: {
        checks: `what ${id} looks at`,
        violation: `what a failing ${id} means`,
        fix,
      },
    };
  }

  it("the prose is carried per row, on evidenced and unevidenced cells alike", () => {
    const projection = foldEntries(
      [evidenceEntry({ recipe: "sbom", timestamp: T1, commit: C1, anchors })],
      T2,
      { recipes: [withPlain("sbom", "sbom", "generate one"), withPlain("secrets", "gitleaks", "rotate it")] },
    );
    const byId = new Map(projection.registers.map((r) => [r.recipeId, r]));
    expect(byId.get("sbom")!.plain!.fix).toBe("generate one");
    // the empty row needs the explanation at least as much as the full one
    expect(byId.get("secrets")!.state).toBe("unevidenced");
    expect(byId.get("secrets")!.plain!.checks).toBe("what secrets looks at");
  });

  it("a recipe with no prose gets no prose — the field is absent, not blank", () => {
    const projection = foldEntries(
      [evidenceEntry({ recipe: "bare", timestamp: T1, commit: C1, anchors })],
      T2,
      { recipes: [recipe("bare")] },
    );
    expect(projection.registers.find((r) => r.recipeId === "bare")!.plain).toBeUndefined();
  });

  it("a recipe that fell out of the catalog is explained by nothing at all", () => {
    // the same refusal the collector makes (J3): the catalog would describe a
    // recipe that is no longer there, and prose about the wrong check is worse
    // than a row with no prose
    const projection = foldEntries(
      [evidenceEntry({ recipe: "legacy", timestamp: T1, commit: C1, anchors })],
      T2,
      { recipes: [] },
    );
    const row = projection.registers.find((r) => r.recipeId === "legacy")!;
    expect(row.state).toBe("evidenced");
    expect(row.plain).toBeUndefined();
    expect(row.collector).toBeUndefined();
  });

  it("prose introduces no cell, moves no state, and is identical across repos", () => {
    // the standing rule, from the other side: the catalog join may DESCRIBE
    // rows, never create or change them. Same recipe, two repos, one of them
    // with evidence — the prose is byte-identical on both rows and neither
    // row's state came from it.
    const recipes = [withPlain("shared", "sbom", "do the thing")];
    const projection = foldEntries(
      [
        evidenceEntry({ recipe: "shared", timestamp: T1, commit: C1, anchors, repo: "fixtures/app" }),
        evidenceEntry({ recipe: "shared", timestamp: T1, commit: C1, anchors, repo: "fixtures/other", verdict: "violated" }),
      ],
      T2,
      { recipes },
    );
    const rows = projection.registers.filter((r) => r.recipeId === "shared");
    expect(rows).toHaveLength(2);
    expect(rows[0]!.plain).toEqual(rows[1]!.plain);
    expect(new Set(rows.map((r) => r.state))).toEqual(new Set(["evidenced", "violated"]));
    // and the row count is exactly the catalog × repos it would have been
    // without any prose in the catalog at all
    const bare = foldEntries(
      [
        evidenceEntry({ recipe: "shared", timestamp: T1, commit: C1, anchors, repo: "fixtures/app" }),
        evidenceEntry({ recipe: "shared", timestamp: T1, commit: C1, anchors, repo: "fixtures/other", verdict: "violated" }),
      ],
      T2,
      { recipes: [recipe("shared", "sbom")] },
    );
    expect(bare.registers.map((r) => [r.repo, r.recipeId, r.state])).toEqual(
      projection.registers.map((r) => [r.repo, r.recipeId, r.state]),
    );
  });

  it("survives the sqlite round trip byte-for-byte, with distinct prose per row", async () => {
    const dbPath = join(await mkdtemp(join(tmpdir(), "rampscan-plain-")), "projection.db");
    const projection = foldEntries(
      [evidenceEntry({ recipe: "a", timestamp: T1, commit: C1, anchors })],
      T2,
      {
        recipes: [
          withPlain("a", "sbom", "fix a"),
          withPlain("b", "gitleaks", "fix b"),
          recipe("c", "semgrep"),
        ],
      },
    );
    // distinct per row so a column that dropped, smeared or reordered shows
    expect(projection.registers.map((r) => r.plain?.fix)).toEqual(["fix a", "fix b", undefined]);
    await writeProjectionSqlite(projection, dbPath);
    expect(readProjectionSqlite(dbPath)).toEqual(projection);
  });
});
