import { cp, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import type { CollectContext, CollectOutput } from "@rampscan/core";
import { ContractConfig } from "@rampscan/schema";
import { GRAPH_DB_ARTIFACT } from "@rampscan/graph";
import {
  BOUNDARY_RECIPE,
  ROUTE_AUTH_RECIPE,
  contract,
  graphCollector,
  inModulePrefix,
} from "../src/index.js";

// The contract gate (plan L1), driven on the REAL fixture rather than a typed
// graph: `vulnerable-app` declares two rules in its own rampscan.config.json
// and breaks both — src/render.js imports the guarded billing module (while
// src/server.js, the allowed importer, also imports it: the contrast that
// proves the allow-list is read rather than ignored), and GET /health serves
// unauthenticated while GET /settings passes through requireAuth.
//
// `bare-app` is the other half: a repo with no contract at all, which must
// SKIP with a stated reason rather than pass vacuously.

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "../../..");
const fixtureRoot = join(repoRoot, "fixtures/vulnerable-app");
const bareRoot = join(repoRoot, "fixtures/bare-app");

function ctx(root: string, artifactDir: string, inputs: Map<string, string>): CollectContext {
  return {
    workspace: { root, repo: root, commit: "f".repeat(40) },
    artifactDir,
    inputs,
    runId: "run-test",
  };
}

/** build a real graph.db for a repo, the way the pipeline does */
async function graphFor(root: string): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "rampscan-contract-graph-"));
  const out = await graphCollector.collect(ctx(root, dir, new Map()));
  return out.artifacts.find((a) => a.name === GRAPH_DB_ARTIFACT)!.path;
}

async function runGate(root: string, graphPath?: string): Promise<CollectOutput> {
  const dir = await mkdtemp(join(tmpdir(), "rampscan-contract-gate-"));
  const inputs = new Map<string, string>();
  if (graphPath) inputs.set(GRAPH_DB_ARTIFACT, graphPath);
  return contract.collect(ctx(root, dir, inputs));
}

/** a copy of the fixture whose contract block is rewritten — for the mutation cases */
async function withContract(rules: unknown): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "rampscan-contract-fixture-"));
  await cp(fixtureRoot, root, { recursive: true });
  if (rules === undefined) {
    await rm(join(root, "rampscan.config.json"), { force: true });
  } else {
    await writeFile(join(root, "rampscan.config.json"), JSON.stringify({ contract: rules }, null, 2));
  }
  return root;
}

let fixtureGraph: string;
let out: CollectOutput;

beforeAll(async () => {
  fixtureGraph = await graphFor(fixtureRoot);
  out = await runGate(fixtureRoot, fixtureGraph);
}, 60_000);

describe("the contract gate on the fixture's own declared rules", () => {
  it("names the offending import and spares the allowed one — the allow-list is read, not ignored", () => {
    const rows = out.observations[BOUNDARY_RECIPE]!;
    const offender = rows.find((r) => r["file"] === "src/render.js")!;
    const allowed = rows.find((r) => r["file"] === "src/server.js")!;
    expect(offender["allowed"]).toBe(false);
    expect(offender["imported"]).toBe("src/billing.js");
    expect(offender["rule_id"]).toBe("billing-isolated");
    // the import itself is the call path, marked like every other displayed edge
    expect(offender["call_path"]).toBe("src/render.js » src/billing.js");
    expect(offender["call_path_resolutions"]).toEqual(["exact"]);
    // the contrast: the same module, imported by the one file the rule permits
    expect(allowed["allowed"]).toBe(true);
    expect(allowed["imported"]).toBe("src/billing.js");
  });

  it("checks the declared routes with the under-approximate walk, and only those", () => {
    const rows = out.observations[ROUTE_AUTH_RECIPE]!;
    const health = rows.find((r) => r["route"] === "GET /health")!;
    const settings = rows.find((r) => r["route"] === "GET /settings")!;
    expect(health["auth_reached"]).toBe(false);
    expect(health["call_path"]).toBeNull();
    // a positive claim rests on a real chain, and the chain is shown
    expect(settings["auth_reached"]).toBe(true);
    expect(settings["auth_symbol"]).toBe("requireAuth");
    expect(String(settings["call_path"])).toContain("requireAuth");
    expect(settings["call_path_resolutions"]).toEqual(["exact", "exact"]);
    // every row names the rule that put it there — a row with no rule would be
    // an observation nobody declared
    for (const row of rows) expect(row["rule_id"]).toBe("all-routes-authed");
  });

  it("both breaches become findings, each citing the rule the repo itself wrote", () => {
    const summaries = out.findings.map((f) => f.summary);
    expect(out.findings).toHaveLength(2);
    expect(summaries.some((s) => s.includes("billing-isolated") && s.includes("src/render.js"))).toBe(true);
    expect(summaries.some((s) => s.includes("all-routes-authed") && s.includes("GET /health"))).toBe(true);
    for (const finding of out.findings) {
      expect(finding.variable).toBe("contract");
      expect(finding.severity).toBe("high");
    }
  });

  it("each recipe's basis signs the rules of ITS OWN kind, and no others", () => {
    // the L0 identity decision made concrete: a boundary edit must re-key the
    // boundary evidence and leave the route evidence alone, which is only true
    // if each basis carries its own kind's rules
    const routeBasis = out.basis![ROUTE_AUTH_RECIPE]!;
    const boundaryBasis = out.basis![BOUNDARY_RECIPE]!;
    expect(routeBasis.contract_rules).toHaveLength(1);
    expect(boundaryBasis.contract_rules).toHaveLength(1);
    expect(routeBasis.contract_rules![0]).toContain("all-routes-authed");
    expect(routeBasis.contract_rules![0]).not.toContain("billing-isolated");
    expect(boundaryBasis.contract_rules![0]).toContain("billing-isolated");
    expect(boundaryBasis.contract_rules![0]).not.toContain("all-routes-authed");
    // canonical JSON: keys sorted, so two spellings of one declaration compare equal
    expect(routeBasis.contract_rules![0]).toMatch(/^\{"description":/);
  });

  it("the two walks err in opposite directions and say so", () => {
    // holding a boundary is a claim of ABSENCE (over-approximate: even the
    // loose read finds nothing); reaching auth is a claim of PRESENCE
    // (under-approximate: only a real chain counts). The two must not read alike.
    expect(out.basis![ROUTE_AUTH_RECIPE]!.approximation).toBe("under");
    expect(out.basis![BOUNDARY_RECIPE]!.approximation).toBe("over");
    expect(out.basis![BOUNDARY_RECIPE]!.statement).toContain("count against the repo");
    expect(out.basis![ROUTE_AUTH_RECIPE]!.statement).toContain("positive claim");
  });

  it("anchors the config AND the files that decide the answer — drift in either kills it", () => {
    const boundary = out.anchors![BOUNDARY_RECIPE]!.map((a) => a.path);
    const route = out.anchors![ROUTE_AUTH_RECIPE]!.map((a) => a.path);
    // the contract itself: amending a rule must drift the anchor
    expect(boundary).toContain("rampscan.config.json");
    expect(route).toContain("rampscan.config.json");
    expect(boundary).toContain("src/render.js");
    expect(boundary).toContain("src/billing.js");
    expect(route).toContain("src/server.js");
  });

  it("spawns nothing: the gate is pure and its manifest says so", () => {
    expect(contract.manifest.tools).toEqual([]);
    expect(contract.manifest.inputs).toEqual([GRAPH_DB_ARTIFACT]);
    // a contract edit must miss the cache even when the graph did not change
    expect(contract.manifest.cacheScope).toContain("rampscan.config.json");
  });
});

describe("the refusals — an absent or broken contract may never read as a pass", () => {
  it("a repo with no contract skips with a stated reason", async () => {
    const skipped = await runGate(bareRoot, await graphFor(bareRoot));
    expect(skipped.skipped?.reason).toContain("no architecture contract declared");
    expect(skipped.observations).toEqual({});
    // an honest skip, not a crash: nothing to fix, and the run record says why
    expect(skipped.exitCode).toBe(0);
  }, 60_000);

  it("a config with no contract block, and one with zero rules, are the same honest skip", async () => {
    const noBlock = await runGate(await withContract(undefined), fixtureGraph);
    const noRules = await runGate(await withContract({ rules: [] }), fixtureGraph);
    expect(noBlock.skipped?.reason).toContain("no architecture contract declared");
    expect(noRules.skipped?.reason).toContain("no architecture contract declared");
  });

  it("an unknown rule kind is a config ERROR, never a silent waiver", async () => {
    // the whole point: `"kind": "boundry"` must not parse to nothing. A typo
    // that quietly removes a rule is indistinguishable from a repo that never
    // declared it — and one of those is a lie.
    const root = await withContract({
      rules: [{ kind: "boundry", id: "typo", module: "src/billing", allowedImporters: [], description: "x" }],
    });
    await expect(runGate(root, fixtureGraph)).rejects.toThrow(/failed validation/);
  });

  it("a misspelled field is refused too — strict rules, for the same reason", async () => {
    const root = await withContract({
      rules: [
        {
          kind: "boundary",
          id: "typo-field",
          module: "src/billing",
          allowedImporter: ["src/server.js"], // singular: would silently mean "nobody may import"
          description: "billing is isolated",
        },
      ],
    });
    await expect(runGate(root, fixtureGraph)).rejects.toThrow(/failed validation/);
  });

  it("a rule that matches nothing FAILS rather than passing vacuously", async () => {
    const root = await withContract({
      rules: [
        {
          kind: "boundary",
          id: "guards-nothing",
          module: "src/bilingual", // the typo a passing verdict would hide
          allowedImporters: ["src/server.js"],
          description: "billing is reached only through the server layer",
        },
        {
          kind: "route-auth",
          id: "checks-nothing",
          routes: "/admin/*", // no such route in this fixture
          description: "admin routes require an authenticated caller",
        },
      ],
    });
    const mistyped = await runGate(root, fixtureGraph);
    const boundaryRow = mistyped.observations[BOUNDARY_RECIPE]![0]!;
    const routeRow = mistyped.observations[ROUTE_AUTH_RECIPE]![0]!;
    expect(boundaryRow["matched"]).toBe(false);
    expect(String(boundaryRow["detail"])).toContain("guarding nothing");
    expect(routeRow["matched"]).toBe(false);
    expect(String(routeRow["detail"])).toContain("checking nothing");
    // and the recipes' `matched` assertions are what turn these into violations
    // — pinned here as rows, and end to end by the scan e2e
  });

  it("without graph.db the gate skips rather than clearing the contract", async () => {
    const nograph = await runGate(fixtureRoot);
    expect(nograph.skipped?.reason).toContain("cannot be checked against a graph that was never built");
    expect(nograph.observations).toEqual({});
  });

  it("a contract-carrying repo whose graph found no routes leaves the route recipe unevidenced", async () => {
    // bare-app has no server surface. Give it the fixture's contract and the
    // route recipe must stay ABSENT (graph.ts's no-routes refusal, inherited)
    // while the boundary half still answers.
    const root = await mkdtemp(join(tmpdir(), "rampscan-contract-noroutes-"));
    await cp(bareRoot, root, { recursive: true });
    await writeFile(
      join(root, "rampscan.config.json"),
      JSON.stringify({
        contract: {
          rules: [
            { kind: "route-auth", id: "r", routes: "/*", description: "routes require a caller identity" },
            { kind: "boundary", id: "b", module: "index", allowedImporters: [], description: "the entry module is imported by nothing" },
          ],
        },
      }),
    );
    const out2 = await runGate(root, await graphFor(root));
    expect(out2.observations[ROUTE_AUTH_RECIPE]).toBeUndefined();
    expect(out2.observations[BOUNDARY_RECIPE]).toBeDefined();
  }, 60_000);
});

describe("the contract schema itself", () => {
  it("refuses duplicate rule ids — two rules under one name cannot both be reported", () => {
    const dup = {
      rules: [
        { kind: "boundary", id: "same", module: "a", allowedImporters: [], description: "a is isolated" },
        { kind: "boundary", id: "same", module: "b", allowedImporters: [], description: "b is isolated" },
      ],
    };
    expect(() => ContractConfig.parse(dup)).toThrow(/unique/);
  });

  it("refuses a description that states a verdict — computed, never typed, across the config boundary", () => {
    // this prose is written OUTSIDE this repository, so the rule is structural
    // rather than a CI grep: a description asserting a verdict would put a
    // typed verdict on every surface that renders the rule
    const claim = {
      rules: [
        {
          kind: "route-auth",
          id: "r",
          routes: "/*",
          description: "this rule is violated by the health endpoint",
        },
      ],
    };
    expect(() => ContractConfig.parse(claim)).toThrow(/may not state a verdict/);
    // …while saying what the rule INTENDS is exactly what the field is for
    expect(() =>
      ContractConfig.parse({
        rules: [{ kind: "route-auth", id: "r", routes: "/*", description: "every route requires an authenticated caller" }],
      }),
    ).not.toThrow();
  });

  it("the fixture's own contract is a valid contract — the fixture is not testing a shape nobody ships", async () => {
    const raw = JSON.parse(await readFile(join(fixtureRoot, "rampscan.config.json"), "utf8")) as {
      contract: unknown;
    };
    expect(() => ContractConfig.parse(raw.contract)).not.toThrow();
  });
});

describe("inModulePrefix — what counts as inside a guarded module", () => {
  it("covers the directory, the file with an extension, and the module itself", () => {
    expect(inModulePrefix("src/billing.js", "src/billing")).toBe(true);
    expect(inModulePrefix("src/billing/invoice.ts", "src/billing")).toBe(true);
    expect(inModulePrefix("src/billing", "src/billing")).toBe(true);
    expect(inModulePrefix("src/billing/", "src/billing/")).toBe(true);
  });

  it("does not catch a neighbour whose name merely starts the same way", () => {
    // "src/billing" must not swallow "src/billingsystem.js" — a boundary that
    // guards more than it declared is as wrong as one that guards less
    expect(inModulePrefix("src/billingsystem.js", "src/billing")).toBe(false);
    expect(inModulePrefix("src/bill.js", "src/billing")).toBe(false);
  });
});
