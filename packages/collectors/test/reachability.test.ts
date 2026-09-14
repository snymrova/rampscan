import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import type { CollectContext, CollectOutput } from "@rampscan/core";
import {
  DEFAULT_AUTH_PATTERNS,
  GRAPH_DB_ARTIFACT,
  detectApplicationRoots,
  detectEntrypoints,
  extractGraph,
  graphToolVersion,
  writeGraphDb,
} from "@rampscan/graph";
import {
  graphCollector,
  reachability,
  purlOf,
  ABSENT_NODE_NOTE,
  OPENVEX_ARTIFACT,
  OSV_RESULTS_ARTIFACT,
} from "../src/index.js";

// The M4 pair on the planted-fault fixture (built once by vitest's
// globalSetup): the graph collector answers route-auth, and the reachability
// collector separates the three answers the gate has. lodash is reachable
// (violated, with the path). minimist is declared and never imported, so it
// has NO node — the walk never saw it, and since S1-1 that is `unknown` and
// counts (GHSA-7jff-6v53-r56x). The third answer, a real not_affected, needs a
// package that HAS a node the walk cannot arrive at; the fixture has none, so
// a mini-repo below plants one.

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "../../..");
const fixtureRoot = join(repoRoot, "fixtures/vulnerable-app");

// a hand-written osv report shaped like the real tool's output — the parser
// has its own schema; the gate must not depend on network or installed tools
const OSV_REPORT = {
  results: [
    {
      source: { path: "package-lock.json" },
      packages: [
        {
          package: { name: "lodash", version: "4.17.15", ecosystem: "npm" },
          vulnerabilities: [
            {
              id: "GHSA-p6mc-m468-83gw",
              summary: "Prototype pollution in lodash",
              aliases: ["CVE-2020-8203"],
            },
          ],
          groups: [{ ids: ["GHSA-p6mc-m468-83gw", "CVE-2020-8203"], max_severity: "7.4" }],
        },
        {
          package: { name: "minimist", version: "1.2.5", ecosystem: "npm" },
          vulnerabilities: [
            {
              id: "GHSA-xvch-5gv4-984h",
              summary: "Prototype pollution in minimist",
              aliases: ["CVE-2021-44906"],
            },
          ],
          groups: [{ ids: ["GHSA-xvch-5gv4-984h", "CVE-2021-44906"], max_severity: "9.8" }],
        },
      ],
    },
  ],
};

function ctx(artifactDir: string, inputs: Map<string, string>): CollectContext {
  return {
    workspace: { root: fixtureRoot, repo: "fixtures/vulnerable-app", commit: "f".repeat(40) },
    artifactDir,
    inputs,
    runId: "run-test",
  };
}

let graphOut: CollectOutput;
let graphDbPath: string;

beforeAll(async () => {
  const dir = await mkdtemp(join(tmpdir(), "rampscan-reach-"));
  graphOut = await graphCollector.collect(ctx(dir, new Map()));
  graphDbPath = graphOut.artifacts.find((a) => a.name === GRAPH_DB_ARTIFACT)!.path;
});

describe("graph collector on the fixture", () => {
  it("builds graph.db and turns route-auth-coverage live", () => {
    expect(graphOut.skipped).toBeUndefined();
    const rows = graphOut.observations["route-auth-coverage"]!;
    expect(rows).toHaveLength(2);
    const health = rows.find((r) => r["route"] === "GET /health")!;
    const settings = rows.find((r) => r["route"] === "GET /settings")!;
    expect(health["auth_reached"]).toBe(false);
    expect(settings["auth_reached"]).toBe(true);
    expect(settings["auth_symbol"]).toBe("requireAuth");
    expect(String(settings["path"])).toContain("requireAuth");
  });

  it("emits a finding for the unauthenticated route, anchored to its file", () => {
    const finding = graphOut.findings.find((f) => f.variable === "route-auth");
    expect(finding).toBeDefined();
    expect(finding!.summary).toContain("GET /health");
    expect(finding!.anchor.node).toBe("src/server.js");
    expect(graphOut.anchors?.["route-auth-coverage"]?.some((a) => a.path === "src/server.js")).toBe(true);
  });
});

describe("reachability gate — the flagship join", () => {
  let out: CollectOutput;

  beforeAll(async () => {
    const dir = await mkdtemp(join(tmpdir(), "rampscan-reach-gate-"));
    const osvPath = join(dir, OSV_RESULTS_ARTIFACT);
    await writeFile(osvPath, JSON.stringify(OSV_REPORT));
    out = await reachability.collect(
      ctx(
        dir,
        new Map([
          [OSV_RESULTS_ARTIFACT, osvPath],
          [GRAPH_DB_ARTIFACT, graphDbPath],
        ]),
      ),
    );
  });

  it("separates reachable from never-walked: lodash has a path, minimist (no node) is unknown", () => {
    const rows = out.observations["no-critical-reachable-advisories"]!;
    const lodash = rows.find((r) => r["package"] === "lodash")!;
    const minimist = rows.find((r) => r["package"] === "minimist")!;
    expect(lodash["reachable"]).toBe("true");
    expect(lodash["not_affected"]).toBe(false);
    expect(String(lodash["path"])).toContain("lodash");
    // absence of a node is the absence of evidence — never a negative verdict
    expect(minimist["reachable"]).toBe("unknown");
    expect(minimist["not_affected"]).toBe(false);
    expect(minimist["path"]).toBeNull();
    expect(minimist["gate_note"]).toBe(ABSENT_NODE_NOTE);
    // the gate note names only the gap it is about: lodash was walked
    expect(lodash["gate_note"]).toBeUndefined();
  });

  it("both advisories count: the reachable one with its call path, the unknown one saying so", () => {
    const advisories = out.findings.filter((f) => f.variable === "advisories");
    expect(advisories).toHaveLength(2);
    const lodash = advisories.find((f) => f.summary.includes("lodash"))!;
    expect(lodash.evidence.some((e) => e.kind === "trace" && e.note?.includes("»"))).toBe(true);
    const minimist = advisories.find((f) => f.summary.includes("minimist"))!;
    expect(minimist.summary).toContain("reachability unknown");
    expect(minimist.severity).toBe("blocker");
  });

  it("emits OpenVEX: affected for lodash, under_investigation for minimist — and no not_affected at all", async () => {
    const vexPath = out.artifacts.find((a) => a.name === OPENVEX_ARTIFACT)!.path;
    const vex = JSON.parse(await readFile(vexPath, "utf8")) as {
      "@context": string;
      statements: Array<Record<string, unknown>>;
    };
    expect(vex["@context"]).toBe("https://openvex.dev/ns/v0.2.0");
    const byStatus = (s: string) => vex.statements.filter((st) => st["status"] === s);
    expect(byStatus("not_affected")).toHaveLength(0);
    expect(byStatus("affected")).toHaveLength(1);
    const investigating = byStatus("under_investigation");
    expect(investigating).toHaveLength(1);
    expect((investigating[0]!["vulnerability"] as { name: string }).name).toBe("GHSA-xvch-5gv4-984h");
    expect((investigating[0]!["products"] as Array<{ "@id": string }>)[0]!["@id"]).toBe(
      "pkg:npm/minimist@1.2.5",
    );
    expect(investigating[0]!["impact_statement"]).toBe(ABSENT_NODE_NOTE);
  });

  it("without graph.db the gate degrades to the honest M1 posture — unknown, never waved through", async () => {
    const dir = await mkdtemp(join(tmpdir(), "rampscan-reach-nograph-"));
    const osvPath = join(dir, OSV_RESULTS_ARTIFACT);
    await writeFile(osvPath, JSON.stringify(OSV_REPORT));
    const degraded = await reachability.collect(ctx(dir, new Map([[OSV_RESULTS_ARTIFACT, osvPath]])));
    const rows = degraded.observations["no-critical-reachable-advisories"]!;
    for (const row of rows) {
      expect(row["reachable"]).toBe("unknown");
      expect(row["not_affected"]).toBe(false);
      expect(String(row["gate_note"])).toContain("graph.db unavailable");
    }
    // both advisories count as findings; the VEX says under_investigation
    expect(degraded.findings.filter((f) => f.variable === "advisories")).toHaveLength(2);
    const vexPath = degraded.artifacts.find((a) => a.name === OPENVEX_ARTIFACT)!.path;
    const vex = JSON.parse(await readFile(vexPath, "utf8")) as { statements: Array<Record<string, unknown>> };
    expect(vex.statements.every((s) => s["status"] === "under_investigation")).toBe(true);
  });

  it("without osv-results.json it skips with the honest reason", async () => {
    const dir = await mkdtemp(join(tmpdir(), "rampscan-reach-noosv-"));
    const skipped = await reachability.collect(ctx(dir, new Map()));
    expect(skipped.skipped?.reason).toContain("osv-scanner must run");
  });

  it("purlOf builds package URLs, scoped npm names percent-encoded", () => {
    expect(purlOf("npm", "lodash", "4.17.15")).toBe("pkg:npm/lodash@4.17.15");
    expect(purlOf("npm", "@scope/pkg", "1.0.0")).toBe("pkg:npm/%40scope/pkg@1.0.0");
  });
});

describe("reachability gate — the one not_affected the graph can earn", () => {
  // A package that HAS a node the walk cannot arrive at: minimist is imported,
  // but only by src/orphan.js, which nothing imports and no entry point is.
  // This is the only shape in which the gate may sign not_affected.
  let out: CollectOutput;

  beforeAll(async () => {
    const root = await mkdtemp(join(tmpdir(), "rampscan-reach-earned-"));
    const put = async (rel: string, content: string) => {
      await mkdir(dirname(join(root, rel)), { recursive: true });
      await writeFile(join(root, rel), content);
    };
    await put(
      "package.json",
      JSON.stringify({ name: "earned", main: "src/index.js", dependencies: { lodash: "4.17.15", minimist: "1.2.5" } }),
    );
    await put("src/index.js", 'const merge = require("lodash/merge");\nmodule.exports = { merge };\n');
    await put("src/orphan.js", 'const parse = require("minimist");\nmodule.exports = { parse };\n');

    const files = ["src/index.js", "src/orphan.js"];
    const graph = await extractGraph(root, files, "worktree");
    const entry = await detectEntrypoints(root, new Set(files));
    const dir = await mkdtemp(join(tmpdir(), "rampscan-reach-earned-out-"));
    const dbPath = join(dir, GRAPH_DB_ARTIFACT);
    writeGraphDb(dbPath, graph, {
      extractorVersion: graphToolVersion(),
      commit: "e".repeat(40),
      entrypoints: entry.files,
      entrypointSource: entry.source,
      entrypointsUnresolved: entry.unresolved,
      authPatterns: DEFAULT_AUTH_PATTERNS,
      // the one root the tree declares is the one the walk enters (S1-3) —
      // without this line the gate cannot know how wide it walked, and refuses
      applicationRoots: await detectApplicationRoots(root, new Set(files), "worktree"),
    });
    const osvPath = join(dir, OSV_RESULTS_ARTIFACT);
    await writeFile(osvPath, JSON.stringify(OSV_REPORT));
    out = await reachability.collect({
      ...ctx(
        dir,
        new Map([
          [OSV_RESULTS_ARTIFACT, osvPath],
          [GRAPH_DB_ARTIFACT, dbPath],
        ]),
      ),
      workspace: { root, repo: "earned", commit: "e".repeat(40) },
    });
  });

  it("minimist has a node and no walk arrives: not_affected, reachable false", () => {
    const rows = out.observations["no-critical-reachable-advisories"]!;
    const minimist = rows.find((r) => r["package"] === "minimist")!;
    expect(minimist["reachable"]).toBe("false");
    expect(minimist["not_affected"]).toBe(true);
    expect(minimist["path"]).toBeNull();
    expect(minimist["gate_note"]).toBeUndefined();
    const lodash = rows.find((r) => r["package"] === "lodash")!;
    expect(lodash["reachable"]).toBe("true");
  });

  it("only the reachable advisory becomes a finding", () => {
    const advisories = out.findings.filter((f) => f.variable === "advisories");
    expect(advisories).toHaveLength(1);
    expect(advisories[0]!.summary).toContain("lodash");
  });

  it("signs not_affected for minimist with the justification and the entry points it rests on", async () => {
    const vexPath = out.artifacts.find((a) => a.name === OPENVEX_ARTIFACT)!.path;
    const vex = JSON.parse(await readFile(vexPath, "utf8")) as { statements: Array<Record<string, unknown>> };
    const notAffected = vex.statements.filter((s) => s["status"] === "not_affected");
    expect(notAffected).toHaveLength(1);
    expect((notAffected[0]!["vulnerability"] as { name: string }).name).toBe("GHSA-xvch-5gv4-984h");
    expect(notAffected[0]!["justification"]).toBe("vulnerable_code_not_in_execute_path");
    expect((notAffected[0]!["products"] as Array<{ "@id": string }>)[0]!["@id"]).toBe("pkg:npm/minimist@1.2.5");
    expect(String(notAffected[0]!["impact_statement"])).toContain("src/index.js");
    // the scope as structured fields, not only inside the prose (S1-3)
    expect(notAffected[0]!["rampscan:scope"]).toEqual({
      commit: "e".repeat(40),
      entrypoints: ["src/index.js"],
      entrypoint_source: "package.json",
      application_roots: [{ dir: ".", name: "earned", walked: true }],
    });
  });

  it("the basis signs the width of the walk: one root, entered", () => {
    const basis = out.basis!["no-critical-reachable-advisories"]!;
    expect(basis.application_roots).toEqual([
      { dir: ".", name: "earned", file_count: 2, reached_file_count: 1 },
    ]);
    expect(basis.degraded).toBeUndefined();
  });
});
