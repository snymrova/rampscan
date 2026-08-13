import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import type { CollectContext, CollectOutput } from "@rampscan/core";
import { GRAPH_DB_ARTIFACT } from "@rampscan/graph";
import { graphCollector, reachability, purlOf, OPENVEX_ARTIFACT, OSV_RESULTS_ARTIFACT } from "../src/index.js";

// The M4 pair on the planted-fault fixture (built once by vitest's
// globalSetup): the graph collector answers route-auth, and the reachability
// collector proves the difference between the reachable lodash and the
// never-imported minimist — the milestone's sharpest sentence, as a test.

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

  it("proves the difference: lodash reachable with a path, minimist not_affected", () => {
    const rows = out.observations["no-critical-reachable-advisories"]!;
    const lodash = rows.find((r) => r["package"] === "lodash")!;
    const minimist = rows.find((r) => r["package"] === "minimist")!;
    expect(lodash["reachable"]).toBe("true");
    expect(lodash["not_affected"]).toBe(false);
    expect(String(lodash["path"])).toContain("lodash");
    expect(minimist["reachable"]).toBe("false");
    expect(minimist["not_affected"]).toBe(true);
    expect(minimist["path"]).toBeNull();
  });

  it("only the reachable advisory becomes a finding, with the call path as evidence", () => {
    const advisories = out.findings.filter((f) => f.variable === "advisories");
    expect(advisories).toHaveLength(1);
    expect(advisories[0]!.summary).toContain("lodash");
    expect(advisories[0]!.evidence.some((e) => e.kind === "trace" && e.note?.includes("»"))).toBe(true);
  });

  it("emits OpenVEX: not_affected for minimist with the justification, affected for lodash", async () => {
    const vexPath = out.artifacts.find((a) => a.name === OPENVEX_ARTIFACT)!.path;
    const vex = JSON.parse(await readFile(vexPath, "utf8")) as {
      "@context": string;
      statements: Array<Record<string, unknown>>;
    };
    expect(vex["@context"]).toBe("https://openvex.dev/ns/v0.2.0");
    const byStatus = (s: string) => vex.statements.filter((st) => st["status"] === s);
    const notAffected = byStatus("not_affected");
    expect(notAffected).toHaveLength(1);
    expect((notAffected[0]!["vulnerability"] as { name: string }).name).toBe("GHSA-xvch-5gv4-984h");
    expect(notAffected[0]!["justification"]).toBe("vulnerable_code_not_in_execute_path");
    expect((notAffected[0]!["products"] as Array<{ "@id": string }>)[0]!["@id"]).toBe(
      "pkg:npm/minimist@1.2.5",
    );
    expect(byStatus("affected")).toHaveLength(1);
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
