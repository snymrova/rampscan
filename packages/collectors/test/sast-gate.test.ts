import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import type { CollectContext, CollectOutput } from "@rampscan/core";
import { GRAPH_DB_ARTIFACT } from "@rampscan/graph";
import {
  SEMGREP_RESULTS_ARTIFACT,
  graphCollector,
  matchIacFiles,
  matchSpecFiles,
  relativizeResultPath,
  sastGate,
} from "../src/index.js";

// The SAST edition of the flagship pair, on the planted-fault fixture: the
// same eval() in two files — src/render.js (required from the entry point)
// and src/legacy-tools.js (imported by nothing). The gate must show the call
// path for one and prove not_affected for the other. semgrep itself is not
// spawned here: the gate consumes a hand-written semgrep-results.json in the
// producer's normalized shape, same posture as the reachability tests.

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "../../..");
const fixtureRoot = join(repoRoot, "fixtures/vulnerable-app");

const SEMGREP_REPORT = {
  tool: "semgrep",
  version: "1.173.0",
  rules: "a".repeat(64),
  results: [
    {
      check_id: "dangerous-eval",
      path: "src/render.js",
      start_line: 8,
      end_line: 8,
      severity: "ERROR",
      message: "eval()/new Function() executes dynamically constructed code",
    },
    {
      check_id: "dangerous-eval",
      path: "src/legacy-tools.js",
      start_line: 6,
      end_line: 6,
      severity: "ERROR",
      message: "eval()/new Function() executes dynamically constructed code",
    },
    {
      check_id: "weak-hash-algorithm",
      path: "src/render.js",
      start_line: 13,
      end_line: 13,
      severity: "WARNING",
      message: "MD5/SHA-1 are cryptographically broken",
    },
  ],
  error_count: 0,
};

function ctx(artifactDir: string, inputs: Map<string, string>): CollectContext {
  return {
    workspace: { root: fixtureRoot, repo: "fixtures/vulnerable-app", commit: "f".repeat(40) },
    artifactDir,
    inputs,
    runId: "run-test",
  };
}

let graphDbPath: string;

beforeAll(async () => {
  const dir = await mkdtemp(join(tmpdir(), "rampscan-sast-graph-"));
  const graphOut = await graphCollector.collect(ctx(dir, new Map()));
  graphDbPath = graphOut.artifacts.find((a) => a.name === GRAPH_DB_ARTIFACT)!.path;
});

describe("sast-reachability gate — the flagship move, SAST edition", () => {
  let out: CollectOutput;

  beforeAll(async () => {
    const dir = await mkdtemp(join(tmpdir(), "rampscan-sast-gate-"));
    const semgrepPath = join(dir, SEMGREP_RESULTS_ARTIFACT);
    await writeFile(semgrepPath, JSON.stringify(SEMGREP_REPORT));
    out = await sastGate.collect(
      ctx(
        dir,
        new Map([
          [SEMGREP_RESULTS_ARTIFACT, semgrepPath],
          [GRAPH_DB_ARTIFACT, graphDbPath],
        ]),
      ),
    );
  });

  it("proves the difference: render.js reachable with a call path, legacy-tools.js not_affected", () => {
    const rows = out.observations["no-reachable-dangerous-code"]!;
    const reachableEval = rows.find(
      (r) => r["path"] === "src/render.js" && r["check_id"] === "dangerous-eval",
    )!;
    const deadEval = rows.find((r) => r["path"] === "src/legacy-tools.js")!;
    expect(reachableEval["reachable"]).toBe("true");
    expect(reachableEval["not_affected"]).toBe(false);
    expect(String(reachableEval["call_path"])).toContain("src/render.js");
    expect(deadEval["reachable"]).toBe("false");
    expect(deadEval["not_affected"]).toBe(true);
    expect(deadEval["call_path"]).toBeNull();
  });

  it("the gate's live rows yield fix pointers — the I2c extraction pinned to the real producer", async () => {
    const { offenderPointer } = await import("@rampscan/core");
    const rows = out.observations["no-reachable-dangerous-code"]!;
    const reachableEval = rows.find(
      (r) => r["path"] === "src/render.js" && r["check_id"] === "dangerous-eval",
    )!;
    const pointer = offenderPointer(reachableEval)!;
    expect(pointer.file).toBe("src/render.js");
    expect(pointer.check).toBe("dangerous-eval");
    expect(typeof pointer.line).toBe("number");
    expect(pointer.call_path).toContain("»");
  });

  it("only the reachable ERROR becomes a finding, with the call path as trace evidence", () => {
    const findings = out.findings.filter((f) => f.variable === "sast");
    expect(findings).toHaveLength(1);
    expect(findings[0]!.summary).toContain("src/render.js");
    expect(findings[0]!.evidence.some((e) => e.kind === "trace" && e.note?.includes("»"))).toBe(true);
  });

  it("WARNING severity rides along as an observation without a finding", () => {
    const rows = out.observations["no-reachable-dangerous-code"]!;
    const warning = rows.find((r) => r["check_id"] === "weak-hash-algorithm")!;
    expect(warning["reachable"]).toBe("true");
    expect(out.findings.some((f) => f.summary.includes("weak-hash"))).toBe(false);
  });

  it("anchors the flagged files — drift there must kill the evidence", () => {
    const anchors = out.anchors?.["no-reachable-dangerous-code"] ?? [];
    expect(anchors.some((a) => a.path === "src/render.js")).toBe(true);
    expect(anchors.some((a) => a.path === "src/legacy-tools.js")).toBe(true);
  });

  it("without graph.db every hit counts as unknown — never waved through", async () => {
    const dir = await mkdtemp(join(tmpdir(), "rampscan-sast-nograph-"));
    const semgrepPath = join(dir, SEMGREP_RESULTS_ARTIFACT);
    await writeFile(semgrepPath, JSON.stringify(SEMGREP_REPORT));
    const degraded = await sastGate.collect(ctx(dir, new Map([[SEMGREP_RESULTS_ARTIFACT, semgrepPath]])));
    const rows = degraded.observations["no-reachable-dangerous-code"]!;
    for (const row of rows) {
      expect(row["reachable"]).toBe("unknown");
      expect(row["not_affected"]).toBe(false);
      expect(String(row["gate_note"])).toContain("graph.db unavailable");
    }
    // both ERROR hits count as findings; the WARNING still does not
    expect(degraded.findings.filter((f) => f.variable === "sast")).toHaveLength(2);
  });

  it("a hit in a file the graph never saw counts as unknown with its own note", async () => {
    const dir = await mkdtemp(join(tmpdir(), "rampscan-sast-ghost-"));
    const semgrepPath = join(dir, SEMGREP_RESULTS_ARTIFACT);
    await writeFile(
      semgrepPath,
      JSON.stringify({
        ...SEMGREP_REPORT,
        results: [{ ...SEMGREP_REPORT.results[0]!, path: "scripts/not-in-graph.sh" }],
      }),
    );
    const out2 = await sastGate.collect(
      ctx(
        dir,
        new Map([
          [SEMGREP_RESULTS_ARTIFACT, semgrepPath],
          [GRAPH_DB_ARTIFACT, graphDbPath],
        ]),
      ),
    );
    const row = out2.observations["no-reachable-dangerous-code"]![0]!;
    expect(row["reachable"]).toBe("unknown");
    expect(row["not_affected"]).toBe(false);
    expect(String(row["gate_note"])).toContain("no node in the code graph");
  });

  it("a clean run is an observation, not an absence — zero rows, still observed", async () => {
    const dir = await mkdtemp(join(tmpdir(), "rampscan-sast-clean-"));
    const semgrepPath = join(dir, SEMGREP_RESULTS_ARTIFACT);
    await writeFile(semgrepPath, JSON.stringify({ ...SEMGREP_REPORT, results: [] }));
    const clean = await sastGate.collect(
      ctx(
        dir,
        new Map([
          [SEMGREP_RESULTS_ARTIFACT, semgrepPath],
          [GRAPH_DB_ARTIFACT, graphDbPath],
        ]),
      ),
    );
    expect(clean.observations["no-reachable-dangerous-code"]).toEqual([]);
    expect(clean.findings).toHaveLength(0);
  });

  it("without semgrep-results.json it skips with the honest reason", async () => {
    const dir = await mkdtemp(join(tmpdir(), "rampscan-sast-noinput-"));
    const skipped = await sastGate.collect(ctx(dir, new Map()));
    expect(skipped.skipped?.reason).toContain("semgrep must run");
  });
});

describe("config-plane detection helpers", () => {
  it("matchIacFiles finds Dockerfiles, workflows, and Terraform — and names the frameworks", () => {
    const { frameworks, files } = matchIacFiles([
      "Dockerfile",
      "deploy/Dockerfile.prod",
      "app.dockerfile",
      ".github/workflows/ci.yml",
      ".github/workflows/release.yaml",
      "infra/main.tf",
      "src/index.ts",
      "README.md",
    ]);
    expect(frameworks).toEqual(["dockerfile", "github_actions", "terraform"]);
    expect(files).toHaveLength(6);
  });

  it("matchIacFiles is empty on a repo with nothing IaC-shaped", () => {
    expect(matchIacFiles(["src/a.ts", "package.json"]).frameworks).toEqual([]);
  });

  it("matchSpecFiles finds OpenAPI/Swagger documents by name, case-insensitive", () => {
    expect(
      matchSpecFiles(["openapi.yaml", "docs/OpenAPI-v2.json", "api/swagger.yml", "src/openapi.ts", "spec.yaml"]),
    ).toEqual(["api/swagger.yml", "docs/OpenAPI-v2.json", "openapi.yaml"]);
  });

  it("relativizeResultPath strips the scan-root prefix and nothing else", () => {
    expect(relativizeResultPath("/rampscan/m1/src/a.js", "/rampscan/m1")).toBe("src/a.js");
    expect(relativizeResultPath("src/a.js", "/rampscan/m1")).toBe("src/a.js");
  });
});
