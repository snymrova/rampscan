import { execSync } from "node:child_process";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { writeFile } from "node:fs/promises";
import { beforeAll, describe, expect, it } from "vitest";
import {
  SEMGREP_RESULTS_ARTIFACT,
  gitleaks,
  graphCollector,
  osvScanner,
  reachability,
  repoFacts,
  sastGate,
  syft,
} from "@rampscan/collectors";
import type { Collector } from "@rampscan/core";
import { DEFAULT_DATASET_PIN } from "@rampscan/dataset";
import { ScanResult } from "@rampscan/schema";
import { renderSummary, scan } from "../src/index.js";

// The M1 vertical slice end to end (plan C5 exit): scan the planted-fault
// fixture and check the verdicts land where the faults were planted. grype is
// left out here (base-image pull + vuln DB is a manual exit-test, not CI
// material); its recipe must therefore come back unevidenced, not silently
// absent. Tool-dependent verdicts assert only when the tool is installed.

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "../../..");
const fixtureRoot = join(repoRoot, "fixtures/vulnerable-app");

function installed(tool: string): boolean {
  try {
    execSync(`command -v ${tool}`, { stdio: "pipe" });
    return true;
  } catch {
    return false;
  }
}

let result: ScanResult;
let resultPath: string;

// A deterministic stand-in for the semgrep PRODUCER only (spawning the real
// tool needs a binary or Docker — not CI material, same call as grype): it
// emits the normalized semgrep-results.json for the fixture's planted pair.
// The gate itself is the REAL sast-reachability collector over the REAL
// graph.db, so the recipe wiring (observation key, verdicts, findings) is
// exercised end to end.
const stubSemgrep: Collector = {
  manifest: { name: "semgrep", toolVersion: "resolved-at-run", recipes: [], outputs: [SEMGREP_RESULTS_ARTIFACT] },
  async collect(ctx) {
    const path = join(ctx.artifactDir, SEMGREP_RESULTS_ARTIFACT);
    await writeFile(
      path,
      JSON.stringify({
        tool: "semgrep",
        version: "1.173.0",
        rules: "0".repeat(64),
        results: [
          {
            check_id: "dangerous-eval",
            path: "src/render.js",
            start_line: 7,
            end_line: 7,
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
        ],
        error_count: 0,
      }),
    );
    return {
      findings: [],
      artifacts: [{ name: SEMGREP_RESULTS_ARTIFACT, path }],
      observations: {},
      toolVersion: "1.173.0",
      exitCode: 0,
    };
  },
};

// the fixture itself is built once for the whole run by vitest's globalSetup

beforeAll(async () => {
  const outcome = await scan({
    path: fixtureRoot,
    outDir: await mkdtemp(join(tmpdir(), "rampscan-e2e-")),
    datasetDir: join(repoRoot, "docs/context/ramprules/derived"),
    datasetPin: DEFAULT_DATASET_PIN,
    recipesDir: join(repoRoot, "recipes/pipeline"),
    collectors: [repoFacts, gitleaks, graphCollector, stubSemgrep, syft, osvScanner, reachability, sastGate],
  });
  result = outcome.result;
  resultPath = outcome.resultPath;
}, 300_000);

function verdictOf(recipeId: string): string {
  const row = result.recipes.find((r) => r.recipe_id === recipeId);
  expect(row, `recipe ${recipeId} missing from scan result`).toBeDefined();
  return row!.verdict;
}

describe("rampscan scan on the planted-fault fixture", () => {
  it("writes a scan-result.json that round-trips the schema", async () => {
    const reparsed = ScanResult.parse(JSON.parse(await readFile(resultPath, "utf8")));
    expect(reparsed.commit).toMatch(/^[0-9a-f]{40}$/);
    expect(reparsed.dataset_version).toBe(DEFAULT_DATASET_PIN);
  });

  it("repo-facts verdicts land where the faults were planted", () => {
    expect(verdictOf("lockfile-pinned-deps")).toBe("evidenced");
    expect(verdictOf("ci-actions-pinned")).toBe("violated");
    expect(verdictOf("ci-provenance-present")).toBe("violated");
    expect(verdictOf("tests-in-ci")).toBe("violated");
    expect(verdictOf("dependency-update-automation")).toBe("violated");
    expect(verdictOf("codeowners-defined")).toBe("violated");
    expect(verdictOf("container-runs-nonroot")).toBe("violated");
  });

  it("route-auth-coverage is live as of M4: the bare /health route violates it", () => {
    const row = result.recipes.find((r) => r.recipe_id === "route-auth-coverage")!;
    expect(row.verdict).toBe("violated");
    expect(row.assertions[0]!.detail).toContain("GET /health");
    expect(result.findings.some((f) => f.variable === "route-auth" && f.summary.includes("GET /health"))).toBe(true);
    // the authed route is NOT among the offenders
    expect(row.assertions[0]!.detail ?? "").not.toContain("GET /settings");
  });

  it("grype's recipe is unevidenced when grype does not run — absent, never hidden", () => {
    expect(verdictOf("container-base-image-patched")).toBe("unevidenced");
  });

  it("the config-plane recipes are unevidenced when their collectors do not run", () => {
    expect(verdictOf("iac-baseline-clean")).toBe("unevidenced");
    expect(verdictOf("api-spec-lint-clean")).toBe("unevidenced");
  });

  it("the SAST gate proves the difference: reachable eval violates with a call path, the dead file does not", () => {
    const row = result.recipes.find((r) => r.recipe_id === "no-reachable-dangerous-code")!;
    expect(row.verdict).toBe("violated");
    // exactly ONE of the two planted evals counts — the reachable one
    expect(row.assertions[0]!.detail).toContain("got 1");
    expect(row.assertions[0]!.detail).toContain("src/render.js");
    const sastFindings = result.findings.filter((f) => f.variable === "sast");
    expect(sastFindings).toHaveLength(1);
    expect(sastFindings[0]!.evidence.some((e) => e.kind === "trace" && e.note?.includes("»"))).toBe(true);
    // the unreachable eval: NO finding — not_affected, proven by the graph
    expect(sastFindings.some((f) => f.summary.includes("legacy-tools"))).toBe(false);
  });

  it.skipIf(!installed("gitleaks"))("the history-only secret violates no-secrets-in-history", () => {
    expect(verdictOf("no-secrets-in-history")).toBe("violated");
    const blockers = result.findings.filter((f) => f.variable === "secrets");
    expect(blockers.length).toBeGreaterThan(0);
  });

  it.skipIf(!installed("syft"))("the SBOM recipe is evidenced with the artifact attached", () => {
    expect(verdictOf("sbom-exists-and-fresh")).toBe("evidenced");
    const row = result.recipes.find((r) => r.recipe_id === "sbom-exists-and-fresh")!;
    expect(row.artifacts.some((a) => a.name === "sbom.cdx.json")).toBe(true);
    expect(row.artifacts[0]!.sha256).toMatch(/^[0-9a-f]{64}$/);
  });

  it.skipIf(!installed("syft") || !installed("osv-scanner"))(
    "M4 proves the difference: reachable lodash violates with a path, minimist becomes a not-affected VEX",
    async () => {
      const row = result.recipes.find((r) => r.recipe_id === "no-critical-reachable-advisories")!;
      if (row.verdict === "unevidenced") {
        // offline is a legitimate skip — but it must say so
        expect(row.reason).toBeTruthy();
        return;
      }
      expect(row.verdict).toBe("violated");
      // the reachable dep: a finding with the call path as the artifact
      const lodashFinding = result.findings.find(
        (f) => f.variable === "advisories" && f.summary.includes("lodash"),
      );
      expect(lodashFinding).toBeDefined();
      expect(lodashFinding!.evidence.some((e) => e.kind === "trace" && e.note?.includes("»"))).toBe(true);
      // the unreachable dep: NO finding — it is not_affected, not violated
      expect(
        result.findings.some((f) => f.variable === "advisories" && f.summary.includes("minimist")),
      ).toBe(false);
      // the OpenVEX export lands in exports/ with the justification
      const vexPath = join(dirname(resultPath), "exports", "openvex.json");
      const vex = JSON.parse(await readFile(vexPath, "utf8")) as {
        statements: Array<Record<string, unknown>>;
      };
      const notAffected = vex.statements.find((s) => s["status"] === "not_affected");
      expect(notAffected).toBeDefined();
      expect(notAffected!["justification"]).toBe("vulnerable_code_not_in_execute_path");
      expect(JSON.stringify(notAffected!["products"])).toContain("minimist");
    },
  );

  it("every verdict cites KSI and control IDs (resolution is recipes.test.ts's job)", () => {
    for (const row of result.recipes) {
      expect(row.ksi_ids.length).toBeGreaterThan(0);
      expect(row.control_ids.length).toBeGreaterThan(0);
    }
  });

  it("the three-register summary renders all three registers", () => {
    const text = renderSummary(result, false);
    expect(text).toContain("EVIDENCED");
    expect(text).toContain("VIOLATED");
    expect(text).toContain("UNEVIDENCED");
  });
});
