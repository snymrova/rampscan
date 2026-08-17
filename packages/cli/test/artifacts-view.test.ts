import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";

// The artifact viewer's normalizers (plan J4), pinned in the export-csv /
// mvx-twin / runs-view posture: this test loads the CONSOLE's copy by path (a
// workspace import would break `tsc --build`, and the console is not a
// workspace package).
//
// Two properties carry the weight:
//
//   1. THE SECRET IS NEVER RENDERED. A gitleaks report carries the matched
//      secret and its line; the table must contain neither, anywhere, in any
//      column — so the assertion greps the whole rendered table rather than
//      checking a column list, because a column list can be right while a
//      message field quietly carries the value.
//   2. THE FAMILY COMES FROM THE ATTESTED NAME, never from sniffing content.
//      The subject name is part of what was signed; the shape of the bytes is
//      not, and a viewer that guessed from content could be steered by the
//      bytes into rendering them as something they are not.

interface ArtifactTable {
  family: string;
  columns: string[];
  rows: string[][];
  total: number;
  note?: string;
}

interface ArtifactsModule {
  ROW_CAP: number;
  artifactFamily(name: string): string | null;
  artifactTable(name: string, content: unknown): ArtifactTable | null;
  noTableReason(name: string): string;
}

const here = dirname(fileURLToPath(import.meta.url));
const consoleLib = join(here, "../../../console/web/lib/artifacts.ts");
const repoRoot = join(here, "../../..");

let M: ArtifactsModule;

beforeAll(async () => {
  M = (await import(consoleLib)) as ArtifactsModule;
});

/** every cell of a table as one string — for asserting an ABSENCE */
function allText(table: ArtifactTable): string {
  return [table.columns.join(" "), ...table.rows.map((r) => r.join(" ")), table.note ?? ""].join(
    "\n",
  );
}

describe("artifactFamily: decided by the attested name, never by the content", () => {
  it("recognizes the normalized artifacts the collectors write", () => {
    expect(M.artifactFamily("semgrep-results.json")).toBe("semgrep");
    expect(M.artifactFamily("checkov-results.json")).toBe("checkov");
    expect(M.artifactFamily("spectral-results.json")).toBe("spectral");
    expect(M.artifactFamily("gitleaks-report.json")).toBe("gitleaks");
    expect(M.artifactFamily("osv-results.json")).toBe("osv-scanner");
    expect(M.artifactFamily("grype-report.json")).toBe("grype");
    expect(M.artifactFamily("openvex.json")).toBe("openvex");
    expect(M.artifactFamily("repo-facts.json")).toBe("repo-facts");
    expect(M.artifactFamily("sbom.cdx.json")).toBe("cyclonedx sbom");
    expect(M.artifactFamily("repo-model.json")).toBe("repo model");
  });

  it("gives an unknown artifact NO family rather than a guessed one", () => {
    expect(M.artifactFamily("graph.db")).toBeNull();
    expect(M.artifactFamily("semgrep-raw.json")).toBeNull();
    expect(M.artifactFamily("whatever.json")).toBeNull();
  });

  it("does not let the content decide: semgrep bytes under another name get no table", () => {
    const semgrepShaped = { tool: "semgrep", results: [{ check_id: "x", path: "a.js", start_line: 1 }] };
    expect(M.artifactTable("attacker-chosen.json", semgrepShaped)).toBeNull();
  });

  it("says why there is no table, and that the bytes are still good", () => {
    expect(M.noTableReason("graph.db")).toMatch(/binary SQLite call graph/);
    expect(M.noTableReason("semgrep-raw.json")).toMatch(/unnormalized output/);
    expect(M.noTableReason("mystery.json")).toMatch(/hash to the attested digest/);
  });
});

describe("gitleaks: the secret is absent, not masked", () => {
  const report = [
    {
      RuleID: "aws-access-token",
      Description: "Identified a pattern that may indicate AWS credentials",
      StartLine: 144,
      File: "fixtures/build-vulnerable-app.mjs",
      Commit: "edf4b6bf0f6c957bba12378240f4c0afc89e5bfb",
      Match: "const key = AKIAIOSFODNN7EXAMPLE",
      Secret: "AKIAIOSFODNN7EXAMPLE",
      Date: "2026-08-13T01:14:02Z",
      Author: "sunny luthra",
      Email: "luthra.sunny@gmail.com",
      Entropy: 4.02,
    },
  ];

  it("renders rule · file:line · commit", () => {
    const table = M.artifactTable("gitleaks-report.json", report)!;
    expect(table.family).toBe("gitleaks");
    expect(table.rows).toEqual([
      [
        "aws-access-token",
        "fixtures/build-vulnerable-app.mjs:144",
        "edf4b6bf0f6c",
        "2026-08-13T01:14:02Z",
      ],
    ]);
  });

  it("contains the secret NOWHERE — not a column, not a cell, not the note", () => {
    const text = allText(M.artifactTable("gitleaks-report.json", report)!);
    expect(text).not.toContain("AKIAIOSFODNN7EXAMPLE");
    expect(text).not.toContain("const key =");
    // and it says out loud that it withheld it, rather than leaving a reader
    // to wonder whether the tool found a value at all
    expect(text).toMatch(/deliberately not rendered/);
  });
});

describe("the findings tables", () => {
  it("semgrep: check id · file:line · severity · message, and errors said out loud", () => {
    const table = M.artifactTable("semgrep-results.json", {
      tool: "semgrep",
      results: [
        { check_id: "eval-injection", path: "src/render.js", start_line: 42, severity: "ERROR", message: "eval" },
      ],
      error_count: 1,
    })!;
    expect(table.columns).toEqual(["check id", "file:line", "severity", "message"]);
    expect(table.rows[0]).toEqual(["eval-injection", "src/render.js:42", "ERROR", "eval"]);
    // a findings table that hid the run's own errors would overstate coverage
    expect(table.note).toMatch(/1 semgrep error/);
  });

  it("checkov: the failed set, and it says the passes are not in it", () => {
    const table = M.artifactTable("checkov-results.json", {
      passed_count: 17,
      failed: [
        { check_id: "CKV_DOCKER_2", check_name: "healthcheck", framework: "dockerfile", file: "Dockerfile", resource: "/Dockerfile." },
      ],
    })!;
    expect(table.rows[0]).toEqual(["CKV_DOCKER_2", "/Dockerfile.", "Dockerfile", "dockerfile"]);
    expect(table.note).toMatch(/17 check\(s\) passed and are not listed here/);
  });

  it("spectral: rule · file:line · severity", () => {
    const table = M.artifactTable("spectral-results.json", {
      results: [{ code: "oas3-api-servers", file: "openapi.yaml", line: 3, severity: "warning", message: "no servers" }],
    })!;
    expect(table.rows[0]).toEqual(["oas3-api-servers", "openapi.yaml:3", "warning", "no servers"]);
  });

  it("osv: package · advisory · severity · fixed-in, joined from the advisory's own ranges", () => {
    const table = M.artifactTable("osv-results.json", {
      results: [
        {
          source: { path: "sbom.cdx.json", type: "sbom" },
          packages: [
            {
              package: { name: "postcss", version: "8.4.31", ecosystem: "npm" },
              groups: [{ ids: ["GHSA-6g55-p6wh-862q"], aliases: ["CVE-2026-45623"], max_severity: "7.5" }],
              vulnerabilities: [
                {
                  id: "GHSA-6g55-p6wh-862q",
                  affected: [{ ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "8.5.12" }] }] }],
                },
              ],
            },
          ],
        },
      ],
    })!;
    expect(table.rows[0]).toEqual(["postcss@8.4.31", "npm", "GHSA-6g55-p6wh-862q", "7.5", "8.5.12"]);
  });

  it("osv: an advisory found only by ALIAS still reports its fixed version", () => {
    const table = M.artifactTable("osv-results.json", {
      results: [
        {
          packages: [
            {
              package: { name: "left-pad", version: "1.0.0", ecosystem: "npm" },
              groups: [{ ids: ["CVE-2026-1"], max_severity: "5.0" }],
              vulnerabilities: [
                {
                  id: "GHSA-zzzz",
                  aliases: ["CVE-2026-1"],
                  affected: [{ ranges: [{ events: [{ fixed: "1.0.1" }] }] }],
                },
              ],
            },
          ],
        },
      ],
    })!;
    expect(table.rows[0]![4]).toBe("1.0.1");
  });

  it("grype: package · vulnerability · severity · fixed-in", () => {
    const table = M.artifactTable("grype-report.json", {
      matches: [
        {
          vulnerability: { id: "CVE-2025-15467", severity: "Critical", fix: { versions: ["3.5.5-r0"], state: "fixed" } },
          artifact: { name: "libcrypto3", version: "3.5.1-r0", type: "apk" },
        },
        {
          vulnerability: { id: "CVE-2025-9", severity: "Low", fix: { versions: [], state: "not-fixed" } },
          artifact: { name: "busybox", version: "1.0", type: "apk" },
        },
      ],
    })!;
    expect(table.rows[0]).toEqual(["libcrypto3@3.5.1-r0", "apk", "CVE-2025-15467", "Critical", "3.5.5-r0"]);
    // no fix is a FACT the table must state, not an empty cell
    expect(table.rows[1]![4]).toBe("not-fixed");
  });

  it("openvex: the status, its justification, and the over-approximation said out loud", () => {
    const table = M.artifactTable("openvex.json", {
      statements: [
        {
          vulnerability: { name: "GHSA-6g55-p6wh-862q" },
          products: [{ "@id": "pkg:npm/postcss@8.4.31" }],
          status: "not_affected",
          justification: "vulnerable_code_not_in_execute_path",
          impact_statement: "postcss@8.4.31 is not reachable",
        },
      ],
    })!;
    expect(table.rows[0]!.slice(0, 4)).toEqual([
      "GHSA-6g55-p6wh-862q",
      "pkg:npm/postcss@8.4.31",
      "not_affected",
      "vulnerable_code_not_in_execute_path",
    ]);
    // the claim's own limit travels with the claim
    expect(table.note).toMatch(/unknowns count against us/);
  });

  it("repo-facts: one row per observation, with the fact that produced it", () => {
    const table = M.artifactTable("repo-facts.json", {
      "codeowners-defined": [{ codeowners_present: false, path: null }],
      "tests-in-ci": [{ workflow_count: 0, test_step_count: 0 }],
    })!;
    expect(table.rows.length).toBe(2);
    expect(table.rows[0]).toEqual(["codeowners-defined", "codeowners_present=false · path=none"]);
  });

  it("an empty result set is a table with no rows — a result, not a gap", () => {
    const table = M.artifactTable("semgrep-results.json", { results: [], error_count: 0 })!;
    expect(table.rows).toEqual([]);
    expect(table.total).toBe(0);
    expect(table.note).toBeUndefined();
  });
});

describe("repo model (L2): nodes AND links, and no second coverage number", () => {
  // the shape the artifact really has — one node of each kind that renders a
  // detail, and one link of each kind that renders differently
  const model = {
    version: 1,
    dataset_version: "2026.07.14.01",
    nodes: [
      { kind: "repo", id: "repo:/app", repo: "/app" },
      {
        kind: "recipe",
        id: "recipe:arch-boundaries-hold",
        recipeId: "arch-boundaries-hold",
        inCatalog: true,
        cadence: "weekly",
        automatable: "full",
      },
      { kind: "recipe", id: "recipe:gone", recipeId: "gone", inCatalog: false },
      { kind: "collector", id: "collector:contract", collector: "contract", pure: true },
      { kind: "collector", id: "collector:graph", collector: "graph", pure: true },
      { kind: "collector", id: "collector:semgrep", collector: "semgrep", pure: false },
      { kind: "tool", id: "tool:semgrep", tool: "semgrep", pinnedVersion: "1.2.3", image: "img:1.2.3" },
      { kind: "tool", id: "tool:unpinned", tool: "unpinned" },
      {
        kind: "contract-rule",
        id: "rule:/app:billing-isolated",
        ruleId: "billing-isolated",
        ruleKind: "boundary",
        repo: "/app",
        declaration:
          '{"allowedImporters":["src/server.js"],"description":"billing is reached only through the server layer","id":"billing-isolated","kind":"boundary","module":"src/billing"}',
      },
      {
        kind: "graph",
        id: "graph:/app",
        repo: "/app",
        commit: "abcdef0123456789abcdef",
        extractorVersion: "1",
        nodeCount: 12,
        edgeCount: 9,
        inferredEdgeCount: 2,
        entrypoints: ["src/index.js"],
        entrypointSource: "package.json",
        routeRoots: 2,
        from: { recipeId: "arch-boundaries-hold", bundleDigest: "dead" },
      },
    ],
    links: [
      { kind: "state", from: "repo:/app", to: "recipe:arch-boundaries-hold", state: "violated", bundleDigest: "dead" },
      { kind: "state", from: "repo:/app", to: "recipe:gone", state: "unevidenced" },
      { kind: "consumes", from: "collector:contract", to: "collector:graph", artifact: "graph.db" },
      { kind: "spawns", from: "collector:semgrep", to: "tool:semgrep" },
      { kind: "declares", from: "repo:/app", to: "rule:/app:billing-isolated" },
      { kind: "checked-by", from: "rule:/app:billing-isolated", to: "recipe:arch-boundaries-hold" },
      { kind: "walked", from: "repo:/app", to: "graph:/app" },
    ],
    problems: [] as string[],
  };

  it("puts every node on a row and every link on the row of the node it leaves", () => {
    const table = M.artifactTable("repo-model.json", model)!;
    expect(table.family).toBe("repo model");
    expect(table.columns).toEqual(["kind", "id", "detail", "links out"]);
    expect(table.total).toBe(model.nodes.length);
    const repo = table.rows.find((r) => r[1] === "repo:/app")!;
    // the state link carries its verdict INTO the label — a link column that
    // said only "state→recipe:x" would render the board as a shrug
    expect(repo[3]).toContain("state:violated→recipe:arch-boundaries-hold");
    expect(repo[3]).toContain("state:unevidenced→recipe:gone");
    expect(repo[3]).toContain("declares→rule:/app:billing-isolated");
    expect(repo[3]).toContain("walked→graph:/app");
    // the consumed artifact is named on the link, not left to be guessed
    const consumer = table.rows.find((r) => r[1] === "collector:contract")!;
    expect(consumer[3]).toBe("consumes:graph.db→collector:graph");
  });

  it("shows the signed declaration itself, never a paraphrase of it", () => {
    const table = M.artifactTable("repo-model.json", model)!;
    const rule = table.rows.find((r) => r[0] === "contract-rule")!;
    expect(rule[2]).toContain("boundary");
    expect(rule[2]).toContain('"module":"src/billing"');
    expect(rule[2]).toContain("billing is reached only through the server layer");
  });

  it("says what each node kind knows about itself, and nothing it does not", () => {
    const table = M.artifactTable("repo-model.json", model)!;
    const by = (id: string) => table.rows.find((r) => r[1] === id)!;
    expect(by("recipe:arch-boundaries-hold")[2]).toBe("cadence weekly · automatable full");
    expect(by("recipe:gone")[2]).toContain("not in the catalog");
    expect(by("collector:contract")[2]).toContain("pure");
    expect(by("collector:semgrep")[2]).toBe("");
    expect(by("tool:semgrep")[2]).toBe("pinned 1.2.3 · img:1.2.3");
    expect(by("tool:unpinned")[2]).toBe("no pin in tools.json");
    expect(by("graph:/app")[2]).toContain("12 nodes, 9 edges (2 name-inferred)");
    expect(by("graph:/app")[2]).toContain("roots: src/index.js (package.json)");
    expect(by("graph:/app")[2]).toContain("from arch-boundaries-hold");
  });

  it("leads the note with the model's own problems, and computes no coverage", () => {
    const clean = M.artifactTable("repo-model.json", model)!;
    expect(clean.note).toContain("model v1 over crosswalk 2026.07.14.01");
    expect(clean.note).toContain(`${model.links.length} link(s)`);
    expect(clean.note).toContain("the board owns the counts");
    expect(clean.note).not.toContain("problem(s)");

    const broken = M.artifactTable("repo-model.json", {
      ...model,
      problems: ['recipe "x" names collector "y", which is not registered'],
    })!;
    expect(broken.note!.startsWith("1 problem(s)")).toBe(true);
    expect(broken.note).toContain('recipe "x" names collector "y"');

    // no percentage, no "N of M" — the board computes coverage, and a second
    // count here is a second answer that merely looks like the same one
    expect(allText(clean)).not.toMatch(/\d+\s*%/);
    expect(allText(clean)).not.toMatch(/\d+ of \d+/);
  });

  it("renders a REAL model — the catalog, the crosswalk and the whole registry", async () => {
    // no ledger: the world is empty of scans, so this is the catalog half of a
    // real artifact, built by the real hand rather than typed above
    const { allCollectors, loadToolManifest } = await import("@rampscan/collectors");
    const { DEFAULT_DATASET_PIN, loadLocalDataset } = await import("@rampscan/dataset");
    const { buildRepoModel, buildToolMap, loadRecipes } = await import("../src/index.js");
    const recipes = await loadRecipes(join(repoRoot, "recipes/commit"));
    const real = buildRepoModel({
      entries: [],
      recipes,
      dataset: await loadLocalDataset(
        join(repoRoot, "docs/context/ramprules/derived"),
        DEFAULT_DATASET_PIN,
      ),
      toolMap: buildToolMap({
        recipes,
        collectors: allCollectors,
        toolManifest: await loadToolManifest(),
      }),
    });
    const table = M.artifactTable("repo-model.json", JSON.parse(JSON.stringify(real)))!;
    expect(table.family).toBe("repo model");
    expect(table.total).toBe(real.nodes.length);
    expect(table.total).toBeGreaterThan(recipes.length);
    for (const row of table.rows) expect(row.length).toBe(table.columns.length);
    // a scan-less world has no repo, no state and no contract — and the table
    // says so by having none, not by inventing an empty one
    expect(table.rows.some((r) => r[0] === "repo")).toBe(false);
    expect(table.rows.some((r) => r[0] === "recipe")).toBe(true);
    expect(allText(table)).not.toContain("state:");
    // the crosswalk pin is stated, because every ksi-control link came from it
    expect(table.note).toContain(DEFAULT_DATASET_PIN);
    // this is the only test in this file that loads the real catalog, the real
    // crosswalk and the whole collector registry — hence the wider budget
  }, 60_000);
});

describe("the row cap says what it cut", () => {
  it("caps the rows and states the TRUE total", () => {
    const results = Array.from({ length: M.ROW_CAP + 31 }, (_, i) => ({
      check_id: `rule-${i}`,
      path: "a.js",
      start_line: i,
      severity: "ERROR",
      message: "m",
    }));
    const table = M.artifactTable("semgrep-results.json", { results, error_count: 0 })!;
    expect(table.rows.length).toBe(M.ROW_CAP);
    expect(table.total).toBe(M.ROW_CAP + 31);
    expect(table.note).toContain(`of ${M.ROW_CAP + 31} rows`);
  });
});

describe("against the real artifacts this repo's own scans wrote", () => {
  // the twin tests above pin the shapes; this one pins that the shapes are
  // the ones the collectors ACTUALLY write, which is how J2's smoke found it
  // was asserting `sbom.json` for a collector that writes `sbom.cdx.json`
  const cases: Array<[string, string]> = [
    ["repo-facts/repo-facts.json", "repo-facts"],
    ["gitleaks/gitleaks-report.json", "gitleaks"],
    ["grype/grype-report.json", "grype"],
    ["osv-scanner/osv-results.json", "osv-scanner"],
    ["reachability/openvex.json", "openvex"],
    ["semgrep/semgrep-results.json", "semgrep"],
    ["syft/sbom.cdx.json", "cyclonedx sbom"],
    ["model/repo-model.json", "repo model"],
  ];

  for (const [path, family] of cases) {
    it(`renders ${path} as a ${family} table`, async () => {
      let raw: string;
      try {
        raw = await readFile(join(repoRoot, "rampscan-out/artifacts", path), "utf8");
      } catch {
        return; // no local scan output — the twin tests above still pin the shape
      }
      const name = path.split("/").pop()!;
      const table = M.artifactTable(name, JSON.parse(raw))!;
      expect(table.family).toBe(family);
      expect(table.rows.length).toBe(Math.min(table.total, M.ROW_CAP));
      // every row is as wide as the header claims — a ragged table is a
      // misread shape, and it would render as silently shifted columns
      for (const row of table.rows) expect(row.length).toBe(table.columns.length);
    });
  }
});
