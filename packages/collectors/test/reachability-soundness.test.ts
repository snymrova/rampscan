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
import type { ApplicationRoot } from "@rampscan/graph";
import {
  graphCollector,
  reachability,
  ABSENT_NODE_NOTE,
  OPENVEX_ARTIFACT,
  OSV_RESULTS_ARTIFACT,
  SBOM_ARTIFACT,
  UNRECORDED_EXCLUSIONS_NOTE,
  UNRECORDED_OPAQUE_IMPORTS_NOTE,
  UNRECORDED_ROOTS_NOTE,
} from "../src/index.js";

// S0-3 — the failing test, first (docs/PLAN-SOUNDNESS.md §5, phase S0).
//
// The finding: `reachability.ts:142` reads
//
//     const notAffected = gated && (dep === undefined || !dep.reachable);
//
// and `dep === undefined` means the package has NO NODE in the code graph —
// the absence of evidence — which is treated as a proof of unreachability
// equal in standing to a completed walk that failed to arrive. Dependency
// nodes come only from first-party import specifiers, so any advisory in a
// package the source does not `import` directly becomes a signed
// `not_affected`. That is ground rule 7 (no vacuous passes) in the one place
// `catalog.test.ts` does not reach, because it gates recipe verdicts and this
// failure moved into the collector's gating.
//
// The fixture reproduces the real shape exactly: `minimist` is declared in
// `fixtures/vulnerable-app/package.json` and never imported, so it has no
// node — and the SBOM below carries `lodash → minimist`, where `lodash` IS
// reachable from the entry point. The same relationship holds in this
// repository's own output, where `sbom.cdx.json` carries
// `next@15.5.23 → postcss@8.4.31` while `graph.db` has no `postcss` node and
// `openvex.json` signs four `not_affected` statements about it.
//
// S0 committed this under `it.fails`: against the code at 2801f8c it threw,
// which was S0's exit gate, and the wrapper kept `main` green while the
// finding was recorded rather than fixed. S1-1 (#128) removed the
// `dep === undefined` disjunct and flipped it back to `it`; it is now the
// regression guard for GHSA-7jff-6v53-r56x.
//
// S1-2 (#129) then let the SBOM edge join the walk: `minimist` is reachable
// through `lodash → minimist`, with that hop marked `sbom`, and the signed
// document says `affected`. The second package below, `sharp`, is the other
// half of the repository's own worked example — in the SBOM, no chain to it
// from anything reached, no node — and it must stay `unknown`: the SBOM graph
// proves presence and never absence.

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "../../..");
const fixtureRoot = join(repoRoot, "fixtures/vulnerable-app");

const OSV_REPORT = {
  results: [
    {
      source: { path: "package-lock.json" },
      packages: [
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
        {
          package: { name: "sharp", version: "0.33.0", ecosystem: "npm" },
          vulnerabilities: [
            {
              id: "GHSA-test-sharp-0001",
              summary: "Synthetic advisory against a package no walk can reach or exclude",
              aliases: [],
            },
          ],
          groups: [{ ids: ["GHSA-test-sharp-0001"], max_severity: "7.5" }],
        },
      ],
    },
  ],
};

// CycloneDX, shaped like syft's real output: `minimist` is not imported by any
// first-party file, and it is a dependency of `lodash`, which is. `sharp` is a
// direct dependency of the application root only — a component with no chain
// from any package the code walk reached.
const SBOM = {
  bomFormat: "CycloneDX",
  specVersion: "1.7",
  components: [
    { "bom-ref": "pkg:npm/vulnerable-app@1.0.0", type: "application", name: "vulnerable-app", version: "1.0.0" },
    { "bom-ref": "pkg:npm/lodash@4.17.15", type: "library", name: "lodash", version: "4.17.15" },
    { "bom-ref": "pkg:npm/minimist@1.2.5", type: "library", name: "minimist", version: "1.2.5" },
    { "bom-ref": "pkg:npm/sharp@0.33.0", type: "library", name: "sharp", version: "0.33.0" },
  ],
  dependencies: [
    {
      ref: "pkg:npm/vulnerable-app@1.0.0",
      dependsOn: ["pkg:npm/lodash@4.17.15", "pkg:npm/minimist@1.2.5", "pkg:npm/sharp@0.33.0"],
    },
    { ref: "pkg:npm/lodash@4.17.15", dependsOn: ["pkg:npm/minimist@1.2.5"] },
    { ref: "pkg:npm/minimist@1.2.5", dependsOn: [] },
    { ref: "pkg:npm/sharp@0.33.0", dependsOn: [] },
  ],
};

function ctx(artifactDir: string, inputs: Map<string, string>): CollectContext {
  return {
    workspace: { root: fixtureRoot, repo: "fixtures/vulnerable-app", commit: "f".repeat(40) },
    artifactDir,
    inputs,
    runId: "run-s0-3",
  };
}

describe("S0-3 — a package absent from the graph is not proof of unreachability", () => {
  let out: CollectOutput;

  beforeAll(async () => {
    const graphDir = await mkdtemp(join(tmpdir(), "rampscan-s0-graph-"));
    const graphOut = await graphCollector.collect(ctx(graphDir, new Map()));
    const graphDbPath = graphOut.artifacts.find((a) => a.name === GRAPH_DB_ARTIFACT)!.path;

    const dir = await mkdtemp(join(tmpdir(), "rampscan-s0-reach-"));
    const osvPath = join(dir, OSV_RESULTS_ARTIFACT);
    const sbomPath = join(dir, SBOM_ARTIFACT);
    await writeFile(osvPath, JSON.stringify(OSV_REPORT));
    await writeFile(sbomPath, JSON.stringify(SBOM));
    out = await reachability.collect(
      ctx(
        dir,
        new Map([
          [OSV_RESULTS_ARTIFACT, osvPath],
          [GRAPH_DB_ARTIFACT, graphDbPath],
          [SBOM_ARTIFACT, sbomPath],
        ]),
      ),
    );
  });

  it("does not sign not_affected for a package the walk never had a node for", async () => {
    const rows = out.observations["no-critical-reachable-advisories"]!;
    const minimist = rows.find((r) => r["package"] === "minimist")!;

    // The whole finding, in one assertion: `minimist` has no node in graph.db,
    // so nothing was walked and nothing may be claimed. Before S1-1 this read
    // `true`, from `dep === undefined` at reachability.ts:142.
    expect(minimist["not_affected"]).toBe(false);

    // And `reachable: "false"` is the same claim in the observation row —
    // it must be anything but a negative verdict the walk did not earn.
    expect(minimist["reachable"]).not.toBe("false");

    // The signed document is where it matters: no `not_affected` statement may
    // rest on an absent node.
    const vexPath = out.artifacts.find((a) => a.name === OPENVEX_ARTIFACT)!.path;
    const vex = JSON.parse(await readFile(vexPath, "utf8")) as {
      statements: Array<Record<string, unknown>>;
    };
    expect(vex.statements.filter((s) => s["status"] === "not_affected")).toHaveLength(0);
  });

  it("S1-2: the SBOM edge carries the walk to minimist — reachable, with the hop marked sbom", async () => {
    const rows = out.observations["no-critical-reachable-advisories"]!;
    const minimist = rows.find((r) => r["package"] === "minimist")!;
    expect(minimist["reachable"]).toBe("true");
    expect(minimist["not_affected"]).toBe(false);
    expect(minimist["gate_note"]).toBeUndefined();
    // the path is the code walk's own path to lodash, continued through the
    // manifest: the reader sees exactly where the parsed call sites stop
    expect(String(minimist["path"])).toMatch(/^src\/index\.js » lodash.* » minimist$/);
    const marks = minimist["call_path_resolutions"] as string[];
    expect(marks).toHaveLength(String(minimist["path"]).split(" » ").length - 1);
    expect(marks.at(-1)).toBe("sbom");
    expect(marks.slice(0, -1).every((m) => m === "exact" || m === "inferred")).toBe(true);

    // the finding carries the path as its trace, and the signed document says
    // affected — the advisory counts with its chain, not as an unknown
    const finding = out.findings.find((f) => f.summary.includes("minimist"))!;
    expect(finding.summary).toContain("reachable:");
    expect(finding.evidence.some((e) => e.kind === "trace" && e.note?.includes("» minimist"))).toBe(true);
    const vexPath = out.artifacts.find((a) => a.name === OPENVEX_ARTIFACT)!.path;
    const vex = JSON.parse(await readFile(vexPath, "utf8")) as {
      statements: Array<Record<string, unknown>>;
    };
    const affected = vex.statements.filter((s) => s["status"] === "affected");
    expect(affected).toHaveLength(1);
    expect(JSON.stringify(affected[0]!["products"])).toContain("pkg:npm/minimist@1.2.5");

    // the basis signs how partial the manifest graph was
    const basis = out.basis!["no-critical-reachable-advisories"]!;
    expect(basis.sbom).toEqual({ component_count: 4, components_with_edges: 2, edge_count: 4 });
    expect(basis.statement).toContain("Unknowns count against us");
    expect(basis.statement).toContain("prove presence only");
  });

  it("S1-2: the SBOM proves presence only — sharp, with no chain and no node, stays unknown", async () => {
    const rows = out.observations["no-critical-reachable-advisories"]!;
    const sharp = rows.find((r) => r["package"] === "sharp")!;
    // in the SBOM, declared by the application root, reached by nothing the
    // code walk arrived at: not provably reachable, not provably unreachable
    expect(sharp["reachable"]).toBe("unknown");
    expect(sharp["not_affected"]).toBe(false);
    expect(sharp["path"]).toBeNull();
    expect(sharp["gate_note"]).toBe(ABSENT_NODE_NOTE);
    const finding = out.findings.find((f) => f.summary.includes("sharp"))!;
    expect(finding.summary).toContain("reachability unknown");
    const vexPath = out.artifacts.find((a) => a.name === OPENVEX_ARTIFACT)!.path;
    const vex = JSON.parse(await readFile(vexPath, "utf8")) as {
      statements: Array<Record<string, unknown>>;
    };
    const investigating = vex.statements.filter((s) => s["status"] === "under_investigation");
    expect(investigating).toHaveLength(1);
    expect(JSON.stringify(investigating[0]!["products"])).toContain("pkg:npm/sharp@0.33.0");
    expect(investigating[0]!["impact_statement"]).toBe(ABSENT_NODE_NOTE);
  });
});

// S1-3 — a negative claim states its scope (docs/PLAN-SOUNDNESS.md §5, S1-3).
//
// The second hole the finding named (§3.3): `rampscan.config.json` declares
// one entry point and the tree holds two applications, so console/web is
// outside every walk and everything only it imports reads "not reachable from
// the entry points" — true, and not a statement about the repository. Below,
// the same shape in miniature: two packages, one named as an entry point, a
// vulnerable package imported only under the other. With one root unwalked
// the gate must refuse the negative and say why; with both roots walked, the
// same miss is the earned not_affected — the mechanism is the width of the
// walk, not a blanket refusal.
describe("S1-3 — a negative claim is refused when the walk did not enter every application root", () => {
  let root: string;
  let files: string[];
  let roots: ApplicationRoot[];

  const TWO_APP_OSV = {
    results: [
      {
        source: { path: "package-lock.json" },
        packages: [
          {
            package: { name: "minimist", version: "1.2.5", ecosystem: "npm" },
            vulnerabilities: [{ id: "GHSA-xvch-5gv4-984h", summary: "Prototype pollution in minimist", aliases: ["CVE-2021-44906"] }],
            groups: [{ ids: ["GHSA-xvch-5gv4-984h", "CVE-2021-44906"], max_severity: "9.8" }],
          },
        ],
      },
    ],
  };

  async function gate(entrypoints: string[], applicationRoots?: ApplicationRoot[]): Promise<CollectOutput> {
    const graph = await extractGraph(root, files, "worktree");
    const dir = await mkdtemp(join(tmpdir(), "rampscan-s13-out-"));
    const dbPath = join(dir, GRAPH_DB_ARTIFACT);
    // the same detection the graph collector runs (S1-4): config wins, and
    // what it left out is recorded — here nothing, because apps/web declares
    // no entry point for detection to find
    const entry = await detectEntrypoints(root, new Set(files), entrypoints, applicationRoots);
    writeGraphDb(dbPath, graph, {
      extractorVersion: graphToolVersion(),
      commit: "d".repeat(40),
      entrypoints: entry.files,
      entrypointSource: entry.source,
      entrypointsUnresolved: entry.unresolved,
      authPatterns: DEFAULT_AUTH_PATTERNS,
      ...(applicationRoots !== undefined ? { applicationRoots } : {}),
      entrypointsDetected: entry.detected,
      entrypointsExcluded: entry.excluded,
    });
    const osvPath = join(dir, OSV_RESULTS_ARTIFACT);
    await writeFile(osvPath, JSON.stringify(TWO_APP_OSV));
    return reachability.collect({
      workspace: { root, repo: "two-apps", commit: "d".repeat(40) },
      artifactDir: dir,
      inputs: new Map([
        [OSV_RESULTS_ARTIFACT, osvPath],
        [GRAPH_DB_ARTIFACT, dbPath],
      ]),
      runId: "run-s1-3",
    });
  }

  async function vexOf(out: CollectOutput): Promise<Array<Record<string, unknown>>> {
    const vexPath = out.artifacts.find((a) => a.name === OPENVEX_ARTIFACT)!.path;
    return (JSON.parse(await readFile(vexPath, "utf8")) as { statements: Array<Record<string, unknown>> }).statements;
  }

  beforeAll(async () => {
    root = await mkdtemp(join(tmpdir(), "rampscan-s13-"));
    const put = async (rel: string, content: string) => {
      await mkdir(dirname(join(root, rel)), { recursive: true });
      await writeFile(join(root, rel), content);
    };
    await put("package.json", JSON.stringify({ name: "two-apps", private: true }));
    await put("apps/cli/package.json", JSON.stringify({ name: "@two/cli", main: "src/main.js" }));
    await put("apps/cli/src/main.js", "module.exports = { run() {} };\n");
    await put("apps/web/package.json", JSON.stringify({ name: "@two/web", private: true, dependencies: { minimist: "1.2.5" } }));
    await put("apps/web/src/page.js", "module.exports = { page() {} };\n");
    // minimist has a node — a first-party file imports it — and only an orphan
    // under apps/web does, so no walk from either entry point arrives at it
    await put("apps/web/src/orphan.js", 'const parse = require("minimist");\nmodule.exports = { parse };\n');
    files = ["apps/cli/src/main.js", "apps/web/src/orphan.js", "apps/web/src/page.js"];
    roots = await detectApplicationRoots(root, new Set(files), "worktree");
  });

  it("the tree declares two application roots; the workspace root owns no source and is not one", () => {
    expect(roots).toEqual([
      { dir: "apps/cli", name: "@two/cli" },
      { dir: "apps/web", name: "@two/web" },
    ]);
  });

  it("one entry point, two applications: not_affected is refused and the reason names the unwalked root", async () => {
    const out = await gate(["apps/cli/src/main.js"], roots);
    const rows = out.observations["no-critical-reachable-advisories"]!;
    const minimist = rows.find((r) => r["package"] === "minimist")!;

    // the walk had a node and missed it — the shape that used to sign
    // not_affected — and it is unknown, because the walk was half as wide as
    // the tree
    expect(minimist["not_affected"]).toBe(false);
    expect(minimist["reachable"]).toBe("unknown");
    expect(String(minimist["gate_note"])).toContain("apps/web (@two/web, 2 files)");
    expect(String(minimist["gate_note"])).toContain("not_affected is refused for this run");

    // the advisory counts: a CRITICAL finding, not a waived one
    expect(out.findings.filter((f) => f.variable === "advisories")).toHaveLength(1);

    // the signed basis carries the width and the refusal
    const basis = out.basis!["no-critical-reachable-advisories"]!;
    expect(basis.application_roots).toEqual([
      { dir: "apps/cli", name: "@two/cli", file_count: 1, reached_file_count: 1 },
      { dir: "apps/web", name: "@two/web", file_count: 2, reached_file_count: 0 },
    ]);
    expect(basis.degraded).toBe(minimist["gate_note"]);

    // the VEX document: no negative, and the scope as structured fields
    const statements = await vexOf(out);
    expect(statements.filter((s) => s["status"] === "not_affected")).toHaveLength(0);
    const [stmt] = statements;
    expect(stmt!["status"]).toBe("under_investigation");
    expect(stmt!["impact_statement"]).toBe(minimist["gate_note"]);
    expect(stmt!["rampscan:scope"]).toEqual({
      commit: "d".repeat(40),
      entrypoints: ["apps/cli/src/main.js"],
      entrypoint_source: "config",
      application_roots: [
        { dir: "apps/cli", name: "@two/cli", walked: true },
        { dir: "apps/web", name: "@two/web", walked: false },
      ],
    });
  });

  it("both applications named: the same miss is the earned not_affected, scoped to the whole tree", async () => {
    const out = await gate(["apps/cli/src/main.js", "apps/web/src/page.js"], roots);
    const rows = out.observations["no-critical-reachable-advisories"]!;
    const minimist = rows.find((r) => r["package"] === "minimist")!;
    expect(minimist["not_affected"]).toBe(true);
    expect(minimist["reachable"]).toBe("false");
    expect(minimist["gate_note"]).toBeUndefined();
    expect(out.findings.filter((f) => f.variable === "advisories")).toHaveLength(0);

    const basis = out.basis!["no-critical-reachable-advisories"]!;
    expect(basis.degraded).toBeUndefined();
    expect(basis.application_roots!.every((r) => r.reached_file_count > 0)).toBe(true);

    const [stmt] = await vexOf(out);
    expect(stmt!["status"]).toBe("not_affected");
    expect(String(stmt!["impact_statement"])).toContain("entered every application root");
    expect((stmt!["rampscan:scope"] as { application_roots: Array<{ walked: boolean }> }).application_roots.every((r) => r.walked)).toBe(true);
  });

  it("a graph that never recorded its roots has an unknown width, and an unknown width refuses too", async () => {
    const out = await gate(["apps/cli/src/main.js", "apps/web/src/page.js"]);
    const rows = out.observations["no-critical-reachable-advisories"]!;
    const minimist = rows.find((r) => r["package"] === "minimist")!;
    expect(minimist["not_affected"]).toBe(false);
    expect(minimist["reachable"]).toBe("unknown");
    expect(minimist["gate_note"]).toBe(UNRECORDED_ROOTS_NOTE);
    const basis = out.basis!["no-critical-reachable-advisories"]!;
    expect(basis.application_roots).toBeUndefined();
    expect(basis.degraded).toBe(UNRECORDED_ROOTS_NOTE);
    const [stmt] = await vexOf(out);
    expect(stmt!["status"]).toBe("under_investigation");
    // the scope is still stated — entry points and commit — minus the roots it cannot know
    expect(stmt!["rampscan:scope"]).toEqual({
      commit: "d".repeat(40),
      entrypoints: ["apps/cli/src/main.js", "apps/web/src/page.js"],
      entrypoint_source: "config",
    });
  });
});

// S1-4 — configured entry points stop hiding detection (docs/PLAN-SOUNDNESS.md
// §5, S1-4). Before it, `detectEntrypoints` returned ONLY the configured
// entries when any were configured: package.json detection was skipped
// entirely and silently, so declaring one entry point to quiet a warning
// converted the rest of a repository into not-affected territory with
// nothing said about it. Below, the smallest tree that shows it: one package
// with a `main` and a `bin`, the vulnerable package required only by the bin,
// and a config naming only the main. S1-3's width is whole — one root, and
// the walk enters it — so this is the hole S1-3 does not cover.
describe("S1-4 — an entry point config left out is named, and a negative is refused while the walk never reached it", () => {
  let root: string;
  let files: string[];
  let roots: ApplicationRoot[];

  const ONE_APP_OSV = {
    results: [
      {
        source: { path: "package-lock.json" },
        packages: [
          {
            package: { name: "minimist", version: "1.2.5", ecosystem: "npm" },
            vulnerabilities: [{ id: "GHSA-xvch-5gv4-984h", summary: "Prototype pollution in minimist", aliases: ["CVE-2021-44906"] }],
            groups: [{ ids: ["GHSA-xvch-5gv4-984h", "CVE-2021-44906"], max_severity: "9.8" }],
          },
        ],
      },
    ],
  };

  async function gate(config: string[] | undefined, record = true): Promise<CollectOutput> {
    const graph = await extractGraph(root, files, "worktree");
    const dir = await mkdtemp(join(tmpdir(), "rampscan-s14-out-"));
    const dbPath = join(dir, GRAPH_DB_ARTIFACT);
    const entry = await detectEntrypoints(root, new Set(files), config, roots);
    writeGraphDb(dbPath, graph, {
      extractorVersion: graphToolVersion(),
      commit: "e".repeat(40),
      entrypoints: entry.files,
      entrypointSource: entry.source,
      entrypointsUnresolved: entry.unresolved,
      authPatterns: DEFAULT_AUTH_PATTERNS,
      applicationRoots: roots,
      ...(record ? { entrypointsDetected: entry.detected, entrypointsExcluded: entry.excluded } : {}),
    });
    const osvPath = join(dir, OSV_RESULTS_ARTIFACT);
    await writeFile(osvPath, JSON.stringify(ONE_APP_OSV));
    return reachability.collect({
      workspace: { root, repo: "one-app", commit: "e".repeat(40) },
      artifactDir: dir,
      inputs: new Map([
        [OSV_RESULTS_ARTIFACT, osvPath],
        [GRAPH_DB_ARTIFACT, dbPath],
      ]),
      runId: "run-s1-4",
    });
  }

  async function vexOf(out: CollectOutput): Promise<Array<Record<string, unknown>>> {
    const vexPath = out.artifacts.find((a) => a.name === OPENVEX_ARTIFACT)!.path;
    return (JSON.parse(await readFile(vexPath, "utf8")) as { statements: Array<Record<string, unknown>> }).statements;
  }

  beforeAll(async () => {
    root = await mkdtemp(join(tmpdir(), "rampscan-s14-"));
    const put = async (rel: string, content: string) => {
      await mkdir(dirname(join(root, rel)), { recursive: true });
      await writeFile(join(root, rel), content);
    };
    await put(
      "package.json",
      JSON.stringify({ name: "one-app", main: "src/main.js", bin: { tool: "src/tool.js" }, dependencies: { minimist: "1.2.5" } }),
    );
    await put("src/main.js", "module.exports = { run() {} };\n");
    // the bin is a second place the program starts, and the only importer
    await put("src/tool.js", 'const parse = require("minimist");\nmodule.exports = { parse };\n');
    files = ["src/main.js", "src/tool.js"];
    roots = await detectApplicationRoots(root, new Set(files), "worktree");
  });

  it("config names the main only: the bin is named as left out, and not_affected is refused", async () => {
    const out = await gate(["src/main.js"]);
    const rows = out.observations["no-critical-reachable-advisories"]!;
    const minimist = rows.find((r) => r["package"] === "minimist")!;

    // S1-3 is satisfied — one root, entered — and the negative is still not
    // earned: the program also starts at src/tool.js, and no walk began there
    expect(minimist["not_affected"]).toBe(false);
    expect(minimist["reachable"]).toBe("unknown");
    expect(String(minimist["gate_note"])).toContain("src/tool.js (package.json, under .)");
    expect(String(minimist["gate_note"])).toContain("the config left out");
    expect(String(minimist["gate_note"])).toContain("not_affected is refused for this run");
    expect(out.findings.filter((f) => f.variable === "advisories")).toHaveLength(1);

    const basis = out.basis!["no-critical-reachable-advisories"]!;
    expect(basis.entrypoint_source).toBe("config");
    expect(basis.entrypoints).toEqual(["src/main.js"]);
    expect(basis.application_roots).toEqual([{ dir: ".", name: "one-app", file_count: 2, reached_file_count: 1 }]);
    expect(basis.entrypoints_excluded).toEqual([{ file: "src/tool.js", via: "package.json", root: ".", reached: false }]);
    expect(basis.degraded).toBe(minimist["gate_note"]);

    const [stmt] = await vexOf(out);
    expect(stmt!["status"]).toBe("under_investigation");
    expect((stmt!["rampscan:scope"] as Record<string, unknown>)["entrypoints_excluded"]).toEqual([
      { file: "src/tool.js", via: "package.json", root: ".", reached: false },
    ]);
  });

  it("no config: detection starts the walk from both, and the advisory is reachable with the bin as its path", async () => {
    const out = await gate(undefined);
    const rows = out.observations["no-critical-reachable-advisories"]!;
    const minimist = rows.find((r) => r["package"] === "minimist")!;
    expect(minimist["reachable"]).toBe("true");
    expect(String(minimist["path"])).toMatch(/^src\/tool\.js » minimist$/);
    const basis = out.basis!["no-critical-reachable-advisories"]!;
    expect(basis.entrypoint_source).toBe("package.json");
    expect(basis.entrypoints).toEqual(["src/main.js", "src/tool.js"]);
    expect(basis.entrypoints_excluded).toBeUndefined();
    expect(basis.degraded).toBeUndefined();
  });

  it("config names both: nothing is left out, and the same walk is the same verdict", async () => {
    const out = await gate(["src/main.js", "src/tool.js"]);
    const rows = out.observations["no-critical-reachable-advisories"]!;
    const minimist = rows.find((r) => r["package"] === "minimist")!;
    expect(minimist["reachable"]).toBe("true");
    const basis = out.basis!["no-critical-reachable-advisories"]!;
    expect(basis.entrypoints_excluded).toBeUndefined();
    expect(basis.degraded).toBeUndefined();
    const [stmt] = await vexOf(out);
    expect(stmt!["status"]).toBe("affected");
    expect((stmt!["rampscan:scope"] as Record<string, unknown>)["entrypoints_excluded"]).toBeUndefined();
  });

  it("a config-narrowed graph that never recorded what it narrowed away has an unknown narrowing, and refuses", async () => {
    const out = await gate(["src/main.js"], false);
    const rows = out.observations["no-critical-reachable-advisories"]!;
    const minimist = rows.find((r) => r["package"] === "minimist")!;
    expect(minimist["not_affected"]).toBe(false);
    expect(minimist["gate_note"]).toBe(UNRECORDED_EXCLUSIONS_NOTE);
    const basis = out.basis!["no-critical-reachable-advisories"]!;
    expect(basis.entrypoints_excluded).toBeUndefined();
    expect(basis.degraded).toBe(UNRECORDED_EXCLUSIONS_NOTE);
  });
});

// S4-1 — the specifiers the extractor cannot read (docs/PLAN-SOUNDNESS.md §5,
// S4-1). `require(expr)` and `import(expr)` with anything but a string
// literal produce no edge and, before this, no record: the walk stopped at
// the call as if nothing were loaded there, and a package required only by
// what that call loads had a node the walk never arrived at — the one shape
// that signs `not_affected`. A plugin loader is the ordinary case, not an
// exotic one. The sound reading is the S1-3 one: a file the walk reached that
// loads by a specifier the extractor cannot read may continue anywhere, so
// the width of the walk is unknown past that file, and the negative is
// refused for the run with the call named. An opaque specifier in a file the
// walk never reached loads nothing, and refuses nothing.
//
// The third case is a workspace package whose `exports` are conditional only
// (`node` / `browser`, no `main`): `entryCandidates` read five fixed keys and
// found none, so the package's import dead-ended on a dependency node. Today
// S1-3 catches that tree — the package's root is never entered — so the
// verdict is `unknown` by the width refusal rather than a false negative;
// the test asserts the walk crosses into every condition target, because a
// negative earned with the root entered through `node.js` alone would be
// scoped to one build of the package.
describe("S4-1 — an opaque specifier is a recorded hole in the walk, and conditional exports are entries", () => {
  const OSV = {
    results: [
      {
        source: { path: "package-lock.json" },
        packages: [
          {
            package: { name: "minimist", version: "1.2.5", ecosystem: "npm" },
            vulnerabilities: [{ id: "GHSA-xvch-5gv4-984h", summary: "Prototype pollution in minimist", aliases: ["CVE-2021-44906"] }],
            groups: [{ ids: ["GHSA-xvch-5gv4-984h", "CVE-2021-44906"], max_severity: "9.8" }],
          },
        ],
      },
    ],
  };

  async function tree(spec: Record<string, string>): Promise<{ root: string; files: string[]; roots: ApplicationRoot[] }> {
    const root = await mkdtemp(join(tmpdir(), "rampscan-s41-"));
    for (const [rel, content] of Object.entries(spec)) {
      await mkdir(dirname(join(root, rel)), { recursive: true });
      await writeFile(join(root, rel), content);
    }
    const files = Object.keys(spec).filter((f) => f.endsWith(".js")).sort();
    const roots = await detectApplicationRoots(root, new Set(files), "worktree");
    return { root, files, roots };
  }

  async function gate(t: { root: string; files: string[]; roots: ApplicationRoot[] }, config?: string[]): Promise<CollectOutput> {
    const graph = await extractGraph(t.root, t.files, "worktree");
    const dir = await mkdtemp(join(tmpdir(), "rampscan-s41-out-"));
    const dbPath = join(dir, GRAPH_DB_ARTIFACT);
    const entry = await detectEntrypoints(t.root, new Set(t.files), config, t.roots);
    writeGraphDb(dbPath, graph, {
      extractorVersion: graphToolVersion(),
      commit: "f".repeat(40),
      entrypoints: entry.files,
      entrypointSource: entry.source,
      entrypointsUnresolved: entry.unresolved,
      authPatterns: DEFAULT_AUTH_PATTERNS,
      applicationRoots: t.roots,
      entrypointsDetected: entry.detected,
      entrypointsExcluded: entry.excluded,
    });
    const osvPath = join(dir, OSV_RESULTS_ARTIFACT);
    await writeFile(osvPath, JSON.stringify(OSV));
    return reachability.collect({
      workspace: { root: t.root, repo: "loader-app", commit: "f".repeat(40) },
      artifactDir: dir,
      inputs: new Map([
        [OSV_RESULTS_ARTIFACT, osvPath],
        [GRAPH_DB_ARTIFACT, dbPath],
      ]),
      runId: "run-s4-1",
    });
  }

  async function vexOf(out: CollectOutput): Promise<Array<Record<string, unknown>>> {
    const vexPath = out.artifacts.find((a) => a.name === OPENVEX_ARTIFACT)!.path;
    return (JSON.parse(await readFile(vexPath, "utf8")) as { statements: Array<Record<string, unknown>> }).statements;
  }

  const PLUGIN = 'const parse = require("minimist");\nmodule.exports = { parse };\n';

  it("a reached `require(expr)` refuses the negative and names the call", async () => {
    const t = await tree({
      "package.json": JSON.stringify({ name: "loader-app", main: "src/main.js" }),
      "src/main.js": 'const name = process.env.PLUGIN;\nconst plugin = require("./plugins/" + name);\nmodule.exports = { plugin };\n',
      "src/plugins/parse.js": PLUGIN,
    });
    const out = await gate(t);
    const rows = out.observations["no-critical-reachable-advisories"]!;
    const minimist = rows.find((r) => r["package"] === "minimist")!;
    // the walk had a node for minimist and never arrived — and it must not
    // read that as a proof, because main.js loads something it cannot name
    expect(minimist["not_affected"]).toBe(false);
    expect(minimist["reachable"]).toBe("unknown");
    expect(String(minimist["gate_note"])).toContain("src/main.js:2 (require)");
    expect(String(minimist["gate_note"])).toContain("not_affected is refused for this run");
    expect(out.findings.filter((f) => f.variable === "advisories")).toHaveLength(1);

    const basis = out.basis!["no-critical-reachable-advisories"]!;
    expect(basis.opaque_imports).toEqual([{ file: "src/main.js", line: 2, form: "require", reached: true }]);
    expect(basis.degraded).toBe(minimist["gate_note"]);

    const [stmt] = await vexOf(out);
    expect(stmt!["status"]).toBe("under_investigation");
    expect((stmt!["rampscan:scope"] as Record<string, unknown>)["opaque_imports"]).toEqual([
      { file: "src/main.js", line: 2, form: "require", reached: true },
    ]);
  });

  it("a reached `import(expr)` refuses the same way, under its own form", async () => {
    const t = await tree({
      "package.json": JSON.stringify({ name: "loader-app", main: "src/main.js" }),
      "src/main.js": "export async function load(name) {\n  return import(`./plugins/${name}.js`);\n}\n",
      "src/plugins/parse.js": PLUGIN,
    });
    const out = await gate(t);
    const minimist = out.observations["no-critical-reachable-advisories"]!.find((r) => r["package"] === "minimist")!;
    expect(minimist["not_affected"]).toBe(false);
    expect(minimist["reachable"]).toBe("unknown");
    expect(String(minimist["gate_note"])).toContain("src/main.js:2 (import())");
    const basis = out.basis!["no-critical-reachable-advisories"]!;
    expect(basis.opaque_imports).toEqual([{ file: "src/main.js", line: 2, form: "import()", reached: true }]);
  });

  it("an opaque specifier in a file the walk never reached loads nothing: recorded, and the negative is earned", async () => {
    const t = await tree({
      "package.json": JSON.stringify({ name: "loader-app", main: "src/main.js" }),
      "src/main.js": "module.exports = { run() {} };\n",
      // neither orphan is reached: one holds the opaque call, the other the package
      "src/orphan-loader.js": 'module.exports = (name) => require("./plugins/" + name);\n',
      "src/plugins/parse.js": PLUGIN,
    });
    const out = await gate(t);
    const minimist = out.observations["no-critical-reachable-advisories"]!.find((r) => r["package"] === "minimist")!;
    expect(minimist["not_affected"]).toBe(true);
    expect(minimist["reachable"]).toBe("false");
    expect(minimist["gate_note"]).toBeUndefined();
    const basis = out.basis!["no-critical-reachable-advisories"]!;
    expect(basis.opaque_imports).toEqual([{ file: "src/orphan-loader.js", line: 1, form: "require", reached: false }]);
    expect(basis.degraded).toBeUndefined();
    const [stmt] = await vexOf(out);
    expect(stmt!["status"]).toBe("not_affected");
  });

  it("a graph written before opaque specifiers were recorded has an unknown width past every file, and refuses", async () => {
    const t = await tree({
      "package.json": JSON.stringify({ name: "loader-app", main: "src/main.js" }),
      "src/main.js": "module.exports = { run() {} };\n",
      "src/plugins/parse.js": PLUGIN,
    });
    const graph = await extractGraph(t.root, t.files, "worktree");
    const dir = await mkdtemp(join(tmpdir(), "rampscan-s41-old-"));
    const dbPath = join(dir, GRAPH_DB_ARTIFACT);
    const entry = await detectEntrypoints(t.root, new Set(t.files), undefined, t.roots);
    writeGraphDb(dbPath, { ...graph, opaqueImports: undefined } as never, {
      extractorVersion: "0.5.0+test",
      commit: "f".repeat(40),
      entrypoints: entry.files,
      entrypointSource: entry.source,
      entrypointsUnresolved: entry.unresolved,
      authPatterns: DEFAULT_AUTH_PATTERNS,
      applicationRoots: t.roots,
      entrypointsDetected: entry.detected,
      entrypointsExcluded: entry.excluded,
    });
    const osvPath = join(dir, OSV_RESULTS_ARTIFACT);
    await writeFile(osvPath, JSON.stringify(OSV));
    const out = await reachability.collect({
      workspace: { root: t.root, repo: "loader-app", commit: "f".repeat(40) },
      artifactDir: dir,
      inputs: new Map([
        [OSV_RESULTS_ARTIFACT, osvPath],
        [GRAPH_DB_ARTIFACT, dbPath],
      ]),
      runId: "run-s4-1-old",
    });
    const minimist = out.observations["no-critical-reachable-advisories"]!.find((r) => r["package"] === "minimist")!;
    expect(minimist["not_affected"]).toBe(false);
    expect(minimist["gate_note"]).toBe(UNRECORDED_OPAQUE_IMPORTS_NOTE);
    expect(out.basis!["no-critical-reachable-advisories"]!.opaque_imports).toBeUndefined();
  });

  it("a workspace package with conditional-only exports is entered through every condition target", async () => {
    const t = await tree({
      "package.json": JSON.stringify({ name: "mono", private: true }),
      "apps/cli/package.json": JSON.stringify({ name: "@mono/cli", main: "src/main.js" }),
      "apps/cli/src/main.js": 'const lib = require("@mono/lib");\nmodule.exports = { lib };\n',
      "packages/lib/package.json": JSON.stringify({
        name: "@mono/lib",
        exports: { ".": { node: "./src/node.js", browser: "./src/browser.js" } },
      }),
      "packages/lib/src/node.js": "module.exports = { node() {} };\n",
      "packages/lib/src/browser.js": PLUGIN,
    });
    const out = await gate(t, ["apps/cli/src/main.js"]);
    const minimist = out.observations["no-critical-reachable-advisories"]!.find((r) => r["package"] === "minimist")!;
    // the import of @mono/lib lands on both build targets, so the browser
    // build's dependency is on the walk — reachable, with the path through it
    expect(minimist["reachable"]).toBe("true");
    expect(String(minimist["path"])).toContain("packages/lib/src/browser.js");
    const basis = out.basis!["no-critical-reachable-advisories"]!;
    expect(basis.application_roots).toEqual([
      { dir: "apps/cli", name: "@mono/cli", file_count: 1, reached_file_count: 1 },
      { dir: "packages/lib", name: "@mono/lib", file_count: 2, reached_file_count: 2 },
    ]);
    expect(basis.degraded).toBeUndefined();
  });
});
