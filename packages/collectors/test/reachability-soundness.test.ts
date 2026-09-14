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
    writeGraphDb(dbPath, graph, {
      extractorVersion: graphToolVersion(),
      commit: "d".repeat(40),
      entrypoints,
      entrypointSource: "config",
      entrypointsUnresolved: [],
      authPatterns: DEFAULT_AUTH_PATTERNS,
      ...(applicationRoots !== undefined ? { applicationRoots } : {}),
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
