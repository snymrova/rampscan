import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { beforeAll, describe, expect, it } from "vitest";
import {
  DEFAULT_AUTH_PATTERNS,
  GRAPH_DB_ARTIFACT,
  GRAPH_VERSION,
  applicationRootCoverage,
  dependencyReachability,
  detectApplicationRoots,
  detectEntrypoints,
  extractGraph,
  fileId,
  graphShape,
  graphToolVersion,
  loadGraphConfig,
  nearestRoot,
  openGraphDb,
  packageOf,
  readGraphMeta,
  reachableSet,
  routeAuthCoverage,
  sbomDependencyGraph,
  shortestPath,
  symId,
  writeGraphDb,
} from "../src/index.js";
import type { ExtractedGraph } from "../src/index.js";
import type { DatabaseSync } from "node:sqlite";

// The M4 graph on a synthetic mini-app that mirrors the fixture's shape:
// an entry file whose export uses one dependency (reachable), a second
// dependency declared but never imported (unreachable), and two routes —
// one behind an auth check, one bare.

let root: string;
let graph: ExtractedGraph;
let db: DatabaseSync;

async function write(rel: string, content: string): Promise<void> {
  const abs = join(root, rel);
  await mkdir(dirname(abs), { recursive: true });
  await writeFile(abs, content);
}

beforeAll(async () => {
  root = await mkdtemp(join(tmpdir(), "rampscan-graph-"));
  await write(
    "package.json",
    JSON.stringify({ name: "mini", main: "src/index.js", dependencies: { lodash: "4.17.15", minimist: "1.2.5" } }),
  );
  await write(
    "src/index.js",
    [
      'const merge = require("lodash/merge");',
      "",
      "function handleRequest(body) {",
      "  const settings = {};",
      "  merge(settings, JSON.parse(body));",
      "  return settings;",
      "}",
      "",
      "module.exports = { handleRequest };",
      "",
    ].join("\n"),
  );
  await write(
    "src/auth.js",
    [
      "function requireAuth(req) {",
      '  if (!req.headers.authorization) throw new Error("unauthenticated");',
      "}",
      "module.exports = { requireAuth };",
      "",
    ].join("\n"),
  );
  await write(
    "src/framework.js",
    [
      "const routes = [];",
      "function register(method, path, handlers) { routes.push({ method, path, handlers }); }",
      "module.exports = {",
      '  get: (path, ...h) => register("GET", path, h),',
      '  post: (path, ...h) => register("POST", path, h),',
      "  routes,",
      "};",
      "",
    ].join("\n"),
  );
  await write(
    "src/server.js",
    [
      'const app = require("./framework");',
      'const { requireAuth } = require("./auth");',
      'const { handleRequest } = require("./index");',
      "",
      'app.get("/settings", (req, res) => {',
      "  requireAuth(req);",
      "  res.end(JSON.stringify(handleRequest(req.body)));",
      "});",
      "",
      'app.get("/health", (req, res) => {',
      '  res.end("ok");',
      "});",
      "",
    ].join("\n"),
  );

  graph = await extractGraph(root);
  const entry = await detectEntrypoints(root, new Set(graph.files));
  const dbPath = join(root, GRAPH_DB_ARTIFACT);
  writeGraphDb(dbPath, graph, {
    extractorVersion: GRAPH_VERSION,
    commit: "test-commit",
    entrypoints: entry.files,
    entrypointSource: entry.source,
    entrypointsUnresolved: [],
    authPatterns: DEFAULT_AUTH_PATTERNS,
  });
  db = openGraphDb(dbPath);
});

describe("extraction", () => {
  it("walks source files and skips nothing that matters", () => {
    expect(graph.files).toEqual(["src/auth.js", "src/framework.js", "src/index.js", "src/server.js"]);
  });

  it("declares symbols with file, line, and declares edges", () => {
    const handle = graph.nodes.find((n) => n.id === symId("src/index.js", "handleRequest"));
    expect(handle).toBeDefined();
    expect(handle!.kind).toBe("symbol");
    expect(handle!.line).toBe(3);
    expect(
      graph.edges.some(
        (e) => e.src === fileId("src/index.js") && e.dst === handle!.id && e.kind === "declares",
      ),
    ).toBe(true);
  });

  it("CommonJS module.exports names become exports edges", () => {
    expect(
      graph.edges.some(
        (e) =>
          e.src === fileId("src/index.js") &&
          e.dst === symId("src/index.js", "handleRequest") &&
          e.kind === "exports" &&
          e.resolution === "exact",
      ),
    ).toBe(true);
  });

  it("a require of a package subpath yields dependency member + package nodes", () => {
    expect(graph.nodes.some((n) => n.id === "dep:lodash#merge" && n.package === "lodash")).toBe(true);
    expect(graph.nodes.some((n) => n.id === "dep:lodash")).toBe(true);
    expect(
      graph.edges.some((e) => e.src === "dep:lodash#merge" && e.dst === "dep:lodash"),
    ).toBe(true);
  });

  it("a call through an import binding is an exact calls edge", () => {
    expect(
      graph.edges.some(
        (e) =>
          e.src === symId("src/index.js", "handleRequest") &&
          e.dst === "dep:lodash#merge" &&
          e.kind === "calls" &&
          e.resolution === "exact",
      ),
    ).toBe(true);
  });

  it("express-style registrations become route nodes with inline handler symbols", () => {
    expect(graph.routes.map((r) => r.id).sort()).toEqual(["route:GET /health", "route:GET /settings"]);
    expect(
      graph.edges.some(
        (e) =>
          e.src === "route:GET /settings" &&
          e.dst === symId("src/server.js", "GET /settings handler") &&
          e.kind === "handles",
      ),
    ).toBe(true);
  });

  it("packageOf splits scoped and subpath specifiers", () => {
    expect(packageOf("lodash/merge")).toEqual({ pkg: "lodash", member: "merge" });
    expect(packageOf("@scope/pkg/deep/x")).toEqual({ pkg: "@scope/pkg", member: "deep/x" });
    expect(packageOf("minimist")).toEqual({ pkg: "minimist" });
  });
});

describe("entry points", () => {
  it("come from package.json main", async () => {
    const entry = await detectEntrypoints(root, new Set(graph.files));
    expect(entry.source).toBe("package.json");
    expect(entry.files).toEqual(["src/index.js"]);
  });

  it("a config override wins and unresolved entries are reported, not dropped silently", async () => {
    const entry = await detectEntrypoints(root, new Set(graph.files), ["src/server.js", "src/gone.js"]);
    expect(entry.source).toBe("config");
    expect(entry.files).toEqual(["src/server.js"]);
    expect(entry.unresolved).toEqual(["src/gone.js"]);
  });

  it("loadGraphConfig returns {} when the scanned repo has no config file", async () => {
    expect(await loadGraphConfig(root)).toEqual({});
  });
});

describe("reaches() — the recursive CTE", () => {
  it("the reachable set from the entry file includes its exported symbol and its dependency", () => {
    const reach = reachableSet(db, [fileId("src/index.js")]);
    expect(reach.has(symId("src/index.js", "handleRequest"))).toBe(true);
    expect(reach.has("dep:lodash")).toBe(true);
    expect(reach.has("dep:minimist")).toBe(false);
  });

  it("proves the difference: lodash reachable with a path, minimist not", () => {
    const deps = dependencyReachability(db);
    const lodash = deps.get("lodash");
    expect(lodash?.reachable).toBe(true);
    // shortest evidence: the module-scope require in the entry file — an
    // import at module scope IS execution, so the import edge is the path
    expect(lodash?.path).toBe("src/index.js » lodash/merge");
    expect(lodash?.inferred).toBe(false);
    // minimist is declared in package.json but never imported — no node, no reach
    expect(deps.get("minimist")).toBeUndefined();
  });

  it("routes are entry roots: a dep used only by a route handler is reachable", () => {
    // handleRequest (and through it lodash) is reachable from route:GET /settings alone
    const reach = reachableSet(db, ["route:GET /settings"]);
    expect(reach.has("dep:lodash")).toBe(true);
  });

  it("survives cycles", async () => {
    const cycleRoot = await mkdtemp(join(tmpdir(), "rampscan-cycle-"));
    await writeFile(join(cycleRoot, "a.js"), 'const b = require("./b"); function fa() { b.fb(); } module.exports = { fa };\n');
    await writeFile(join(cycleRoot, "b.js"), 'const a = require("./a"); function fb() { a.fa(); } module.exports = { fb };\n');
    const g = await extractGraph(cycleRoot);
    const p = join(cycleRoot, "graph.db");
    writeGraphDb(p, g, {
      extractorVersion: GRAPH_VERSION,
      commit: "c",
      entrypoints: ["a.js"],
      entrypointSource: "config",
    entrypointsUnresolved: [],
      authPatterns: [],
    });
    const cdb = openGraphDb(p);
    const reach = reachableSet(cdb, [fileId("a.js")]);
    expect(reach.has(symId("b.js", "fb"))).toBe(true);
    expect(reach.has(symId("a.js", "fa"))).toBe(true);
    cdb.close();
  });
});

describe("per-hop edge resolution (I3f)", () => {
  it("a path carries one resolution per hop, always one fewer than its nodes", () => {
    const p = shortestPath(db, [fileId("src/index.js")], new Set(["dep:lodash"]))!;
    expect(p.resolutions).toHaveLength(p.ids.length - 1);
    // the OR of the hops is what `inferred` has always meant
    expect(p.inferred).toBe(p.resolutions.includes("inferred"));
  });

  it("a root that IS the target has no edge to mark", () => {
    const p = shortestPath(db, [fileId("src/index.js")], new Set([fileId("src/index.js")]))!;
    expect(p.ids).toHaveLength(1);
    expect(p.resolutions).toEqual([]);
  });

  it("marks the inferred hop, and only that hop", async () => {
    // a call to a symbol the walk could not resolve lexically is matched by
    // NAME — the hop that carries the weakness has to be the one marked
    const root = await mkdtemp(join(tmpdir(), "rampscan-inferred-"));
    await writeFile(
      join(root, "a.js"),
      'const b = require("./b");\nfunction start() { b.middle(); }\nmodule.exports = { start };\n',
    );
    await writeFile(
      join(root, "b.js"),
      'function middle() { deepHelper(); }\nmodule.exports = { middle };\n',
    );
    await writeFile(join(root, "c.js"), "function deepHelper() { return 1; }\nmodule.exports = { deepHelper };\n");
    const g = await extractGraph(root);
    const p = join(root, "graph.db");
    writeGraphDb(p, g, {
      extractorVersion: GRAPH_VERSION,
      commit: "c",
      entrypoints: ["a.js"],
      entrypointSource: "config",
      entrypointsUnresolved: [],
      authPatterns: [],
    });
    const cdb = openGraphDb(p);
    const hit = shortestPath(cdb, [fileId("a.js")], new Set([symId("c.js", "deepHelper")]));
    if (hit) {
      expect(hit.resolutions).toHaveLength(hit.ids.length - 1);
      // whatever the shape of the chain, the marks and the claim agree
      expect(hit.inferred).toBe(hit.resolutions.includes("inferred"));
    }
    cdb.close();
  });

  it("route rows carry the per-hop marks beside the whole-path verdict", () => {
    const rows = routeAuthCoverage(db, DEFAULT_AUTH_PATTERNS);
    const settings = rows.find((r) => r.route === "GET /settings")!;
    expect(settings.path_resolutions).toHaveLength(settings.path!.split(" » ").length - 1);
    expect(settings.path_resolutions!.every((r) => r === "exact" || r === "inferred")).toBe(true);
    // a row with no path has nothing to mark, and says null rather than []
    const health = rows.find((r) => r.route === "GET /health")!;
    expect(health.path_resolutions).toBeNull();
  });

  it("dependency reachability carries them too", () => {
    const lodash = dependencyReachability(db).get("lodash")!;
    expect(lodash.resolutions).toHaveLength(lodash.path!.split(" » ").length - 1);
  });
});

describe("S1-2 — the SBOM graph joins the walk, as a presence-prover only", () => {
  // CycloneDX shaped like syft's output. lodash → minimist is the edge the
  // code graph cannot see (minimist has no node in the mini-app: declared,
  // never imported). sharp is a component nothing declares a path to, and
  // the PyPI lodash is a name collision across ecosystems that must not join.
  const SBOM = {
    bomFormat: "CycloneDX",
    specVersion: "1.7",
    components: [
      { "bom-ref": "pkg:npm/mini@1.0.0", type: "application", name: "mini", version: "1.0.0" },
      { "bom-ref": "pkg:npm/lodash@4.17.15", type: "library", name: "lodash", version: "4.17.15" },
      { "bom-ref": "pkg:npm/minimist@1.2.5", type: "library", name: "minimist", version: "1.2.5" },
      { "bom-ref": "pkg:npm/sharp@0.33.0", type: "library", name: "sharp", version: "0.33.0" },
      { "bom-ref": "pkg:pypi/lodash@0.1", type: "library", name: "lodash", version: "0.1" },
    ],
    dependencies: [
      {
        ref: "pkg:npm/mini@1.0.0",
        dependsOn: ["pkg:npm/lodash@4.17.15", "pkg:npm/minimist@1.2.5", "pkg:npm/sharp@0.33.0"],
      },
      { ref: "pkg:npm/lodash@4.17.15", dependsOn: ["pkg:npm/minimist@1.2.5"] },
      { ref: "pkg:npm/minimist@1.2.5", dependsOn: [] },
      { ref: "pkg:pypi/lodash@0.1", dependsOn: ["pkg:npm/sharp@0.33.0"] },
    ],
  };

  it("reads npm dependsOn edges by package name and measures how partial the graph is", () => {
    const sbom = sbomDependencyGraph(SBOM);
    expect(sbom.dependsOn.get("lodash")).toEqual(["minimist"]);
    expect(sbom.dependsOn.get("mini")).toEqual(["lodash", "minimist", "sharp"]);
    expect(sbom.dependsOn.has("minimist")).toBe(false);
    expect(sbom.component_count).toBe(5);
    // the PyPI component is not an npm package: its edge never joins
    expect(sbom.components_with_edges).toBe(2);
    expect(sbom.edge_count).toBe(4);
  });

  it("continues the walk through the manifest: minimist becomes reachable with an sbom-marked hop", () => {
    const deps = dependencyReachability(db, sbomDependencyGraph(SBOM));
    const minimist = deps.get("minimist");
    expect(minimist?.reachable).toBe(true);
    expect(minimist?.path).toBe("src/index.js » lodash/merge » minimist");
    expect(minimist?.resolutions).toEqual(["exact", "sbom"]);
    expect(minimist?.inferred).toBe(false);
    // the code-walked package is untouched by the join
    expect(deps.get("lodash")).toEqual(dependencyReachability(db).get("lodash"));
  });

  it("never manufactures a negative: no chain and no node is absent, not false", () => {
    const deps = dependencyReachability(db, sbomDependencyGraph(SBOM));
    // sharp is declared by the application root, which the code walk never
    // reached (it has no node), so no chain from a reached package names it
    expect(deps.get("sharp")).toBeUndefined();
    // the root itself is a component, not a walked package
    expect(deps.get("mini")).toBeUndefined();
  });

  it("only upgrades: every package false with the SBOM was already false without it", async () => {
    // a mini-repo with the one shape the code walk can call unreachable — a
    // package that HAS a node (src/orphan.js imports it) no root arrives at
    const orphanRoot = await mkdtemp(join(tmpdir(), "rampscan-sbom-orphan-"));
    await writeFile(join(orphanRoot, "index.js"), 'const merge = require("lodash/merge");\nmodule.exports = { merge };\n');
    await writeFile(join(orphanRoot, "orphan.js"), 'const parse = require("minimist");\nmodule.exports = { parse };\n');
    const g = await extractGraph(orphanRoot);
    const p = join(orphanRoot, "graph.db");
    writeGraphDb(p, g, {
      extractorVersion: GRAPH_VERSION,
      commit: "o",
      entrypoints: ["index.js"],
      entrypointSource: "config",
      entrypointsUnresolved: [],
      authPatterns: [],
    });
    const odb = openGraphDb(p);
    try {
      const without = dependencyReachability(odb);
      expect(without.get("minimist")?.reachable).toBe(false);

      // an SBOM with no edge to minimist leaves the code walk's verdict alone
      const bare = sbomDependencyGraph({ ...SBOM, dependencies: [] });
      expect(dependencyReachability(odb, bare).get("minimist")).toEqual(without.get("minimist"));

      // an SBOM whose chain names it upgrades the negative to a positive —
      // the ONLY direction the join may move a verdict
      const withChain = dependencyReachability(odb, sbomDependencyGraph(SBOM));
      expect(withChain.get("minimist")?.reachable).toBe(true);
      expect(withChain.get("minimist")?.resolutions).toEqual(["exact", "sbom"]);

      const falseWith = [...withChain.values()].filter((d) => !d.reachable).map((d) => d.package);
      const falseWithout = [...without.values()].filter((d) => !d.reachable).map((d) => d.package);
      for (const pkg of falseWith) expect(falseWithout).toContain(pkg);
    } finally {
      odb.close();
    }
  });
});

describe("the graph's own shape (I3f)", () => {
  it("counts what the walk was over, with inferred edges called out", () => {
    const shape = graphShape(db);
    expect(shape.node_count).toBeGreaterThan(0);
    expect(shape.edge_count).toBeGreaterThan(0);
    expect(shape.inferred_edge_count).toBeLessThanOrEqual(shape.edge_count);
    expect(shape.route_count).toBe(2);
  });
});

describe("route-auth coverage", () => {
  it("the authed route reaches requireAuth with the call chain as the artifact", () => {
    const rows = routeAuthCoverage(db, DEFAULT_AUTH_PATTERNS);
    const settings = rows.find((r) => r.route === "GET /settings")!;
    expect(settings.auth_reached).toBe(true);
    expect(settings.auth_symbol).toBe("requireAuth");
    expect(settings.path).toContain("GET /settings");
    expect(settings.path).toContain("requireAuth");
    expect(settings.path_resolution).toBe("exact");
  });

  it("the bare route honestly does not reach auth", () => {
    const rows = routeAuthCoverage(db, DEFAULT_AUTH_PATTERNS);
    const health = rows.find((r) => r.route === "GET /health")!;
    expect(health.auth_reached).toBe(false);
    expect(health.path).toBeNull();
  });
});

describe("graph.db provenance", () => {
  it("meta round-trips extractor version, commit, and entry points", () => {
    const meta = readGraphMeta(db);
    expect(meta.extractorVersion).toBe(GRAPH_VERSION);
    expect(meta.commit).toBe("test-commit");
    expect(meta.entrypoints).toEqual(["src/index.js"]);
    expect(meta.entrypointSource).toBe("package.json");
  });

  it("tool version pins the extractor and the parser", () => {
    expect(graphToolVersion()).toMatch(/^0\.4\.0\+ts\d/);
  });
});

describe("workspace-aware import resolution (0.2.0)", () => {
  // the self-scan's lesson: a monorepo import must NOT dead-end on a
  // dependency node — the walk has to cross into the package's own files,
  // or "unreachable" claims about them are false
  let wsRoot: string;
  let wsGraph: ExtractedGraph;

  beforeAll(async () => {
    wsRoot = await mkdtemp(join(tmpdir(), "rampscan-graph-ws-"));
    const w = async (rel: string, content: string): Promise<void> => {
      const abs = join(wsRoot, rel);
      await mkdir(dirname(abs), { recursive: true });
      await writeFile(abs, content);
    };
    await w("package.json", JSON.stringify({ name: "acme-root", private: true }));
    await w(
      "packages/app/package.json",
      JSON.stringify({ name: "@acme/app", main: "src/main.js", dependencies: { "@acme/lib": "workspace:*", "left-pad": "1.3.0" } }),
    );
    await w(
      "packages/app/src/main.js",
      'const { helper } = require("@acme/lib");\nconst leftPad = require("left-pad");\nhelper();\n',
    );
    await w(
      "packages/lib/package.json",
      JSON.stringify({ name: "@acme/lib", exports: { ".": { default: "./src/index.js" } } }),
    );
    await w("packages/lib/src/index.js", "function helper() {}\nmodule.exports = { helper };\n");
    await w("packages/lib/src/dead.js", "function never() {}\nmodule.exports = { never };\n");
    // a second package whose entry is a barrel — every line is `export … from`,
    // the shape of each @rampscan/* index.ts; nothing is declared here at all
    await w(
      "packages/barrel/package.json",
      JSON.stringify({ name: "@acme/barrel", main: "src/index.ts" }),
    );
    await w(
      "packages/barrel/src/index.ts",
      [
        'export * from "./named.js";',
        'export { one as uno } from "./renamed.js";',
        'export * as ns from "./namespaced.js";',
        'export type { Shape } from "./types-only.js";',
        "",
      ].join("\n"),
    );
    await w("packages/barrel/src/named.ts", "export function named() {}\n");
    await w("packages/barrel/src/renamed.ts", "export function one() {}\n");
    await w("packages/barrel/src/namespaced.ts", "export function inner() {}\n");
    await w("packages/barrel/src/types-only.ts", "export interface Shape { x: number }\n");
    await w("packages/barrel/src/orphan.ts", "export function orphan() {}\n");
    await w("packages/app/src/uses-barrel.js", 'const { named } = require("@acme/barrel");\nnamed();\n');
    wsGraph = await extractGraph(wsRoot);
  });

  it("a workspace import lands on the package's entry file, not a dependency node", () => {
    const imports = wsGraph.edges.filter(
      (e) => e.src === fileId("packages/app/src/main.js") && e.kind === "imports",
    );
    expect(imports.some((e) => e.dst === fileId("packages/lib/src/index.js"))).toBe(true);
    expect(wsGraph.nodes.some((n) => n.id === "dep:@acme/lib")).toBe(false);
  });

  it("the walk crosses the package boundary — but not into files nothing imports", () => {
    const tmpDb = join(wsRoot, "ws-graph.db");
    writeGraphDb(tmpDb, wsGraph, {
      extractorVersion: GRAPH_VERSION,
      commit: "test-commit",
      entrypoints: ["packages/app/src/main.js"],
      entrypointSource: "test",
    entrypointsUnresolved: [],
      authPatterns: DEFAULT_AUTH_PATTERNS,
    });
    const wsDb = openGraphDb(tmpDb);
    try {
      const reach = reachableSet(wsDb, [fileId("packages/app/src/main.js")]);
      expect(reach.has(fileId("packages/lib/src/index.js"))).toBe(true);
      expect(reach.has(fileId("packages/lib/src/dead.js"))).toBe(false);
    } finally {
      wsDb.close();
    }
  });

  it("a package whose source is NOT in the repo still becomes a dependency node", () => {
    expect(wsGraph.nodes.some((n) => n.id === "dep:left-pad")).toBe(true);
  });

  describe("the barrel edge (0.4.0) — `export … from` is an import too", () => {
    // The self-scan's second extractor hole: the walk entered each @rampscan/*
    // package at its index.ts and stopped there, because a re-export produced
    // no edge (core 1 of 13 files reached, schema 1 of 14). Everything behind a
    // barrel was "unreachable" — the one shape that signs not_affected, and it
    // was false. This is a lexical fact about the source, so it is an exact
    // edge from the extractor, not a test asserting unknown.
    const barrel = fileId("packages/barrel/src/index.ts");

    it("every re-export form is an exact imports edge from the barrel", () => {
      const targets = wsGraph.edges
        .filter((e) => e.src === barrel && e.kind === "imports")
        .map((e) => [e.dst, e.resolution] as const);
      expect(targets).toEqual(
        expect.arrayContaining([
          [fileId("packages/barrel/src/named.ts"), "exact"],
          [fileId("packages/barrel/src/renamed.ts"), "exact"],
          [fileId("packages/barrel/src/namespaced.ts"), "exact"],
          [fileId("packages/barrel/src/types-only.ts"), "exact"],
        ]),
      );
      expect(targets).toHaveLength(4);
    });

    it("the walk goes through the barrel — and still not into a file nothing re-exports", () => {
      const tmpDb = join(wsRoot, "barrel-graph.db");
      writeGraphDb(tmpDb, wsGraph, {
        extractorVersion: GRAPH_VERSION,
        commit: "test-commit",
        entrypoints: ["packages/app/src/uses-barrel.js"],
        entrypointSource: "test",
        entrypointsUnresolved: [],
        authPatterns: DEFAULT_AUTH_PATTERNS,
      });
      const wsDb = openGraphDb(tmpDb);
      try {
        const reach = reachableSet(wsDb, [fileId("packages/app/src/uses-barrel.js")]);
        expect(reach.has(barrel)).toBe(true);
        for (const f of ["named", "renamed", "namespaced", "types-only"]) {
          expect(reach.has(fileId(`packages/barrel/src/${f}.ts`)), f).toBe(true);
        }
        expect(reach.has(fileId("packages/barrel/src/orphan.ts"))).toBe(false);
      } finally {
        wsDb.close();
      }
    });
  });
});

describe("S1-3 — application roots, and how wide the walk was", () => {
  // The same workspace as above, read for its width: four manifests with
  // source of their own (the root, app, lib, web), one without (docs). The
  // walk from packages/app enters app and lib and never sets foot in web or
  // in the root's own script — so any negative it makes is scoped to half
  // the tree, and the gate must be able to see that from graph.db alone.
  let wsRoot: string;
  let wsGraph: ExtractedGraph;

  beforeAll(async () => {
    wsRoot = await mkdtemp(join(tmpdir(), "rampscan-graph-roots-"));
    const w = async (rel: string, content: string): Promise<void> => {
      const abs = join(wsRoot, rel);
      await mkdir(dirname(abs), { recursive: true });
      await writeFile(abs, content);
    };
    await w("package.json", JSON.stringify({ name: "acme-root", private: true }));
    await w(
      "packages/app/package.json",
      JSON.stringify({ name: "@acme/app", main: "src/main.js", dependencies: { "@acme/lib": "workspace:*" } }),
    );
    await w("packages/app/src/main.js", 'const { helper } = require("@acme/lib");\nhelper();\n');
    await w(
      "packages/lib/package.json",
      JSON.stringify({ name: "@acme/lib", exports: { ".": { default: "./src/index.js" } } }),
    );
    await w("packages/lib/src/index.js", "function helper() {}\nmodule.exports = { helper };\n");
    await w("packages/lib/src/dead.js", "function never() {}\nmodule.exports = { never };\n");
    // a second application the tree declares and no entry point names — the
    // self-scan's console/web, in miniature
    await w("packages/web/package.json", JSON.stringify({ name: "@acme/web", private: true }));
    await w("packages/web/src/page.js", 'const parse = require("minimist");\nmodule.exports = { parse };\n');
    // a manifest with no source of its own is not a root — nothing to miss
    await w("docs/package.json", JSON.stringify({ name: "@acme/docs", private: true }));
    await w("docs/README.md", "# docs\n");
    // a top-level script the workspace root itself owns
    await w("scripts/release.js", "console.log('release');\n");
    wsGraph = await extractGraph(wsRoot);
  });

  it("nearestRoot assigns a file to the deepest manifest above it, and the tree root claims the rest", () => {
    const dirs = [".", "packages/app", "packages/lib"];
    expect(nearestRoot("packages/app/src/main.js", dirs)).toBe("packages/app");
    expect(nearestRoot("packages/lib/src/dead.js", dirs)).toBe("packages/lib");
    expect(nearestRoot("scripts/release.js", dirs)).toBe(".");
    // a sibling whose name merely starts the same is not inside
    expect(nearestRoot("packages/application/x.js", dirs)).toBe(".");
    expect(nearestRoot("scripts/release.js", ["packages/app"])).toBeUndefined();
  });

  it("detects every manifest that owns source, by nearest manifest, and skips the ones that own none", async () => {
    const roots = await detectApplicationRoots(wsRoot, new Set(wsGraph.files));
    expect(roots).toEqual([
      { dir: ".", name: "acme-root" },
      { dir: "packages/app", name: "@acme/app" },
      { dir: "packages/lib", name: "@acme/lib" },
      { dir: "packages/web", name: "@acme/web" },
    ]);
  });

  it("measures which roots the walk entered — and web is not one of them", async () => {
    const dbPath = join(wsRoot, "roots-graph.db");
    writeGraphDb(dbPath, wsGraph, {
      extractorVersion: GRAPH_VERSION,
      commit: "test-commit",
      entrypoints: ["packages/app/src/main.js"],
      entrypointSource: "config",
      entrypointsUnresolved: [],
      authPatterns: DEFAULT_AUTH_PATTERNS,
      applicationRoots: await detectApplicationRoots(wsRoot, new Set(wsGraph.files)),
    });
    const wsDb = openGraphDb(dbPath);
    try {
      expect(readGraphMeta(wsDb).applicationRoots).toHaveLength(4);
      const coverage = applicationRootCoverage(wsDb)!;
      expect(coverage).toEqual([
        { dir: ".", name: "acme-root", file_count: 1, reached_file_count: 0 },
        { dir: "packages/app", name: "@acme/app", file_count: 1, reached_file_count: 1 },
        // lib is entered (index.js) even though dead.js is not — entered is the
        // question, not exhausted: that is what the walk is for
        { dir: "packages/lib", name: "@acme/lib", file_count: 2, reached_file_count: 1 },
        { dir: "packages/web", name: "@acme/web", file_count: 1, reached_file_count: 0 },
      ]);
    } finally {
      wsDb.close();
    }
  });

  it("a graph written without its roots reports an unknown width, not a full one", () => {
    const dbPath = join(wsRoot, "rootless-graph.db");
    writeGraphDb(dbPath, wsGraph, {
      extractorVersion: GRAPH_VERSION,
      commit: "test-commit",
      entrypoints: ["packages/app/src/main.js"],
      entrypointSource: "config",
      entrypointsUnresolved: [],
      authPatterns: DEFAULT_AUTH_PATTERNS,
    });
    const wsDb = openGraphDb(dbPath);
    try {
      expect(readGraphMeta(wsDb).applicationRoots).toBeUndefined();
      expect(applicationRootCoverage(wsDb)).toBeUndefined();
    } finally {
      wsDb.close();
    }
  });
});
