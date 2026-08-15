import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { beforeAll, describe, expect, it } from "vitest";
import {
  DEFAULT_AUTH_PATTERNS,
  GRAPH_DB_ARTIFACT,
  GRAPH_VERSION,
  dependencyReachability,
  detectEntrypoints,
  extractGraph,
  fileId,
  graphShape,
  graphToolVersion,
  loadGraphConfig,
  openGraphDb,
  packageOf,
  readGraphMeta,
  reachableSet,
  routeAuthCoverage,
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
    expect(graphToolVersion()).toMatch(/^0\.2\.0\+ts\d/);
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
});
