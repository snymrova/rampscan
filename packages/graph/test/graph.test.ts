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
  graphToolVersion,
  loadGraphConfig,
  openGraphDb,
  packageOf,
  readGraphMeta,
  reachableSet,
  routeAuthCoverage,
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
      authPatterns: [],
    });
    const cdb = openGraphDb(p);
    const reach = reachableSet(cdb, [fileId("a.js")]);
    expect(reach.has(symId("b.js", "fb"))).toBe(true);
    expect(reach.has(symId("a.js", "fa"))).toBe(true);
    cdb.close();
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
    expect(graphToolVersion()).toMatch(/^0\.1\.0\+ts\d/);
  });
});
