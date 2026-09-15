import { DatabaseSync } from "node:sqlite";
import type { ApplicationRoot, DetectedEntrypoint } from "./entrypoints.js";
import type { ExtractedGraph, OpaqueImport } from "./extract.js";

// graph.db — SPEC §3: "SQLite file per repo-snapshot, queried with recursive
// CTEs". The graph is a derived artifact, rebuildable from the commit; the
// db carries its own provenance (extractor version, commit, entry points) so
// a bundle citing it is self-describing.

export const GRAPH_DB_ARTIFACT = "graph.db";

export interface GraphMeta {
  extractorVersion: string;
  commit: string;
  entrypoints: string[];
  entrypointSource: string;
  /**
   * Declared entries that resolved to no file the walk saw (I3f). A dropped
   * root silently shrinks the reachable set and therefore silently widens
   * every "not affected" claim, so it travels with the graph and gets named
   * wherever the claim is read.
   */
  entrypointsUnresolved: string[];
  authPatterns: string[];
  /**
   * The application roots the tree declared when the graph was built (S1-3) —
   * what the entry points could have covered, beside what they did. Absent on
   * a graph written before the field existed, and absence is NOT an empty
   * list: a reader that cannot tell which roots a walk covered must not claim
   * the walk covered them all.
   */
  applicationRoots?: ApplicationRoot[];
  /**
   * What entry-point detection found across those roots, and which of it the
   * config left out (S1-4). Absent on a graph written before the field
   * existed; for a graph whose entry points came from config, absence means
   * the narrowing is unknown — which is not the same as none.
   */
  entrypointsDetected?: DetectedEntrypoint[];
  entrypointsExcluded?: DetectedEntrypoint[];
  /**
   * Every load by a specifier the extractor could not read (S4-1), as the
   * extractor found them — written from the graph, not supplied by the
   * caller. Absent on a graph written before the field existed, and absence
   * is NOT an empty list: a reader that cannot tell where the walk may have
   * continued unseen must not claim it saw everything.
   */
  opaqueImports?: OpaqueImport[];
}

export function writeGraphDb(dbPath: string, graph: ExtractedGraph, meta: GraphMeta): void {
  const db = new DatabaseSync(dbPath);
  try {
    db.exec("BEGIN");
    for (const table of ["nodes", "edges", "routes", "meta"]) {
      db.exec(`DROP TABLE IF EXISTS ${table}`);
    }
    db.exec(`
      CREATE TABLE nodes (
        id      TEXT PRIMARY KEY,
        kind    TEXT NOT NULL,   -- file | symbol | dependency | route
        name    TEXT NOT NULL,
        path    TEXT,
        line    INTEGER,
        package TEXT
      )
    `);
    db.exec(`
      CREATE TABLE edges (
        src        TEXT NOT NULL,
        dst        TEXT NOT NULL,
        kind       TEXT NOT NULL, -- imports | declares | exports | calls | handles
        resolution TEXT NOT NULL, -- exact | inferred
        detail     TEXT
      )
    `);
    db.exec("CREATE INDEX edges_src ON edges(src)");
    db.exec(`
      CREATE TABLE routes (
        id         TEXT PRIMARY KEY,
        method     TEXT NOT NULL,
        route_path TEXT NOT NULL,
        file       TEXT NOT NULL,
        line       INTEGER NOT NULL
      )
    `);
    db.exec("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)");

    const insertNode = db.prepare(
      "INSERT INTO nodes (id, kind, name, path, line, package) VALUES (?, ?, ?, ?, ?, ?)",
    );
    for (const n of graph.nodes) {
      insertNode.run(n.id, n.kind, n.name, n.path ?? null, n.line ?? null, n.package ?? null);
    }
    const insertEdge = db.prepare(
      "INSERT INTO edges (src, dst, kind, resolution, detail) VALUES (?, ?, ?, ?, ?)",
    );
    for (const e of graph.edges) {
      insertEdge.run(e.src, e.dst, e.kind, e.resolution, e.detail ?? null);
    }
    const insertRoute = db.prepare(
      "INSERT INTO routes (id, method, route_path, file, line) VALUES (?, ?, ?, ?, ?)",
    );
    for (const r of graph.routes) {
      insertRoute.run(r.id, r.method, r.routePath, r.file, r.line);
    }
    const insertMeta = db.prepare("INSERT INTO meta (key, value) VALUES (?, ?)");
    insertMeta.run("extractor_version", meta.extractorVersion);
    insertMeta.run("commit", meta.commit);
    insertMeta.run("entrypoints", JSON.stringify(meta.entrypoints));
    insertMeta.run("entrypoint_source", meta.entrypointSource);
    insertMeta.run("entrypoints_unresolved", JSON.stringify(meta.entrypointsUnresolved));
    insertMeta.run("auth_patterns", JSON.stringify(meta.authPatterns));
    if (meta.applicationRoots !== undefined) {
      insertMeta.run("application_roots", JSON.stringify(meta.applicationRoots));
    }
    if (meta.entrypointsDetected !== undefined) {
      insertMeta.run("entrypoints_detected", JSON.stringify(meta.entrypointsDetected));
    }
    if (meta.entrypointsExcluded !== undefined) {
      insertMeta.run("entrypoints_excluded", JSON.stringify(meta.entrypointsExcluded));
    }
    if (graph.opaqueImports !== undefined) {
      insertMeta.run("opaque_imports", JSON.stringify(graph.opaqueImports));
    }
    insertMeta.run("file_count", String(graph.files.length));
    db.exec("COMMIT");
  } catch (error) {
    db.exec("ROLLBACK");
    throw error;
  } finally {
    db.close();
  }
}

export function openGraphDb(dbPath: string): DatabaseSync {
  return new DatabaseSync(dbPath, { readOnly: true });
}

export function readGraphMeta(db: DatabaseSync): GraphMeta {
  const rows = db.prepare("SELECT key, value FROM meta").all() as Array<{
    key: string;
    value: string;
  }>;
  const map = new Map(rows.map((r) => [r.key, r.value]));
  const roots = map.get("application_roots");
  const detected = map.get("entrypoints_detected");
  const excluded = map.get("entrypoints_excluded");
  const opaque = map.get("opaque_imports");
  return {
    extractorVersion: map.get("extractor_version") ?? "unknown",
    commit: map.get("commit") ?? "unknown",
    entrypoints: JSON.parse(map.get("entrypoints") ?? "[]") as string[],
    entrypointSource: map.get("entrypoint_source") ?? "none",
    entrypointsUnresolved: JSON.parse(map.get("entrypoints_unresolved") ?? "[]") as string[],
    authPatterns: JSON.parse(map.get("auth_patterns") ?? "[]") as string[],
    ...(roots !== undefined ? { applicationRoots: JSON.parse(roots) as ApplicationRoot[] } : {}),
    ...(detected !== undefined ? { entrypointsDetected: JSON.parse(detected) as DetectedEntrypoint[] } : {}),
    ...(excluded !== undefined ? { entrypointsExcluded: JSON.parse(excluded) as DetectedEntrypoint[] } : {}),
    ...(opaque !== undefined ? { opaqueImports: JSON.parse(opaque) as OpaqueImport[] } : {}),
  };
}
