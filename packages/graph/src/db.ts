import { DatabaseSync } from "node:sqlite";
import type { ExtractedGraph } from "./extract.js";

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
  return {
    extractorVersion: map.get("extractor_version") ?? "unknown",
    commit: map.get("commit") ?? "unknown",
    entrypoints: JSON.parse(map.get("entrypoints") ?? "[]") as string[],
    entrypointSource: map.get("entrypoint_source") ?? "none",
    entrypointsUnresolved: JSON.parse(map.get("entrypoints_unresolved") ?? "[]") as string[],
    authPatterns: JSON.parse(map.get("auth_patterns") ?? "[]") as string[],
  };
}
