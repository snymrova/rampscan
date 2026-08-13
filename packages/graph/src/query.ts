import type { DatabaseSync } from "node:sqlite";
import { readGraphMeta } from "./db.js";
import { fileId, type EdgeKind } from "./extract.js";

// Graph queries — plan §M4: `reaches(entrypoints, target)` answered by
// recursive CTE. The CTE computes the reachable SET (the verdict); the
// display path is reconstructed by BFS over the same edges, because the
// verdict is what must be provably derived in SQL and the path is
// presentation.
//
// Two traversals, two deliberate approximation directions:
//   - dependency reachability walks EVERY edge kind (over-approximate):
//     a not-affected VEX claim is only made when even the loose walk cannot
//     reach the package.
//   - route→auth walks calls/handles edges only (under-approximate): "this
//     route reaches an auth check" is a positive evidence claim, so it must
//     rest on an actual call chain, and rows say when that chain includes an
//     inferred edge.

const EDGE_KINDS: readonly EdgeKind[] = ["imports", "declares", "exports", "calls", "handles"];

function kindList(kinds: readonly EdgeKind[]): string {
  // kinds come from the closed EdgeKind enum — safe to inline
  return kinds.map((k) => `'${k}'`).join(", ");
}

/** the reachable set from `roots`, via recursive CTE */
export function reachableSet(
  db: DatabaseSync,
  roots: string[],
  kinds: readonly EdgeKind[] = EDGE_KINDS,
): Set<string> {
  if (roots.length === 0) return new Set();
  const rows = db
    .prepare(
      `WITH RECURSIVE reach(id) AS (
         SELECT value FROM json_each(?)
         UNION
         SELECT e.dst FROM edges e JOIN reach r ON e.src = r.id
         WHERE e.kind IN (${kindList(kinds)})
       )
       SELECT id FROM reach`,
    )
    .all(JSON.stringify(roots)) as Array<{ id: string }>;
  return new Set(rows.map((r) => r.id));
}

export interface PathResult {
  /** node ids, root first */
  ids: string[];
  /** true when any edge on the path was name-inferred rather than lexically resolved */
  inferred: boolean;
}

/** shortest path from any root to any target — BFS over the stored edges */
export function shortestPath(
  db: DatabaseSync,
  roots: string[],
  targets: ReadonlySet<string>,
  kinds: readonly EdgeKind[] = EDGE_KINDS,
): PathResult | undefined {
  if (roots.length === 0 || targets.size === 0) return undefined;
  for (const root of roots) {
    if (targets.has(root)) return { ids: [root], inferred: false };
  }
  const kindSet = new Set(kinds);
  const adjacency = new Map<string, Array<{ dst: string; inferred: boolean }>>();
  const all = db.prepare("SELECT src, dst, kind, resolution FROM edges").all() as Array<{
    src: string;
    dst: string;
    kind: EdgeKind;
    resolution: string;
  }>;
  for (const e of all) {
    if (!kindSet.has(e.kind)) continue;
    const list = adjacency.get(e.src);
    const entry = { dst: e.dst, inferred: e.resolution === "inferred" };
    if (list) list.push(entry);
    else adjacency.set(e.src, [entry]);
  }
  const parent = new Map<string, { prev: string; inferred: boolean }>();
  const queue = [...roots];
  const seen = new Set(roots);
  while (queue.length > 0) {
    const cur = queue.shift()!;
    for (const { dst, inferred } of adjacency.get(cur) ?? []) {
      if (seen.has(dst)) continue;
      seen.add(dst);
      parent.set(dst, { prev: cur, inferred });
      if (targets.has(dst)) {
        const ids = [dst];
        let anyInferred = false;
        let at = dst;
        while (parent.has(at)) {
          const p = parent.get(at)!;
          anyInferred = anyInferred || p.inferred;
          ids.unshift(p.prev);
          at = p.prev;
        }
        return { ids, inferred: anyInferred };
      }
      queue.push(dst);
    }
  }
  return undefined;
}

/** human-readable path: node ids → display names, " » "-joined */
export function labelPath(db: DatabaseSync, ids: string[]): string {
  const stmt = db.prepare("SELECT name FROM nodes WHERE id = ?");
  return ids
    .map((id) => {
      const row = stmt.get(id) as { name: string } | undefined;
      return row?.name ?? id;
    })
    .join(" » ");
}

/** advisory-gating roots: entry point files (from meta) + every declared route */
export function entryRoots(db: DatabaseSync): string[] {
  const meta = readGraphMeta(db);
  const routeIds = (db.prepare("SELECT id FROM routes").all() as Array<{ id: string }>).map(
    (r) => r.id,
  );
  return [...meta.entrypoints.map((rel) => fileId(rel)), ...routeIds];
}

export interface DepReachability {
  package: string;
  reachable: boolean;
  /** display path, root » … » package node; undefined when unreachable */
  path?: string;
  /** the path rests on at least one name-inferred edge */
  inferred?: boolean;
}

/** package-level reachability for every dependency node in the graph */
export function dependencyReachability(db: DatabaseSync): Map<string, DepReachability> {
  const roots = entryRoots(db);
  const reach = reachableSet(db, roots);
  const depNodes = db
    .prepare("SELECT id, package FROM nodes WHERE kind = 'dependency'")
    .all() as Array<{ id: string; package: string }>;

  const byPackage = new Map<string, string[]>();
  for (const n of depNodes) {
    const list = byPackage.get(n.package);
    if (list) list.push(n.id);
    else byPackage.set(n.package, [n.id]);
  }

  const out = new Map<string, DepReachability>();
  for (const [pkg, ids] of byPackage) {
    const hit = ids.some((id) => reach.has(id));
    if (!hit) {
      out.set(pkg, { package: pkg, reachable: false });
      continue;
    }
    const path = shortestPath(db, roots, new Set(ids));
    out.set(pkg, {
      package: pkg,
      reachable: true,
      ...(path
        ? { path: labelPath(db, path.ids), inferred: path.inferred }
        : {}),
    });
  }
  return out;
}

export interface RouteAuthRow extends Record<string, unknown> {
  route: string; // "GET /health"
  file: string;
  line: number;
  auth_reached: boolean;
  auth_symbol: string | null;
  path: string | null;
  /** "exact" | "inferred" when auth was reached; null otherwise */
  path_resolution: string | null;
}

const AUTH_EDGE_KINDS: readonly EdgeKind[] = ["handles", "calls"];

/** every declared route × does its call path reach an auth-named symbol */
export function routeAuthCoverage(db: DatabaseSync, authPatterns: string[]): RouteAuthRow[] {
  const regexes = authPatterns.map((p) => new RegExp(p, "i"));
  const candidates = db
    .prepare("SELECT id, name FROM nodes WHERE kind IN ('symbol', 'dependency')")
    .all() as Array<{ id: string; name: string }>;
  const authNodes = new Map(
    candidates.filter((n) => regexes.some((r) => r.test(n.name))).map((n) => [n.id, n.name]),
  );
  const routes = db
    .prepare("SELECT id, method, route_path, file, line FROM routes ORDER BY id")
    .all() as Array<{ id: string; method: string; route_path: string; file: string; line: number }>;

  return routes.map((route) => {
    const reach = reachableSet(db, [route.id], AUTH_EDGE_KINDS);
    const hitId = [...reach].find((id) => authNodes.has(id));
    if (hitId === undefined) {
      return {
        route: `${route.method} ${route.route_path}`,
        file: route.file,
        line: route.line,
        auth_reached: false,
        auth_symbol: null,
        path: null,
        path_resolution: null,
      };
    }
    const path = shortestPath(db, [route.id], new Set(authNodes.keys()), AUTH_EDGE_KINDS);
    return {
      route: `${route.method} ${route.route_path}`,
      file: route.file,
      line: route.line,
      auth_reached: true,
      auth_symbol: authNodes.get(hitId) ?? null,
      path: path ? labelPath(db, path.ids) : null,
      path_resolution: path ? (path.inferred ? "inferred" : "exact") : null,
    };
  });
}
