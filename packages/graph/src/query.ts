import type { DatabaseSync } from "node:sqlite";
import { readGraphMeta } from "./db.js";
import { nearestRoot, type DetectedEntrypoint } from "./entrypoints.js";
import { fileId, type EdgeKind, type Resolution } from "./extract.js";
import type { SbomDependencyGraph } from "./sbom.js";

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
  /**
   * How each HOP was resolved, root-first — always `ids.length - 1` entries
   * (I3f). `inferred` above is the OR of these: it answers "can this path be
   * trusted end to end", and this answers "which hop is the weak one", which
   * is the question a reader looking at a call path actually has.
   */
  resolutions: Array<"exact" | "inferred">;
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
    if (targets.has(root)) return { ids: [root], inferred: false, resolutions: [] };
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
        const resolutions: Array<"exact" | "inferred"> = [];
        let anyInferred = false;
        let at = dst;
        while (parent.has(at)) {
          const p = parent.get(at)!;
          anyInferred = anyInferred || p.inferred;
          // walking backwards, so each hop goes on the FRONT beside the node
          // it arrives at — resolutions[i] is the edge ids[i] → ids[i+1]
          resolutions.unshift(p.inferred ? "inferred" : "exact");
          ids.unshift(p.prev);
          at = p.prev;
        }
        return { ids, inferred: anyInferred, resolutions };
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

/**
 * One application root of the tree, and whether the advisory-gating walk
 * ever entered it (S1-3). `file_count` is what the root owns by nearest
 * manifest; `reached_file_count` is how many of those the walk from every
 * entry point and declared route arrived at. Zero reached means the walk
 * never set foot in this application, and a negative claim scoped to the
 * others is not a claim about the repository.
 */
export interface ApplicationRootCoverage {
  dir: string;
  name?: string;
  file_count: number;
  reached_file_count: number;
}

/**
 * Which application roots the advisory-gating walk entered — the width of
 * every negative claim it makes. Undefined when the graph was written without
 * its roots recorded: an unknown width is not a full width, and the caller
 * must refuse the negative rather than assume it.
 */
export function applicationRootCoverage(db: DatabaseSync): ApplicationRootCoverage[] | undefined {
  const meta = readGraphMeta(db);
  if (meta.applicationRoots === undefined) return undefined;
  const reach = reachableSet(db, entryRoots(db));
  // a file node's name IS its repo-relative path; graphs from before the
  // path column was filled for file nodes still have the name
  const files = db.prepare("SELECT id, COALESCE(path, name) AS path FROM nodes WHERE kind = 'file'").all() as Array<{
    id: string;
    path: string;
  }>;
  const dirs = meta.applicationRoots.map((r) => r.dir);
  const out = new Map<string, ApplicationRootCoverage>(
    meta.applicationRoots.map((r) => [
      r.dir,
      { dir: r.dir, ...(r.name !== undefined ? { name: r.name } : {}), file_count: 0, reached_file_count: 0 },
    ]),
  );
  for (const f of files) {
    const dir = nearestRoot(f.path, dirs);
    if (dir === undefined) continue;
    const row = out.get(dir)!;
    row.file_count += 1;
    if (reach.has(f.id)) row.reached_file_count += 1;
  }
  return [...out.values()];
}

/** an entry point detection found that the config left out, and whether the walk got there anyway */
export interface ExcludedEntrypointCoverage extends DetectedEntrypoint {
  reached: boolean;
}

/**
 * The entry points config excluded (S1-4), each with whether the walk from
 * the configured set reached it regardless. One it did not reach is a place
 * the program starts that no walk began from or arrived at — a negative made
 * over that walk is scoped to less than the program, and the gate refuses it.
 * Undefined when the graph does not carry the record and its entry points
 * came from config: the narrowing is then unknown, which is not none. A graph
 * whose entry points were detected rather than configured excluded nothing.
 */
export function excludedEntrypointCoverage(db: DatabaseSync): ExcludedEntrypointCoverage[] | undefined {
  const meta = readGraphMeta(db);
  if (meta.entrypointsExcluded === undefined) {
    return meta.entrypointSource === "config" ? undefined : [];
  }
  if (meta.entrypointsExcluded.length === 0) return [];
  const reach = reachableSet(db, entryRoots(db));
  return meta.entrypointsExcluded.map((e) => ({ ...e, reached: reach.has(fileId(e.file)) }));
}

/**
 * How one hop of a dependency path was sourced. `exact` and `inferred` are
 * the code graph's own edge resolutions; `sbom` is a hop the code graph never
 * saw — a `dependsOn` edge declared in a package manifest and read from the
 * CycloneDX SBOM (S1-2). A reader is owed the difference: the first two are
 * parsed call sites, the third is a manifest's word for it.
 */
export type HopResolution = Resolution | "sbom";

export interface DepReachability {
  package: string;
  reachable: boolean;
  /** display path, root » … » package node; undefined when unreachable */
  path?: string;
  /** the path rests on at least one name-inferred edge */
  inferred?: boolean;
  /** per-hop resolution of `path`, one entry shorter than its node count (I3f) */
  resolutions?: HopResolution[];
}

/**
 * Package-level reachability for every dependency node in the graph — and,
 * given the SBOM's dependency graph, for every package a `dependsOn` chain
 * leads to from a package the code walk reached (S1-2).
 *
 * The SBOM may only ever ADD to the reachable set. A package the code walk
 * reached stays reached; a package with a node the walk did not arrive at is
 * upgraded to reachable when a chain from a reached package names it, and is
 * otherwise left exactly as the code walk found it; a package with no node
 * and no chain is absent from the result, never `reachable: false` — the SBOM
 * graph is partial, so "no chain" is not a finding. This is the direction
 * the fix for GHSA-7jff-6v53-r56x must never regress in.
 */
export function dependencyReachability(
  db: DatabaseSync,
  sbom?: SbomDependencyGraph,
): Map<string, DepReachability> {
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
        ? { path: labelPath(db, path.ids), inferred: path.inferred, resolutions: path.resolutions }
        : {}),
    });
  }
  if (sbom === undefined) return out;

  // continue forward through the manifest graph from every package the code
  // walk arrived at — BFS, so the chain recorded for each package is the
  // shortest one, and a package is claimed from the first chain that names it
  const reachedByCode = [...out.values()].filter((d) => d.reachable).map((d) => d.package);
  const via = new Map<string, string>(); // package → the package whose dependsOn named it
  const seen = new Set(reachedByCode);
  const queue = [...reachedByCode];
  while (queue.length > 0) {
    const cur = queue.shift()!;
    for (const next of sbom.dependsOn.get(cur) ?? []) {
      if (seen.has(next)) continue;
      seen.add(next);
      via.set(next, cur);
      queue.push(next);
    }
  }
  for (const pkg of via.keys()) {
    // walk the chain back to the code-reached package it hangs from
    const chain = [pkg];
    let at = via.get(pkg)!;
    while (via.has(at)) {
      chain.unshift(at);
      at = via.get(at)!;
    }
    const origin = out.get(at)!;
    const originPath = origin.path ?? at;
    out.set(pkg, {
      package: pkg,
      reachable: true,
      path: [originPath, ...chain].join(" » "),
      inferred: origin.inferred ?? false,
      resolutions: [...(origin.resolutions ?? []), ...chain.map((): HopResolution => "sbom")],
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
  /** per-hop resolution of `path` (I3f); null when there is no path to mark */
  path_resolutions: string[] | null;
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
        path_resolutions: null,
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
      path_resolutions: path ? path.resolutions : null,
    };
  });
}

export interface GraphShape {
  node_count: number;
  edge_count: number;
  /** edges matched by NAME rather than lexically resolved to a file the walk saw */
  inferred_edge_count: number;
  /** declared routes, which seed the gates' walks alongside the entry points */
  route_count: number;
}

/**
 * The graph's own shape (I3f) — what a reachability claim was computed over.
 * Two graphs with the same entry points can still disagree, and the honest
 * way to say "this walk saw 412 edges, 37 of them name-inferred" is to count
 * them at claim time and sign the count with the claim.
 */
export function graphShape(db: DatabaseSync): GraphShape {
  const one = (sql: string): number =>
    Number((db.prepare(sql).get() as { n: number } | undefined)?.n ?? 0);
  return {
    node_count: one("SELECT COUNT(*) AS n FROM nodes"),
    edge_count: one("SELECT COUNT(*) AS n FROM edges"),
    inferred_edge_count: one("SELECT COUNT(*) AS n FROM edges WHERE resolution = 'inferred'"),
    route_count: one("SELECT COUNT(*) AS n FROM routes"),
  };
}
