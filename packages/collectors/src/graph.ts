import { join } from "node:path";
import type { Collector, CollectOutput } from "@rampscan/core";
import type { ClaimBasis, Finding } from "@rampscan/schema";
import {
  DEFAULT_AUTH_PATTERNS,
  GRAPH_DB_ARTIFACT,
  detectEntrypoints,
  extractGraph,
  graphShape,
  graphToolVersion,
  listSourceFiles,
  loadGraphConfig,
  openGraphDb,
  routeAuthCoverage,
  writeGraphDb,
} from "@rampscan/graph";
import { fileSha256, makeFinding } from "./support.js";

// graph — the M4 collector: builds graph.db for the snapshot (TS/JS only in
// the prototype) and answers the first graph-native recipe, route-auth
// coverage, by recursive CTE. The graph.db artifact is also the input the
// `reachability` collector joins advisories against.

export const graphCollector: Collector = {
  manifest: {
    name: "graph",
    toolVersion: "resolved-at-run",
    recipes: ["route-auth-coverage"],
    outputs: [GRAPH_DB_ARTIFACT],
    cacheScope: [
      "**/*.ts",
      "**/*.tsx",
      "**/*.mts",
      "**/*.cts",
      "**/*.js",
      "**/*.jsx",
      "**/*.mjs",
      "**/*.cjs",
      "package.json",
      "**/package.json",
      "rampscan.config.json", // entrypoints/authPatterns overrides change the graph
    ],
  },

  async collect(ctx): Promise<CollectOutput> {
    const version = graphToolVersion();
    // the workspace states which tree it is (committed for every scan; the
    // worktree only under the `rampscan check` dry run, whose output cannot
    // become evidence)
    const tree = ctx.workspace.tree ?? "committed";
    const files = await listSourceFiles(ctx.workspace.root, tree);
    if (files.length === 0) {
      return {
        findings: [],
        artifacts: [],
        observations: {},
        toolVersion: version,
        exitCode: 0,
        skipped: {
          reason: "no TypeScript/JavaScript sources found — the prototype graph is TS/JS-only",
        },
      };
    }

    const config = await loadGraphConfig(ctx.workspace.root);
    const graph = await extractGraph(ctx.workspace.root, files, tree);
    const entry = await detectEntrypoints(ctx.workspace.root, new Set(files), config.entrypoints);
    const authPatterns = config.authPatterns ?? DEFAULT_AUTH_PATTERNS;

    const dbPath = join(ctx.artifactDir, GRAPH_DB_ARTIFACT);
    writeGraphDb(dbPath, graph, {
      extractorVersion: version,
      commit: ctx.workspace.commit,
      entrypoints: entry.files,
      entrypointSource: entry.source,
      entrypointsUnresolved: entry.unresolved,
      authPatterns,
    });

    const db = openGraphDb(dbPath);
    let rows;
    let shape;
    try {
      rows = routeAuthCoverage(db, authPatterns);
      shape = graphShape(db);
    } finally {
      db.close();
    }

    // This recipe's walk errs the OTHER way from the two gates (I3f): "this
    // route reaches an auth check" is a positive claim, so it may only rest on
    // an actual call chain — an over-approximate walk would let a coincidence
    // of names read as authentication.
    const basis: ClaimBasis = {
      approximation: "under",
      statement:
        "auth coverage is claimed only when a real call chain runs from the route to a symbol matching " +
        `[${authPatterns.join(", ")}] over calls/handles edges alone; a route whose chain cannot be walked reads as UNCOVERED, never as covered. ` +
        "Inferred hops are marked, because a chain that rests on a name match is weaker than one resolved to a file.",
      entrypoints: entry.files,
      entrypoint_source: entry.source,
      ...(entry.unresolved.length > 0 ? { entrypoints_unresolved: entry.unresolved } : {}),
      route_roots: shape.route_count,
      graph: {
        commit: ctx.workspace.commit,
        extractor_version: version,
        node_count: shape.node_count,
        edge_count: shape.edge_count,
        inferred_edge_count: shape.inferred_edge_count,
      },
    };

    const provenance = { analyzer: "graph", version, runId: ctx.runId };
    const findings: Finding[] = [];
    for (const row of rows) {
      if (row.auth_reached) continue;
      findings.push(
        makeFinding(
          {
            variable: "route-auth",
            anchorNode: row.file,
            anchorContentHash: await fileSha256(join(ctx.workspace.root, row.file)),
            signature: `route-auth ${row.route}`,
            severity: "high",
            summary: `${row.route} (${row.file}:${row.line}) reaches no authentication check in its call path`,
            failureScenario:
              "the route serves unauthenticated traffic; every handler and dependency in its call path is exposed to anonymous callers",
            evidence: [
              {
                kind: "counterexample",
                path: row.file,
                note: `${row.route} — call-graph walk from the route node found no symbol matching [${authPatterns.join(", ")}]`,
              },
            ],
            reproduce: "rampscan scan <repo> (graph collector: routeAuthCoverage over graph.db)",
            ksiIds: ["KSI-IAM-ELP"],
            controlIds: ["ac-3", "ac-14"],
          },
          provenance,
        ),
      );
    }

    // the evidence is about the files that declare the routes — drift there
    // must kill it (a new route or an edited handler changes the answer)
    const anchorPaths: Array<{ path: string; contentHash: string }> = [];
    for (const rel of [...new Set(rows.map((r) => r.file))].sort()) {
      anchorPaths.push({ path: rel, contentHash: await fileSha256(join(ctx.workspace.root, rel)) });
    }

    return {
      findings,
      artifacts: [{ name: GRAPH_DB_ARTIFACT, path: dbPath }],
      // no routes → no observation: the recipe stays honestly unevidenced
      // rather than vacuously evidenced on a repo with no server surface
      observations: rows.length > 0 ? { "route-auth-coverage": rows } : {},
      anchors: rows.length > 0 ? { "route-auth-coverage": anchorPaths } : {},
      ...(rows.length > 0 ? { basis: { "route-auth-coverage": basis } } : {}),
      toolVersion: version,
      exitCode: 0,
      reproduce: "rampscan scan <repo> (graph collector: routeAuthCoverage over graph.db)",
    };
  },
};
