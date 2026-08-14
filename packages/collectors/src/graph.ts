import { join } from "node:path";
import type { Collector, CollectOutput } from "@rampscan/core";
import type { Finding } from "@rampscan/schema";
import {
  DEFAULT_AUTH_PATTERNS,
  GRAPH_DB_ARTIFACT,
  detectEntrypoints,
  extractGraph,
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
    const files = await listSourceFiles(ctx.workspace.root);
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
    const graph = await extractGraph(ctx.workspace.root, files);
    const entry = await detectEntrypoints(ctx.workspace.root, new Set(files), config.entrypoints);
    const authPatterns = config.authPatterns ?? DEFAULT_AUTH_PATTERNS;

    const dbPath = join(ctx.artifactDir, GRAPH_DB_ARTIFACT);
    writeGraphDb(dbPath, graph, {
      extractorVersion: version,
      commit: ctx.workspace.commit,
      entrypoints: entry.files,
      entrypointSource: entry.source,
      authPatterns,
    });

    const db = openGraphDb(dbPath);
    let rows;
    try {
      rows = routeAuthCoverage(db, authPatterns);
    } finally {
      db.close();
    }

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
      toolVersion: version,
      exitCode: 0,
      reproduce: "rampscan scan <repo> (graph collector: routeAuthCoverage over graph.db)",
    };
  },
};
