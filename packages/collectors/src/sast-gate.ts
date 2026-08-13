import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { Collector, CollectOutput, ObservationRows } from "@rampscan/core";
import type { Finding } from "@rampscan/schema";
import {
  GRAPH_CONFIG_FILE,
  GRAPH_DB_ARTIFACT,
  GRAPH_VERSION,
  entryRoots,
  fileId,
  labelPath,
  openGraphDb,
  reachableSet,
  readGraphMeta,
  shortestPath,
} from "@rampscan/graph";
import { SEMGREP_RESULTS_ARTIFACT, SemgrepResults } from "./semgrep.js";
import { fileSha256, makeFinding, sha256 } from "./support.js";

// sast-reachability — M4's flagship move generalized from advisories to code
// findings: semgrep-results.json × graph.db → gated SAST rows. A hit in a
// file reachable from an entry point → violated, with the call path as the
// artifact; a hit in a file even the loose walk cannot reach → not_affected,
// with the non-path as the reason. Same approximation direction as the
// advisory gate (over-approximate: every edge kind counts), because
// not_affected is a claim and claims lean conservative. No graph, no entry
// points, or a file the graph never saw → the honest posture: the hit
// counts, marked "unknown", never silently waved through.

export const SAST_GATE_VERSION = "0.1.0";

export const sastGate: Collector = {
  manifest: {
    name: "sast-reachability",
    toolVersion: "resolved-at-run",
    recipes: ["no-reachable-dangerous-code"],
    inputs: [SEMGREP_RESULTS_ARTIFACT, GRAPH_DB_ARTIFACT],
    cacheScope: ["@inputs"], // pure join of semgrep-results × graph.db
  },

  async collect(ctx): Promise<CollectOutput> {
    const version = `${SAST_GATE_VERSION}+graph${GRAPH_VERSION}`;

    const semgrepPath = ctx.inputs.get(SEMGREP_RESULTS_ARTIFACT);
    if (!semgrepPath) {
      return {
        findings: [],
        artifacts: [],
        observations: {},
        toolVersion: version,
        exitCode: -1,
        skipped: {
          reason: `no ${SEMGREP_RESULTS_ARTIFACT} available — semgrep must run (and succeed) first`,
        },
      };
    }
    const report = SemgrepResults.parse(JSON.parse(await readFile(semgrepPath, "utf8")));

    const graphPath = ctx.inputs.get(GRAPH_DB_ARTIFACT);
    const db = graphPath ? openGraphDb(graphPath) : undefined;
    try {
      let roots: string[] = [];
      let reach: Set<string> | undefined;
      let hasNode: ((rel: string) => boolean) | undefined;
      let gateNote: string | undefined;
      if (!db) {
        gateNote =
          "graph.db unavailable (graph collector skipped) — every SAST hit counts, none can be proven unreachable";
      } else {
        const meta = readGraphMeta(db);
        if (meta.entrypoints.length === 0) {
          gateNote = `graph built but no entry points detected — set graph.entrypoints in ${GRAPH_CONFIG_FILE}; every SAST hit counts until then`;
        } else {
          roots = entryRoots(db);
          reach = reachableSet(db, roots);
          const nodeStmt = db.prepare("SELECT 1 AS hit FROM nodes WHERE id = ?");
          hasNode = (rel: string) => nodeStmt.get(fileId(rel)) !== undefined;
        }
      }

      const rows: ObservationRows = [];
      const provenance = { analyzer: "sast-reachability", version, runId: ctx.runId };
      const findings: Finding[] = [];

      for (const hit of report.results) {
        // gate by the file the hit lives in — over-approximate walk, every edge kind
        let reachable: "true" | "false" | "unknown";
        let rowNote = gateNote;
        if (reach === undefined || hasNode === undefined) {
          reachable = "unknown";
        } else if (!hasNode(hit.path)) {
          reachable = "unknown";
          rowNote = `${hit.path} has no node in the code graph — the graph cannot prove it unreachable, so the hit counts`;
        } else if (reach.has(fileId(hit.path))) {
          reachable = "true";
        } else {
          reachable = "false";
        }
        const notAffected = reachable === "false";

        let path: string | null = null;
        let inferred = false;
        if (reachable === "true" && db) {
          const p = shortestPath(db, roots, new Set([fileId(hit.path)]));
          if (p) {
            path = labelPath(db, p.ids);
            inferred = p.inferred;
          }
        }

        rows.push({
          check_id: hit.check_id,
          path: hit.path,
          line: hit.start_line,
          severity: hit.severity,
          message: hit.message,
          reachable,
          not_affected: notAffected,
          call_path: path,
          ...(inferred ? { path_resolution: "inferred" } : {}),
          ...(rowNote !== undefined ? { gate_note: rowNote } : {}),
        });

        if (hit.severity === "ERROR" && !notAffected) {
          findings.push(
            makeFinding(
              {
                variable: "sast",
                anchorNode: hit.path,
                anchorContentHash: await fileSha256(join(ctx.workspace.root, hit.path)).catch(() =>
                  sha256(`${hit.path}:${hit.start_line}`),
                ),
                signature: `${hit.check_id} ${hit.path} ${hit.start_line}`,
                severity: "high",
                summary:
                  `${hit.check_id}: ${hit.message} — ${hit.path}:${hit.start_line}` +
                  (path ? ` (reachable: ${path})` : " (reachability unknown)"),
                failureScenario: path
                  ? "the dangerous construct sits in the execute path from an entry point; any input that reaches it is an injection primitive"
                  : "reachability could not be proven either way, so the hit counts — honesty over magic",
                evidence: [
                  path
                    ? { kind: "trace", path: hit.path, note: `call path: ${path}` }
                    : {
                        kind: "counterexample",
                        path: hit.path,
                        note: `${hit.check_id} at ${hit.path}:${hit.start_line} (reachability ${reachable})`,
                      },
                ],
                reproduce: "rampscan scan <repo> (sast-reachability: semgrep-results.json × graph.db)",
                ksiIds: ["KSI-SCR-MIT", "KSI-PIY-RSD"],
                controlIds: ["sa-11", "si-10"],
              },
              provenance,
            ),
          );
        }
      }

      // anchored to what decides the answer: the flagged files (the hits) and
      // the graph config (what counts as an entry point). A clean run anchors
      // only the config — the claim "nothing dangerous anywhere" is about the
      // whole commit, and the recipe's cadence re-checks it.
      const anchorPaths: Array<{ path: string; contentHash: string }> = [];
      for (const rel of [...new Set(report.results.map((r) => r.path))].sort()) {
        try {
          anchorPaths.push({ path: rel, contentHash: await fileSha256(join(ctx.workspace.root, rel)) });
        } catch {
          // flagged at a path that is not in the working tree — the row still stands
        }
      }
      try {
        anchorPaths.push({
          path: GRAPH_CONFIG_FILE,
          contentHash: await fileSha256(join(ctx.workspace.root, GRAPH_CONFIG_FILE)),
        });
      } catch {
        // no graph config — fine
      }

      return {
        findings,
        artifacts: [],
        // rows may be EMPTY: semgrep ran and found nothing — that is an
        // observation (count_eq 0 passes → evidenced), not an absence
        observations: { "no-reachable-dangerous-code": rows },
        anchors: { "no-reachable-dangerous-code": anchorPaths },
        toolVersion: version,
        exitCode: 0,
      };
    } finally {
      db?.close();
    }
  },
};
