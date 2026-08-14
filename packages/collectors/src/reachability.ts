import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { Collector, CollectOutput, ObservationRows } from "@rampscan/core";
import type { Finding } from "@rampscan/schema";
import {
  GRAPH_CONFIG_FILE,
  GRAPH_DB_ARTIFACT,
  GRAPH_VERSION,
  dependencyReachability,
  openGraphDb,
  readGraphMeta,
} from "@rampscan/graph";
import type { DepReachability } from "@rampscan/graph";
import { OSV_RESULTS_ARTIFACT, OsvResults, advisoryRows } from "./osv-report.js";
import { fileSha256, makeFinding, sha256 } from "./support.js";

// reachability — the M4 flagship join (plan §M4, SPEC §3 "Reachability/VEX"):
// osv-results.json × graph.db → gated advisory rows. Reachable → violated
// with the call path as the artifact; provably unreachable → not_affected,
// emitted as OpenVEX with the justification. The gate only ever CLAIMS
// not_affected when the graph proves the package is beyond every entry
// point; no graph, or no detectable entry points, degrades to the honest M1
// posture — every advisory counts, marked "unknown", never silently waved
// through.

export const REACHABILITY_VERSION = "0.1.0";
export const OPENVEX_ARTIFACT = "openvex.json";

interface OpenVexStatement {
  vulnerability: { name: string; aliases?: string[] };
  products: Array<{ "@id": string }>;
  status: "affected" | "not_affected" | "under_investigation";
  justification?: string;
  impact_statement?: string;
  action_statement?: string;
}

/** package URL for an OSV row — npm names with scopes get percent-encoded */
export function purlOf(ecosystem: string, name: string, version: string): string {
  const eco = ecosystem.toLowerCase().split(":")[0] || "generic";
  return `pkg:${eco}/${name.replace("@", "%40")}@${version}`;
}

export const reachability: Collector = {
  manifest: {
    name: "reachability",
    toolVersion: "resolved-at-run",
    recipes: ["no-critical-reachable-advisories"],
    inputs: [OSV_RESULTS_ARTIFACT, GRAPH_DB_ARTIFACT],
    outputs: [OPENVEX_ARTIFACT],
    cacheScope: ["@inputs"], // pure join of osv-results × graph.db
  },

  async collect(ctx): Promise<CollectOutput> {
    const version = `${REACHABILITY_VERSION}+graph${GRAPH_VERSION}`;

    const osvPath = ctx.inputs.get(OSV_RESULTS_ARTIFACT);
    if (!osvPath) {
      return {
        findings: [],
        artifacts: [],
        observations: {},
        toolVersion: version,
        exitCode: -1,
        skipped: {
          reason: `no ${OSV_RESULTS_ARTIFACT} available — osv-scanner must run (and succeed) first`,
        },
      };
    }
    const report = OsvResults.parse(JSON.parse(await readFile(osvPath, "utf8")));
    const advisories = advisoryRows(report);

    // the gate: package-level reachability from the snapshot graph
    const graphPath = ctx.inputs.get(GRAPH_DB_ARTIFACT);
    let deps: Map<string, DepReachability> | undefined;
    let gateNote: string | undefined;
    let entrypoints: string[] = [];
    if (graphPath) {
      const db = openGraphDb(graphPath);
      try {
        const meta = readGraphMeta(db);
        entrypoints = meta.entrypoints;
        if (meta.entrypoints.length === 0) {
          gateNote = `graph built but no entry points detected — set graph.entrypoints in ${GRAPH_CONFIG_FILE}; every advisory counts until then`;
        } else {
          deps = dependencyReachability(db);
        }
      } finally {
        db.close();
      }
    } else {
      gateNote = "graph.db unavailable (graph collector skipped) — every advisory counts, none can be proven unreachable";
    }

    const rows: ObservationRows = [];
    const statements: OpenVexStatement[] = [];
    const provenance = { analyzer: "reachability", version, runId: ctx.runId };
    const findings: Finding[] = [];

    for (const adv of advisories) {
      const dep = deps?.get(adv.package);
      const gated = deps !== undefined;
      // proven unreachable = the package has no node in the graph (declared
      // but never imported) or no walk from any entry point reaches it
      const notAffected = gated && (dep === undefined || !dep.reachable);
      const reachable = !gated ? "unknown" : notAffected ? "false" : "true";
      const path = dep?.reachable ? (dep.path ?? null) : null;

      rows.push({
        advisory: adv.advisory,
        severity: adv.severity,
        package: adv.package,
        version: adv.version,
        ecosystem: adv.ecosystem,
        reachable,
        not_affected: notAffected,
        path,
        ...(dep?.inferred ? { path_resolution: "inferred" } : {}),
        ...(gateNote !== undefined ? { gate_note: gateNote } : {}),
        aliases: adv.aliases,
      });

      const product = purlOf(adv.ecosystem, adv.package, adv.version);
      const vulnerability: OpenVexStatement["vulnerability"] = { name: adv.advisory };
      if (adv.aliases.length > 1) vulnerability.aliases = adv.aliases.filter((a) => a !== adv.advisory);
      if (notAffected) {
        statements.push({
          vulnerability,
          products: [{ "@id": product }],
          status: "not_affected",
          justification: "vulnerable_code_not_in_execute_path",
          impact_statement:
            `${adv.package}@${adv.version} is not reachable from any entry point ` +
            `(${entrypoints.join(", ")}) or declared route in the code graph at commit ${ctx.workspace.commit}`,
        });
      } else if (reachable === "true") {
        statements.push({
          vulnerability,
          products: [{ "@id": product }],
          status: "affected",
          action_statement:
            `upgrade ${adv.package} beyond ${adv.version}; the vulnerable package is in the execute path` +
            (path ? ` (${path})` : ""),
        });
      } else {
        statements.push({
          vulnerability,
          products: [{ "@id": product }],
          status: "under_investigation",
          ...(gateNote !== undefined ? { impact_statement: gateNote } : {}),
        });
      }

      if ((adv.severity === "CRITICAL" || adv.severity === "HIGH") && !notAffected) {
        findings.push(
          makeFinding(
            {
              variable: "advisories",
              anchorNode: "package.json",
              anchorContentHash: sha256(`${adv.package}@${adv.version}`),
              signature: `${adv.advisory} ${adv.package}@${adv.version}`,
              severity: adv.severity === "CRITICAL" ? "blocker" : "high",
              summary:
                `${adv.advisory}: ${adv.severity} advisory against ${adv.package}@${adv.version}` +
                (adv.summary ? ` — ${adv.summary}` : "") +
                (path ? ` (reachable: ${path})` : reachable === "unknown" ? " (reachability unknown)" : ""),
              failureScenario: path
                ? "the vulnerable package is in the execute path from an entry point; an exploit for a published advisory is the cheapest attack there is"
                : "reachability could not be proven either way, so the advisory counts — honesty over magic",
              evidence: [
                path
                  ? { kind: "trace", note: `call path: ${path}` }
                  : {
                      kind: "counterexample",
                      note: `${adv.aliases.join(", ")} — ${adv.ecosystem}:${adv.package}@${adv.version} (reachability ${reachable})`,
                    },
              ],
              reproduce: "rampscan scan <repo> (reachability: osv-results.json × graph.db)",
              ksiIds: ["KSI-SCR-MON", "KSI-CMT-VTD"],
              controlIds: ["ra-5", "si-2"],
            },
            provenance,
          ),
        );
      }
    }

    const artifacts: Array<{ name: string; path: string }> = [];
    if (statements.length > 0) {
      const vexPath = join(ctx.artifactDir, OPENVEX_ARTIFACT);
      const doc = {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": `https://rampscan.dev/vex/${ctx.runId}`,
        author: "rampscan",
        timestamp: new Date().toISOString(),
        version: 1,
        tooling: `rampscan reachability ${version}`,
        statements,
      };
      await writeFile(vexPath, JSON.stringify(doc, null, 2) + "\n");
      artifacts.push({ name: OPENVEX_ARTIFACT, path: vexPath });
    }

    // anchored to what decides the answer: the dependency manifests (what is
    // declared) and the graph config (what counts as an entry point). Import
    // sites are covered by the recipe's cadence, not by anchors — a re-scan
    // re-gates; see plan §M4 scope.
    const anchorPaths: Array<{ path: string; contentHash: string }> = [];
    for (const rel of ["package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock", GRAPH_CONFIG_FILE]) {
      try {
        anchorPaths.push({ path: rel, contentHash: await fileSha256(join(ctx.workspace.root, rel)) });
      } catch {
        // not present — fine
      }
    }

    return {
      findings,
      artifacts,
      observations: { "no-critical-reachable-advisories": rows },
      anchors: { "no-critical-reachable-advisories": anchorPaths },
      toolVersion: version,
      exitCode: 0,
      reproduce: "rampscan scan <repo> (reachability: osv-results.json × graph.db)",
    };
  },
};
