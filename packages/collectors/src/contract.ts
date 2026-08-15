import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { Collector, CollectOutput, ObservationRows } from "@rampscan/core";
import { globToRegExp } from "@rampscan/core";
import type { BoundaryRule, ClaimBasis, ContractRule, Finding, RouteAuthRule } from "@rampscan/schema";
import { ContractConfig, canonicalJson } from "@rampscan/schema";
import type { DatabaseSync } from "node:sqlite";
import {
  GRAPH_CONFIG_FILE,
  GRAPH_DB_ARTIFACT,
  GRAPH_VERSION,
  fileId,
  graphShape,
  labelPath,
  openGraphDb,
  readGraphMeta,
  routeAuthCoverage,
} from "@rampscan/graph";
import { fileSha256, makeFinding } from "./support.js";

// contract — the L1 gate: the scanned repo DECLARES architecture intent in
// rampscan.config.json's `contract` block, and this collector checks the
// declaration against graph.db and signs the result. Pure: it consumes the
// graph and spawns nothing; the rules it evaluated ride each recipe's basis as
// canonical JSON, keyed into evidence identity, so editing a rule re-keys its
// recipe's evidence and kills the stale claim.
//
// Two walks, two approximation directions, matching the recipes they answer:
//
//   route-auth  UNDER — "this route reaches an auth check" is a positive
//               claim, so it may only rest on a real calls/handles chain
//               (routeAuthCoverage's own walk, reused, filtered to the rule's
//               route glob).
//   boundary    OVER  — an import edge counts however it was resolved; the
//               boundary is only called held when even the loose reading finds
//               no importer outside the allow-list.
//
// The honesty edges, decided in L0 rather than discovered later:
//   - no config file / no contract block / zero rules → a stated SKIP, so
//     K1's empty states quote the reason instead of shrugging;
//   - an invalid contract (unknown kind, misspelled field, duplicate id) is a
//     thrown CONFIG ERROR, never a silent waiver — the run records the crash
//     and both contract rows read unevidenced with the refusal as the reason;
//   - a declared rule that matches NOTHING in the graph emits a
//     `matched: false` row and VIOLATES, because a typo'd glob or module path
//     must fail the rule it mistyped rather than pass it.

export const CONTRACT_GATE_VERSION = "0.1.0";

export const ROUTE_AUTH_RECIPE = "arch-route-auth-declared";
export const BOUNDARY_RECIPE = "arch-boundaries-hold";

export const ROUTE_AUTH_UNDER_STATEMENT =
  "a route matched by a declared rule counts as authenticated only when a real call chain runs from the route to an auth-named symbol " +
  "over calls/handles edges alone — the UNDER-approximate walk, because 'this route reaches auth' is a positive claim. A matched route whose " +
  "chain cannot be walked reads as UNAUTHENTICATED, and a declared rule that matches no route at all fails rather than passes.";

export const BOUNDARY_OVER_STATEMENT =
  "the boundary is called held only when even the OVER-approximate reading — every import edge into the guarded module, name-inferred edges " +
  "included — finds no importer outside the allow-list. Unknowns count against the repo: an inferred import still violates, and a declared " +
  "module that matches no file in the graph fails rather than passes.";

/** is `rel` inside the module prefix? "src/billing" covers src/billing, src/billing/* and src/billing.js */
export function inModulePrefix(rel: string, prefix: string): boolean {
  const p = prefix.replace(/\/+$/, "");
  if (rel === p || rel.startsWith(`${p}/`)) return true;
  const dot = rel.lastIndexOf(".");
  return dot > 0 && rel.slice(0, dot) === p;
}

interface ParsedContract {
  routeAuth: RouteAuthRule[];
  boundary: BoundaryRule[];
}

/**
 * The contract block, parsed strictly. `undefined` when the file or the block
 * is honestly absent — the callers' skip case. A PRESENT block that fails the
 * schema throws: an unknown rule kind or a misspelled field is a config error,
 * and a config error must not read as "nothing to check".
 */
async function loadContract(root: string): Promise<ParsedContract | undefined> {
  let raw: string;
  try {
    raw = await readFile(join(root, GRAPH_CONFIG_FILE), "utf8");
  } catch {
    return undefined;
  }
  const parsed = JSON.parse(raw) as Record<string, unknown>;
  if (parsed["contract"] === undefined) return undefined;
  let contract;
  try {
    contract = ContractConfig.parse(parsed["contract"]);
  } catch (cause) {
    const issue =
      cause instanceof Error && "issues" in cause
        ? (cause as { issues: Array<{ path: Array<string | number>; message: string }> }).issues
            .map((i) => `${["contract", ...i.path].join(".")}: ${i.message}`)
            .join("; ")
        : String(cause);
    throw new Error(
      `the contract block in ${GRAPH_CONFIG_FILE} failed validation (exit refused): ${issue} — a mistyped rule must not silently waive itself`,
      { cause },
    );
  }
  if (contract.rules.length === 0) return undefined;
  return {
    routeAuth: contract.rules.filter((r): r is RouteAuthRule => r.kind === "route-auth"),
    boundary: contract.rules.filter((r): r is BoundaryRule => r.kind === "boundary"),
  };
}

/** the rules a recipe's basis signs, normalized: canonical JSON, sorted by rule id */
function normalizedRules(rules: ContractRule[]): string[] {
  return [...rules].sort((a, b) => a.id.localeCompare(b.id)).map((r) => canonicalJson(r));
}

interface ImportEdgeRow {
  src: string;
  dst: string;
  /** "exact" | "inferred" — an inferred import still counts (the over-approximate read) */
  resolution: string;
}

/** every `imports` edge whose destination is a file inside the module and whose source file is outside it */
function importsIntoModule(db: DatabaseSync, moduleFiles: string[]): ImportEdgeRow[] {
  const inside = new Set(moduleFiles.map((rel) => fileId(rel)));
  const edges = db
    .prepare("SELECT src, dst, resolution FROM edges WHERE kind = 'imports'")
    .all() as Array<{ src: string; dst: string; resolution: string }>;
  return edges.filter(
    (e) => inside.has(e.dst) && e.src.startsWith("file:") && !inside.has(e.src),
  );
}

export const contract: Collector = {
  manifest: {
    name: "contract",
    toolVersion: "resolved-at-run",
    recipes: [ROUTE_AUTH_RECIPE, BOUNDARY_RECIPE],
    inputs: [GRAPH_DB_ARTIFACT],
    // pure join of graph.db × the declared rules — but the rules live in the
    // config file, whose bytes graph.db does not carry, so the file itself is
    // in scope: a contract edit must miss the cache even when the graph did not
    // change shape
    cacheScope: ["@inputs", GRAPH_CONFIG_FILE],
    tools: [],
  },

  async collect(ctx): Promise<CollectOutput> {
    const version = `${CONTRACT_GATE_VERSION}+graph${GRAPH_VERSION}`;
    const reproduce = "rampscan scan <repo> (contract gate: rampscan.config.json contract × graph.db)";

    const declared = await loadContract(ctx.workspace.root);
    if (!declared) {
      return {
        findings: [],
        artifacts: [],
        observations: {},
        toolVersion: version,
        exitCode: 0,
        skipped: {
          reason: `no architecture contract declared in ${GRAPH_CONFIG_FILE} — nothing of its kind to check`,
        },
      };
    }

    const graphPath = ctx.inputs.get(GRAPH_DB_ARTIFACT);
    if (!graphPath) {
      return {
        findings: [],
        artifacts: [],
        observations: {},
        toolVersion: version,
        exitCode: -1,
        skipped: {
          reason: `no ${GRAPH_DB_ARTIFACT} available — the graph collector must run (and succeed) first; a contract cannot be checked against a graph that was never built`,
        },
      };
    }

    const db = openGraphDb(graphPath);
    try {
      const meta = readGraphMeta(db);
      const shape = graphShape(db);
      const graphFacts = {
        commit: meta.commit,
        extractor_version: meta.extractorVersion,
        node_count: shape.node_count,
        edge_count: shape.edge_count,
        inferred_edge_count: shape.inferred_edge_count,
      };
      const basisShared = {
        entrypoints: meta.entrypoints,
        entrypoint_source: meta.entrypointSource,
        ...(meta.entrypointsUnresolved.length > 0
          ? { entrypoints_unresolved: meta.entrypointsUnresolved }
          : {}),
        route_roots: shape.route_count,
        graph: graphFacts,
      };

      const observations: Record<string, ObservationRows> = {};
      const anchors: Record<string, Array<{ path: string; contentHash: string }>> = {};
      const basis: Record<string, ClaimBasis> = {};
      const findings: Finding[] = [];
      const provenance = { analyzer: "contract", version, runId: ctx.runId };
      const configHash = await fileSha256(join(ctx.workspace.root, GRAPH_CONFIG_FILE));

      const anchorSet = async (paths: Iterable<string>) => {
        const out: Array<{ path: string; contentHash: string }> = [
          { path: GRAPH_CONFIG_FILE, contentHash: configHash },
        ];
        for (const rel of [...new Set(paths)].sort()) {
          try {
            out.push({ path: rel, contentHash: await fileSha256(join(ctx.workspace.root, rel)) });
          } catch {
            // a graph node whose file is not in the working tree — the row still stands
          }
        }
        return out;
      };

      // ── route-auth: declared intent over the under-approximate auth walk ──
      // No detected routes → no observation: the recipe stays honestly
      // unevidenced (graph.ts's no-routes refusal, inherited) — a declared
      // rule cannot be checked against routes the extractor never saw, and
      // vacuous evidence would be worse than an empty cell.
      if (declared.routeAuth.length > 0 && shape.route_count > 0) {
        const coverage = routeAuthCoverage(db, meta.authPatterns);
        const rows: ObservationRows = [];
        for (const rule of declared.routeAuth) {
          const re = globToRegExp(rule.routes);
          const matched = coverage.filter((row) => {
            const routePath = row.route.slice(row.route.indexOf(" ") + 1);
            return re.test(routePath);
          });
          if (matched.length === 0) {
            rows.push({
              rule_id: rule.id,
              rule_kind: "route-auth",
              matched: false,
              detail: `the declared pattern "${rule.routes}" matches no route the graph found — the rule is checking nothing`,
            });
            continue;
          }
          for (const row of matched) {
            rows.push({
              rule_id: rule.id,
              rule_kind: "route-auth",
              matched: true,
              route: row.route,
              file: row.file,
              line: row.line,
              auth_reached: row.auth_reached,
              auth_symbol: row.auth_symbol,
              call_path: row.path,
              ...(row.path_resolutions ? { call_path_resolutions: row.path_resolutions } : {}),
            });
            if (!row.auth_reached) {
              findings.push(
                makeFinding(
                  {
                    variable: "contract",
                    anchorNode: row.file,
                    anchorContentHash: await fileSha256(join(ctx.workspace.root, row.file)),
                    signature: `contract route-auth ${rule.id} ${row.route}`,
                    severity: "high",
                    summary: `${row.route} (${row.file}:${row.line}) breaks declared rule "${rule.id}": no authentication check in its call path`,
                    failureScenario:
                      "the repo's own contract says this route must reach an auth check, and it serves requests without one — the declaration and the code disagree, and the code is what runs",
                    evidence: [
                      {
                        kind: "counterexample",
                        path: row.file,
                        note: `${row.route} — declared by rule "${rule.id}" (${rule.routes}); the calls/handles walk from the route reached no symbol matching [${meta.authPatterns.join(", ")}]`,
                      },
                    ],
                    reproduce,
                    ksiIds: ["KSI-IAM-ELP"],
                    controlIds: ["ac-3", "cm-2.7"],
                  },
                  provenance,
                ),
              );
            }
          }
        }
        observations[ROUTE_AUTH_RECIPE] = rows;
        anchors[ROUTE_AUTH_RECIPE] = await anchorSet(
          rows.flatMap((r) => (typeof r["file"] === "string" ? [r["file"] as string] : [])),
        );
        basis[ROUTE_AUTH_RECIPE] = {
          approximation: "under",
          statement: ROUTE_AUTH_UNDER_STATEMENT,
          ...basisShared,
          contract_rules: normalizedRules(declared.routeAuth),
        };
      }

      // ── boundary: declared allow-lists over the over-approximate import read ──
      if (declared.boundary.length > 0) {
        const allFiles = (
          db.prepare("SELECT path FROM nodes WHERE kind = 'file'").all() as Array<{ path: string }>
        ).map((n) => n.path);
        const rows: ObservationRows = [];
        for (const rule of declared.boundary) {
          const moduleFiles = allFiles.filter((rel) => inModulePrefix(rel, rule.module));
          if (moduleFiles.length === 0) {
            rows.push({
              rule_id: rule.id,
              rule_kind: "boundary",
              matched: false,
              detail: `the declared module "${rule.module}" matches no file in the code graph — the rule is guarding nothing`,
            });
            continue;
          }
          const incoming = importsIntoModule(db, moduleFiles);
          if (incoming.length === 0) {
            rows.push({
              rule_id: rule.id,
              rule_kind: "boundary",
              matched: true,
              module: rule.module,
              detail: "no file outside the module imports it",
            });
            continue;
          }
          for (const edge of incoming) {
            const importer = edge.src.slice("file:".length);
            const imported = edge.dst.slice("file:".length);
            const allowed = rule.allowedImporters.some((p) => inModulePrefix(importer, p));
            rows.push({
              rule_id: rule.id,
              rule_kind: "boundary",
              matched: true,
              module: rule.module,
              file: importer,
              imported,
              allowed,
              call_path: labelPath(db, [edge.src, edge.dst]),
              call_path_resolutions: [edge.resolution],
            });
            if (!allowed) {
              findings.push(
                makeFinding(
                  {
                    variable: "contract",
                    anchorNode: importer,
                    anchorContentHash: await fileSha256(join(ctx.workspace.root, importer)),
                    signature: `contract boundary ${rule.id} ${importer} ${imported}`,
                    severity: "high",
                    summary: `${importer} imports ${imported}, breaking declared boundary "${rule.id}": only [${rule.allowedImporters.join(", ")}] may import ${rule.module}`,
                    failureScenario:
                      "a module the repo declared isolated is coupled to code outside its allow-list — every change inside the boundary can now break a caller the architecture says must not exist",
                    evidence: [
                      {
                        kind: "counterexample",
                        path: importer,
                        note: `imports ${imported} (${edge.resolution} edge); rule "${rule.id}" allows [${rule.allowedImporters.join(", ")}]`,
                      },
                    ],
                    reproduce,
                    ksiIds: ["KSI-CNA-DFP", "KSI-SVC-ACM"],
                    controlIds: ["cm-2", "cm-6"],
                  },
                  provenance,
                ),
              );
            }
          }
        }
        observations[BOUNDARY_RECIPE] = rows;
        anchors[BOUNDARY_RECIPE] = await anchorSet(
          rows.flatMap((r) => {
            const paths: string[] = [];
            if (typeof r["file"] === "string") paths.push(r["file"] as string);
            if (typeof r["imported"] === "string") paths.push(r["imported"] as string);
            return paths;
          }),
        );
        basis[BOUNDARY_RECIPE] = {
          approximation: "over",
          statement: BOUNDARY_OVER_STATEMENT,
          ...basisShared,
          contract_rules: normalizedRules(declared.boundary),
        };
      }

      return {
        findings,
        artifacts: [],
        observations,
        anchors,
        ...(Object.keys(basis).length > 0 ? { basis } : {}),
        toolVersion: version,
        exitCode: 0,
        reproduce,
      };
    } finally {
      db.close();
    }
  },
};
