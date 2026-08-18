import { readFile } from "node:fs/promises";
import type { Collector } from "@rampscan/core";
import { checkov } from "./checkov.js";
import { contract } from "./contract.js";
import { documents } from "./documents.js";
import { gitleaks } from "./gitleaks.js";
import { graphCollector } from "./graph.js";
import { grype } from "./grype.js";
import { osvScanner } from "./osv-scanner.js";
import { reachability } from "./reachability.js";
import { repoFacts } from "./repo-facts.js";
import { sastGate } from "./sast-gate.js";
import { SEMGREP_RULES_PATH, semgrep } from "./semgrep.js";
import { spectral } from "./spectral.js";
import { sha256 } from "./support.js";
import { syft } from "./syft.js";
import { loadToolManifest } from "./tools.js";

export * from "./support.js";
export * from "./tools.js";
export * from "./journal.js";
export { repoFacts, REPO_FACTS_VERSION } from "./repo-facts.js";
export { gitleaks } from "./gitleaks.js";
export { syft, SBOM_ARTIFACT } from "./syft.js";
export { osvScanner } from "./osv-scanner.js";
export { OSV_RESULTS_ARTIFACT, advisoryRows, normalizeSeverity } from "./osv-report.js";
export { grype, finalBaseImage } from "./grype.js";
export { graphCollector } from "./graph.js";
export { reachability, OPENVEX_ARTIFACT, REACHABILITY_VERSION, purlOf } from "./reachability.js";
export { semgrep, SEMGREP_RESULTS_ARTIFACT, SEMGREP_RULES_PATH, SemgrepResults, relativizeResultPath } from "./semgrep.js";
export { sastGate, SAST_GATE_VERSION } from "./sast-gate.js";
export {
  contract,
  CONTRACT_GATE_VERSION,
  ROUTE_AUTH_RECIPE,
  BOUNDARY_RECIPE,
  inModulePrefix,
} from "./contract.js";
export {
  documents,
  DOCUMENTS_VERSION,
  POLICY_RECIPE,
  SYSTEM_DOCS_RECIPE,
  loadDocuments,
} from "./documents.js";
export { checkov, CHECKOV_RESULTS_ARTIFACT, matchIacFiles } from "./checkov.js";
export { spectral, SPECTRAL_RESULTS_ARTIFACT, matchSpecFiles } from "./spectral.js";

/**
 * Everything pinned that the per-collector cacheScope cannot see: the tool
 * manifest (re-pinning an image must invalidate) and the vendored semgrep
 * ruleset (editing a rule must invalidate semgrep runs the same way).
 * scan() folds this into every cache key — ground rule 5's second half.
 */
export async function cacheKeySalt(): Promise<string> {
  const manifest = JSON.stringify(await loadToolManifest());
  const rules = await readFile(SEMGREP_RULES_PATH, "utf8");
  return sha256(manifest + "\n" + rules);
}

/**
 * The collector set, in execution order — cheapest first, producers before
 * consumers: syft's SBOM feeds osv-scanner, osv-results.json × graph.db feed
 * the advisory gate, and semgrep-results.json × graph.db feed the SAST gate.
 * checkov and spectral are config-plane — independent of the graph by design.
 */
export const allCollectors: Collector[] = [
  repoFacts,
  documents,
  gitleaks,
  graphCollector,
  contract,
  semgrep,
  syft,
  osvScanner,
  reachability,
  sastGate,
  checkov,
  spectral,
  grype,
];
