import type { Collector } from "@rampscan/core";
import { gitleaks } from "./gitleaks.js";
import { graphCollector } from "./graph.js";
import { grype } from "./grype.js";
import { osvScanner } from "./osv-scanner.js";
import { reachability } from "./reachability.js";
import { repoFacts } from "./repo-facts.js";
import { syft } from "./syft.js";

export * from "./support.js";
export * from "./tools.js";
export { repoFacts, REPO_FACTS_VERSION } from "./repo-facts.js";
export { gitleaks } from "./gitleaks.js";
export { syft, SBOM_ARTIFACT } from "./syft.js";
export { osvScanner } from "./osv-scanner.js";
export { OSV_RESULTS_ARTIFACT, advisoryRows, normalizeSeverity } from "./osv-report.js";
export { grype, finalBaseImage } from "./grype.js";
export { graphCollector } from "./graph.js";
export { reachability, OPENVEX_ARTIFACT, REACHABILITY_VERSION, purlOf } from "./reachability.js";

/**
 * The M4 collector set, in execution order — cheapest first, producers before
 * consumers: syft's SBOM feeds osv-scanner, and osv-results.json × graph.db
 * feed the reachability gate.
 */
export const allCollectors: Collector[] = [
  repoFacts,
  gitleaks,
  graphCollector,
  syft,
  osvScanner,
  reachability,
  grype,
];
