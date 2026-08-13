import type { Collector } from "@rampscan/core";
import { gitleaks } from "./gitleaks.js";
import { grype } from "./grype.js";
import { osvScanner } from "./osv-scanner.js";
import { repoFacts } from "./repo-facts.js";
import { syft } from "./syft.js";

export * from "./support.js";
export * from "./tools.js";
export { repoFacts, REPO_FACTS_VERSION } from "./repo-facts.js";
export { gitleaks } from "./gitleaks.js";
export { syft, SBOM_ARTIFACT } from "./syft.js";
export { osvScanner, normalizeSeverity } from "./osv-scanner.js";
export { grype, finalBaseImage } from "./grype.js";

/**
 * The M1 collector set, in execution order — cheapest first, producers before
 * consumers (osv-scanner reads syft's SBOM from the run's input map).
 */
export const allCollectors: Collector[] = [repoFacts, gitleaks, syft, osvScanner, grype];
