import { z } from "zod";

// Collector manifest — SPEC §7 (Tool Interfaces): a collector is a program
// plus a manifest declaring inputs, dirty-set depth, the recipe IDs it can
// evidence, and its tool version. Adding a collector is adding a manifest,
// not touching the pipeline. The full format firms up in M1 (C1); the ports
// in @rampscan/core need the type now.

export const CollectorManifest = z.object({
  name: z.string(), // "repo-facts" | "gitleaks" | "syft" | ...
  toolVersion: z.string(), // participates in cache keys and bundle provenance
  recipes: z.array(z.string()), // recipe IDs this collector can evidence
  inputs: z.array(z.string()).optional(), // artifacts consumed from earlier collectors
  outputs: z.array(z.string()).optional(), // artifacts produced (e.g. "sbom.cdx.json")
  dirtySetDepth: z.number().int().min(0).optional(), // blast-radius depth for incremental scans
  /**
   * What this collector's output depends on — the incremental-scan dirty set
   * (M5). Repo-path globs (`*`, `**`, `?`) matched against the committed tree,
   * or one of three markers:
   *   "@commit" — the full git history (any new commit re-runs it: gitleaks)
   *   "@tree"   — the committed tree hash (any content change re-runs: syft)
   *   "@inputs" — the artifacts this collector consumes from earlier
   *               collectors in the run (osv-scanner, reachability)
   * Absent → the collector is never cached and always runs.
   */
  cacheScope: z.array(z.string()).optional(),
});
export type CollectorManifest = z.infer<typeof CollectorManifest>;
