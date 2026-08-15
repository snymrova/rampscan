import { z } from "zod";
import { AssertionResult, AnchorPath, ClaimBasis, Verdict } from "./bundle.js";
import { Finding } from "./finding.js";

// scan-result.json — the M1 output of `rampscan scan` (plan C5). Each recipe
// row carries everything the M2 EvidencePredicate needs (verdict, assertions,
// anchor paths, artifacts, commit), so a row becomes a bundle by re-keying,
// not by re-scanning.

export const ArtifactRef = z.object({
  name: z.string(), // e.g. "sbom.cdx.json"
  path: z.string(), // relative to the scan's artifact dir
  sha256: z.string(),
});
export type ArtifactRef = z.infer<typeof ArtifactRef>;

export const RecipeResult = z.object({
  recipe_id: z.string(),
  ksi_ids: z.array(z.string()),
  control_ids: z.array(z.string()),
  collector: z.string(),
  verdict: Verdict,
  /** why the verdict is what it is when no assertions ran (skips, missing tools) */
  reason: z.string().optional(),
  /** how to re-run the check (I2c) — the collector's own statement, when it made one */
  reproduce: z.string().optional(),
  /** the walk this verdict rests on (I3f), for the graph-gated recipes only */
  basis: ClaimBasis.optional(),
  assertions: z.array(AssertionResult),
  artifacts: z.array(ArtifactRef),
  anchor_paths: z.array(AnchorPath),
});
export type RecipeResult = z.infer<typeof RecipeResult>;

export const ScanResult = z.object({
  run_id: z.string(),
  repo: z.string(),
  commit: z.string(),
  dataset_version: z.string(),
  timestamp: z.string(), // ISO 8601
  tool_versions: z.record(z.string(), z.string()), // { "repo-facts": "...", syft: "...", ... }
  /** collectors that did not produce observations, with the honest reason */
  skipped_collectors: z.array(
    z.object({ collector: z.string(), reason: z.string() }),
  ),
  recipes: z.array(RecipeResult),
  findings: z.array(Finding),
  summary: z.object({
    evidenced: z.number().int(),
    violated: z.number().int(),
    unevidenced: z.number().int(),
  }),
});
export type ScanResult = z.infer<typeof ScanResult>;
