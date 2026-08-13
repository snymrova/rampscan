import type {
  EvidenceBundle,
  PipelineRecipe,
  RecipeResult,
  Subject,
} from "@rampscan/schema";
import {
  IN_TOTO_STATEMENT_TYPE,
  RAMPSCAN_PREDICATE_TYPE,
} from "@rampscan/schema";

// RecipeResult → EvidenceBundle (plan M2): a scan-result row becomes an
// in-toto statement by re-keying, not by re-scanning (scanresult.ts's
// promise). Only evidenced/violated rows become bundles — unevidenced rows
// have no artifacts and no assertions; they live in scan-result.json and the
// board renders them from the recipe set, honestly absent from the ledger.

export interface BundleContext {
  repo: string;
  commit: string;
  datasetVersion: string;
  /** version of the one tool that produced this evidence — per-recipe, not the
   * whole run's map, so an unrelated tool upgrade doesn't re-key everything */
  toolVersion: string;
  runId: string;
  timestamp: string; // ISO 8601 — the run's single clock
}

/**
 * Subjects are the artifacts the statement is about: collector outputs plus
 * the anchoring repo files. Returns undefined when the row has neither
 * (nothing to attest to — callers must surface that, never silently drop).
 */
export function toEvidenceBundle(
  recipe: PipelineRecipe,
  result: RecipeResult,
  ctx: BundleContext,
): EvidenceBundle | undefined {
  if (result.verdict === "unevidenced") return undefined;

  const subjects: Subject[] = [
    ...result.artifacts.map((a) => ({ name: a.name, digest: { sha256: a.sha256 } })),
    ...result.anchor_paths.map((a) => ({ name: a.path, digest: { sha256: a.contentHash } })),
  ];
  const seen = new Set<string>();
  const subject = subjects.filter((s) => {
    const key = `${s.name}@${s.digest["sha256"]}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
  if (subject.length === 0) return undefined;

  return {
    _type: IN_TOTO_STATEMENT_TYPE,
    subject,
    predicateType: RAMPSCAN_PREDICATE_TYPE,
    predicate: {
      recipe_id: result.recipe_id,
      ksi_ids: result.ksi_ids,
      control_ids: result.control_ids,
      verdict: result.verdict,
      repo: ctx.repo,
      commit: ctx.commit,
      anchor_paths: result.anchor_paths,
      dataset_version: ctx.datasetVersion,
      tool_versions: { [result.collector]: ctx.toolVersion },
      assertions: result.assertions,
      cadence: recipe.cadence,
      run_id: ctx.runId,
      timestamp: ctx.timestamp,
    },
  };
}

/**
 * Evidence identity — decides whether a fresh scan re-keys a bundle or the
 * existing one survives with its original signature.
 *
 * Keyed on: verdict, anchor paths + content hashes, assertion outcomes,
 * tool version, dataset version. Deliberately NOT keyed on artifact hashes:
 * collector artifacts aggregate every recipe the collector observes (e.g.
 * repo-facts.json), so hashing them into identity would kill every recipe's
 * evidence whenever any one file changes — recreating exactly the coupling
 * anchor-death exists to measure.
 */
export function sameEvidence(a: EvidenceBundle, b: EvidenceBundle): boolean {
  const p = a.predicate;
  const q = b.predicate;
  return (
    p.recipe_id === q.recipe_id &&
    p.repo === q.repo &&
    p.verdict === q.verdict &&
    p.dataset_version === q.dataset_version &&
    JSON.stringify(p.tool_versions) === JSON.stringify(q.tool_versions) &&
    JSON.stringify(p.anchor_paths) === JSON.stringify(q.anchor_paths) &&
    p.assertions.length === q.assertions.length &&
    p.assertions.every((ar, i) => {
      const br = q.assertions[i]!;
      return ar.description === br.description && ar.passed === br.passed && ar.detail === br.detail;
    })
  );
}
