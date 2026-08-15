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
      // the producer, signed with the claim (J5): the chain's second hop must
      // not depend on what the catalog says today
      collector: result.collector,
      ksi_ids: result.ksi_ids,
      control_ids: result.control_ids,
      verdict: result.verdict,
      repo: ctx.repo,
      commit: ctx.commit,
      anchor_paths: result.anchor_paths,
      dataset_version: ctx.datasetVersion,
      tool_versions: { [result.collector]: ctx.toolVersion },
      assertions: result.assertions,
      ...(result.reproduce !== undefined ? { reproduce: result.reproduce } : {}),
      ...(result.basis !== undefined ? { basis: result.basis } : {}),
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
 * tool version, dataset version, the producing collector and the claim's basis
 * (J5/I3f — see below). Deliberately NOT keyed on artifact hashes:
 * collector artifacts aggregate every recipe the collector observes (e.g.
 * repo-facts.json), so hashing them into identity would kill every recipe's
 * evidence whenever any one file changes — recreating exactly the coupling
 * anchor-death exists to measure. Also deliberately NOT keyed on the I2c
 * additions (assertion `offenders`/`offender_count`, predicate `reproduce`):
 * they restate what detail already witnesses, so comparing them would re-key
 * every pre-I2c bundle for zero informational change — existing evidence
 * survives and gains pointers only when real drift re-keys it.
 *
 * `collector` and `basis` (J5) go the OTHER way, and the difference is not
 * taste. Both are claims about what the evidence rests on, not restatements
 * of what it says, and there is a hole that proves it: `sast-reachability`
 * anchors the flagged files and `rampscan.config.json` — not `package.json`.
 * With the basis outside identity, editing `package.json` so that entry-point
 * inference lands on a different set leaves every "not affected" bundle alive,
 * still claiming unreachability from a set that no longer exists. Keyed on the
 * basis, that scan re-keys and the old claim dies, which is what it is for.
 * The same argument holds for the producer: a recipe re-pointed at a different
 * collector with an identical verdict is different evidence, and a chain that
 * names the old producer is worse than one that names none.
 *
 * A bundle predating J5 carries neither field and therefore does NOT match one
 * minted after it — deliberately, with no back-compat exemption: every live
 * bundle supersedes once on the first scan after this change, honestly
 * recorded, because an exemption saying "absent means whatever is there now"
 * is precisely how an identity rule stops being one.
 */
export function sameEvidence(a: EvidenceBundle, b: EvidenceBundle): boolean {
  const p = a.predicate;
  const q = b.predicate;
  return (
    p.recipe_id === q.recipe_id &&
    p.repo === q.repo &&
    p.verdict === q.verdict &&
    p.collector === q.collector &&
    p.dataset_version === q.dataset_version &&
    JSON.stringify(p.basis) === JSON.stringify(q.basis) &&
    JSON.stringify(p.tool_versions) === JSON.stringify(q.tool_versions) &&
    JSON.stringify(p.anchor_paths) === JSON.stringify(q.anchor_paths) &&
    p.assertions.length === q.assertions.length &&
    p.assertions.every((ar, i) => {
      const br = q.assertions[i]!;
      return ar.description === br.description && ar.passed === br.passed && ar.detail === br.detail;
    })
  );
}
