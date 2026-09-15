import { createHash } from "node:crypto";
import type { EvidenceBundle, IngestSubmission } from "@rampscan/schema";
import {
  IN_TOTO_STATEMENT_TYPE,
  RAMPSCAN_PREDICATE_TYPE,
  canonicalJson,
  isDigested,
  methodId,
  submissionVerdict,
} from "@rampscan/schema";

// IngestSubmission → EvidenceBundle (SPEC §12.8, Q4.1): a client-run result
// becomes a ledger citizen by MINTING a regular evidence bundle — no new
// statement type, because citizenship IS the bundle. The appliance never
// executed anything; what it signs is that this submission, at this digest,
// was accepted under the contract.

export interface IngestContext {
  /** the offering/repo whose register this evidence joins — the fold's row key */
  repo: string;
  /** the pin the submission's KSI was validated against */
  datasetVersion: string;
}

/** the address of exactly what was accepted — sha256 over the canonical submission */
export function ingestDigest(submission: IngestSubmission): string {
  return createHash("sha256").update(canonicalJson(submission)).digest("hex");
}

/**
 * The mint. Everything the predicate says is computed from the submission or
 * the context — never typed here:
 *
 * - subjects are the submitted artifact digests (≥1 digested by contract, so
 *   the statement's `subject` floor holds without a special case); an
 *   artifact the submission only NAMES (S3-1) is no subject — it stays in
 *   the submission the handoff digest addresses, and the bundle attests to
 *   nothing it has no bytes for;
 * - `anchor_paths: []` and `commit: ""` — ingested evidence has no commit
 *   anchor, so it dies superseded or goes stale (G3) but never by anchor
 *   drift: the honest death model for evidence about a cloud account rather
 *   than a checkout;
 * - `evidence_class` is the SUBMITTER's G6 assertion, copied verbatim into
 *   the slot the pipeline mint asserts for its own bundles;
 * - `run_id = ingest:<digest[0..12]>` — derived, never typed; the upstream
 *   run's identity is the digest itself;
 * - the `ingest` block carries the handoff (signer identity + digest), and
 *   `sameEvidence` keys on it: different signer or different submitted
 *   bytes is different evidence.
 */
export function toIngestedBundle(
  submission: IngestSubmission,
  ctx: IngestContext,
): EvidenceBundle {
  const digest = ingestDigest(submission);
  return {
    _type: IN_TOTO_STATEMENT_TYPE,
    subject: submission.artifacts.filter(isDigested).map((a) => ({
      name: a.name,
      digest: { sha256: a.sha256 },
    })),
    predicateType: RAMPSCAN_PREDICATE_TYPE,
    predicate: {
      recipe_id: submission.recipe_id,
      method_id: methodId("aws-ingested", submission.recipe_id, submission.ksi),
      evidence_class: submission.evidence_class,
      ingest: {
        signer_identity: submission.signer_identity,
        ingest_digest: digest,
        // copied only when declared: an undeclared submission mints the same
        // bytes it always did, and the method reads absent as true (S3-1)
        ...(submission.automated !== undefined ? { automated: submission.automated } : {}),
        // the runner's provenance, when a runner produced the bytes (T2-3)
        ...(submission.runner !== undefined ? { runner: submission.runner } : {}),
      },
      ksi_ids: [submission.ksi],
      // the crosswalk rides the KSI in the pinned dataset (§12.2) — an
      // ingested bundle never claims controls the submitter did not name
      control_ids: [],
      verdict: submissionVerdict(submission),
      repo: ctx.repo,
      commit: "",
      anchor_paths: [],
      dataset_version: ctx.datasetVersion,
      tool_versions: submission.tool_versions ?? {},
      assertions: submission.assertions,
      ...(submission.reproduce !== undefined ? { reproduce: submission.reproduce } : {}),
      cadence: submission.cadence,
      run_id: `ingest:${digest.slice(0, 12)}`,
      timestamp: submission.timestamp,
    },
  };
}
