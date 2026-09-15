import { z } from "zod";
import { EvidenceClass, OffenderPointer } from "./bundle.js";
import type { Verdict } from "./bundle.js";
import { Cadence, RecipeAssertion } from "./recipe.js";

// The ingestion contract (SPEC §12.8, plan Q4.1): the shape under which a
// CLIENT-RUN result becomes a ledger citizen. The no-SaaS / no-execution
// boundary holds — ramprules' AWS recipes remain the client's to run; what
// crosses the boundary is this document, one per (upstream recipe × KSI).
//
// Strict at every level, the manifest/contract rule: provenance is what an
// assessor pulls on (FRR-PVA-AA-06), and a misspelled field that parses to
// nothing is a question the interrogation view can no longer answer.

export const INGEST_SUBMISSION_TYPE =
  "https://rampscan.dev/ingest-submission/v1" as const;
export const INGEST_MANIFEST_TYPE =
  "https://rampscan.dev/ingest-manifest/v1" as const;

/** a client output file, by digest — becomes a subject of the minted bundle */
export const IngestedArtifact = z.strictObject({
  name: z.string().min(1),
  sha256: z.string().regex(/^[0-9a-f]{64}$/),
});
export type IngestedArtifact = z.infer<typeof IngestedArtifact>;

/**
 * One assertion outcome. On the native path it is what the client's run
 * recorded and the signer stands behind; on the tree path it is what the
 * appliance evaluated over the result rows (#147) — the same shape a pipeline
 * recipe's assertion produces, offenders included. `population` is the N0
 * discrimination ("0 of 412" vs "0 of 0"): the rows the script emitted.
 */
export const IngestedAssertion = z.strictObject({
  description: z.string().min(1),
  passed: z.boolean(),
  detail: z.string().optional(),
  offenders: z.array(OffenderPointer).optional(),
  offender_count: z.number().int().optional(),
  population: z.number().int().optional(),
});
export type IngestedAssertion = z.infer<typeof IngestedAssertion>;

export const IngestSubmission = z.strictObject({
  _type: z.literal(INGEST_SUBMISSION_TYPE),
  /** upstream's recipe id — their names, not ours */
  recipe_id: z.string().min(1),
  /** exactly one KSI, mnemonic form; must resolve in the pinned catalog */
  ksi: z.string().min(1),
  /**
   * The G6 evidence-class assertion, made by the SUBMITTER — the one fact
   * the appliance cannot compute: only the party that ran the recipe knows
   * whether the output is a repeatable process over declared inputs or a
   * captured state.
   */
  evidence_class: EvidenceClass,
  /** the cycle the client runs this on — artifact 2's record */
  cadence: Cadence,
  /** ≥1: a result with nothing to attest to is not evidence */
  artifacts: z.array(IngestedArtifact).min(1),
  /**
   * The verdict is computed from these. Empty is permitted and means exactly
   * what it says (#147): the artifacts were collected and nothing evaluated
   * them — the submission is `unevidenced`, a signed record of what was
   * handed over that a later judgment can point at, never a pass.
   */
  assertions: z.array(IngestedAssertion),
  /** the client RUN's clock, not the ingest's */
  timestamp: z.iso.datetime({ offset: true }),
  /** who ran it and stands behind it */
  signer_identity: z.string().min(1),
  tool_versions: z.record(z.string(), z.string()).optional(),
  reproduce: z.string().optional(),
});
export type IngestSubmission = z.infer<typeof IngestSubmission>;

/**
 * Verdict is COMPUTED, never declared (SPEC §12.8): any assertion failed →
 * violated; every assertion passed → evidenced; no assertion at all →
 * unevidenced. The third arm is #147's: `evidenced` is earned only by an
 * assertion that passed over the rows, so a submission carrying none can
 * say the bytes were collected and nothing more. A total function with no
 * vacuous branch — `[].every(...)` is true, and that is the one truth this
 * function must not sign.
 */
export function submissionVerdict(submission: Pick<IngestSubmission, "assertions">): Verdict {
  if (submission.assertions.length === 0) return "unevidenced";
  return submission.assertions.every((a) => a.passed) ? "evidenced" : "violated";
}

/**
 * The tree adapter's manifest (SPEC §12.8): what the CLIENT authors at the
 * root of an `Evidence/<family>/<KSI-ID>/` tree — the facts the tree itself
 * does not carry. Signer identity, evidence class, and cadence are uniform
 * for the batch (with a per-entry evidence-class override, because one
 * orchestrator run can mix repeatable checks with captured state); per entry,
 * the script name, exit code, and timestamp come from the orchestrator's own
 * run log, and the assertions — if any — are the client's claim about what
 * the rows must say, which the appliance evaluates itself (#147).
 */
export const IngestManifestEntry = z.strictObject({
  /** must name a directory in the tree whose basename is exactly this KSI */
  ksi: z.string().min(1),
  /** the script that produced this result — becomes the upstream recipe id */
  script: z.string().min(1),
  /**
   * The run's exit code as the orchestrator recorded it. 0 means the script
   * finished READING the account; non-zero means it could not — a failed run
   * with nothing to attest to, which the adapter skips and names. Neither is
   * a verdict: the scripts this convention was read from exit 0 over a
   * non-compliant account (docs/RESEARCH-PARAMIFY-PILOT.md §8.1).
   */
  exit_code: z.number().int(),
  timestamp: z.iso.datetime({ offset: true }),
  evidence_class: EvidenceClass.optional(),
  /**
   * Structured assertions over the result file's `results` rows, in the
   * vocabulary aws-evidence.json's recipes use (`field`/`op`/`value`/`where`),
   * evaluated by the appliance with the pipeline's own evaluator. Absent or
   * empty, the entry is collected and `unevidenced`; only an assertion that
   * passed over the rows makes it `evidenced`.
   */
  assertions: z.array(RecipeAssertion).optional(),
});
export type IngestManifestEntry = z.infer<typeof IngestManifestEntry>;

export const IngestManifest = z.strictObject({
  _type: z.literal(INGEST_MANIFEST_TYPE),
  signer_identity: z.string().min(1),
  evidence_class: EvidenceClass,
  cadence: Cadence,
  entries: z.array(IngestManifestEntry).min(1),
});
export type IngestManifest = z.infer<typeof IngestManifest>;
