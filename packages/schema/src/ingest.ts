import { z } from "zod";
import { EvidenceClass } from "./bundle.js";
import { Cadence } from "./recipe.js";

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
 * One assertion outcome as the client's run recorded it. `population` is the
 * N0 discrimination ("0 of 412" vs "0 of 0"), carried when the upstream run
 * can state it — the tree adapter sets it to the result rows the script
 * emitted.
 */
export const IngestedAssertion = z.strictObject({
  description: z.string().min(1),
  passed: z.boolean(),
  detail: z.string().optional(),
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
  /** ≥1: verdict is computed from these — a run that observed nothing has nothing to submit */
  assertions: z.array(IngestedAssertion).min(1),
  /** the client RUN's clock, not the ingest's */
  timestamp: z.iso.datetime({ offset: true }),
  /** who ran it and stands behind it */
  signer_identity: z.string().min(1),
  tool_versions: z.record(z.string(), z.string()).optional(),
  reproduce: z.string().optional(),
});
export type IngestSubmission = z.infer<typeof IngestSubmission>;

/**
 * Verdict is COMPUTED, never declared (SPEC §12.8): every assertion passed →
 * evidenced; any failed → violated. There is no `unevidenced` submission —
 * the schema refuses empty `assertions` structurally, so this total function
 * never has to invent an answer.
 */
export function submissionVerdict(
  submission: Pick<IngestSubmission, "assertions">,
): "evidenced" | "violated" {
  return submission.assertions.every((a) => a.passed) ? "evidenced" : "violated";
}

/**
 * The tree adapter's manifest (SPEC §12.8): what the CLIENT authors at the
 * root of an `Evidence/<family>/<KSI-ID>/` tree — the facts the tree itself
 * does not carry. Signer identity, evidence class, and cadence are uniform
 * for the batch (with a per-entry evidence-class override, because one
 * orchestrator run can mix repeatable checks with captured state); per entry,
 * the script name, exit code, and timestamp come from the orchestrator's own
 * run log.
 */
export const IngestManifestEntry = z.strictObject({
  /** must name a directory in the tree whose basename is exactly this KSI */
  ksi: z.string().min(1),
  /** the script that produced this result — becomes the upstream recipe id */
  script: z.string().min(1),
  /** the validation outcome, as the orchestrator recorded it: 0 = pass */
  exit_code: z.number().int(),
  timestamp: z.iso.datetime({ offset: true }),
  evidence_class: EvidenceClass.optional(),
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
