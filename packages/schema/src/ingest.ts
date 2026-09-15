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
export const DigestedArtifact = z.strictObject({
  name: z.string().min(1),
  sha256: z.string().regex(/^[0-9a-f]{64}$/),
});
export type DigestedArtifact = z.infer<typeof DigestedArtifact>;

/**
 * An artifact the submission NAMES but does not hand over (S3-1): an assessed
 * package lists its evidence files by reference — a file name, a URL — and
 * ships none of the bytes. Carried as what it is, a pointer, and never given
 * a digest the appliance did not compute over bytes it held. Not a subject of
 * the minted bundle: subjects are content addresses.
 */
export const ReferencedArtifact = z.strictObject({
  name: z.string().min(1),
  reference: z.string().min(1).optional(),
});
export type ReferencedArtifact = z.infer<typeof ReferencedArtifact>;

export const IngestedArtifact = z.union([DigestedArtifact, ReferencedArtifact]);
export type IngestedArtifact = z.infer<typeof IngestedArtifact>;

export function isDigested(artifact: IngestedArtifact): artifact is DigestedArtifact {
  return "sha256" in artifact;
}

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

/**
 * The runner provenance block (T0-1, SPEC §14.2): present exactly on a
 * submission the appliance built from a runner's transcript, so a manual
 * submission and a runner's stay distinguishable to an assessor. What STS
 * returned during the run, not configuration; and the digest of the request
 * the run answered. Carried into the bundle's `ingest` block unchanged.
 */
export const RunnerProvenance = z.strictObject({
  name: z.string().min(1),
  caller_arn: z.string().min(1),
  account: z.string().regex(/^\d{12}$/),
  partition: z.enum(["aws", "aws-us-gov"]),
  region: z.string().min(1),
  request_digest: z.string().regex(/^[0-9a-f]{64}$/),
});
export type RunnerProvenance = z.infer<typeof RunnerProvenance>;

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
  /**
   * ≥1 DIGESTED: a result with nothing to attest to is not evidence, and what
   * is attested to is bytes the appliance held — referenced artifacts may
   * ride beside a digested one, never instead of it.
   */
  artifacts: z
    .array(IngestedArtifact)
    .min(1)
    .refine((artifacts) => artifacts.some(isDigested), {
      message: "at least one artifact must carry a sha256 — a submission of pointers alone has nothing to attest to",
    }),
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
  /**
   * Whether a MACHINE validated this result — the FRC-CSX-VVK numerator, as
   * the method derived from the minted bundle will carry it. Absent means
   * true, which is what every submission before S3-1 was: a client-run
   * recipe with the assertions it evaluated. The package adapter declares
   * false, because an assessed package carries a person's reading and no
   * machine assertion — whatever produced the artifact, nothing validated it
   * by machine, and the numerator of a legal floor does not move for it.
   */
  automated: z.boolean().optional(),
  tool_versions: z.record(z.string(), z.string()).optional(),
  reproduce: z.string().optional(),
  /** present exactly when a client-deployed runner produced the bytes (T2-3) */
  runner: RunnerProvenance.optional(),
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

/**
 * A KSI crosswalk (S3-1): the reviewed mapping the package adapter applies
 * when a package names its KSIs in an earlier catalog's ids. Not a rename
 * table — between the Phase One numbering and the 2026 rules, family
 * acronyms, numbering and scope all moved (docs/RESEARCH-PARAMIFY-PILOT.md
 * §4), one indicator can land on two successors or on none, and nothing
 * upstream publishes the mapping. So it is a reviewed artifact with a basis
 * per row, strict like every contract, and pinned to the catalog version it
 * resolves into: a crosswalk into another pin is refused, not reinterpreted.
 */
export const KSI_CROSSWALK_TYPE = "https://rampscan.dev/ksi-crosswalk/v1" as const;

export const KsiCrosswalkEntry = z.strictObject({
  /** the id as the package spells it (`CNA-01`) */
  from: z.string().min(1),
  /** every pinned-catalog KSI the indicator lands on; empty = retired from the KSI catalog */
  to: z.array(z.string().min(1)),
  /** the reviewer's reason — and, for a retired indicator, where the subject went */
  basis: z.string().min(1),
});
export type KsiCrosswalkEntry = z.infer<typeof KsiCrosswalkEntry>;

export const KsiCrosswalk = z.strictObject({
  _type: z.literal(KSI_CROSSWALK_TYPE),
  from: z.strictObject({
    catalog: z.string().min(1),
    observed_in: z.string().min(1).optional(),
  }),
  /** the dataset pin the `to` ids resolve in — must equal the ingest's pin */
  to: z.string().min(1),
  reviewed: z.string().min(1),
  rule: z.string().min(1).optional(),
  entries: z.array(KsiCrosswalkEntry).min(1),
});
export type KsiCrosswalk = z.infer<typeof KsiCrosswalk>;
