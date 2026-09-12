import { z } from "zod";
import { IN_TOTO_STATEMENT_TYPE, Subject } from "./bundle.js";

// Attestation: the third two-key write (plan Q4.2, SPEC §12.9). The pipeline
// and ingestion planes both evidence what a machine can observe; what remains
// after both is acts-on-people, and `VDR-TFR-NMV` exists for exactly that
// remainder. A human statement signed through the same two keys as a scoping
// becomes the `source: attestation` leg of §12.2's register — a counted
// method rather than an apology.
//
// Like a scoping or a sufficiency judgment, an attestation is a policy
// statement, not evidence: no commit anchor, no assertions, subject = the
// claim the approver signs. It dies only by being superseded by a later
// attestation for the same (repo, statement_id, KSI) — which is also how one
// is WITHDRAWN: a signed `withdrawn` supersedes an `attested`, because an
// append-only ledger un-decides by deciding again, never by deleting.

export const RAMPSCAN_ATTESTATION_TYPE = "https://rampscan.dev/attestation/v1" as const;

/**
 * The mechanism's name, not the occasion's — "incident-review", not
 * "incident-review-2026-Q3". It becomes the method's `source_ref`
 * (`attestation:<statement_id>#<ksi>`), so the same programme re-signed every
 * quarter stays ONE method whose clock is satisfied again.
 *
 * Slug-shaped on purpose: the id is a composite key, and a `#` or `:` inside
 * this segment would make `attestation:a#b#KSI-X` ambiguous while still
 * looking like an id — the contract-rule class, one level up from field names.
 */
export const StatementId = z
  .string()
  .min(1)
  .regex(
    /^[A-Za-z0-9][A-Za-z0-9._-]*$/,
    "statement_id is a slug: it becomes part of the method id, so ':' and '#' would make that id ambiguous",
  );
export type StatementId = z.infer<typeof StatementId>;

export const AttestationPredicate = z.object({
  /** `withdrawn` retracts a standing `attested` — same two keys */
  action: z.enum(["attested", "withdrawn"]),
  statement_id: StatementId,
  /** exactly one KSI id, mnemonic form ("KSI-CNA-CIC") */
  ksi_id: z.string().min(1),
  /**
   * The accountable ROLE, not a person: people change and the mechanism does
   * not, so the method survives the post-holder. The two-key identities of
   * who actually drafted and approved this one live below, in the event.
   */
  attestor_role: z.string().min(1),
  /** what is attested, in the attestor's words — the subject digests this */
  statement: z.string().min(1),
  repo: z.string(),
  /** console identity that drafted the proposal, e.g. "viewer@rampscan.local (pb:abc123)" */
  proposed_by: z.string().min(1),
  /** approver identity whose key turn made this real — recorded in the signed event */
  approved_by: z.string().min(1),
  dataset_version: z.string(),
  timestamp: z.string(), // ISO 8601
});
export type AttestationPredicate = z.infer<typeof AttestationPredicate>;

export const Attestation = z.object({
  _type: z.literal(IN_TOTO_STATEMENT_TYPE),
  subject: z.array(Subject).min(1),
  predicateType: z.literal(RAMPSCAN_ATTESTATION_TYPE),
  predicate: AttestationPredicate,
});
export type Attestation = z.infer<typeof Attestation>;
