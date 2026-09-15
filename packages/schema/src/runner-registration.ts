import { z } from "zod";
import { IN_TOTO_STATEMENT_TYPE, Subject } from "./bundle.js";

// Runner registration: the fourth two-key write (docs/PLAN-CLOUD-RUNNER.md
// T3-2, SPEC §14). A client-deployed runner signs its transcripts with its
// own key; the appliance accepts a transcript only from a key an approver's
// key turn has recorded here. Like a scoping, a judgment or an attestation,
// this is a policy statement, not evidence: no commit anchor, no
// assertions, subject = the public key the approver signs. It dies only by
// being superseded — a signed `revoked` for the same runner name supersedes
// a `registered`, because an append-only ledger un-decides by deciding
// again, never by deleting.

export const RAMPSCAN_RUNNER_REGISTRATION_TYPE = "https://rampscan.dev/runner-registration/v1" as const;

/** the DSSE payload type a runner's transcript envelope carries — not the in-toto type, so a transcript never parses as a ledger statement */
export const RUN_TRANSCRIPT_PAYLOAD_TYPE = "application/vnd.rampscan.run-transcript+json" as const;

/**
 * The runner's name is a slug: it becomes `runner:<name>` in a bundle's
 * `signer_identity` and the key of the registry fold, so `:` or `#` inside
 * it would make both ambiguous.
 */
export const RunnerName = z
  .string()
  .min(1)
  .regex(/^[A-Za-z0-9][A-Za-z0-9._-]*$/, "a runner name is a slug: it becomes part of a signer identity and a registry key");
export type RunnerName = z.infer<typeof RunnerName>;

export const RunnerRegistrationPredicate = z.strictObject({
  /** `revoked` retracts a standing `registered` — same two keys */
  action: z.enum(["registered", "revoked"]),
  runner_name: RunnerName,
  /** the runner's public key, SPKI PEM, ECDSA P-256 — what verifies its transcripts */
  public_key: z.string().min(1),
  /** sha256 over the SPKI DER: the `keyid` the runner's envelopes carry */
  keyid: z.string().regex(/^[0-9a-f]{64}$/),
  /** where the runner is deployed, as the approver understood it — a sidecar, CloudShell one-shots, an ECS task */
  host: z.string().min(1),
  /** the account and partition the runner is expected to observe; a transcript from elsewhere is refused at intake anyway */
  account: z.string().regex(/^\d{12}$/),
  partition: z.enum(["aws", "aws-us-gov"]),
  repo: z.string(),
  /** console identity that proposed the registration */
  proposed_by: z.string().min(1),
  /** approver identity whose key turn made this real */
  approved_by: z.string().min(1),
  dataset_version: z.string(),
  timestamp: z.iso.datetime({ offset: true }),
});
export type RunnerRegistrationPredicate = z.infer<typeof RunnerRegistrationPredicate>;

export const RunnerRegistration = z.object({
  _type: z.literal(IN_TOTO_STATEMENT_TYPE),
  subject: z.array(Subject).min(1),
  predicateType: z.literal(RAMPSCAN_RUNNER_REGISTRATION_TYPE),
  predicate: RunnerRegistrationPredicate,
});
export type RunnerRegistration = z.infer<typeof RunnerRegistration>;
