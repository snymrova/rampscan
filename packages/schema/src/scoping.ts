import { z } from "zod";
import { IN_TOTO_STATEMENT_TYPE, EvidenceBundle, Subject } from "./bundle.js";

// ScopingEvent: the first two-key write (plan M3 E4). A `notApplicable`
// scoping is drafted in the console, signed by the approver's identity, and
// appended to the ledger like any other statement — PocketBase never holds a
// fact the ledger doesn't (SPEC §6 rule 1). It is an in-toto statement whose
// subject is the justification text itself: what the approver signs is the
// reasoning, not an artifact.
//
// A scoping is a policy statement, not evidence: it carries no commit anchor
// and no assertions. It dies only by being superseded by a later scoping for
// the same (repo, recipe) — never by anchor drift.

export const RAMPSCAN_SCOPING_TYPE = "https://rampscan.dev/scoping/v1" as const;

export const ScopingPredicate = z.object({
  action: z.literal("notApplicable"),
  recipe_id: z.string(),
  ksi_ids: z.array(z.string()),
  control_ids: z.array(z.string()),
  repo: z.string(),
  justification: z.string().min(1),
  /** console identity that drafted the proposal, e.g. "viewer@rampscan.local (pb:abc123)" */
  proposed_by: z.string().min(1),
  /** approver identity whose key turn made this real — recorded in the signed event */
  approved_by: z.string().min(1),
  dataset_version: z.string(),
  timestamp: z.string(), // ISO 8601
});
export type ScopingPredicate = z.infer<typeof ScopingPredicate>;

export const ScopingEvent = z.object({
  _type: z.literal(IN_TOTO_STATEMENT_TYPE),
  subject: z.array(Subject).min(1),
  predicateType: z.literal(RAMPSCAN_SCOPING_TYPE),
  predicate: ScopingPredicate,
});
export type ScopingEvent = z.infer<typeof ScopingEvent>;

/** Everything the ledger stores: evidence bundles and scoping events. */
export const LedgerStatement = z.discriminatedUnion("predicateType", [
  EvidenceBundle,
  ScopingEvent,
]);
export type LedgerStatement = z.infer<typeof LedgerStatement>;

export function isEvidenceBundle(s: LedgerStatement): s is EvidenceBundle {
  return s.predicateType === "https://rampscan.dev/evidence/v1";
}

export function isScopingEvent(s: LedgerStatement): s is ScopingEvent {
  return s.predicateType === RAMPSCAN_SCOPING_TYPE;
}
