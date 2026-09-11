import { z } from "zod";
import { IN_TOTO_STATEMENT_TYPE, Subject } from "./bundle.js";

// ArtifactJudgment: the second two-key write (plan Q3.3, G5). Of the five
// KSI default artifacts (`default_artifacts.KSI`, the rules' own order),
// presence of 2 and 5 is MECHANICAL — artifact 5 is the method's evidence
// itself, artifact 2 is the cadence record the scheduler already keeps —
// and the fold computes them, so no event may assert them. Sufficiency of
// 1, 3, and 4 is JUDGMENT: a human decision routed through the same two-key
// pattern as scoping — drafted in the console, signed by the approver's
// identity, appended to the ledger — never a checkbox. Artifact 4 (accuracy
// of the measurement system) is where the #23 class of defect formally
// lives from now on.
//
// Like a scoping, a judgment is a policy statement, not evidence: no commit
// anchor, no assertions, subject = the justification the approver signs. It
// dies only by being superseded by a later judgment for the same
// (repo, KSI, artifact) — which is also how a judgment is WITHDRAWN: a
// signed `insufficient` supersedes a `sufficient`, because an append-only
// ledger un-decides by deciding again, never by deleting.

export const RAMPSCAN_ARTIFACT_JUDGMENT_TYPE =
  "https://rampscan.dev/artifact-judgment/v1" as const;

/**
 * The judged artifacts, 1-based into `default_artifacts.KSI`. CLOSED to
 * 1 | 3 | 4 on purpose: artifacts 2 and 5 are computed by the fold, and a
 * schema that accepted a judgment about them would let a signature override
 * a computation — the checkbox this event type exists to refuse.
 */
export const JudgedArtifact = z.union([z.literal(1), z.literal(3), z.literal(4)]);
export type JudgedArtifact = z.infer<typeof JudgedArtifact>;

export const ArtifactJudgmentPredicate = z.object({
  /** `insufficient` withdraws a standing `sufficient` — same two keys */
  action: z.enum(["sufficient", "insufficient"]),
  /** exactly one KSI id, mnemonic form ("KSI-SCR-MIT") */
  ksi_id: z.string().min(1),
  artifact: JudgedArtifact,
  repo: z.string(),
  justification: z.string().min(1),
  /** console identity that drafted the proposal, e.g. "viewer@rampscan.local (pb:abc123)" */
  proposed_by: z.string().min(1),
  /** approver identity whose key turn made this real — recorded in the signed event */
  approved_by: z.string().min(1),
  dataset_version: z.string(),
  timestamp: z.string(), // ISO 8601
});
export type ArtifactJudgmentPredicate = z.infer<typeof ArtifactJudgmentPredicate>;

export const ArtifactJudgment = z.object({
  _type: z.literal(IN_TOTO_STATEMENT_TYPE),
  subject: z.array(Subject).min(1),
  predicateType: z.literal(RAMPSCAN_ARTIFACT_JUDGMENT_TYPE),
  predicate: ArtifactJudgmentPredicate,
});
export type ArtifactJudgment = z.infer<typeof ArtifactJudgment>;
