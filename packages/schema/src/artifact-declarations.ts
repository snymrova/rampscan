import { z } from "zod";
import { IN_TOTO_STATEMENT_TYPE, Subject } from "./bundle.js";

// ArtifactDeclarations: what a scan observed about the repository's declared
// KSI artifacts (plan R1.4, SPEC §13.3). The companion this plane needed and
// did not have.
//
// THE PROBLEM IT SOLVES. An `Artifact` has no withdrawal — §13.2 settled that
// an append-only ledger revises by writing again — and that works when a file
// CHANGES, because new bytes supersede the old. It does not work when a file is
// DELETED: there is no body to append, so the standing artifact would keep
// counting toward the KSI's `k / 5` until its three-month clock ran out, which
// is the failure mode this whole plane exists to prevent. Evidence has the same
// shape of problem and answers it the same way: a later bundle that OBSERVED
// the path is what kills the earlier one. So the artifact plane gets its own
// observation, and the explicit signed absence is what kills the body.
//
// WHY THIS MAY MOVE A BOARD CELL WHEN A RUN RECORD MAY NOT. `ScanRun` (J1) is
// about the machinery — which collector ran, which tool resolved — and letting
// it move a cell would make the board partly a function of the run log. This
// statement is not about the run: it is an observation OF THE REPOSITORY, the
// same kind of fact an evidence bundle carries, and it is signed and anchored
// to the commit it observed. What it says is "at this commit, these declared
// slots resolved and these did not", which is exactly the sort of claim the
// fold is built to age and supersede.
//
// SILENCE IS NOT A STATEMENT. Only an entry naming a slot as UNRESOLVED kills
// the body standing in it. A slot that has simply left the config is not
// killed: the repository has stopped claiming that file answers for this KSI,
// which is not the same as saying the answer is gone, and the clock is what
// ages an artifact nobody is maintaining.

export const RAMPSCAN_ARTIFACT_DECLARATIONS_TYPE =
  "https://rampscan.dev/artifact-declarations/v1" as const;

export const DeclarationObservation = z
  .object({
    /** exactly one KSI id, mnemonic form, as the declaration named it */
    ksi_id: z.string().min(1),
    artifact: z.union([z.literal(1), z.literal(2), z.literal(3), z.literal(4), z.literal(5)]),
    /** the repo-relative path the declaration named */
    path: z.string().min(1),
    /** whether this scan could resolve the declaration to a body */
    resolved: z.boolean(),
    /** resolved only: the body's digest, so a reader can match it to the artifact */
    body_digest: z.string().regex(/^[0-9a-f]{64}$/).optional(),
    /** unresolved only: why — the sentence that is printed on the empty cell */
    reason: z.string().min(1).optional(),
  })
  .superRefine((o, ctx) => {
    // An unresolved observation with no reason would be the thing this whole
    // codebase refuses elsewhere: an absence nobody has to account for.
    if (!o.resolved && o.reason === undefined) {
      ctx.addIssue({
        code: "custom",
        path: ["reason"],
        message: "an unresolved declaration must say why — an absence is recorded with its reason",
      });
    }
    if (o.resolved && o.body_digest === undefined) {
      ctx.addIssue({
        code: "custom",
        path: ["body_digest"],
        message: "a resolved declaration names the body it resolved to",
      });
    }
  });
export type DeclarationObservation = z.infer<typeof DeclarationObservation>;

export const ArtifactDeclarationsPredicate = z
  .object({
    repo: z.string(),
    /** the commit this observation was made at — it is a claim about a tree */
    commit: z.string().min(1),
    declarations: z.array(DeclarationObservation).min(1),
    dataset_version: z.string(),
    timestamp: z.string(), // ISO 8601
  })
  .superRefine((p, ctx) => {
    const slots = new Set(p.declarations.map((d) => `${d.ksi_id} ${d.artifact}`));
    if (slots.size !== p.declarations.length) {
      ctx.addIssue({
        code: "custom",
        path: ["declarations"],
        message: "one slot, one observation — a repeated slot would let a scan say two things",
      });
    }
  });
export type ArtifactDeclarationsPredicate = z.infer<typeof ArtifactDeclarationsPredicate>;

export const ArtifactDeclarations = z.object({
  _type: z.literal(IN_TOTO_STATEMENT_TYPE),
  /** the declaration file this was read from, by digest */
  subject: z.array(Subject).min(1),
  predicateType: z.literal(RAMPSCAN_ARTIFACT_DECLARATIONS_TYPE),
  predicate: ArtifactDeclarationsPredicate,
});
export type ArtifactDeclarations = z.infer<typeof ArtifactDeclarations>;
