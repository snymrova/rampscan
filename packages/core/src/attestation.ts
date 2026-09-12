import { createHash } from "node:crypto";
import type { Attestation } from "@rampscan/schema";
import { IN_TOTO_STATEMENT_TYPE, RAMPSCAN_ATTESTATION_TYPE } from "@rampscan/schema";

// Attestation → in-toto statement (plan Q4.2, SPEC §12.9). Same shape
// discipline as `toScopingEvent` and `toArtifactJudgment`: the statement's
// subject is the attested text, because what the approver signs is the CLAIM.
// That subject digest is also the method's `statement_ref` — the address of
// exactly the words two keys were turned for — so the derivation never has to
// re-hash anything the signature already covers.

export interface AttestationContext {
  repo: string;
  /** the mechanism's name ("incident-review"), not the occasion's — SPEC §12.9 */
  statementId: string;
  ksiId: string;
  /** the accountable role ("ciso"): people change, the mechanism doesn't */
  attestorRole: string;
  /** what is attested, in the attestor's words */
  statement: string;
  action: "attested" | "withdrawn";
  proposedBy: string;
  approvedBy: string;
  datasetVersion: string;
  timestamp: string; // ISO 8601
}

export function toAttestation(ctx: AttestationContext): Attestation {
  return {
    _type: IN_TOTO_STATEMENT_TYPE,
    subject: [
      {
        name: "attestation.txt",
        digest: {
          sha256: createHash("sha256").update(ctx.statement, "utf8").digest("hex"),
        },
      },
    ],
    predicateType: RAMPSCAN_ATTESTATION_TYPE,
    predicate: {
      action: ctx.action,
      statement_id: ctx.statementId,
      ksi_id: ctx.ksiId,
      attestor_role: ctx.attestorRole,
      statement: ctx.statement,
      repo: ctx.repo,
      proposed_by: ctx.proposedBy,
      approved_by: ctx.approvedBy,
      dataset_version: ctx.datasetVersion,
      timestamp: ctx.timestamp,
    },
  };
}
