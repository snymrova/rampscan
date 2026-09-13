import { createHash } from "node:crypto";
import type { ArtifactJudgment, JudgedArtifact } from "@rampscan/schema";
import {
  IN_TOTO_STATEMENT_TYPE,
  RAMPSCAN_ARTIFACT_JUDGMENT_TYPE,
} from "@rampscan/schema";

// Artifact-sufficiency judgment → in-toto statement (plan Q3.3, G5; R1.1).
// Same shape discipline as `toScopingEvent`: the statement's subject is the
// justification text, because what the approver signs is the reasoning. The
// KSI rides in the predicate; the schema's `JudgedArtifact` union (1 | 3 | 4)
// structurally refuses a judgment about the computed artifacts 2 and 5.
//
// R1.1 adds the second subject (SPEC §13.6): the `body_digest` of the artifact
// being judged. Two subjects, two facts — the reasoning that was signed and
// the bytes it was about — and neither stands in for the other. Until the
// artifact plane existed there was nothing to put here, which is precisely the
// defect the plane was built to close.

export interface ArtifactJudgmentContext {
  repo: string;
  ksiId: string;
  artifact: JudgedArtifact;
  action: "sufficient" | "insufficient";
  /** the artifact body being judged (§13.6) — omitted only for a pre-R1.1 replay */
  bodyDigest?: string;
  justification: string;
  proposedBy: string;
  approvedBy: string;
  datasetVersion: string;
  timestamp: string; // ISO 8601
}

export function toArtifactJudgment(ctx: ArtifactJudgmentContext): ArtifactJudgment {
  return {
    _type: IN_TOTO_STATEMENT_TYPE,
    subject: [
      {
        name: "justification.txt",
        digest: {
          sha256: createHash("sha256").update(ctx.justification, "utf8").digest("hex"),
        },
      },
      ...(ctx.bodyDigest !== undefined
        ? [{ name: "artifact.md", digest: { sha256: ctx.bodyDigest } }]
        : []),
    ],
    predicateType: RAMPSCAN_ARTIFACT_JUDGMENT_TYPE,
    predicate: {
      action: ctx.action,
      ksi_id: ctx.ksiId,
      artifact: ctx.artifact,
      repo: ctx.repo,
      ...(ctx.bodyDigest !== undefined ? { body_digest: ctx.bodyDigest } : {}),
      justification: ctx.justification,
      proposed_by: ctx.proposedBy,
      approved_by: ctx.approvedBy,
      dataset_version: ctx.datasetVersion,
      timestamp: ctx.timestamp,
    },
  };
}
