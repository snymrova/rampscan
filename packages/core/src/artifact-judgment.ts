import { createHash } from "node:crypto";
import type { ArtifactJudgment, JudgedArtifact } from "@rampscan/schema";
import {
  IN_TOTO_STATEMENT_TYPE,
  RAMPSCAN_ARTIFACT_JUDGMENT_TYPE,
} from "@rampscan/schema";

// Artifact-sufficiency judgment → in-toto statement (plan Q3.3, G5). Same
// shape discipline as `toScopingEvent`: the statement's subject is the
// justification text, because what the approver signs is the reasoning. The
// KSI rides in the predicate; the schema's `JudgedArtifact` union (1 | 3 | 4)
// structurally refuses a judgment about the computed artifacts 2 and 5.

export interface ArtifactJudgmentContext {
  repo: string;
  ksiId: string;
  artifact: JudgedArtifact;
  action: "sufficient" | "insufficient";
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
    ],
    predicateType: RAMPSCAN_ARTIFACT_JUDGMENT_TYPE,
    predicate: {
      action: ctx.action,
      ksi_id: ctx.ksiId,
      artifact: ctx.artifact,
      repo: ctx.repo,
      justification: ctx.justification,
      proposed_by: ctx.proposedBy,
      approved_by: ctx.approvedBy,
      dataset_version: ctx.datasetVersion,
      timestamp: ctx.timestamp,
    },
  };
}
