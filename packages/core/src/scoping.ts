import { createHash } from "node:crypto";
import type { PipelineRecipe, ScopingEvent } from "@rampscan/schema";
import {
  IN_TOTO_STATEMENT_TYPE,
  RAMPSCAN_SCOPING_TYPE,
} from "@rampscan/schema";

// notApplicable scoping → in-toto statement (plan M3 E4). The statement's
// subject is the justification text: the approver signs the reasoning. The
// recipe's KSI/control IDs ride along so the projection can place the scoping
// on the board without consulting the catalog.

export interface ScopingContext {
  repo: string;
  justification: string;
  proposedBy: string;
  approvedBy: string;
  datasetVersion: string;
  timestamp: string; // ISO 8601
}

export function toScopingEvent(
  recipe: Pick<PipelineRecipe, "id" | "ksi_ids" | "control_ids">,
  ctx: ScopingContext,
): ScopingEvent {
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
    predicateType: RAMPSCAN_SCOPING_TYPE,
    predicate: {
      action: "notApplicable",
      recipe_id: recipe.id,
      ksi_ids: recipe.ksi_ids,
      control_ids: recipe.control_ids,
      repo: ctx.repo,
      justification: ctx.justification,
      proposed_by: ctx.proposedBy,
      approved_by: ctx.approvedBy,
      dataset_version: ctx.datasetVersion,
      timestamp: ctx.timestamp,
    },
  };
}
