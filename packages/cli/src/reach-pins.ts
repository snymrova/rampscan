import type { PipelineRecipe, ReachPin } from "@rampscan/schema";
import type { AwsRecipesReport } from "./aws-recipes.js";
import type { ProwlerKsiFramework } from "./prowler-framework.js";
import { checksFor } from "./prowler-framework.js";

// The three pins, read once per command and handed to the fold as data
// (docs/PLAN-REACH.md N0-1). The fold computes the rung; this module says
// what each plane observes and what of ours wires it, per KSI, with the ids
// a reader can open. Nothing here reads a file: the catalog, the classified
// overlay and the framework arrive already loaded, so the same three
// arguments a test plants give the same pins the command prints.
//
//   pipeline  a catalog recipe claiming the KSI observes it AND wires it —
//             the recipe is the method's derivation (`methodsOfRecipe`), and
//             `wired` is the most a recipe confers by existing.
//   aws       every upstream recipe claiming the KSI observes it; the ones
//             `classifyAwsRecipe` reads as runnable under the allowlist and
//             the bound parameters wire it. A manual recipe is a tool a
//             client could run by hand, which is reach on the shelf.
//   prowler   every check the pinned framework maps to the KSI on the AWS
//             provider observes it, and the same checks wire it, because the
//             ingest adapter is pinned to that framework and derives a method
//             from any of them (P3). The thirteen KSIs the framework maps no
//             check to (`recipes/prowler/uncovered.json`) get an empty pin.

export interface ReachPinsInput {
  /** the owed catalog's KSI ids — every one gets an entry, observed or not */
  ksiIds: readonly string[];
  recipes: readonly PipelineRecipe[];
  /** `classifyAwsRecipes` over the pinned overlay, the allowlist, the table and the config */
  aws: Pick<AwsRecipesReport, "recipes">;
  prowler: ProwlerKsiFramework;
}

export function buildReachPins(input: ReachPinsInput): Record<string, ReachPin[]> {
  const pipeline = new Map<string, string[]>();
  for (const recipe of input.recipes) {
    for (const ksi of recipe.ksi_ids) {
      (pipeline.get(ksi) ?? pipeline.set(ksi, []).get(ksi)!).push(recipe.id);
    }
  }
  const awsObserves = new Map<string, string[]>();
  const awsWired = new Map<string, string[]>();
  for (const recipe of input.aws.recipes) {
    for (const ksi of recipe.ksi_ids) {
      (awsObserves.get(ksi) ?? awsObserves.set(ksi, []).get(ksi)!).push(recipe.id);
      if (recipe.result.kind === "runnable") {
        (awsWired.get(ksi) ?? awsWired.set(ksi, []).get(ksi)!).push(recipe.id);
      }
    }
  }
  const prowler = new Map<string, readonly string[]>();
  for (const requirement of input.prowler.requirements) {
    prowler.set(requirement.id, checksFor(requirement, "aws"));
  }
  const sorted = (ids: readonly string[] | undefined) => [...(ids ?? [])].sort();
  const out: Record<string, ReachPin[]> = {};
  for (const ksi of [...input.ksiIds].sort()) {
    const checks = sorted(prowler.get(ksi));
    out[ksi] = [
      { plane: "pipeline", observes: sorted(pipeline.get(ksi)), wired: sorted(pipeline.get(ksi)) },
      { plane: "aws", observes: sorted(awsObserves.get(ksi)), wired: sorted(awsWired.get(ksi)) },
      { plane: "prowler", observes: checks, wired: checks },
    ];
  }
  return out;
}
