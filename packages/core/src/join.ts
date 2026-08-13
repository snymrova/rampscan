import type { PipelineRecipe, RecipeResult, ScanResult, Finding } from "@rampscan/schema";
import { evaluateAssertions } from "./assert.js";
import type { RunResult, Workspace } from "./ports.js";

// The join — plan C4, the thesis of M1: collector output × recipe assertions
// → per-recipe verdict, each with artifacts and the commit hash.
//
// Verdict semantics (honest by construction):
//   unevidenced — nothing ran that could speak to the recipe: the collector
//                 is unregistered, skipped (tool missing, no Dockerfile),
//                 produced no observation for this recipe, or the recipe has
//                 no machine assertions yet (route-auth-coverage until M4).
//                 The reason is recorded, never hidden.
//   evidenced   — the collector observed, and every assertion passed.
//   violated    — the collector observed, and at least one assertion failed.

export interface JoinInput {
  recipes: PipelineRecipe[];
  /** collector name → its run result (only collectors that were attempted) */
  runs: Map<string, RunResult>;
  workspace: Workspace;
  datasetVersion: string;
  runId: string;
  /** the run's single clock — every max_age_days and the result timestamp use it */
  now: Date;
}

function unevidenced(recipe: PipelineRecipe, reason: string): RecipeResult {
  return {
    recipe_id: recipe.id,
    ksi_ids: recipe.ksi_ids,
    control_ids: recipe.control_ids,
    collector: recipe.collection.collector,
    verdict: "unevidenced",
    reason,
    assertions: [],
    artifacts: [],
    anchor_paths: [],
  };
}

export function joinRecipeResults(input: JoinInput): RecipeResult[] {
  return input.recipes.map((recipe) => {
    const collectorName = recipe.collection.collector;
    const run = input.runs.get(collectorName);
    if (!run) {
      return unevidenced(recipe, `collector "${collectorName}" is not registered in this run`);
    }
    if (run.skipped) {
      return unevidenced(recipe, `collector "${collectorName}" skipped: ${run.skipped.reason}`);
    }
    const rows = run.observations[recipe.id];
    if (rows === undefined) {
      return unevidenced(
        recipe,
        `collector "${collectorName}" ran but produced no observation for this recipe`,
      );
    }
    if (!recipe.assertions || recipe.assertions.length === 0) {
      return unevidenced(recipe, "recipe has no machine assertions yet");
    }

    const assertions = evaluateAssertions(recipe.assertions, rows, input.now);
    const verdict = assertions.every((a) => a.passed) ? "evidenced" : "violated";
    return {
      recipe_id: recipe.id,
      ksi_ids: recipe.ksi_ids,
      control_ids: recipe.control_ids,
      collector: collectorName,
      verdict,
      assertions,
      artifacts: run.artifacts,
      anchor_paths: run.anchors[recipe.id] ?? [],
    };
  });
}

export function buildScanResult(input: JoinInput): ScanResult {
  const recipes = joinRecipeResults(input);
  const findings: Finding[] = [...input.runs.values()].flatMap((r) => r.findings);
  const toolVersions: Record<string, string> = {};
  const skipped: Array<{ collector: string; reason: string }> = [];
  for (const [name, run] of input.runs) {
    toolVersions[name] = run.toolVersion;
    if (run.skipped) skipped.push({ collector: name, reason: run.skipped.reason });
  }
  return {
    run_id: input.runId,
    repo: input.workspace.repo,
    commit: input.workspace.commit,
    dataset_version: input.datasetVersion,
    timestamp: input.now.toISOString(),
    tool_versions: toolVersions,
    skipped_collectors: skipped,
    recipes,
    findings,
    summary: {
      evidenced: recipes.filter((r) => r.verdict === "evidenced").length,
      violated: recipes.filter((r) => r.verdict === "violated").length,
      unevidenced: recipes.filter((r) => r.verdict === "unevidenced").length,
    },
  };
}
