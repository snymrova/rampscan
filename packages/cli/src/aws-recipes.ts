import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { AwsRecipe } from "@rampscan/dataset";
import { GRAPH_CONFIG_FILE } from "@rampscan/graph";
import { AwsConfig } from "@rampscan/schema";
import type { AwsActionAllowlist, AwsLiteralBindings } from "@rampscan/schema";
import { applyLiteralBindings, bindAwsParams, unboundParamsOf } from "./aws-bindings.js";
import type { RequestWindow } from "./aws-bindings.js";
import { classifyAwsRecipe, describeReason } from "./aws-classify.js";
import type { RecipeClass } from "./aws-classify.js";

// `rampscan recipes --aws` (docs/PLAN-CLOUD-RUNNER.md T1-5): the
// classification of the pinned overlay under the reviewed allowlist, the
// reviewed literal table and the configured parameters — every manual recipe
// with every reason. Ground rule 4: the runnable count is printed from the
// same function the runner will be handed argv by, never typed anywhere.

/**
 * The `aws` block, same three-state contract as `loadOffering`: absent →
 * undefined (every placeholder unbound, and the print says so); present but
 * malformed → throw (a mistyped account id must not quietly bind nothing);
 * valid → the block.
 */
export async function loadAwsConfig(root: string): Promise<AwsConfig | undefined> {
  let raw: string;
  try {
    raw = await readFile(join(root, GRAPH_CONFIG_FILE), "utf8");
  } catch {
    return undefined;
  }
  const parsed = JSON.parse(raw) as Record<string, unknown>;
  if (parsed["aws"] === undefined) return undefined;
  try {
    return AwsConfig.parse(parsed["aws"]);
  } catch (cause) {
    const issue =
      cause instanceof Error && "issues" in cause
        ? (cause as { issues: Array<{ path: Array<string | number>; message: string }> }).issues
            .map((i) => `${["aws", ...i.path].join(".")}: ${i.message}`)
            .join("; ")
        : String(cause);
    throw new Error(`the aws block in ${GRAPH_CONFIG_FILE} failed validation (exit refused): ${issue}`, { cause });
  }
}

export interface ClassifiedRecipe {
  id: string;
  ksi_ids: string[];
  automatable: string;
  /** whether the upstream recipe carries structured assertions — without them a run is collected, then judged (T0-2) */
  has_assertions: boolean;
  result: RecipeClass;
}

export interface AwsRecipesReport {
  dataset: string;
  config: { account_id: string; partition: string; region: string } | undefined;
  window: RequestWindow;
  /** the table's non-reserved names the config does not supply */
  owed_params: string[];
  recipes: ClassifiedRecipe[];
  runnable: number;
  /** KSIs at least one runnable recipe reaches */
  runnable_ksis: number;
  /** runnable AND carrying assertions: what can be judged without a person */
  runnable_with_assertions: number;
}

/** a window of `days` ending at `now`, for a print; the real request's window is per method (T4/T5) */
export function windowEnding(now: Date, days: number): RequestWindow {
  const end = new Date(now);
  const start = new Date(now.getTime() - days * 86_400_000);
  return { start: start.toISOString(), end: end.toISOString() };
}

export function classifyAwsRecipes(
  recipes: readonly AwsRecipe[],
  list: AwsActionAllowlist,
  table: AwsLiteralBindings,
  aws: AwsConfig | undefined,
  window: RequestWindow,
  dataset: string,
): AwsRecipesReport {
  const params = aws === undefined ? {} : bindAwsParams(aws, window);
  const out: ClassifiedRecipe[] = recipes.map((r) => ({
    id: r.id,
    ksi_ids: r.ksi_ids,
    automatable: r.automatable,
    has_assertions: Array.isArray(r["assertions"]) && r["assertions"].length > 0,
    result: classifyAwsRecipe(applyLiteralBindings(r, table).recipe, list, params),
  }));
  const runnable = out.filter((r) => r.result.kind === "runnable");
  return {
    dataset,
    config: aws === undefined ? undefined : { account_id: aws.account_id, partition: aws.partition, region: aws.regions[0]! },
    window,
    owed_params: aws === undefined ? unboundParamsOf(table, {}) : unboundParamsOf(table, params),
    recipes: out,
    runnable: runnable.length,
    runnable_ksis: new Set(runnable.flatMap((r) => r.ksi_ids)).size,
    runnable_with_assertions: runnable.filter((r) => r.has_assertions).length,
  };
}

export function renderAwsRecipes(report: AwsRecipesReport): string {
  const lines: string[] = [];
  lines.push(`rampscan recipes --aws — the pinned overlay (${report.dataset}) under the reviewed allowlist and literal table`);
  lines.push(
    report.config === undefined
      ? `config: no \`aws\` block in ${GRAPH_CONFIG_FILE} — every placeholder is unbound; the shape of each recipe is still classified`
      : `config: account ${report.config.account_id} · partition ${report.config.partition} · region ${report.config.region}`,
  );
  lines.push(`window: ${report.window.start} → ${report.window.end} (a print's window; a request's is per method)`);
  lines.push("");
  const total = report.recipes.length;
  lines.push(
    `runnable  ${report.runnable} of ${total} recipes, ${report.runnable_ksis} KSIs — ${report.runnable_with_assertions} carry assertions and can be judged by machine; ` +
      `${report.runnable - report.runnable_with_assertions} are collected, then judged (T0-2)`,
  );
  lines.push(`manual    ${total - report.runnable}`);
  if (report.owed_params.length > 0) {
    lines.push(`owed by config (aws.params): ${report.owed_params.join(", ")}`);
  }
  lines.push("");
  lines.push("runnable:");
  for (const r of report.recipes) {
    if (r.result.kind !== "runnable") continue;
    lines.push(`  ${r.id}  ${r.ksi_ids.join(", ")}  (${r.result.steps.length} step${r.result.steps.length === 1 ? "" : "s"}${r.has_assertions ? ", assertions" : ", no assertions"})`);
  }
  lines.push("");
  lines.push("manual, with every reason:");
  for (const r of report.recipes) {
    if (r.result.kind !== "manual") continue;
    lines.push(`  ${r.id}  ${r.ksi_ids.join(", ")}`);
    for (const reason of r.result.reasons) lines.push(`    - ${describeReason(reason)}`);
  }
  return lines.join("\n");
}
