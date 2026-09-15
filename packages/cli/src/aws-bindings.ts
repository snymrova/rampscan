import { readFile } from "node:fs/promises";
import type { AwsRecipe } from "@rampscan/dataset";
import { AwsLiteralBindings, RESERVED_AWS_PARAMS } from "@rampscan/schema";
import type { AwsConfig, AwsLiteralBinding, ReservedAwsParam } from "@rampscan/schema";

// Parameter binding (docs/PLAN-CLOUD-RUNNER.md T1-3). Two halves:
//
//   1. `applyLiteralBindings` rewrites a pinned recipe's commands so every
//      example literal the reviewed table names becomes a `<NAME>` — before
//      the classifier ever sees it. A literal with no row stays a literal,
//      and a runner handed it would run against the documentation's account;
//      so the table is golden-tested against the overlay both ways.
//   2. `bindAwsParams` produces the values: the reserved names from the
//      configured account and the request's window, the rest from
//      `aws.params`. Nothing is detected by regex at run time.

/** the checked-in table; `rampscan recipes --aws` reads this path by default */
export const DEFAULT_BINDINGS_PATH = "recipes/aws-actions/bindings.json";

export async function loadAwsLiteralBindings(path: string): Promise<AwsLiteralBindings> {
  return AwsLiteralBindings.parse(JSON.parse(await readFile(path, "utf8")));
}

/** the text a row substitutes for its literal */
export function replacementOf(row: AwsLiteralBinding): string {
  return row.becomes ?? `<${row.param}>`;
}

export interface BoundRecipe {
  recipe: Pick<AwsRecipe, "id" | "collection">;
  /** rows for this recipe whose literal did not occur in any command — the table is stale here */
  stale: AwsLiteralBinding[];
}

/**
 * Rewrite one recipe's commands by the table. Every occurrence of a row's
 * literal is replaced (a bucket name that appears twice is the same bucket
 * twice). Rows are applied longest literal first, so `s3://bucket/athena/`
 * is not half-rewritten by `s3://bucket`.
 */
export function applyLiteralBindings(
  recipe: Pick<AwsRecipe, "id" | "collection">,
  table: AwsLiteralBindings,
): BoundRecipe {
  const rows = table.entries
    .filter((r) => r.recipe === recipe.id)
    .sort((a, b) => b.literal.length - a.literal.length);
  const commands = (recipe.collection as { commands?: unknown }).commands;
  if (rows.length === 0 || !Array.isArray(commands)) return { recipe, stale: rows };
  const seen = new Set<AwsLiteralBinding>();
  const rewritten = (commands as unknown[]).map((raw) => {
    let c = String(raw);
    for (const row of rows) {
      if (c.includes(row.literal)) {
        seen.add(row);
        c = c.split(row.literal).join(replacementOf(row));
      }
    }
    return c;
  });
  return {
    recipe: { id: recipe.id, collection: { ...(recipe.collection as object), kind: recipe.collection.kind, commands: rewritten } },
    stale: rows.filter((r) => !seen.has(r)),
  };
}

export interface RequestWindow {
  /** ISO 8601 with offset — the window the request covers */
  start: string;
  end: string;
}

function epochSeconds(iso: string): string {
  const ms = Date.parse(iso);
  if (Number.isNaN(ms)) throw new Error(`request window is not an ISO 8601 instant: ${iso}`);
  return String(Math.floor(ms / 1000));
}

/**
 * The values a request binds: reserved names from the configured account
 * and the window, then `aws.params`. A config that tries to set a reserved
 * name was refused by the schema, so nothing here can be overridden.
 */
export function bindAwsParams(aws: AwsConfig, window: RequestWindow): Record<string, string> {
  const reserved: Record<ReservedAwsParam, string> = {
    ACCOUNT_ID: aws.account_id,
    PARTITION: aws.partition,
    REGION: aws.regions[0]!,
    WINDOW_START: window.start,
    WINDOW_END: window.end,
    EPOCH_START: epochSeconds(window.start),
    EPOCH_END: epochSeconds(window.end),
  };
  return { ...aws.params, ...reserved };
}

/** every name a table row binds that is neither reserved nor in `params` — what the config still owes */
export function unboundParamsOf(table: AwsLiteralBindings, params: Readonly<Record<string, string>>): string[] {
  const names = new Set(table.entries.map((r) => r.param));
  return [...names].filter((n) => !(RESERVED_AWS_PARAMS as readonly string[]).includes(n) && params[n] === undefined).sort();
}
