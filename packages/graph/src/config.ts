import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";

// Graph configuration read from the SCANNED repo's root — the plan's
// "honesty over magic" clause: an `entrypoints` override in config beats a
// silently wrong graph, and auth detection is a name heuristic the target
// repo can correct.

export const GRAPH_CONFIG_FILE = "rampscan.config.json";

/** default auth heuristic: any symbol/import whose name contains one of these (case-insensitive) */
export const DEFAULT_AUTH_PATTERNS = ["auth"];

const ConfigSchema = z
  .object({
    graph: z
      .object({
        /** repo-relative entry point files; overrides package.json detection */
        entrypoints: z.array(z.string()).optional(),
        /** case-insensitive regexes matched against symbol/import names */
        authPatterns: z.array(z.string()).optional(),
      })
      .optional(),
  })
  .passthrough();

export interface GraphConfig {
  entrypoints?: string[];
  authPatterns?: string[];
}

/** rampscan.config.json in the workspace root; absent file → {} */
export async function loadGraphConfig(root: string): Promise<GraphConfig> {
  let raw: string;
  try {
    raw = await readFile(join(root, GRAPH_CONFIG_FILE), "utf8");
  } catch {
    return {};
  }
  const parsed = ConfigSchema.parse(JSON.parse(raw));
  const out: GraphConfig = {};
  if (parsed.graph?.entrypoints) out.entrypoints = parsed.graph.entrypoints;
  if (parsed.graph?.authPatterns) out.authPatterns = parsed.graph.authPatterns;
  return out;
}
