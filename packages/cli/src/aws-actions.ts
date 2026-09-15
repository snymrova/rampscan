import { readFile } from "node:fs/promises";
import { AwsActionAllowlist } from "@rampscan/schema";
import type { AwsActionEntry } from "@rampscan/schema";

// Reading the reviewed allowlist (T1-1) and looking a recipe's commands up in
// it. The classifier (T1-2) and the policy generator (T3-3) both come through
// here; neither ever decides an action by its verb.

/** the checked-in list; `rampscan runner policy` and `recipes --aws` read this path by default */
export const DEFAULT_ALLOWLIST_PATH = "recipes/aws-actions/allowlist.json";

export async function loadAwsActionAllowlist(path: string): Promise<AwsActionAllowlist> {
  return AwsActionAllowlist.parse(JSON.parse(await readFile(path, "utf8")));
}

/**
 * The `<service> <operation>` of one shell segment, or undefined when the
 * segment is not an `aws` invocation at all (a pipe into `base64`, `jq`, or
 * a bare word). Global options before the service (`aws --profile x iam …`)
 * are skipped; anything else is the caller's to refuse as a shell construct.
 */
export function awsActionOf(segment: string): string | undefined {
  const words = segment.trim().split(/\s+/);
  if (words[0] !== "aws") return undefined;
  const rest: string[] = [];
  for (let i = 1; i < words.length && rest.length < 2; i++) {
    const w = words[i]!;
    if (w.startsWith("--")) {
      // a global option with a value (`--profile x`, `--region r`)
      if (!w.includes("=")) i++;
      continue;
    }
    rest.push(w);
  }
  return rest.length === 2 ? `${rest[0]} ${rest[1]}` : undefined;
}

export type ActionClass =
  | { kind: "admitted"; entry: AwsActionEntry }
  | { kind: "refused"; entry: AwsActionEntry }
  /** on neither list: manual until a reviewer reads it — never runnable by default */
  | { kind: "unknown" };

export function classifyAwsAction(list: AwsActionAllowlist, cli: string): ActionClass {
  const admitted = list.admitted.find((e) => e.cli === cli);
  if (admitted) return { kind: "admitted", entry: admitted };
  const refused = list.refused.find((e) => e.cli === cli);
  if (refused) return { kind: "refused", entry: refused };
  return { kind: "unknown" };
}

/** the verbs a reviewer may admit without a `review` line — everything else needs one */
const PLAINLY_READ = /^(describe|get|list|lookup|select|batch-get)(-|$)/;

/** whether an admitted entry's operation is one the verb alone would have admitted */
export function isPlainlyRead(entry: AwsActionEntry): boolean {
  const op = entry.cli.split(" ")[1] ?? "";
  return PLAINLY_READ.test(op);
}
