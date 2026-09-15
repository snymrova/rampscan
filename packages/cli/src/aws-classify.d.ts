import type { AwsRecipe } from "@rampscan/dataset";
import type { AwsActionAllowlist } from "@rampscan/schema";
export type ManualReason = 
/** the action is on the allowlist's `refused` list — the runner will never run it */
{
    kind: "refused-action";
    action: string;
    why: string;
}
/** the action is on neither list — manual until a reviewer reads it */
 | {
    kind: "unknown-action";
    action: string;
}
/** a `<NAME>` placeholder the bound parameters do not supply */
 | {
    kind: "unbound";
    name: string;
}
/** the command is not one argv: a pipe, a redirection, a substitution, or a chain */
 | {
    kind: "shell";
    construct: "pipe" | "redirect" | "substitution" | "chain";
    command: string;
}
/** the segment does not start with `aws` (a transform after a pipe reports as `pipe`, not here) */
 | {
    kind: "not-aws";
    command: string;
}
/**
 * The command is a `kubectl` read (T1-4a): a second axis the runner does
 * not have yet — cluster RBAC and an access entry, not an IAM policy —
 * so it is manual until T3-3 prints the ClusterRole beside the policy.
 * No pinned recipe issues one; the Paramify pilot's four scripts do.
 */
 | {
    kind: "kubectl";
    command: string;
}
/** the recipe publishes no commands at all */
 | {
    kind: "no-commands";
};
/**
 * The transforms a published pipe may become (T1-4). Applied by the runner
 * to captured stdout AFTER the raw bytes are digested and stored, so the
 * artifact is what the CLI printed and the transform is reproducible from
 * it. One exists in the pinned overlay: `iam get-credential-report` prints
 * base64 and the CSV the assertions read is the decoded bytes.
 */
export type StepTransform = "base64-decode";
export interface RecipeStep {
    argv: string[];
    transform?: StepTransform;
}
export type RecipeClass = {
    kind: "runnable";
    steps: RecipeStep[];
} | {
    kind: "manual";
    reasons: ManualReason[];
};
interface Split {
    argv: string[];
    construct?: "pipe" | "redirect" | "substitution" | "chain";
}
/**
 * Split one published command into argv the way a POSIX shell would, and
 * name the first construct that means it is NOT one argv. Single quotes are
 * literal (a JMESPath backtick or `$LATEST` inside them is text); double
 * quotes honour backslash and still carry `$`/backtick substitution; outside
 * quotes, `|`, `;`, `&&`, `||`, `<`, `>`, `$(`, `${`, `$NAME` and backticks
 * are constructs. A construct is reported, never executed around.
 */
export declare function splitCommand(command: string): Split;
/** every `<NAME>` in a command, in order, once each */
export declare function placeholdersOf(command: string): string[];
/**
 * Classify one pinned recipe under the reviewed allowlist and the bound
 * parameters. `params` is what T1-3 binds from `rampscan.config.json`;
 * pass `{}` to see every placeholder as a reason.
 */
export declare function classifyAwsRecipe(recipe: Pick<AwsRecipe, "id" | "collection">, list: AwsActionAllowlist, params?: Readonly<Record<string, string>>): RecipeClass;
/** one line per reason, for `rampscan recipes --aws` and the console's "manual because" */
export declare function describeReason(r: ManualReason): string;
export {};
//# sourceMappingURL=aws-classify.d.ts.map