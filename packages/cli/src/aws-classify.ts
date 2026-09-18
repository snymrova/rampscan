import type { AwsRecipe } from "@rampscan/dataset";
import type { AwsActionAllowlist } from "@rampscan/schema";
import { awsActionOf, classifyAwsAction } from "./aws-actions.js";

// `classifyAwsRecipe` (docs/PLAN-CLOUD-RUNNER.md T1-2): a pure function from
// a pinned upstream recipe, the reviewed allowlist and the bound parameters
// to `runnable` — every command an argv the runner may execute as published
// — or `manual` with every reason. Reasons accumulate; a recipe is never
// manual for the first thing found when a reviewer would want to see all of
// them. Nothing here runs anything, and nothing here reads a verb.

export type ManualReason =
  /** the action is on the allowlist's `refused` list — the runner will never run it */
  | { kind: "refused-action"; action: string; why: string }
  /** the action is on neither list — manual until a reviewer reads it */
  | { kind: "unknown-action"; action: string }
  /** a `<NAME>` placeholder the bound parameters do not supply */
  | { kind: "unbound"; name: string }
  /** the command is not one argv: a pipe, a redirection, a substitution, or a chain */
  | { kind: "shell"; construct: "pipe" | "redirect" | "substitution" | "chain"; command: string }
  /** the segment does not start with `aws` (a transform after a pipe reports as `pipe`, not here) */
  | { kind: "not-aws"; command: string }
  /**
   * The command is a `kubectl` read (T1-4a): a second axis the runner does
   * not have yet — cluster RBAC and an access entry, not an IAM policy —
   * so it is manual until T3-3 prints the ClusterRole beside the policy.
   * No pinned recipe issues one; the Paramify pilot's four scripts do.
   */
  | { kind: "kubectl"; command: string }
  /** the recipe publishes no commands at all */
  | { kind: "no-commands" };

/**
 * The transforms a published pipe may become (T1-4). Applied by the runner
 * to captured stdout AFTER the raw bytes are digested and stored, so the
 * artifact is what the CLI printed and the transform is reproducible from
 * it. One exists in the pinned overlay: `iam get-credential-report` prints
 * base64 and the CSV the assertions read is the decoded bytes.
 */
export type StepTransform = "base64-decode";

/** what a published pipe tail may be, exactly — anything else is a shell construct */
const TRANSFORM_TAILS: ReadonlyMap<string, StepTransform> = new Map([
  ["base64 --decode", "base64-decode"],
  ["base64 -d", "base64-decode"],
]);

export interface RecipeStep {
  argv: string[];
  /**
   * The name upstream published for this step, which is the label an
   * assertion's `<label>.<JMESPath>` addresses its document by (SPEC §14.4a).
   * Upstream's, never derived here: it travels from the overlay through the
   * request into intake, so no index is ever the join.
   */
  label: string;
  transform?: StepTransform;
}

export type RecipeClass =
  | { kind: "runnable"; steps: RecipeStep[] }
  | { kind: "manual"; reasons: ManualReason[] };

const PLACEHOLDER = /<([A-Za-z][A-Za-z0-9_-]*)>/g;

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
export function splitCommand(command: string): Split {
  const argv: string[] = [];
  let word = "";
  let inWord = false;
  let i = 0;
  const s = command;
  const push = () => {
    if (inWord) argv.push(word);
    word = "";
    inWord = false;
  };
  while (i < s.length) {
    const c = s[i]!;
    if (c === "'") {
      const end = s.indexOf("'", i + 1);
      if (end === -1) return { argv, construct: "substitution" };
      word += s.slice(i + 1, end);
      inWord = true;
      i = end + 1;
      continue;
    }
    if (c === '"') {
      let j = i + 1;
      while (j < s.length && s[j] !== '"') {
        if (s[j] === "\\" && j + 1 < s.length) {
          word += s[j + 1];
          j += 2;
          continue;
        }
        if (s[j] === "$" || s[j] === "`") return { argv, construct: "substitution" };
        word += s[j];
        j++;
      }
      if (j >= s.length) return { argv, construct: "substitution" };
      inWord = true;
      i = j + 1;
      continue;
    }
    if (c === "\\" && i + 1 < s.length) {
      word += s[i + 1];
      inWord = true;
      i += 2;
      continue;
    }
    if (c === " " || c === "\t" || c === "\n") {
      push();
      i++;
      continue;
    }
    if (c === "|") return { argv, construct: s[i + 1] === "|" ? "chain" : "pipe" };
    if (c === ";" || (c === "&" && s[i + 1] === "&")) return { argv, construct: "chain" };
    if (c === "<" || c === ">") {
      // `<NAME>` is a placeholder, not a redirection — it is bound, not read
      const m = /^<([A-Za-z][A-Za-z0-9_-]*)>/.exec(s.slice(i));
      if (c === "<" && m) {
        word += m[0];
        inWord = true;
        i += m[0].length;
        continue;
      }
      return { argv, construct: "redirect" };
    }
    if (c === "`" || (c === "$" && /[({A-Za-z_]/.test(s[i + 1] ?? ""))) {
      return { argv, construct: "substitution" };
    }
    word += c;
    inWord = true;
    i++;
  }
  push();
  return { argv };
}

/** the offset of the first `|` outside quotes, or -1 */
function pipeIndex(command: string): number {
  let q: string | undefined;
  for (let i = 0; i < command.length; i++) {
    const c = command[i]!;
    if (q !== undefined) {
      if (c === "\\" && q === '"') i++;
      else if (c === q) q = undefined;
    } else if (c === "'" || c === '"') q = c;
    else if (c === "\\") i++;
    else if (c === "|") return i;
  }
  return -1;
}

/** every `<NAME>` in a command, in order, once each */
export function placeholdersOf(command: string): string[] {
  const out: string[] = [];
  for (const m of command.matchAll(PLACEHOLDER)) if (!out.includes(m[1]!)) out.push(m[1]!);
  return out;
}

function bind(word: string, params: Readonly<Record<string, string>>): string {
  return word.replace(PLACEHOLDER, (whole, name: string) => params[name] ?? whole);
}

/**
 * Classify one pinned recipe under the reviewed allowlist and the bound
 * parameters. `params` is what T1-3 binds from `rampscan.config.json`;
 * pass `{}` to see every placeholder as a reason.
 */
export function classifyAwsRecipe(
  recipe: Pick<AwsRecipe, "id" | "collection">,
  list: AwsActionAllowlist,
  params: Readonly<Record<string, string>> = {},
): RecipeClass {
  const commands = recipe.collection.commands;
  if (commands === undefined || commands.length === 0) return { kind: "manual", reasons: [{ kind: "no-commands" }] };
  const reasons: ManualReason[] = [];
  const steps: RecipeStep[] = [];
  for (const { name, run: command } of commands) {
    let split = splitCommand(command);
    let transform: StepTransform | undefined;
    if (split.construct === "pipe") {
      // a pipe whose tail is exactly a known transform is a step, not a
      // shell; the head is re-split on its own so its own constructs still count
      const at = pipeIndex(command);
      const tail = TRANSFORM_TAILS.get(command.slice(at + 1).trim());
      if (tail !== undefined) {
        split = splitCommand(command.slice(0, at));
        transform = tail;
      }
    }
    if (split.construct !== undefined) {
      reasons.push({ kind: "shell", construct: split.construct, command });
    }
    // the action is judged on the first segment even when a construct follows,
    // so a piped `ssm send-command` is reported as refused AND as a pipe
    const action = awsActionOf(command.split("|")[0]!);
    if (action === undefined) {
      if (/^\s*kubectl\s/.test(command)) reasons.push({ kind: "kubectl", command });
      else if (split.construct === undefined) reasons.push({ kind: "not-aws", command });
    } else {
      const cls = classifyAwsAction(list, action);
      if (cls.kind === "refused") reasons.push({ kind: "refused-action", action, why: cls.entry.why });
      else if (cls.kind === "unknown") reasons.push({ kind: "unknown-action", action });
    }
    for (const name of placeholdersOf(command)) {
      if (params[name] === undefined && !reasons.some((r) => r.kind === "unbound" && r.name === name)) {
        reasons.push({ kind: "unbound", name });
      }
    }
    if (split.construct === undefined) {
      const argv = split.argv.map((w) => bind(w, params));
      steps.push(transform === undefined ? { argv, label: name } : { argv, label: name, transform });
    }
  }
  return reasons.length > 0 ? { kind: "manual", reasons } : { kind: "runnable", steps };
}

/** one line per reason, for `rampscan recipes --aws` and the console's "manual because" */
export function describeReason(r: ManualReason): string {
  switch (r.kind) {
    case "refused-action":
      return `refused action ${r.action}: ${r.why}`;
    case "unknown-action":
      return `action ${r.action} is on neither list — manual until reviewed`;
    case "unbound":
      return `unbound parameter <${r.name}>`;
    case "shell":
      return `shell ${r.construct} in: ${r.command}`;
    case "not-aws":
      return `not an aws invocation: ${r.command}`;
    case "kubectl":
      return `kubectl is a second axis the runner does not have yet (T1-4a): ${r.command}`;
    case "no-commands":
      return "the recipe publishes no commands";
  }
}
