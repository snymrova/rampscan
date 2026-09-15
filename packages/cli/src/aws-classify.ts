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
  /** the recipe publishes no commands at all */
  | { kind: "no-commands" };

export type RecipeClass =
  | { kind: "runnable"; steps: string[][] }
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
  const commands = (recipe.collection as { commands?: unknown }).commands;
  if (!Array.isArray(commands) || commands.length === 0) return { kind: "manual", reasons: [{ kind: "no-commands" }] };
  const reasons: ManualReason[] = [];
  const steps: string[][] = [];
  for (const raw of commands as unknown[]) {
    const command = String(raw);
    const split = splitCommand(command);
    if (split.construct !== undefined) {
      reasons.push({ kind: "shell", construct: split.construct, command });
    }
    // the action is judged on the first segment even when a construct follows,
    // so a piped `ssm send-command` is reported as refused AND as a pipe
    const action = awsActionOf(command.split("|")[0]!);
    if (action === undefined) {
      if (split.construct === undefined) reasons.push({ kind: "not-aws", command });
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
    if (split.construct === undefined) steps.push(split.argv.map((w) => bind(w, params)));
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
    case "no-commands":
      return "the recipe publishes no commands";
  }
}
