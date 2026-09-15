import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { DEFAULT_DATASET_PIN, loadLocalDataset } from "@rampscan/dataset";
import type { AwsRecipe } from "@rampscan/dataset";
import type { AwsActionAllowlist } from "@rampscan/schema";
import { DEFAULT_ALLOWLIST_PATH, loadAwsActionAllowlist } from "../src/aws-actions.js";
import { classifyAwsRecipe, describeReason, placeholdersOf, splitCommand } from "../src/aws-classify.js";
import type { ManualReason } from "../src/aws-classify.js";

// T1-2 (docs/PLAN-CLOUD-RUNNER.md, #168): the classifier is golden over the
// 49 pinned recipes. The counts below are what the plan's §1 table is
// replaced by (ground rule 4 — computed, never typed): T1-5 prints them from
// the same function. Two readings — unbound, so every placeholder is a
// reason; and with every placeholder bound, so what remains is the shape of
// the commands themselves. No parameter table exists yet (T1-3): example
// literals such as `123456789012` are still literals here and are the next
// item's to turn into placeholders.

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");

let cachedList: AwsActionAllowlist | undefined;
async function list(): Promise<AwsActionAllowlist> {
  cachedList ??= await loadAwsActionAllowlist(join(REPO_ROOT, DEFAULT_ALLOWLIST_PATH));
  return cachedList;
}

async function recipes() {
  const ds = await loadLocalDataset(join(REPO_ROOT, "docs/context/ramprules/derived"), DEFAULT_DATASET_PIN);
  return ds.recipes();
}

/** every placeholder any recipe names, bound to a visibly synthetic value */
function bindAll(rs: readonly AwsRecipe[]): Record<string, string> {
  const params: Record<string, string> = {};
  for (const r of rs) {
    for (const c of ((r.collection as { commands?: string[] }).commands ?? [])) {
      for (const name of placeholdersOf(c)) params[name] = `bound:${name}`;
    }
  }
  return params;
}

const kinds = (reasons: ManualReason[]) => [...new Set(reasons.map((r) => r.kind))].sort();

describe("splitCommand — one argv, or the construct that means it is not", () => {
  it("splits words, honours single quotes as literal and double quotes with escapes", () => {
    expect(splitCommand("aws iam list-roles --query 'Roles[?MaxSessionDuration>`3600`]' --output json").argv).toEqual([
      "aws",
      "iam",
      "list-roles",
      "--query",
      "Roles[?MaxSessionDuration>`3600`]",
      "--output",
      "json",
    ]);
    expect(splitCommand(`aws ssm get-document --document-version '$LATEST'`).argv).toEqual([
      "aws",
      "ssm",
      "get-document",
      "--document-version",
      "$LATEST",
    ]);
    expect(splitCommand(String.raw`aws x y --a "he said \"hi\""`).argv).toEqual(["aws", "x", "y", "--a", 'he said "hi"']);
  });

  it("keeps a <PLACEHOLDER> as a word and does not read its angle brackets as redirection", () => {
    expect(splitCommand("aws sso-admin list-permission-sets --instance-arn <INSTANCE_ARN>").argv).toEqual([
      "aws",
      "sso-admin",
      "list-permission-sets",
      "--instance-arn",
      "<INSTANCE_ARN>",
    ]);
    expect(splitCommand("aws x y --start-time <T0> --end-time <T1>").construct).toBeUndefined();
  });

  it("names a pipe, a chain, a redirection and a substitution — and a | inside quotes is text", () => {
    expect(splitCommand("aws iam get-credential-report --output text | base64 --decode").construct).toBe("pipe");
    expect(splitCommand("aws a b && aws c d").construct).toBe("chain");
    expect(splitCommand("aws a b; aws c d").construct).toBe("chain");
    expect(splitCommand("aws a b > out.json").construct).toBe("redirect");
    expect(splitCommand("aws a b < in.json").construct).toBe("redirect");
    expect(splitCommand("aws a b --x $(date)").construct).toBe("substitution");
    expect(splitCommand("aws a b --x `date`").construct).toBe("substitution");
    expect(splitCommand("aws a b --x $HOME").construct).toBe("substitution");
    expect(splitCommand('aws a b --x "$HOME"').construct).toBe("substitution");
    expect(splitCommand("aws logs start-query --query-string 'fields a | filter b = 1'").construct).toBeUndefined();
    expect(splitCommand("aws a b --x 'unterminated").construct).toBe("substitution");
  });
});

describe("T1-2 — classifyAwsRecipe is golden over the 49 pinned recipes (#168)", () => {
  it("unbound: every placeholder is a reason, and the two refused actions are named on their recipes", async () => {
    const l = await list();
    const rs = await recipes();
    expect(rs).toHaveLength(49);
    const out = new Map(rs.map((r) => [r.id, classifyAwsRecipe(r, l)]));

    const runnable = [...out.values()].filter((c) => c.kind === "runnable").length;
    // computed, never typed: this is the number T1-5 prints and the plan's §1 table is replaced by
    expect(runnable).toBe(31);

    const clock = out.get("clock-synchronization-and-timestamps")!;
    expect(clock.kind).toBe("manual");
    if (clock.kind === "manual") {
      expect(clock.reasons.some((r) => r.kind === "refused-action" && r.action === "ssm send-command")).toBe(true);
    }
    const audit = out.get("audit-reduction-and-report-generation")!;
    expect(audit.kind).toBe("manual");
    if (audit.kind === "manual") {
      expect(kinds(audit.reasons)).toEqual(["refused-action", "unbound"]);
      expect(audit.reasons.find((r) => r.kind === "refused-action")).toMatchObject({ action: "athena start-query-execution" });
    }
    const jit = out.get("identity-center-jit-elevation-workflow")!;
    expect(jit.kind).toBe("manual");
    if (jit.kind === "manual") {
      expect(jit.reasons.map(describeReason)).toEqual([
        "unbound parameter <INSTANCE_ARN>",
        "unbound parameter <PERMISSION_SET_ARN>",
        "unbound parameter <ACCOUNT_ID>",
      ]);
    }
  });

  it("the one pipe in the overlay outside quotes is iam-credential-report's base64 — a step with a transform (T1-4), the raw bytes still the artifact", async () => {
    const l = await list();
    const rs = await recipes();
    const shell = rs
      .map((r) => [r.id, classifyAwsRecipe(r, l, bindAll(rs))] as const)
      .filter(([, c]) => c.kind === "manual" && c.reasons.some((x) => x.kind === "shell"));
    expect(shell).toEqual([]);
    const report = classifyAwsRecipe(rs.find((x: AwsRecipe) => x.id === "iam-credential-report")!, l);
    expect(report).toEqual({
      kind: "runnable",
      steps: [
        { argv: ["aws", "iam", "generate-credential-report"] },
        { argv: ["aws", "iam", "get-credential-report", "--query", "Content", "--output", "text"], transform: "base64-decode" },
      ],
    });
    // a pipe whose tail is not a known transform is still a shell construct
    const other = classifyAwsRecipe({ id: "x", collection: { kind: "cli", commands: ["aws iam list-roles | jq '.Roles[]'"] } }, l);
    expect(other).toEqual({
      kind: "manual",
      reasons: [{ kind: "shell", construct: "pipe", command: "aws iam list-roles | jq '.Roles[]'" }],
    });
    // and the head keeps its own judgment: a refused action piped into a transform is refused
    const refused = classifyAwsRecipe({ id: "x", collection: { kind: "cli", commands: ["aws ssm send-command --x y | base64 -d"] } }, l);
    expect(refused.kind).toBe("manual");
    if (refused.kind === "manual") expect(refused.reasons.map((r) => r.kind)).toEqual(["refused-action"]);
  });

  it("bound: what remains manual is a refused action — nothing is unknown, no pipe is left", async () => {
    const l = await list();
    const rs = await recipes();
    const params = bindAll(rs);
    const manual = rs
      .map((r) => [r.id, classifyAwsRecipe(r, l, params)] as const)
      .filter(([, c]) => c.kind === "manual");
    const summary = Object.fromEntries(manual.map(([id, c]) => [id, c.kind === "manual" ? kinds(c.reasons) : []]));
    expect(summary).toEqual({
      "audit-reduction-and-report-generation": ["refused-action"],
      "clock-synchronization-and-timestamps": ["refused-action"],
    });
    expect(rs.length - manual.length).toBe(47);
  });

  it("a runnable recipe's steps are argv with placeholders bound — the command run is the command published", async () => {
    const l = await list();
    const rs = await recipes();
    const r = rs.find((x: AwsRecipe) => x.id === "identity-center-jit-elevation-workflow")!;
    const c = classifyAwsRecipe(r, l, {
      INSTANCE_ARN: "arn:aws:sso:::instance/ssoins-0000",
      PERMISSION_SET_ARN: "arn:aws:sso:::permissionSet/ssoins-0000/ps-0000",
      ACCOUNT_ID: "111111111111",
    });
    expect(c.kind).toBe("runnable");
    if (c.kind === "runnable") {
      expect(c.steps[0]).toEqual({ argv: ["aws", "sso-admin", "list-instances", "--query", "Instances[0].InstanceArn", "--output", "text"] });
      expect(c.steps[1]).toEqual({ argv: ["aws", "sso-admin", "list-permission-sets", "--instance-arn", "arn:aws:sso:::instance/ssoins-0000"] });
      for (const step of c.steps) expect(step.argv.join(" ")).not.toMatch(/<[A-Z_]+>/);
    }
  });

  it("a config-rule recipe is runnable as published: whether the rule is deployed is a run-time failure, not a classification", async () => {
    const l = await list();
    const rs = await recipes();
    const r = rs.find((x: AwsRecipe) => x.id === "config-mfa-enabled-console-access")!;
    const c = classifyAwsRecipe(r, l);
    expect(c.kind).toBe("runnable");
    if (c.kind === "runnable") {
      expect(c.steps[0]!.argv.slice(0, 3)).toEqual(["aws", "configservice", "get-compliance-details-by-config-rule"]);
    }
  });

  it("a recipe with no commands, and one whose action nobody reviewed, are manual with the reason", async () => {
    const l = await list();
    expect(classifyAwsRecipe({ id: "x", collection: { kind: "narrative" } }, l)).toEqual({
      kind: "manual",
      reasons: [{ kind: "no-commands" }],
    });
    const c = classifyAwsRecipe({ id: "x", collection: { kind: "cli", commands: ["aws iam delete-user --user-name a"] } }, l);
    expect(c).toEqual({ kind: "manual", reasons: [{ kind: "unknown-action", action: "iam delete-user" }] });
  });

  it("a kubectl read is its own reason (T1-4a): a second axis the runner does not have yet", async () => {
    const l = await list();
    const c = classifyAwsRecipe({ id: "x", collection: { kind: "cli", commands: ["kubectl get pods -A -o json"] } }, l);
    expect(c).toEqual({ kind: "manual", reasons: [{ kind: "kubectl", command: "kubectl get pods -A -o json" }] });
    if (c.kind === "manual") expect(describeReason(c.reasons[0]!)).toMatch(/T1-4a/);
  });
});
