import { readFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import type { AwsActionAllowlist } from "@rampscan/schema";
import {
  DEFAULT_ALLOWLIST_PATH,
  awsActionOf,
  classifyAwsAction,
  isPlainlyRead,
  loadAwsActionAllowlist,
} from "../src/aws-actions.js";

// T1-1 (docs/PLAN-CLOUD-RUNNER.md, #167): the reviewed allowlist is golden
// against the pinned overlay. Every `aws <service> <operation>` any of the
// 49 recipes issues resolves to an entry a reviewer wrote — admitted with
// its IAM action and its reason, or refused with its reason. Nothing is
// unknown, because unknown is manual, and the count of runnable recipes the
// plan prints must come from this file and not from a verb regex.

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const OVERLAY = join(REPO_ROOT, "docs/context/ramprules/derived/aws-evidence.json");

interface Overlay {
  data: { recipes: Array<{ id: string; collection: { kind: string; commands?: string[] } }> };
}

/** every distinct aws action the pinned recipes issue, with the recipes that issue it */
async function pinnedActions(): Promise<Map<string, Set<string>>> {
  const overlay = JSON.parse(await readFile(OVERLAY, "utf8")) as Overlay;
  const out = new Map<string, Set<string>>();
  for (const recipe of overlay.data.recipes) {
    for (const command of recipe.collection.commands ?? []) {
      for (const segment of command.split("|")) {
        const action = awsActionOf(segment);
        if (action === undefined) continue;
        if (!out.has(action)) out.set(action, new Set());
        out.get(action)!.add(recipe.id);
      }
    }
  }
  return out;
}

let cached: AwsActionAllowlist | undefined;
async function allowlist(): Promise<AwsActionAllowlist> {
  cached ??= await loadAwsActionAllowlist(join(REPO_ROOT, DEFAULT_ALLOWLIST_PATH));
  return cached;
}

describe("T1-1 — the reviewed AWS action allowlist is golden against the pinned overlay (#167)", () => {
  it("parses as the strict contract, dated, pinned to the dataset it was read from", async () => {
    const list = await allowlist();
    expect(list.reviewed).toMatch(/^\d{4}-\d{2}-\d{2}$/);
    expect(list.dataset).toBe("2026.07.14.01");
  });

  it("every action the 49 recipes issue is admitted or refused — none is unknown", async () => {
    const list = await allowlist();
    const actions = await pinnedActions();
    expect(actions.size).toBeGreaterThan(100);
    const unknown = [...actions.keys()].filter((a) => classifyAwsAction(list, a).kind === "unknown");
    expect(unknown).toEqual([]);
  });

  it("every admitted or refused entry is issued by a pinned recipe — the list carries no dead weight", async () => {
    const list = await allowlist();
    const actions = await pinnedActions();
    const dead = [...list.admitted, ...list.refused].map((e) => e.cli).filter((cli) => !actions.has(cli));
    expect(dead).toEqual([]);
  });

  it("the two actions that change the account are refused, with the reason stated", async () => {
    const list = await allowlist();
    const send = classifyAwsAction(list, "ssm send-command");
    expect(send.kind).toBe("refused");
    if (send.kind === "refused") expect(send.entry.why).toMatch(/AWS-RunShellScript/);
    const athena = classifyAwsAction(list, "athena start-query-execution");
    expect(athena.kind).toBe("refused");
    if (athena.kind === "refused") expect(athena.entry.why).toMatch(/writes/);
    expect(list.refused).toHaveLength(2);
  });

  it("an admitted verb the pattern would not have read as read-only carries the reviewer's line", async () => {
    const list = await allowlist();
    const byReview = list.admitted.filter((e) => !isPlainlyRead(e));
    expect(byReview.map((e) => e.cli).sort()).toEqual([
      "cloudtrail start-query",
      "cloudtrail validate-logs",
      "iam generate-credential-report",
      "logs start-query",
    ]);
    for (const e of byReview) expect(e.review, e.cli).toMatch(/admitted by review, not by verb/);
    // and the plainly-read ones do not pretend to have been reviewed harder than they were
    for (const e of list.admitted.filter(isPlainlyRead)) expect(e.review, e.cli).toBeUndefined();
  });

  it("no cli action appears twice across the three lists, and every IAM action is well-formed", async () => {
    const list = await allowlist();
    const all = [...list.admitted, ...list.refused, ...list.runner].map((e) => e.cli);
    expect(new Set(all).size).toBe(all.length);
    for (const e of [...list.admitted, ...list.refused, ...list.runner]) {
      for (const iam of e.iam) expect(iam, e.cli).toMatch(/^[a-z0-9-]+:[A-Z][A-Za-z0-9]+$/);
    }
  });

  it("the runner's own two calls are listed apart: identity, and the self-check", async () => {
    const list = await allowlist();
    expect(list.runner.map((e) => e.cli).sort()).toEqual(["iam simulate-principal-policy", "sts get-caller-identity"]);
  });

  it("awsActionOf reads the service and operation past global options, and nothing from a non-aws segment", () => {
    expect(awsActionOf("aws iam get-credential-report --query Content --output text")).toBe("iam get-credential-report");
    expect(awsActionOf("  aws --profile audit --region us-gov-west-1 cloudtrail lookup-events")).toBe("cloudtrail lookup-events");
    expect(awsActionOf("aws --output=json ec2 describe-vpcs")).toBe("ec2 describe-vpcs");
    expect(awsActionOf(" base64 --decode")).toBeUndefined();
    expect(awsActionOf("jq '.Findings[]'")).toBeUndefined();
    expect(awsActionOf("aws")).toBeUndefined();
  });
});
