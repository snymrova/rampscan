import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { DEFAULT_DATASET_PIN, loadLocalDataset } from "@rampscan/dataset";
import { DENIAL_PROBES as RUNNER_PROBES } from "@rampscan/runner";
import { AwsConfig } from "@rampscan/schema";
import { DEFAULT_ALLOWLIST_PATH, loadAwsActionAllowlist } from "../src/aws-actions.js";
import { DEFAULT_BINDINGS_PATH, loadAwsLiteralBindings } from "../src/aws-bindings.js";
import { classifyAwsRecipes, windowEnding } from "../src/aws-recipes.js";
import { DENIAL_PROBES, runnerPolicy } from "../src/runner-policy.js";

// T3-3 (docs/PLAN-CLOUD-RUNNER.md, #178): the policy is generated from the
// allowlist for exactly the runnable recipes — never typed, never wider
// than what a reviewer read — and the probe set the runner checks is the
// one the appliance names.

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const NOW = new Date("2026-09-16T12:00:00Z");

async function inputs() {
  const ds = await loadLocalDataset(join(REPO_ROOT, "docs/context/ramprules/derived"), DEFAULT_DATASET_PIN);
  return {
    recipes: ds.recipes(),
    list: await loadAwsActionAllowlist(join(REPO_ROOT, DEFAULT_ALLOWLIST_PATH)),
    table: await loadAwsLiteralBindings(join(REPO_ROOT, DEFAULT_BINDINGS_PATH)),
  };
}

describe("rampscan runner policy (T3-3)", () => {
  it("the runner's probe set is the appliance's, action for action", () => {
    expect([...RUNNER_PROBES]).toEqual([...DENIAL_PROBES]);
    expect(DENIAL_PROBES).toContain("ssm:SendCommand");
    expect(DENIAL_PROBES).toContain("athena:StartQueryExecution");
  });

  it("no config: the actions of the 22 runnable recipes plus the runner's own; no refused action, no mutating probe, reproducible", async () => {
    const { recipes, list, table } = await inputs();
    const report = classifyAwsRecipes(recipes, list, table, undefined, windowEnding(NOW, 30), DEFAULT_DATASET_PIN);
    const { policy, recipes: runnable } = runnerPolicy(report, list);
    expect(runnable).toHaveLength(22);
    expect(policy.Version).toBe("2012-10-17");
    const [own, reads] = policy.Statement;
    expect(own!.Action).toEqual(["iam:SimulatePrincipalPolicy", "sts:GetCallerIdentity"]);
    expect(reads!.Action).toContain("iam:GetCredentialReport");
    expect(reads!.Action).toContain("iam:GenerateCredentialReport");
    expect(reads!.Action).toContain("config:GetComplianceDetailsByConfigRule");
    for (const refused of list.refused.flatMap((e) => e.iam)) expect(reads!.Action).not.toContain(refused);
    for (const probe of DENIAL_PROBES) expect(reads!.Action).not.toContain(probe);
    expect(reads!.Action).toEqual([...reads!.Action].sort());
    expect(new Set(reads!.Action).size).toBe(reads!.Action.length);
    // the same inputs, the same bytes
    expect(JSON.stringify(runnerPolicy(report, list).policy)).toBe(JSON.stringify(policy));
  });

  it("binding parameters widens the runnable set and therefore the policy — and only that way", async () => {
    const { recipes, list, table } = await inputs();
    const bare = runnerPolicy(classifyAwsRecipes(recipes, list, table, undefined, windowEnding(NOW, 30), DEFAULT_DATASET_PIN), list);
    const aws = AwsConfig.parse({ account_id: "111111111111", partition: "aws", regions: ["us-east-1"], params: { INSTANCE_ID: "i-0aaa", SECURITY_GROUP_ID: "sg-0aaa" } });
    const bound = runnerPolicy(classifyAwsRecipes(recipes, list, table, aws, windowEnding(NOW, 30), DEFAULT_DATASET_PIN), list);
    expect(bound.recipes.length).toBeGreaterThan(bare.recipes.length);
    expect(bound.recipes).toContain("patch-and-vulnerability-remediation");
    const bareReads = new Set(bare.policy.Statement[1]!.Action);
    for (const a of bareReads) expect(bound.policy.Statement[1]!.Action).toContain(a);
    expect(bound.policy.Statement[1]!.Action).toContain("inspector2:BatchGetAccountStatus");
    expect(bareReads.has("inspector2:BatchGetAccountStatus")).toBe(false);
  });
});
