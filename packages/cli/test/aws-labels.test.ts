import { createHash } from "node:crypto";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import jmespath from "jmespath";
import { describe, expect, it } from "vitest";
import { labeledField } from "@rampscan/core";
import { DEFAULT_DATASET_PIN, loadLocalDataset } from "@rampscan/dataset";
import type { AwsRecipe } from "@rampscan/dataset";
import { RUN_REQUEST_TYPE, RUN_TRANSCRIPT_TYPE, submissionVerdict } from "@rampscan/schema";
import type { RecipeAssertion, RunRequest, RunTranscript } from "@rampscan/schema";
import { DEFAULT_ALLOWLIST_PATH, loadAwsActionAllowlist } from "../src/aws-actions.js";
import { DEFAULT_BINDINGS_PATH, applyLiteralBindings, loadAwsLiteralBindings } from "../src/aws-bindings.js";
import { classifyAwsRecipe, placeholdersOf } from "../src/aws-classify.js";
import { DEFAULT_LABELS_PATH, derivedStepLabel, loadAwsStepLabels, stepLabels } from "../src/aws-labels.js";
import { intakeTranscript, requestDigest } from "../src/runs-intake.js";

// T2-5 (docs/PLAN-CLOUD-RUNNER.md, SPEC §14.4a): golden over the pinned
// overlay — every assertion of every recipe is either row-wise (a bare
// column) or names a label the recipe's steps carry, by rule or by the
// reviewed table, and every JMESPath compiles. Then one end-to-end run
// through the intake with a hand-written Config document, so the labeled
// vocabulary is proven from transcript to verdict, resource named.

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const sha256 = (s: string) => createHash("sha256").update(s).digest("hex");

async function inputs() {
  const ds = await loadLocalDataset(join(REPO_ROOT, "docs/context/ramprules/derived"), DEFAULT_DATASET_PIN);
  return {
    recipes: ds.recipes(),
    list: await loadAwsActionAllowlist(join(REPO_ROOT, DEFAULT_ALLOWLIST_PATH)),
    table: await loadAwsLiteralBindings(join(REPO_ROOT, DEFAULT_BINDINGS_PATH)),
    labels: await loadAwsStepLabels(join(REPO_ROOT, DEFAULT_LABELS_PATH)),
  };
}

const assertionsOf = (r: AwsRecipe): RecipeAssertion[] => (Array.isArray(r["assertions"]) ? (r["assertions"] as RecipeAssertion[]) : []);

/** every placeholder, the table's included, bound to a synthetic value so every recipe classifies to steps */
function bindAll(rs: readonly AwsRecipe[], table: Parameters<typeof applyLiteralBindings>[1]): Record<string, string> {
  const params: Record<string, string> = {};
  for (const r of rs) {
    for (const c of ((applyLiteralBindings(r, table).recipe.collection as { commands?: string[] }).commands ?? [])) {
      for (const n of placeholdersOf(c)) params[n] = `bound:${n}`;
    }
  }
  return params;
}

describe("T2-5 — every pinned assertion is row-wise or names a step the recipe has, and every path compiles", () => {
  it("22 recipes carry assertions; 20 use the labeled vocabulary, 2 the row vocabulary; nothing is unresolvable", async () => {
    const { recipes, list, table, labels } = await inputs();
    const params = bindAll(recipes, table);
    const withAssertions = recipes.filter((r) => assertionsOf(r).length > 0);
    expect(withAssertions).toHaveLength(22);
    const unresolvable: string[] = [];
    const notCompiling: string[] = [];
    let labeledRecipes = 0;
    let rowRecipes = 0;
    let labeledAssertions = 0;
    for (const r of withAssertions) {
      const c = classifyAwsRecipe(applyLiteralBindings(r, table).recipe, list, params);
      // the two refused recipes carry no assertions, so every recipe here classifies to steps
      expect(c.kind, r.id).toBe("runnable");
      if (c.kind !== "runnable") continue;
      const stepNames = stepLabels(r.id, c.steps.map((s) => s.argv), labels);
      let labeled = 0;
      for (const a of assertionsOf(r)) {
        const fields = [a.field, ...(a.where ?? []).map((w) => w.field)];
        for (const f of fields) {
          if (!f.includes(".")) continue; // a bare column: the row vocabulary
          const lf = labeledField(f, stepNames);
          if (lf === undefined) {
            unresolvable.push(`${r.id}: ${f} (steps: ${stepNames.join(", ")})`);
            continue;
          }
          labeled++;
          try {
            jmespath.search({}, lf.path);
          } catch (e) {
            notCompiling.push(`${r.id}: ${lf.path} — ${(e as Error).message}`);
          }
        }
      }
      if (labeled > 0) labeledRecipes++;
      else rowRecipes++;
      labeledAssertions += labeled;
    }
    expect(unresolvable).toEqual([]);
    expect(notCompiling).toEqual([]);
    expect([labeledRecipes, rowRecipes]).toEqual([20, 2]);
    expect(labeledAssertions).toBeGreaterThan(50);
  });

  it("every reviewed label row names a step the recipe has, and no row repeats the rule", async () => {
    const { recipes, list, table, labels } = await inputs();
    const params = bindAll(recipes, table);
    for (const row of labels.entries) {
      const r = recipes.find((x) => x.id === row.recipe);
      expect(r, row.recipe).toBeDefined();
      const c = classifyAwsRecipe(applyLiteralBindings(r!, table).recipe, list, params);
      expect(c.kind).toBe("runnable");
      if (c.kind !== "runnable") continue;
      const step = c.steps[row.step - 1];
      expect(step, `${row.recipe} step ${row.step}`).toBeDefined();
      expect(derivedStepLabel(step!.argv), `${row.recipe} step ${row.step} is already labeled by rule`).not.toBe(row.label);
    }
    expect(labels.dataset).toBe("2026.07.14.01");
  });

  it("the rule: the config rule name, the first of --config-rule-names, else the operation past global options", () => {
    expect(derivedStepLabel(["aws", "configservice", "get-compliance-details-by-config-rule", "--config-rule-name", "restricted-ssh"])).toBe("restricted-ssh");
    expect(derivedStepLabel(["aws", "configservice", "describe-config-rules", "--config-rule-names", "a", "b"])).toBe("a");
    expect(derivedStepLabel(["aws", "--profile", "x", "organizations", "describe-organization"])).toBe("describe-organization");
    expect(stepLabels("route53-dnssec-signing", [["aws", "route53", "list-hosted-zones"], ["aws", "route53", "get-dnssec"]], {
      _type: "https://rampscan.dev/aws-step-labels/v1",
      reviewed: "x",
      dataset: "x",
      rule: "x",
      entries: [{ recipe: "route53-dnssec-signing", step: 2, label: "public-zone-dnssec", why: "x" }],
    })).toEqual(["list-hosted-zones", "public-zone-dnssec"]);
  });

  it("end to end: config-network-boundary-protection over a planted open security group is violated, the resource named; three rules under one label merge", async () => {
    const { recipes } = await inputs();
    const recipe = recipes.find((r) => r.id === "config-network-boundary-protection")!;
    const rules = ["restricted-ssh", "vpc-sg-open-only-to-authorized-ports", "vpc-default-security-group-closed"];
    const docs = rules.map((rule) =>
      JSON.stringify({
        EvaluationResults:
          rule === "restricted-ssh"
            ? [
                {
                  EvaluationResultIdentifier: { EvaluationResultQualifier: { ConfigRuleName: rule, ResourceType: "AWS::EC2::SecurityGroup", ResourceId: "sg-0open" } },
                  ComplianceType: "NON_COMPLIANT",
                },
              ]
            : [],
      }) + "\n",
    );
    const request: RunRequest = {
      _type: RUN_REQUEST_TYPE,
      nonce: "5f2c9a1e7b3d4c6a8e0f1a2b3c4d5e6f",
      recipe_id: recipe.id,
      recipe_digest: sha256("recipe"),
      ksi: "KSI-CNA-ULN",
      params: {},
      issued_at: "2026-09-16T10:00:00Z",
      expires_at: "2026-09-16T11:00:00Z",
      requester: "operator@example.test",
    };
    const t: RunTranscript = {
      _type: RUN_TRANSCRIPT_TYPE,
      request_digest: requestDigest(request),
      nonce: request.nonce,
      recipe_id: recipe.id,
      ksi: request.ksi,
      runner: { name: "sidecar-1", caller_arn: "arn:aws:sts::111111111111:assumed-role/r/i", account: "111111111111", partition: "aws", region: "us-east-1" },
      steps: rules.map((rule, i) => ({
        argv: ["aws", "configservice", "get-compliance-details-by-config-rule", "--config-rule-name", rule, "--compliance-types", "NON_COMPLIANT"],
        exit_code: 0,
        started_at: "2026-09-16T10:05:00Z",
        finished_at: "2026-09-16T10:05:01Z",
        stdout_sha256: sha256(docs[i]!),
        stdout_bytes: Buffer.byteLength(docs[i]!),
        stderr_class: "none" as const,
      })),
      started_at: "2026-09-16T10:05:00Z",
      finished_at: "2026-09-16T10:05:10Z",
    };
    const outcome = intakeTranscript(t, new Map(docs.map((d) => [sha256(d), new TextEncoder().encode(d)])), {
      request,
      account: "111111111111",
      partition: "aws",
      assertions: assertionsOf(recipe),
      cadence: "monthly",
      acceptedNonces: new Set(),
      receivedAt: "2026-09-16T10:06:00Z",
    });
    expect(outcome.kind).toBe("submission");
    if (outcome.kind !== "submission") return;
    expect(submissionVerdict(outcome.submission)).toBe("violated");
    expect(outcome.submission.assertions.map((a) => [a.passed, a.population])).toEqual([[false, 1], [true, 0], [true, 0]]);
    expect(outcome.submission.assertions[0]!.offenders).toEqual([{ resource_id: "sg-0open", resource_type: "AWS::EC2::SecurityGroup" }]);
    expect(outcome.submission.automated).toBe(true);
  });
});
