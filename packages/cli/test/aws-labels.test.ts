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
import { derivedStepLabel } from "../src/aws-labels.js";
import { intakeTranscript, requestDigest } from "../src/runs-intake.js";

// T2-5 (docs/PLAN-CLOUD-RUNNER.md, SPEC §14.4a): golden over the pinned
// overlay — every assertion of every recipe names a step the recipe
// publishes, BY THE NAME UPSTREAM GAVE IT, and every JMESPath compiles.
// This test is what replaced `recipes/aws-actions/labels.json`: the five
// labels that table carried by hand are now upstream's own step names, so
// the check is no longer "the reviewed rows are current" but the stronger
// "no assertion addresses a step that does not exist". Then one end-to-end
// run through the intake with a hand-written Config document, so the
// labeled vocabulary is proven from transcript to verdict, resource named.

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const sha256 = (s: string) => createHash("sha256").update(s).digest("hex");

async function inputs() {
  const ds = await loadLocalDataset(join(REPO_ROOT, "docs/context/ramprules/derived"), DEFAULT_DATASET_PIN);
  return {
    recipes: ds.recipes(),
    list: await loadAwsActionAllowlist(join(REPO_ROOT, DEFAULT_ALLOWLIST_PATH)),
    table: await loadAwsLiteralBindings(join(REPO_ROOT, DEFAULT_BINDINGS_PATH)),
  };
}

const assertionsOf = (r: AwsRecipe): RecipeAssertion[] => (Array.isArray(r["assertions"]) ? (r["assertions"] as RecipeAssertion[]) : []);

/** every placeholder, the table's included, bound to a synthetic value so every recipe classifies to steps */
function bindAll(rs: readonly AwsRecipe[], table: Parameters<typeof applyLiteralBindings>[1]): Record<string, string> {
  const params: Record<string, string> = {};
  for (const r of rs) {
    for (const step of applyLiteralBindings(r, table).recipe.collection.commands ?? []) {
      for (const n of placeholdersOf(step.run)) params[n] = `bound:${n}`;
    }
  }
  return params;
}

describe("T2-5 — every pinned assertion names a step the recipe publishes, and every path compiles", () => {
  it("36 recipes carry assertions; all 188 resolve to a step the recipe publishes, and no two steps of one recipe share a name", async () => {
    const { recipes } = await inputs();
    const withAssertions = recipes.filter((r) => assertionsOf(r).length > 0);
    expect(withAssertions).toHaveLength(36);
    const unresolvable: string[] = [];
    const notCompiling: string[] = [];
    const collided: string[] = [];
    let resolved = 0;
    for (const r of withAssertions) {
      // the PUBLISHED names, so a recipe that is manual under this config is
      // checked too — whether an assertion addresses a step that exists is a
      // fact about upstream's file, not about what the runner may execute
      const stepNames = (r.collection.commands ?? []).map((c) => c.name);
      for (const [i, n] of stepNames.entries()) if (stepNames.indexOf(n) !== i) collided.push(`${r.id}: ${n}`);
      for (const a of assertionsOf(r)) {
        const lf = labeledField(a.field, stepNames);
        if (lf === undefined) {
          unresolvable.push(`${r.id}: ${a.field} (steps: ${stepNames.join(", ")})`);
          continue;
        }
        resolved++;
        for (const path of [lf.path, ...(a.where ?? []).map((w) => w.field)]) {
          try {
            jmespath.search({}, path);
          } catch (e) {
            notCompiling.push(`${r.id}: ${path} — ${(e as Error).message}`);
          }
        }
      }
    }
    expect(unresolvable).toEqual([]);
    expect(notCompiling).toEqual([]);
    expect(collided).toEqual([]);
    expect(resolved).toBe(188);
  });

  it("what the classifier hands the request is exactly those published names, for all 54 runnable recipes", async () => {
    const { recipes, list, table } = await inputs();
    const params = bindAll(recipes, table);
    const manual: string[] = [];
    const drifted: string[] = [];
    for (const r of recipes) {
      const c = classifyAwsRecipe(applyLiteralBindings(r, table).recipe, list, params);
      if (c.kind !== "runnable") {
        manual.push(r.id);
        continue;
      }
      const published = (r.collection.commands ?? []).map((x) => x.name);
      if (c.steps.map((x) => x.label).join("|") !== published.join("|")) drifted.push(r.id);
    }
    expect(drifted).toEqual([]);
    // the only recipes that do not classify are the three that issue a write
    // the allowlist refuses: a shell command, an Athena query, an SBOM export
    expect(manual.sort()).toEqual(["acquisition-scanning-and-sbom-inventory", "audit-reduction-and-report-generation", "clock-synchronization-and-timestamps"]);
    expect(recipes.length - manual.length).toBe(54);
  });

  it("the classifier carries upstream's name, never an index: the credential report's three steps", async () => {
    const { recipes, list, table } = await inputs();
    const report = recipes.find((r) => r.id === "iam-credential-report")!;
    const c = classifyAwsRecipe(applyLiteralBindings(report, table).recipe, list, {});
    expect(c.kind).toBe("runnable");
    if (c.kind !== "runnable") return;
    expect(c.steps.map((s) => s.label)).toEqual(["generate-credential-report", "credential-report-generated-time", "credential-report"]);
    // and the assertions address the second and third by those names — the
    // reviewed table this replaced would have had to key them 2 and 3, which
    // is exactly the join that broke when upstream inserted the middle step
    expect(assertionsOf(report).map((a) => a.field)).toEqual([
      "credential-report-generated-time",
      "credential-report[].mfa_active",
      "credential-report[].access_key_1_last_rotated",
      "credential-report[].access_key_2_last_rotated",
    ]);
  });

  it("the rule, kept only for a transcript that arrives with no names: the config rule name, else the operation", () => {
    expect(derivedStepLabel(["aws", "configservice", "get-compliance-details-by-config-rule", "--config-rule-name", "restricted-ssh"])).toBe("restricted-ssh");
    expect(derivedStepLabel(["aws", "configservice", "describe-config-rules", "--config-rule-names", "a", "b"])).toBe("a");
    expect(derivedStepLabel(["aws", "--profile", "x", "organizations", "describe-organization"])).toBe("describe-organization");
  });

  it("end to end: config-network-boundary-protection over a planted open security group is violated, the resource named, and upstream's own anti-vacuity steps judged", async () => {
    const { recipes, list, table } = await inputs();
    const recipe = recipes.find((r) => r.id === "config-network-boundary-protection")!;
    const cls = classifyAwsRecipe(applyLiteralBindings(recipe, table).recipe, list, {});
    expect(cls.kind).toBe("runnable");
    if (cls.kind !== "runnable") return;
    // nine steps: three Config rules, the recorder's status, one evaluation
    // status per rule, and the region and account catalogues. Three of the
    // names could not be derived from the argv — `--config-rule-names
    // restricted-ssh` appears in two steps — which is why the name is
    // upstream's and the index is nobody's join.
    const labels = cls.steps.map((s) => s.label);
    expect(labels).toEqual([
      "restricted-ssh",
      "vpc-sg-open-only-to-authorized-ports",
      "vpc-default-security-group-closed",
      "configuration-recorder-status",
      "restricted-ssh-evaluation-status",
      "vpc-sg-open-only-to-authorized-ports-evaluation-status",
      "vpc-default-security-group-closed-evaluation-status",
      "describe-regions",
      "list-accounts",
    ]);
    const evaluated = JSON.stringify({ ConfigRulesEvaluationStatus: [{ FirstEvaluationStarted: true, LastSuccessfulEvaluationTime: "2026-09-16T09:00:00Z" }] }) + "\n";
    const bodies = [
      JSON.stringify({
        EvaluationResults: [
          {
            EvaluationResultIdentifier: { EvaluationResultQualifier: { ConfigRuleName: "restricted-ssh", ResourceType: "AWS::EC2::SecurityGroup", ResourceId: "sg-0open" } },
            ComplianceType: "NON_COMPLIANT",
          },
        ],
      }) + "\n",
      JSON.stringify({ EvaluationResults: [] }) + "\n",
      JSON.stringify({ EvaluationResults: [] }) + "\n",
      JSON.stringify({ ConfigurationRecordersStatus: [{ name: "default", recording: true, lastStatus: "SUCCESS" }] }) + "\n",
      evaluated,
      evaluated,
      evaluated,
      "us-east-1\tus-west-2\n",
      "111111111111\n",
    ];
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
      self_check: { probes: ["iam:CreateUser"], all_denied: true },
      steps: cls.steps.map((step, i) => ({
        argv: step.argv,
        exit_code: 0,
        started_at: "2026-09-16T10:05:00Z",
        finished_at: "2026-09-16T10:05:01Z",
        stdout_sha256: sha256(bodies[i]!),
        stdout_bytes: Buffer.byteLength(bodies[i]!),
        stderr_class: "none" as const,
      })),
      started_at: "2026-09-16T10:05:00Z",
      finished_at: "2026-09-16T10:05:10Z",
    };
    const outcome = intakeTranscript(t, new Map(bodies.map((d) => [sha256(d), new TextEncoder().encode(d)])), {
      request,
      account: "111111111111",
      partition: "aws",
      assertions: assertionsOf(recipe),
      labels,
      cadence: "monthly",
      acceptedNonces: new Set(),
      receivedAt: "2026-09-16T10:06:00Z",
    });
    expect(outcome.kind).toBe("submission");
    if (outcome.kind !== "submission") return;
    expect(submissionVerdict(outcome.submission)).toBe("violated");
    expect(outcome.submission.assertions.map((a) => [a.passed, a.population])).toEqual([
      [false, 1],
      [true, 0],
      [true, 0],
      [true, 1],
      [true, 1],
      [true, 1],
      [true, 1],
      [true, 1],
      [true, 1],
      [true, 1],
    ]);
    expect(outcome.submission.assertions[0]!.offenders).toEqual([{ resource_id: "sg-0open", resource_type: "AWS::EC2::SecurityGroup" }]);
    expect(outcome.submission.automated).toBe(true);
    // and the recorder being off is caught rather than read as a clean rule set
    const off = bodies.slice();
    off[3] = JSON.stringify({ ConfigurationRecordersStatus: [{ name: "default", recording: false, lastStatus: "PENDING" }] }) + "\n";
    const offSteps = t.steps.map((step, i) => ({ ...step, stdout_sha256: sha256(off[i]!), stdout_bytes: Buffer.byteLength(off[i]!) }));
    const offOutcome = intakeTranscript(
      { ...t, steps: offSteps, request_digest: requestDigest(request) },
      new Map(off.map((d) => [sha256(d), new TextEncoder().encode(d)])),
      { request, account: "111111111111", partition: "aws", assertions: assertionsOf(recipe), labels, cadence: "monthly", acceptedNonces: new Set(), receivedAt: "2026-09-16T10:06:00Z" },
    );
    expect(offOutcome.kind).toBe("submission");
    if (offOutcome.kind !== "submission") return;
    expect(offOutcome.submission.assertions[3]).toMatchObject({ passed: false, population: 1 });
  });
});
