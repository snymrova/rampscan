import { describe, expect, it } from "vitest";
import type { RecipeAssertion } from "@rampscan/schema";
import { cloudOffender, evaluateLabeledAssertion, labeledField } from "../src/assert-labeled.js";

// T2-5 (docs/PLAN-CLOUD-RUNNER.md, SPEC §14.4a): upstream's `<label>.<JMESPath>`
// vocabulary, op by op, over documents written by hand in the shapes the
// CLI prints. The discipline is the row evaluator's: population stated,
// nothing vacuous, offenders named where a resource is.

const NOW = new Date("2026-09-16T00:00:00Z");
const A = (field: string, op: RecipeAssertion["op"], value?: unknown, where?: RecipeAssertion["where"]): RecipeAssertion => ({
  field,
  op,
  ...(value !== undefined ? { value: value as never } : {}),
  ...(where !== undefined ? { where } : {}),
  description: `${field} ${op}`,
});

const CONFIG_DOC = {
  "restricted-ssh": {
    EvaluationResults: [
      {
        EvaluationResultIdentifier: { EvaluationResultQualifier: { ConfigRuleName: "restricted-ssh", ResourceType: "AWS::EC2::SecurityGroup", ResourceId: "sg-0aaa" } },
        ComplianceType: "NON_COMPLIANT",
      },
      {
        EvaluationResultIdentifier: { EvaluationResultQualifier: { ConfigRuleName: "restricted-ssh", ResourceType: "AWS::EC2::SecurityGroup", ResourceId: "sg-0bbb" } },
        ComplianceType: "NON_COMPLIANT",
      },
    ],
  },
  "vpc-default-security-group-closed": { EvaluationResults: [] },
};

describe("labeledField", () => {
  it("splits at the longest label the documents carry; a bare column is not labeled", () => {
    const labels = ["restricted-ssh", "restricted", "get-dnssec"];
    expect(labeledField("restricted-ssh.EvaluationResults", labels)).toEqual({ label: "restricted-ssh", path: "EvaluationResults" });
    expect(labeledField("get-dnssec.Status.ServeSignature", labels)).toEqual({ label: "get-dnssec", path: "Status.ServeSignature" });
    expect(labeledField("mfa_active", labels)).toBeUndefined();
    expect(labeledField("restricted-sshd.X", labels)).toBeUndefined();
  });
});

describe("evaluateLabeledAssertion — the ops over a step's document", () => {
  it("count_eq over an array: the length, the population, and each NON_COMPLIANT resource named", () => {
    const r = evaluateLabeledAssertion(A("restricted-ssh.EvaluationResults", "count_eq", 0), CONFIG_DOC, NOW);
    expect(r).toMatchObject({ passed: false, population: 2, offender_count: 2 });
    expect(r.offenders).toEqual([
      { resource_id: "sg-0aaa", resource_type: "AWS::EC2::SecurityGroup" },
      { resource_id: "sg-0bbb", resource_type: "AWS::EC2::SecurityGroup" },
    ]);
    const ok = evaluateLabeledAssertion(A("vpc-default-security-group-closed.EvaluationResults", "count_eq", 0), CONFIG_DOC, NOW);
    expect(ok).toMatchObject({ passed: true, population: 0 });
    expect(ok.detail).toContain("0 at EvaluationResults");
  });

  it("eq over a scalar, a boolean written as a string, and every element of a projection", () => {
    const docs = {
      "describe-organization": { Organization: { FeatureSet: "ALL" } },
      "identity-pool": { AllowUnauthenticatedIdentities: false },
      "get-dnssec": { KeySigningKeys: [{ Status: "ACTIVE" }, { Status: "INACTIVE" }] },
    };
    expect(evaluateLabeledAssertion(A("describe-organization.Organization.FeatureSet", "eq", "ALL"), docs, NOW).passed).toBe(true);
    expect(evaluateLabeledAssertion(A("identity-pool.AllowUnauthenticatedIdentities", "eq", "False"), docs, NOW).passed).toBe(true);
    const ksk = evaluateLabeledAssertion(A("get-dnssec.KeySigningKeys[].Status", "eq", "ACTIVE"), docs, NOW);
    expect(ksk).toMatchObject({ passed: false, population: 2, offender_count: 1 });
  });

  it("eq / max_age_days over nothing is a failure, never a vacuous pass; exists and not_exists read presence", () => {
    const docs = { "get-dnssec": { KeySigningKeys: [] }, "list-roots": { Roots: [{ PolicyTypes: [{ Type: "SERVICE_CONTROL_POLICY", Status: "ENABLED" }] }] } };
    const empty = evaluateLabeledAssertion(A("get-dnssec.KeySigningKeys[].Status", "eq", "ACTIVE"), docs, NOW);
    expect(empty).toMatchObject({ passed: false, population: 0 });
    expect(empty.detail).toMatch(/nothing at/);
    expect(evaluateLabeledAssertion(A("list-roots.Roots[0].PolicyTypes[?Type=='SERVICE_CONTROL_POLICY'] | [0].Status", "exists"), docs, NOW).passed).toBe(true);
    expect(evaluateLabeledAssertion(A("get-dnssec.KeySigningKeys[0].DSRecord", "exists"), docs, NOW)).toMatchObject({ passed: false, population: 0 });
    expect(evaluateLabeledAssertion(A("get-dnssec.KeySigningKeys[0]", "not_exists"), docs, NOW).passed).toBe(true);
  });

  it("lte and max_age_days over projected values, judged at the run's clock", () => {
    const docs = {
      "iam-user-unused-credentials-check": { ConfigRules: [{ InputParameters: { maxCredentialUsageAge: 45 } }] },
      "get-credential-report": { GeneratedTime: "2026-09-15T20:00:00Z" },
    };
    expect(evaluateLabeledAssertion(A("iam-user-unused-credentials-check.ConfigRules[].InputParameters.maxCredentialUsageAge", "lte", 90), docs, NOW).passed).toBe(true);
    expect(evaluateLabeledAssertion(A("get-credential-report.GeneratedTime", "max_age_days", 1), docs, NOW).passed).toBe(true);
    expect(evaluateLabeledAssertion(A("get-credential-report.GeneratedTime", "max_age_days", 1), docs, new Date("2026-09-18T00:00:00Z")).passed).toBe(false);
  });

  it("a labeled where is a guard over its own path: any element satisfying it lets the field be judged over every element", () => {
    const docs = {
      "get-account-authorization-details": {
        UserDetailList: [
          { UserName: "tmp-1", CreateDate: "2026-09-01T00:00:00Z", Tags: [{ Key: "AccountType", Value: "temporary" }] },
          { UserName: "old", CreateDate: "2025-01-01T00:00:00Z", Tags: [] },
        ],
      },
    };
    const where: RecipeAssertion["where"] = [
      { field: "get-account-authorization-details.UserDetailList[].Tags[?Key=='AccountType'].Value", op: "in", value: ["temporary", "emergency"] },
    ];
    const r = evaluateLabeledAssertion(A("get-account-authorization-details.UserDetailList[].CreateDate", "max_age_days", 90, where), docs, NOW);
    expect(r).toMatchObject({ passed: false, population: 2, offender_count: 1 });
    // and when no user is tagged, the guard does not hold and the assertion does not apply
    const none = { "get-account-authorization-details": { UserDetailList: [{ CreateDate: "2025-01-01T00:00:00Z", Tags: [] }] } };
    expect(evaluateLabeledAssertion(A("get-account-authorization-details.UserDetailList[].CreateDate", "max_age_days", 90, where), none, NOW)).toMatchObject({ passed: true, population: 0 });
  });

  it("a label the run did not produce, or a path that does not parse, is a failure that names the problem", () => {
    const r = evaluateLabeledAssertion(A("securityhub-enabled.EvaluationResults", "count_eq", 0), CONFIG_DOC, NOW);
    expect(r.passed).toBe(false);
    expect(r.detail).toMatch(/names no step of this run/);
    const bad = evaluateLabeledAssertion(A("restricted-ssh.EvaluationResults[?", "count_eq", 0), CONFIG_DOC, NOW);
    expect(bad.passed).toBe(false);
    expect(bad.detail).toMatch(/does not parse/);
  });

  it("cloudOffender reads AWS's own keys and invents nothing", () => {
    expect(cloudOffender({ Id: "arn:aws:x", Type: "Software", Region: "us-east-1" })).toEqual({ resource_id: "arn:aws:x", region: "us-east-1" });
    expect(cloudOffender({ Status: "pending" })).toBeUndefined();
    expect(cloudOffender("sg-1")).toBeUndefined();
  });
});
