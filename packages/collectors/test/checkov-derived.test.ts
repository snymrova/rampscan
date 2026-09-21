import { describe, expect, it } from "vitest";
import { derivedObservations } from "../src/checkov.js";
import type { FailedCheck } from "../src/checkov.js";

// The soundness rule of the crosswalk-derived recipes (docs/PLAN-REACH.md
// N2-1): a KSI whose rule set matched nothing in the tree is `unevidenced`,
// never `evidenced`. Empty means clean only when the rules were there to
// fail — and "there" is decided by what checkov EVALUATED this run, passed
// or failed, not by what it reported as failed.

const failed: FailedCheck[] = [
  { check_id: "CKV_AWS_24", check_name: "ssh open", framework: "terraform", file: "main.tf", resource: "aws_security_group.a" },
  { check_id: "CKV_DOCKER_8", check_name: "root user", framework: "dockerfile", file: "Dockerfile", resource: "" },
];
const traffic = { id: "iac-traffic-restricted-declared", derived_from: { checks: ["CKV_AWS_24", "CKV_AWS_25"] } };
const surface = { id: "iac-attack-surface-declared", derived_from: { checks: ["CKV_DOCKER_3", "CKV_DOCKER_8"] } };
const backups = { id: "iac-backups-declared", derived_from: { checks: ["CKV_AWS_133", "CKV_AWS_134"] } };
const base = { id: "iac-baseline-clean" };

describe("derivedObservations — empty means clean only when the rules were evaluated", () => {
  it("a recipe none of whose rules ran gets NO observation set — unevidenced, not a vacuous pass", () => {
    // a Dockerfile-only tree: checkov evaluated the docker rules and never the terraform ones
    const evaluated = new Set(["CKV_DOCKER_3", "CKV_DOCKER_8"]);
    const out = derivedObservations(evaluated, [failed[1]!], [traffic, surface, backups]);
    expect(Object.keys(out)).toEqual(["iac-attack-surface-declared"]);
    expect(out["iac-traffic-restricted-declared"]).toBeUndefined();
    expect(out["iac-backups-declared"]).toBeUndefined();
  });

  it("a recipe whose rules ran and all passed gets an EMPTY set — a searched, clean result", () => {
    const evaluated = new Set(["CKV_AWS_24", "CKV_AWS_25", "CKV_AWS_133"]);
    const out = derivedObservations(evaluated, [], [traffic, backups]);
    expect(out).toEqual({ "iac-traffic-restricted-declared": [], "iac-backups-declared": [] });
  });

  it("one evaluated rule is enough to make the set exist, and only the recipe's own failures are its rows", () => {
    const evaluated = new Set(["CKV_AWS_24", "CKV_DOCKER_8"]);
    const out = derivedObservations(evaluated, failed, [traffic, surface]);
    expect(out["iac-traffic-restricted-declared"]).toEqual([failed[0]]);
    expect(out["iac-attack-surface-declared"]).toEqual([failed[1]]);
  });

  it("a recipe that derives from nothing is not this function's business", () => {
    expect(derivedObservations(new Set(["CKV_AWS_24"]), failed, [base])).toEqual({});
  });

  it("with no recipes handed in (an older caller, a unit test) it emits nothing", () => {
    expect(derivedObservations(new Set(["CKV_AWS_24"]), failed, [])).toEqual({});
  });
});
