import type { AwsActionAllowlist } from "@rampscan/schema";
import { awsActionOf, classifyAwsAction } from "./aws-actions.js";
import type { AwsRecipesReport } from "./aws-recipes.js";

// `rampscan runner policy` (docs/PLAN-CLOUD-RUNNER.md T3-3): the IAM policy
// the client attaches to the runner's role, generated from the reviewed
// allowlist and ONLY for the recipes that classify runnable under the
// current parameters — the role can do exactly what the admitted recipes
// need, plus the two calls the runner makes on its own behalf, and nothing
// the reviewer did not read. Resource "*" throughout: these are read APIs
// whose resource-level restriction would need the account's own ARNs, and
// a policy that is too narrow fails closed (a denied step is a failed run),
// never open.

export interface RunnerPolicy {
  Version: "2012-10-17";
  Statement: Array<{ Sid: string; Effect: "Allow"; Action: string[]; Resource: "*" }>;
}

/** the mutating actions the self-check probes; every one must be denied to the role */
export const DENIAL_PROBES = [
  "iam:CreateUser",
  "iam:AttachRolePolicy",
  "iam:PutUserPolicy",
  "iam:CreateAccessKey",
  "s3:PutObject",
  "s3:DeleteObject",
  "ec2:RunInstances",
  "ec2:AuthorizeSecurityGroupIngress",
  "ssm:SendCommand",
  "cloudtrail:StopLogging",
  "config:StopConfigurationRecorder",
  "guardduty:DeleteDetector",
  "kms:ScheduleKeyDeletion",
  "athena:StartQueryExecution",
] as const;

/**
 * The IAM actions the runnable recipes need, from the allowlist: every
 * admitted entry each runnable step's action resolves to. Read once per
 * step, never by verb. Sorted and de-duplicated, so the policy is
 * reproducible from the same inputs.
 */
export function iamActionsFor(report: AwsRecipesReport, list: AwsActionAllowlist): { actions: string[]; recipes: string[] } {
  const actions = new Set<string>();
  const recipes: string[] = [];
  for (const r of report.recipes) {
    if (r.result.kind !== "runnable") continue;
    recipes.push(r.id);
    for (const step of r.result.steps) {
      const cli = awsActionOf(step.argv.join(" "));
      if (cli === undefined) continue;
      const cls = classifyAwsAction(list, cli);
      if (cls.kind !== "admitted") throw new Error(`runnable recipe ${r.id} issues ${cli}, which the allowlist does not admit — the classifier and the allowlist disagree`);
      for (const a of cls.entry.iam) actions.add(a);
    }
  }
  return { actions: [...actions].sort(), recipes };
}

export function runnerPolicy(report: AwsRecipesReport, list: AwsActionAllowlist): { policy: RunnerPolicy; recipes: string[] } {
  const { actions, recipes } = iamActionsFor(report, list);
  const own = list.runner.flatMap((e) => e.iam).sort();
  return {
    recipes,
    policy: {
      Version: "2012-10-17",
      Statement: [
        { Sid: "RampscanRunnerOwn", Effect: "Allow", Action: own, Resource: "*" },
        { Sid: "RampscanRunnerRecipes", Effect: "Allow", Action: actions, Resource: "*" },
      ],
    },
  };
}
