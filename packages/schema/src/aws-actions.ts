import { z } from "zod";

// The reviewed AWS action allowlist (docs/PLAN-CLOUD-RUNNER.md T1-1, ground
// rule 4): read-only by allowlist, never by blocklist. A recipe is runnable
// under the client's runner only when every CLI action it issues is on this
// list, and the list is a reviewed artifact in `recipes/aws-actions/` —
// admission is a code-reviewed change, and nothing is admitted by a verb
// pattern. The same file is what the runner's IAM policy is generated from
// (T3-3), so the role can do exactly what the admitted recipes need and
// nothing the reviewer did not read.

export const AWS_ACTION_ALLOWLIST_TYPE = "https://rampscan.dev/aws-action-allowlist/v1" as const;

const CliAction = z.string().regex(/^[a-z0-9-]+ [a-z0-9-]+$/, "an AWS CLI action is `<service> <operation>`");
const IamAction = z.string().regex(/^[a-z0-9-]+:[A-Za-z0-9]+$/, "an IAM action is `service:Operation`");

/** one CLI action the reviewer read: what IAM it needs and why it does not mutate */
export const AwsActionEntry = z.strictObject({
  /** `<service> <operation>` as the CLI spells it — the join key against a recipe's commands */
  cli: CliAction,
  /** the IAM action(s) the call needs; what the generated policy allows */
  iam: z.array(IamAction).min(1),
  /** one line on why this call does not change the account (or, under `refused`, why it does) */
  why: z.string().min(1),
  /**
   * Present when the verb alone would not have admitted the action —
   * `start`, `generate`, `validate` — and a reviewer read what it does.
   * Its absence on a non-Describe/Get/List verb is a test failure.
   */
  review: z.string().min(1).optional(),
});
export type AwsActionEntry = z.infer<typeof AwsActionEntry>;

export const AwsActionAllowlist = z.strictObject({
  _type: z.literal(AWS_ACTION_ALLOWLIST_TYPE),
  reviewed: z.string().min(1),
  /** the dataset pin whose recipes were read to build the list */
  dataset: z.string().min(1),
  rule: z.string().min(1),
  /** the actions a runnable recipe may issue */
  admitted: z.array(AwsActionEntry).min(1),
  /** the actions the pinned recipes use that the runner will never run */
  refused: z.array(AwsActionEntry),
  /** the calls the runner makes on its own behalf, in every run */
  runner: z.array(AwsActionEntry).min(1),
});
export type AwsActionAllowlist = z.infer<typeof AwsActionAllowlist>;
