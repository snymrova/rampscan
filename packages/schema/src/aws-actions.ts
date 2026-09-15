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

// ---------------------------------------------------------------------------
// Parameter binding (T1-3): the `aws` block of rampscan.config.json, and the
// reviewed table that turns an upstream recipe's EXAMPLE literals into
// placeholders. Upstream's recipes were written to be read by people — an
// account id `123456789012`, a bucket `my-cloudtrail-logs-bucket`, a July
// 2026 window — and a runner that executed them as published would query a
// stranger's account, or nobody's. So a literal becomes a `<NAME>` only by a
// reviewed row keyed by recipe id; nothing is detected by regex at run time,
// and a recipe whose literal has no row runs with the literal and is
// therefore, by the classifier, manual until someone reads it.

/**
 * The names the appliance binds on its own at request time, not from config:
 * the configured account and primary region, and the window the request is
 * for, as ISO 8601 and as epoch seconds (`cloudtrail lookup-events` takes the
 * first, `logs start-query` the second).
 */
export const RESERVED_AWS_PARAMS = [
  "ACCOUNT_ID",
  "PARTITION",
  "REGION",
  "WINDOW_START",
  "WINDOW_END",
  "EPOCH_START",
  "EPOCH_END",
] as const;
export type ReservedAwsParam = (typeof RESERVED_AWS_PARAMS)[number];

const ParamName = z.string().regex(/^[A-Za-z][A-Za-z0-9_-]*$/, "a parameter name is the text inside `<…>`");

/**
 * `{ aws: { ... } }` in rampscan.config.json, beside `offering`, `contract`
 * and `documents`. Strict: a misspelled key is an exit, never a parameter
 * that quietly bound nothing.
 */
export const AwsConfig = z.strictObject({
  account_id: z.string().regex(/^\d{12}$/),
  partition: z.enum(["aws", "aws-us-gov"]),
  /** the first is the primary region every unqualified call runs in */
  regions: z.array(z.string().min(1)).min(1),
  /**
   * The account-specific values a recipe's `<NAME>` placeholders take —
   * `INSTANCE_ARN`, `DETECTOR_ID`, `CLOUDTRAIL_BUCKET` … A reserved name here
   * is refused: the appliance binds those itself.
   */
  params: z
    .record(ParamName, z.string().min(1))
    .default({})
    .refine((p) => !Object.keys(p).some((k) => (RESERVED_AWS_PARAMS as readonly string[]).includes(k)), {
      message: `a reserved parameter (${RESERVED_AWS_PARAMS.join(", ")}) is bound by the appliance, not by config`,
    }),
});
export type AwsConfig = z.infer<typeof AwsConfig>;

export const AWS_LITERAL_BINDINGS_TYPE = "https://rampscan.dev/aws-literal-bindings/v1" as const;

/** one example literal in one recipe's published commands, and the parameter it stands for */
export const AwsLiteralBinding = z.strictObject({
  /** upstream's recipe id */
  recipe: z.string().min(1),
  /** the exact text as it appears in the command — must occur, or the row is stale */
  literal: z.string().min(1),
  /** the `<NAME>` it becomes: reserved, or one the config's `params` must supply */
  param: ParamName,
  /**
   * What replaces the literal, when it is not `<param>` alone — a literal
   * that carries fixed text around the variable part (`Name=Region,Value=us-east-1`
   * → `Name=Region,Value=<REGION>`). Must contain `<param>`.
   */
  becomes: z.string().min(1).optional(),
  /** one line on what the reviewer read the literal as */
  why: z.string().min(1),
});
export type AwsLiteralBinding = z.infer<typeof AwsLiteralBinding>;

export const AwsLiteralBindings = z.strictObject({
  _type: z.literal(AWS_LITERAL_BINDINGS_TYPE),
  reviewed: z.string().min(1),
  dataset: z.string().min(1),
  rule: z.string().min(1),
  entries: z.array(AwsLiteralBinding).min(1),
});
export type AwsLiteralBindings = z.infer<typeof AwsLiteralBindings>;
