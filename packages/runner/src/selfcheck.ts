import { execStep } from "./run.js";
import type { ExecOptions } from "./run.js";

// The denial self-check (docs/PLAN-CLOUD-RUNNER.md T3-3): before any recipe
// runs, the runner simulates a probe set of MUTATING actions against its
// own role and refuses to run unless every one is denied. The result rides
// in every transcript, so a reader can see the role was read-only when the
// run happened, not merely when the policy was generated. Needs real IAM:
// the emulator answers simulate-principal-policy with a 500, and that is
// reported as "could not check", never as "denied".

/**
 * The mutating actions probed. Held equal to the appliance's list
 * (`packages/cli/src/runner-policy.ts`) by a test — duplicated because
 * neither program imports the other.
 */
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

export interface SelfCheckResult {
  probes: string[];
  all_denied: boolean;
  /** per probe: allowed | explicitDeny | implicitDeny, or unknown when IAM did not answer */
  decisions: Record<string, string>;
  /** set when the simulation itself failed — the check could not be made */
  error?: string;
}

/** the IAM principal a caller ARN's policies are evaluated for: an assumed role's role, else the ARN itself */
export function policySourceArn(callerArn: string): string {
  const m = /^arn:(aws[a-z-]*):sts::(\d{12}):assumed-role\/([^/]+)\/.+$/.exec(callerArn);
  return m === null ? callerArn : `arn:${m[1]}:iam::${m[2]}:role/${m[3]}`;
}

export async function selfCheck(callerArn: string, probes: readonly string[], opts: ExecOptions = {}): Promise<SelfCheckResult> {
  const source = policySourceArn(callerArn);
  const r = await execStep(["aws", "iam", "simulate-principal-policy", "--policy-source-arn", source, "--action-names", ...probes, "--output", "json"], opts);
  const decisions: Record<string, string> = Object.fromEntries(probes.map((p) => [p, "unknown"]));
  if (r.step.exit_code !== 0) {
    return { probes: [...probes], all_denied: false, decisions, error: `simulate-principal-policy exited ${r.step.exit_code} (${r.step.stderr_class}); the role could not be shown read-only` };
  }
  let parsed: { EvaluationResults?: Array<{ EvalActionName?: string; EvalDecision?: string }> };
  try {
    parsed = JSON.parse(Buffer.from(r.stdout).toString("utf8")) as typeof parsed;
  } catch {
    return { probes: [...probes], all_denied: false, decisions, error: "simulate-principal-policy printed no JSON" };
  }
  for (const e of parsed.EvaluationResults ?? []) {
    if (typeof e.EvalActionName === "string" && typeof e.EvalDecision === "string") decisions[e.EvalActionName] = e.EvalDecision;
  }
  const all_denied = probes.every((p) => decisions[p] === "explicitDeny" || decisions[p] === "implicitDeny");
  return { probes: [...probes], all_denied, decisions };
}
