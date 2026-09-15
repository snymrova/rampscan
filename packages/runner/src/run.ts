import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import type { RunRequest, RunTranscript, StderrClass, TranscriptStep } from "@rampscan/schema";

// rampscan-runner (docs/PLAN-CLOUD-RUNNER.md T3-1, SPEC §14): the program
// the CLIENT deploys in their own account. It executes the `aws` binary
// with argv arrays — never a shell — captures what each step printed, and
// hands back a transcript that says which role, in which account, ran
// which commands and received bytes of which digests. It evaluates
// nothing and has no field to put a verdict in (ground rule 3). It holds
// no ledger key. It has no runtime dependencies: the types above are
// erased at build, and T3-5 fails the build if a value import of any
// rampscan package ever appears here.

/** what one step yielded: the transcript's record and the raw bytes it names */
export interface StepResult {
  step: TranscriptStep;
  stdout: Uint8Array;
}

export interface ExecOptions {
  /** the binary to execute — `aws`; a test may point at a shim */
  binary?: string;
  /** environment the CLI runs under; `AWS_ENDPOINT_URL` reaches the emulator (T3-0) */
  env?: NodeJS.ProcessEnv;
  /** wall-clock cap per step; a step past it is `error` with exit -1 */
  timeoutMs?: number;
  /** the clock, for a deterministic transcript in tests */
  now?: () => Date;
}

/**
 * The runner's reading of stderr — a class, and the bytes are discarded
 * here and nowhere later, because AWS error text carries ARNs, account
 * ids and resource names into whatever log holds the transcript. The
 * patterns are the CLI's own error codes; anything else it printed is
 * `other`, which the appliance reads as `error`.
 */
export function classifyStderr(stderr: string): StderrClass {
  if (stderr.trim() === "") return "none";
  if (/AccessDenied|UnauthorizedOperation|AuthorizationError|not authorized to perform|AccessDeniedException/i.test(stderr)) return "access-denied";
  if (/Throttling|ThrottlingException|Rate exceeded|TooManyRequests|RequestLimitExceeded/i.test(stderr)) return "throttled";
  if (/ReportNotPresent|ReportInProgress|ReportExpired|not yet available|is still being generated/i.test(stderr)) return "incomplete";
  if (/OptInRequired|SubscriptionRequiredException|is not enabled|not subscribed|NoSuchEntity.*detector|BadRequestException.*detector|ResourceNotFoundException.*(analyzer|detector|recorder)/i.test(stderr)) {
    return "not-enabled";
  }
  return "other";
}

const sha256 = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("hex");

/**
 * Execute one published command. `argv[0]` must be `aws` — the runner runs
 * nothing else — and the command run is exactly the command published
 * (T1-2's argv, bound). stdout is captured whole and digested; stderr is
 * classified and dropped.
 */
export async function execStep(argv: readonly string[], opts: ExecOptions = {}): Promise<StepResult> {
  if (argv[0] !== "aws") throw new Error(`the runner executes aws and nothing else; refused: ${argv[0] ?? "(empty)"}`);
  const now = opts.now ?? (() => new Date());
  const started = now();
  const bin = opts.binary ?? "aws";
  const child = spawn(bin, argv.slice(1), {
    env: opts.env ?? process.env,
    stdio: ["ignore", "pipe", "pipe"],
    shell: false,
  });
  const out: Buffer[] = [];
  const err: Buffer[] = [];
  child.stdout.on("data", (b: Buffer) => out.push(b));
  child.stderr.on("data", (b: Buffer) => err.push(b));
  const exit = await new Promise<number>((resolve) => {
    const timer = opts.timeoutMs === undefined ? undefined : setTimeout(() => child.kill("SIGKILL"), opts.timeoutMs);
    child.on("error", (e) => {
      err.push(Buffer.from(String(e.message)));
      resolve(-1);
    });
    child.on("close", (code, signal) => {
      if (timer !== undefined) clearTimeout(timer);
      resolve(code ?? (signal ? -1 : 0));
    });
  });
  const stdout = new Uint8Array(Buffer.concat(out));
  const finished = now();
  return {
    stdout,
    step: {
      argv: [...argv],
      exit_code: exit,
      started_at: started.toISOString(),
      finished_at: finished.toISOString(),
      stdout_sha256: sha256(stdout),
      stdout_bytes: stdout.byteLength,
      stderr_class: exit === -1 && err.length === 0 ? "other" : classifyStderr(Buffer.concat(err).toString("utf8")),
    },
  };
}

/** what `sts get-caller-identity` said: the one fact about itself the runner records */
export interface CallerIdentity {
  account: string;
  arn: string;
  partition: "aws" | "aws-us-gov";
}

export async function callerIdentity(opts: ExecOptions = {}): Promise<CallerIdentity> {
  const r = await execStep(["aws", "sts", "get-caller-identity", "--output", "json"], opts);
  if (r.step.exit_code !== 0) {
    throw new Error(`sts get-caller-identity exited ${r.step.exit_code} (${r.step.stderr_class}): the runner cannot say who it is, so it runs nothing`);
  }
  const parsed = JSON.parse(Buffer.from(r.stdout).toString("utf8")) as { Account?: string; Arn?: string };
  if (typeof parsed.Account !== "string" || typeof parsed.Arn !== "string") throw new Error("sts get-caller-identity returned no Account/Arn");
  return { account: parsed.Account, arn: parsed.Arn, partition: parsed.Arn.startsWith("arn:aws-us-gov:") ? "aws-us-gov" : "aws" };
}

export interface RunInput {
  request: RunRequest;
  /** sha256 over the canonical request, as the appliance computed it and sent it */
  request_digest: string;
  /** the steps, as argv, bound — what the appliance classified (T1-2) */
  steps: ReadonlyArray<readonly string[]>;
  runner: { name: string; region: string };
  /** the self-check, when performed (T3-3) */
  self_check?: { probes: string[]; all_denied: boolean };
}

export interface RunOutput {
  transcript: RunTranscript;
  /** the raw bytes each step printed, by the digest the transcript names */
  outputs: Map<string, Uint8Array>;
}

/**
 * Run every step of one request and assemble the transcript. Every step
 * runs even after one fails: the appliance classifies the run from the
 * first failing step, and the later steps' bytes are still evidence of
 * what the account yielded. Nothing here evaluates anything.
 */
export async function runRequest(input: RunInput, opts: ExecOptions = {}): Promise<RunOutput> {
  const now = opts.now ?? (() => new Date());
  const started = now();
  const identity = await callerIdentity(opts);
  if (input.self_check !== undefined && !input.self_check.all_denied) {
    throw new Error("the self-check found a mutating probe allowed to this role; the runner refuses to run under it");
  }
  const outputs = new Map<string, Uint8Array>();
  const steps: TranscriptStep[] = [];
  for (const argv of input.steps) {
    const r = await execStep(argv, opts);
    steps.push(r.step);
    outputs.set(r.step.stdout_sha256, r.stdout);
  }
  const finished = now();
  const transcript: RunTranscript = {
    _type: "https://rampscan.dev/run-transcript/v1",
    request_digest: input.request_digest,
    nonce: input.request.nonce,
    recipe_id: input.request.recipe_id,
    ksi: input.request.ksi,
    runner: {
      name: input.runner.name,
      caller_arn: identity.arn,
      account: identity.account,
      partition: identity.partition,
      region: input.runner.region,
    },
    ...(input.self_check !== undefined ? { self_check: input.self_check } : {}),
    steps,
    started_at: started.toISOString(),
    finished_at: finished.toISOString(),
  };
  return { transcript, outputs };
}
