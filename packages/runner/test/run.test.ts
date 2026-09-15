import { createHash } from "node:crypto";
import { mkdtemp, readFile, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { RunTranscript } from "@rampscan/schema";
import type { RunRequest } from "@rampscan/schema";
import { callerIdentity, classifyStderr, execStep, runRequest } from "../src/run.js";

// T3-1 (docs/PLAN-CLOUD-RUNNER.md, #176): the runner executes argv, never
// a shell; captures stdout whole and digests it; classifies stderr and
// drops it; records who it ran as. Against a shim that stands in for the
// aws binary, so nothing here needs an account — the emulator (T3-0) and
// the sandbox are where the real binary runs.

const HERE = dirname(fileURLToPath(import.meta.url));
const SHIM = resolve(HERE, "aws-shim.mjs");
const sha256 = (s: string) => createHash("sha256").update(s).digest("hex");

const IDENTITY = JSON.stringify({ UserId: "AROA...", Account: "111111111111", Arn: "arn:aws:sts::111111111111:assumed-role/rampscan-runner/i-0abc" });

function withShim(spec: Record<string, { stdout?: string; stderr?: string; exit?: number }>) {
  let tick = 0;
  return {
    binary: SHIM,
    env: { ...process.env, AWS_SHIM_SPEC: JSON.stringify(spec) },
    now: () => new Date(Date.UTC(2026, 8, 16, 10, 0, tick++)),
  };
}

const REQUEST: RunRequest = {
  _type: "https://rampscan.dev/run-request/v1",
  nonce: "5f2c9a1e7b3d4c6a8e0f1a2b3c4d5e6f",
  recipe_id: "iam-credential-report",
  recipe_digest: sha256("recipe"),
  ksi: "KSI-IAM-APM",
  params: {},
  issued_at: "2026-09-16T09:00:00Z",
  expires_at: "2026-09-16T11:00:00Z",
  requester: "operator@example.test",
};

describe("classifyStderr — a class, never the bytes", () => {
  it("reads the CLI's own error codes and calls everything else other", () => {
    expect(classifyStderr("")).toBe("none");
    expect(classifyStderr("An error occurred (AccessDenied) when calling the GetCredentialReport operation: User: arn:... is not authorized")).toBe("access-denied");
    expect(classifyStderr("An error occurred (Throttling) when calling the LookupEvents operation: Rate exceeded")).toBe("throttled");
    expect(classifyStderr("An error occurred (ReportInProgress) when calling the GetCredentialReport operation")).toBe("incomplete");
    expect(classifyStderr("An error occurred (OptInRequired) when calling the DescribeSubscription operation")).toBe("not-enabled");
    expect(classifyStderr("An error occurred (BadRequestException) when calling the GetDetector operation: The request is rejected because the input detectorId is not owned by the current account")).toBe("not-enabled");
    expect(classifyStderr("Unknown options: --foo")).toBe("other");
  });
});

describe("execStep — argv in, bytes and a classified record out", () => {
  it("captures stdout whole, digests it, and records the exit and the class", async () => {
    const csv = "user,mfa_active\nalice,true\n";
    const r = await execStep(["aws", "iam", "get-credential-report", "--output", "text"], withShim({ "iam get-credential-report --output text": { stdout: csv } }));
    expect(Buffer.from(r.stdout).toString()).toBe(csv);
    expect(r.step).toEqual({
      argv: ["aws", "iam", "get-credential-report", "--output", "text"],
      exit_code: 0,
      started_at: "2026-09-16T10:00:00.000Z",
      finished_at: "2026-09-16T10:00:01.000Z",
      stdout_sha256: sha256(csv),
      stdout_bytes: csv.length,
      stderr_class: "none",
    });
  });

  it("a denied call: non-zero exit, class access-denied, and the stderr bytes are nowhere in the record", async () => {
    const r = await execStep(["aws", "iam", "list-users"], withShim({ "iam list-users": { stderr: "An error occurred (AccessDenied) when calling the ListUsers operation: arn:aws:iam::111111111111:role/x", exit: 254 } }));
    expect(r.step.exit_code).toBe(254);
    expect(r.step.stderr_class).toBe("access-denied");
    expect(JSON.stringify(r.step)).not.toContain("111111111111");
    expect(r.stdout.byteLength).toBe(0);
  });

  it("refuses to execute anything but aws, and a shell metacharacter is an argument, not a shell", async () => {
    await expect(execStep(["sh", "-c", "echo hi"], withShim({}))).rejects.toThrow(/executes aws and nothing else/);
    const r = await execStep(["aws", "iam", "list-users", "--query", "Users[?Name=='a'] | [0]"], withShim({ "iam list-users --query Users[?Name=='a'] | [0]": { stdout: "[]" } }));
    expect(r.step.exit_code).toBe(0);
  });

  it("a binary that cannot be spawned is exit -1, class other", async () => {
    const r = await execStep(["aws", "iam", "list-users"], { binary: "/nonexistent/aws" });
    expect(r.step.exit_code).toBe(-1);
    expect(r.step.stderr_class).toBe("other");
  });
});

describe("runRequest — the transcript, who it ran as, every step run", () => {
  it("records STS's answer as the runner's identity, runs every step even after a failure, and validates as the contract", async () => {
    const generate = '{"State": "STARTED"}\n';
    const opts = withShim({
      "sts get-caller-identity --output json": { stdout: IDENTITY },
      "iam generate-credential-report": { stdout: generate },
      "iam get-credential-report --query Content --output text": { stderr: "An error occurred (ReportInProgress) when calling the GetCredentialReport operation", exit: 254 },
    });
    const { transcript, outputs } = await runRequest(
      {
        request: REQUEST,
        request_digest: sha256("request"),
        steps: [["aws", "iam", "generate-credential-report"], ["aws", "iam", "get-credential-report", "--query", "Content", "--output", "text"]],
        runner: { name: "sidecar-1", region: "us-east-1" },
      },
      opts,
    );
    expect(RunTranscript.parse(transcript)).toEqual(transcript);
    expect(transcript.runner).toEqual({
      name: "sidecar-1",
      caller_arn: "arn:aws:sts::111111111111:assumed-role/rampscan-runner/i-0abc",
      account: "111111111111",
      partition: "aws",
      region: "us-east-1",
    });
    expect(transcript.steps.map((s) => [s.exit_code, s.stderr_class])).toEqual([[0, "none"], [254, "incomplete"]]);
    expect(outputs.get(transcript.steps[0]!.stdout_sha256)).toEqual(new TextEncoder().encode(generate));
    expect(JSON.stringify(transcript)).not.toMatch(/passed|verdict|evidenced/);
  });

  it("without an identity it runs nothing", async () => {
    await expect(callerIdentity(withShim({ "sts get-caller-identity --output json": { stderr: "Unable to locate credentials", exit: 253 } }))).rejects.toThrow(/runs nothing/);
  });

  it("the CLI: run --request writes transcript.json and outputs/<digest>", async () => {
    const dir = await mkdtemp(join(tmpdir(), "rampscan-runner-"));
    const inputPath = join(dir, "run-input.json");
    const { writeFile } = await import("node:fs/promises");
    await writeFile(inputPath, JSON.stringify({ request: REQUEST, request_digest: sha256("request"), steps: [["aws", "iam", "list-roles"]], runner: { name: "sidecar-1", region: "us-east-1" } }));
    const { execFile } = await import("node:child_process");
    const { promisify } = await import("node:util");
    const spec = JSON.stringify({ "sts get-caller-identity --output json": { stdout: IDENTITY }, "iam list-roles": { stdout: '{"Roles": []}\n' } });
    const out = join(dir, "out");
    // the shim replaces the aws binary through PATH: a directory holding an `aws` symlink to it
    const { symlink, mkdir } = await import("node:fs/promises");
    await mkdir(join(dir, "bin"));
    await symlink(SHIM, join(dir, "bin", "aws"));
    const { stderr } = await promisify(execFile)(process.execPath, ["--import", "tsx", resolve(HERE, "../src/main.ts"), "run", "--request", inputPath, "--out", out], {
      env: { ...process.env, AWS_SHIM_SPEC: spec, PATH: `${join(dir, "bin")}:${process.env["PATH"]}` },
    });
    expect(stderr).toMatch(/1 step\(s\) as arn:aws:sts::111111111111/);
    expect(stderr).toMatch(/nothing evaluated here/);
    const transcript = RunTranscript.parse(JSON.parse(await readFile(join(out, "transcript.json"), "utf8")));
    expect(await readdir(join(out, "outputs"))).toEqual([transcript.steps[0]!.stdout_sha256]);
  });
});
