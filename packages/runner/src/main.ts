#!/usr/bin/env node
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { runRequest } from "./run.js";
import type { RunInput } from "./run.js";

// `rampscan-runner run --request <file> --out <dir>` (T3-1): the smallest
// mode — read what the appliance handed out, run it, write the transcript
// and the bytes. `once --request <token>` and `poll` (T3-4) wrap this.

function usage(): never {
  console.error("usage: rampscan-runner run --request <run-input.json> --out <dir> [--region <r>] [--name <runner-name>]");
  process.exit(2);
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  if (args[0] !== "run") usage();
  const opt = (name: string): string | undefined => {
    const i = args.indexOf(`--${name}`);
    return i === -1 ? undefined : args[i + 1];
  };
  const requestPath = opt("request");
  const out = opt("out");
  if (requestPath === undefined || out === undefined) usage();
  const input = JSON.parse(await readFile(requestPath, "utf8")) as RunInput;
  const region = opt("region") ?? input.runner?.region ?? process.env["AWS_REGION"] ?? process.env["AWS_DEFAULT_REGION"] ?? "us-east-1";
  const name = opt("name") ?? input.runner?.name ?? "runner";
  const result = await runRequest({ ...input, runner: { name, region } });
  await mkdir(join(out, "outputs"), { recursive: true });
  await writeFile(join(out, "transcript.json"), `${JSON.stringify(result.transcript, null, 2)}\n`);
  for (const [digest, bytes] of result.outputs) await writeFile(join(out, "outputs", digest), bytes);
  const failed = result.transcript.steps.filter((s) => s.exit_code !== 0 || s.stderr_class !== "none").length;
  console.error(
    `rampscan-runner: ${result.transcript.steps.length} step(s) as ${result.transcript.runner.caller_arn} in ${result.transcript.runner.account}; ` +
      `${failed} did not complete cleanly; transcript and ${result.outputs.size} output(s) in ${out} — nothing evaluated here`,
  );
}

main().catch((e: unknown) => {
  console.error(`rampscan-runner: ${e instanceof Error ? e.message : String(e)}`);
  process.exit(1);
});
