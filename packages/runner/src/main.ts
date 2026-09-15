#!/usr/bin/env node
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { initRunnerKeys, loadRunnerKeys, signTranscript } from "./keys.js";
import { runRequest } from "./run.js";
import type { RunInput } from "./run.js";

// `rampscan-runner init --keys <dir>` (T3-2): generate the runner's own
// P-256 key once and print the public half for an operator to propose in
// the console; an approver's key turn registers it.
// `rampscan-runner run --request <file> --out <dir> [--keys <dir>]` (T3-1):
// the smallest mode — read what the appliance handed out, run it, write
// the transcript and the bytes; with `--keys`, write the signed envelope
// too. `once --request <token>` and `poll` (T3-4) wrap this.

function usage(): never {
  console.error(
    [
      "usage: rampscan-runner init --keys <dir>",
      "       rampscan-runner run --request <run-input.json> --out <dir> [--keys <dir>] [--region <r>] [--name <runner-name>]",
    ].join("\n"),
  );
  process.exit(2);
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const opt = (name: string): string | undefined => {
    const i = args.indexOf(`--${name}`);
    return i === -1 ? undefined : args[i + 1];
  };
  if (args[0] === "init") {
    const dir = opt("keys");
    if (dir === undefined) usage();
    const keys = await initRunnerKeys(dir);
    console.error(
      keys.created
        ? `rampscan-runner: generated ECDSA P-256 keypair in ${dir} (keyid ${keys.keyid.slice(0, 12)}…); propose the public key below in the console — an approver's key turn registers it`
        : `rampscan-runner: keypair already present in ${dir} (keyid ${keys.keyid.slice(0, 12)}…)`,
    );
    process.stdout.write(keys.publicKeyPem);
    return;
  }
  if (args[0] !== "run") usage();
  const requestPath = opt("request");
  const out = opt("out");
  if (requestPath === undefined || out === undefined) usage();
  const input = JSON.parse(await readFile(requestPath, "utf8")) as RunInput;
  const region = opt("region") ?? input.runner?.region ?? process.env["AWS_REGION"] ?? process.env["AWS_DEFAULT_REGION"] ?? "us-east-1";
  const name = opt("name") ?? input.runner?.name ?? "runner";
  const result = await runRequest({ ...input, runner: { name, region } });
  await mkdir(join(out, "outputs"), { recursive: true });
  await writeFile(join(out, "transcript.json"), `${JSON.stringify(result.transcript, null, 2)}\n`);
  const keysDir = opt("keys");
  if (keysDir !== undefined) {
    const envelope = signTranscript(result.transcript, await loadRunnerKeys(keysDir));
    await writeFile(join(out, "transcript.dsse.json"), `${JSON.stringify(envelope, null, 2)}\n`);
  }
  for (const [digest, bytes] of result.outputs) await writeFile(join(out, "outputs", digest), bytes);
  const failed = result.transcript.steps.filter((s) => s.exit_code !== 0 || s.stderr_class !== "none").length;
  console.error(
    `rampscan-runner: ${result.transcript.steps.length} step(s) as ${result.transcript.runner.caller_arn} in ${result.transcript.runner.account}; ` +
      `${failed} did not complete cleanly; transcript${keysDir !== undefined ? " (signed)" : " (unsigned — pass --keys)"} and ${result.outputs.size} output(s) in ${out} — nothing evaluated here`,
  );
}

main().catch((e: unknown) => {
  console.error(`rampscan-runner: ${e instanceof Error ? e.message : String(e)}`);
  process.exit(1);
});
