#!/usr/bin/env node
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { initRunnerKeys, loadRunnerKeys, signTranscript } from "./keys.js";
import { once, poll } from "./modes.js";
import { callerIdentity, runRequest } from "./run.js";
import type { RunInput } from "./run.js";
import { DENIAL_PROBES, selfCheck } from "./selfcheck.js";

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
      "                           [--skip-self-check]   (emulators only: IAM's simulate-principal-policy is where the role is shown read-only)",
      "       rampscan-runner poll --console <url> --keys <dir> --name <runner-name> [--region <r>] [--interval <s>] [--max <n>]",
      "                           the sidecar: ask the console for the next request under the registered key, run it, post the transcript, repeat",
      "       rampscan-runner once --request <token> [--region <r>]",
      "                           the CloudShell one-shot: the token the console showed, an ephemeral key, one run",
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
  const regionOf = (fallback?: string) => opt("region") ?? fallback ?? process.env["AWS_REGION"] ?? process.env["AWS_DEFAULT_REGION"] ?? "us-east-1";
  const log = (line: string) => console.error(`rampscan-runner: ${line}`);
  if (args[0] === "poll") {
    const consoleUrl = opt("console");
    const keysDir = opt("keys");
    const name = opt("name");
    if (consoleUrl === undefined || keysDir === undefined || name === undefined) usage();
    const keys = await loadRunnerKeys(keysDir);
    log(`polling ${consoleUrl} as ${name} (keyid ${keys.keyid.slice(0, 12)}…), outbound only`);
    const max = opt("max");
    const { handled } = await poll({
      console: consoleUrl.replace(/\/+$/, ""),
      keys,
      runner: { name, region: regionOf() },
      intervalMs: Number(opt("interval") ?? "30") * 1000,
      ...(max !== undefined ? { maxRequests: Number(max) } : {}),
      skipSelfCheck: args.includes("--skip-self-check"),
      log,
    });
    log(`${handled} request(s) handled`);
    return;
  }
  if (args[0] === "once") {
    const token = opt("request");
    if (token === undefined) usage();
    const reply = await once({ token, region: regionOf(), skipSelfCheck: args.includes("--skip-self-check"), log });
    process.exit(reply.kind === "submission" ? 0 : reply.kind === "failed" ? 4 : 5);
  }
  if (args[0] !== "run") usage();
  const requestPath = opt("request");
  const out = opt("out");
  if (requestPath === undefined || out === undefined) usage();
  const input = JSON.parse(await readFile(requestPath, "utf8")) as RunInput;
  const region = regionOf(input.runner?.region);
  const name = opt("name") ?? input.runner?.name ?? "runner";
  // T3-3: the role is shown read-only before anything runs, and the result
  // rides in the transcript. Skipping is for emulators that cannot answer
  // the simulation, and it is said out loud
  let self_check: RunInput["self_check"];
  if (args.includes("--skip-self-check")) {
    console.error("rampscan-runner: self-check SKIPPED — this transcript will not show the role read-only, and the appliance refuses it unless configured for an emulator");
  } else {
    const identity = await callerIdentity();
    const check = await selfCheck(identity.arn, DENIAL_PROBES);
    if (check.error !== undefined || !check.all_denied) {
      const allowed = Object.entries(check.decisions).filter(([, d]) => d === "allowed").map(([a]) => a);
      console.error(
        `rampscan-runner: refused to run as ${identity.arn} — ` +
          (check.error ?? `the role may ${allowed.join(", ")}; a runner role must be denied every probe`),
      );
      process.exit(3);
    }
    self_check = { probes: check.probes, all_denied: true };
    console.error(`rampscan-runner: self-check passed — ${check.probes.length} mutating probes denied to ${identity.arn}`);
  }
  const result = await runRequest({ ...input, runner: { name, region }, ...(self_check !== undefined ? { self_check } : {}) });
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
