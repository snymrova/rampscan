#!/usr/bin/env node
// A stand-in for the aws binary in unit tests: prints what AWS_SHIM_SPEC
// (a JSON map from the argv joined by spaces to {stdout, stderr, exit})
// says for the invocation, so the runner's capture, digest and
// classification are tested without an account or an emulator.
const spec = JSON.parse(process.env.AWS_SHIM_SPEC ?? "{}");
const key = process.argv.slice(2).join(" ");
// an exact key first; then a key ending in " *" as a prefix, for invocations
// whose tail a test does not care to spell (the self-check's fourteen probes)
const prefixed = Object.keys(spec).find((k) => k.endsWith(" *") && key.startsWith(k.slice(0, -2)));
const entry = spec[key] ?? (prefixed !== undefined ? spec[prefixed] : undefined) ?? { stdout: "", stderr: `Unknown shim invocation: ${key}`, exit: 252 };
if (entry.stdout) process.stdout.write(entry.stdout);
if (entry.stderr) process.stderr.write(entry.stderr);
process.exitCode = entry.exit ?? 0;
