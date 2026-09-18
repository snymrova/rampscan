#!/usr/bin/env tsx
// P1's scheduled check, as a script rather than as shell inside a workflow.
//
// It takes ONE argument — a local copy of upstream's consolidated rules — and
// prints what `pinDrift` says about it. Nothing here fetches: the workflow
// curls the file and this reads it, so the whole comparison runs offline in a
// test or by hand (`pnpm exec tsx scripts/pin-drift.ts <file>`), and a network
// failure in CI is a curl that failed rather than a drift result nobody can
// reproduce.
//
// Exit codes are the job's: 0 at the pin, 1 on drift in either direction.
// Nothing here edits a pin — see `packages/dataset/src/pins.ts` for why a
// re-pin is a reviewed change and not a version bump.

import { readFileSync } from "node:fs";
import { DEFAULT_DATASET_PIN, pinDrift, renderPinDrift } from "../packages/dataset/src/index.js";

const path = process.argv[2];
if (path === undefined) {
  console.error("usage: pin-drift.ts <path to upstream fedramp-consolidated-rules.json>");
  process.exit(2);
}

const rules = JSON.parse(readFileSync(path, "utf8")) as { info?: { version?: unknown } };
const upstream = rules.info?.version;
if (typeof upstream !== "string") {
  console.error(`${path} carries no info.version — refusing to report drift against a file this shape`);
  process.exit(2);
}

const drift = pinDrift(DEFAULT_DATASET_PIN, upstream);
console.log(renderPinDrift(drift));
if (process.env["GITHUB_OUTPUT"] !== undefined) {
  const { appendFileSync } = await import("node:fs");
  appendFileSync(process.env["GITHUB_OUTPUT"], `kind=${drift.kind}\n`);
}
process.exit(drift.kind === "current" ? 0 : 1);
