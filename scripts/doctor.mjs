#!/usr/bin/env node
// rampscan doctor — checks how each scan tool will resolve at run time.
//
// Policy (deliberate): rampscan never installs anything on the host. With
// Docker present, a missing tool runs its PINNED image from
// packages/collectors/tools.json automatically — so "install X" hints only
// appear when there is no Docker either.

import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const { tools: pinned } = JSON.parse(
  readFileSync(join(root, "packages/collectors/tools.json"), "utf8"),
);

function versionOf(cmd, args) {
  try {
    return execFileSync(cmd, args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] })
      .split("\n")[0]
      .trim();
  } catch {
    return null;
  }
}

const dockerVersion = versionOf("docker", ["version", "--format", "Docker {{.Server.Version}}"]);

const tools = [
  { name: "syft", versionArgs: ["--version"], why: "SBOM (CycloneDX) — M1 collector" },
  { name: "osv-scanner", versionArgs: ["--version"], why: "advisories against the SBOM — M1 collector" },
  { name: "grype", versionArgs: ["--version"], why: "container base-image scan — M1 collector" },
  { name: "gitleaks", versionArgs: ["version"], why: "secrets, full history — M1 collector" },
  { name: "semgrep", versionArgs: ["--version"], why: "SAST over committed sources, gated by the code graph" },
  { name: "checkov", versionArgs: ["--version"], why: "IaC misconfiguration baseline (Dockerfile, workflows, Terraform)" },
  { name: "spectral", versionArgs: ["--version"], why: "OpenAPI/Swagger document lint" },
];

console.log(
  dockerVersion
    ? `  ok       ${"docker".padEnd(12)} ${dockerVersion} — missing tools run pinned images; nothing to install`
    : `  absent   ${"docker".padEnd(12)} no Docker — tools must be installed as binaries (https://docs.docker.com/engine/install/)`,
);

let unresolved = 0;
for (const tool of tools) {
  const version = versionOf(tool.name, tool.versionArgs);
  const pin = pinned[tool.name];
  if (version) {
    console.log(`  ok       ${tool.name.padEnd(12)} binary: ${version}`);
  } else if (dockerVersion && pin) {
    console.log(`  ok       ${tool.name.padEnd(12)} docker: ${pin.image} (pulled on first use)`);
  } else {
    unresolved += 1;
    console.log(`  MISSING  ${tool.name.padEnd(12)} ${tool.why}`);
    console.log(`           install ${tool.name} — or install Docker and nothing else is needed`);
  }
}

// cosign stays informational: the M2 signer is node:crypto; cosign only adds
// independent DSSE verification
const cosign = versionOf("cosign", ["version"]);
console.log(
  cosign
    ? `  ok       ${"cosign".padEnd(12)} ${cosign}`
    : `  absent   ${"cosign".padEnd(12)} (optional) independent verification of DSSE envelopes — signer needs no binary`,
);

// The drafting model (L4a). Informational for the same reason cosign is, and
// more strongly: the model has NO standing in the evidence path, so its
// absence never counts toward `unresolved` and never fails this command. A
// doctor that exited 1 over a missing model would say a scan is impaired when
// nothing about a scan changes.
//
// Three states, not two — the port's own split. "No runtime" and "runtime up,
// weights not pulled" are different fixes, and this machine was the second one
// on the day it was written.
const model = JSON.parse(readFileSync(join(root, "packages/model/models.json"), "utf8"));
const endpoint = process.env.OLLAMA_HOST ?? model.endpoint;
const label = model.runtime.padEnd(12);
try {
  const version = await fetch(`${endpoint}/api/version`, { signal: AbortSignal.timeout(2000) })
    .then((r) => (r.ok ? r.json() : null))
    .then((b) => b?.version);
  if (!version) throw new Error("no version");
  const shown = await fetch(`${endpoint}/api/show`, {
    signal: AbortSignal.timeout(2000),
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ name: model.model }),
  });
  // Status words map 1:1 onto the port's ModelResolution states — ready → ok,
  // unprovisioned → no-model, absent → absent. The middle one needs its own
  // word: printing "absent" beside "0.3.12 running" would have this column
  // contradict the sentence next to it, and the runtime is not what is missing.
  console.log(
    shown.ok
      ? `  ok       ${label} ${version} — ${model.model} ready to draft (drafts are advisory; nothing signed)`
      : `  no-model ${label} ${version} running, ${model.model} not pulled — \`${model.runtime} pull ${model.model}\` (optional: drafting only)`,
  );
} catch {
  console.log(
    `  absent   ${label} (optional) no runtime at ${endpoint} — drafting affordances hide themselves; scans are unaffected`,
  );
}

if (unresolved > 0) {
  console.log(`\n${unresolved} tool(s) cannot resolve. Their collectors will skip with the reason recorded, and their recipes will read unevidenced.`);
  process.exitCode = 1;
} else {
  console.log(`\nAll scan tools resolve${dockerVersion ? " (binary or pinned Docker image)" : ""}.`);
}
