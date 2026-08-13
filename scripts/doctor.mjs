#!/usr/bin/env node
// rampscan doctor — checks the local environment for the collector toolchain
// (plan A4). Stub-grade on purpose: reports and hints, installs nothing.

import { execFileSync } from "node:child_process";

const tools = [
  {
    name: "syft",
    versionArgs: ["--version"],
    why: "SBOM (CycloneDX) — M1 collector",
    install: "brew install syft | apt: see https://github.com/anchore/syft#installation",
  },
  {
    name: "osv-scanner",
    versionArgs: ["--version"],
    why: "advisories against the SBOM — M1 collector",
    install: "brew install osv-scanner | go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest",
  },
  {
    name: "grype",
    versionArgs: ["version"],
    why: "container image scan (repo Dockerfile) — M1 collector, skipped gracefully without Docker",
    install: "brew install grype | apt: see https://github.com/anchore/grype#installation",
  },
  {
    name: "gitleaks",
    versionArgs: ["version"],
    why: "secrets, full history — M1 collector",
    install: "brew install gitleaks | https://github.com/gitleaks/gitleaks/releases",
  },
  {
    name: "cosign",
    versionArgs: ["version"],
    why: "optional independent verification of DSSE envelopes — the M2 signer itself is node:crypto, no binary needed",
    install: "brew install cosign | https://github.com/sigstore/cosign/releases",
    optional: true,
  },
  {
    name: "docker",
    versionArgs: ["--version"],
    why: "optional fallback runner for collectors not installed natively",
    install: "https://docs.docker.com/engine/install/",
    optional: true,
  },
];

let missingRequired = 0;
for (const tool of tools) {
  let version;
  try {
    version = execFileSync(tool.name, tool.versionArgs, {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    })
      .split("\n")[0]
      .trim();
  } catch {
    version = null;
  }
  if (version) {
    console.log(`  ok       ${tool.name.padEnd(12)} ${version}`);
  } else if (tool.optional) {
    console.log(`  absent   ${tool.name.padEnd(12)} (optional) ${tool.why}`);
    console.log(`           install: ${tool.install}`);
  } else {
    missingRequired += 1;
    console.log(`  MISSING  ${tool.name.padEnd(12)} ${tool.why}`);
    console.log(`           install: ${tool.install}`);
  }
}

if (missingRequired > 0) {
  console.log(`\n${missingRequired} required tool(s) missing. M0 runs without them; M1 collectors need them (Docker can substitute).`);
  process.exitCode = 1;
} else {
  console.log("\nAll collector tools present.");
}
