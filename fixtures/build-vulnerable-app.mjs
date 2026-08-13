#!/usr/bin/env node
// Builds fixtures/vulnerable-app — the planted-fault toy repo (plan B4).
//
// Faults, planted deliberately:
//   1. a secret in git HISTORY but not at HEAD (added then removed — gitleaks
//      must scan history, not the working tree, to find it)
//   2. a known-vulnerable dependency (lodash 4.17.15 — GHSA-p6mc-m468-83gw,
//      prototype pollution) declared in package.json + package-lock.json
//   3. an unpinned CI action (tag ref, not a commit SHA) and no provenance step
//   4. an EOL base image in the Dockerfile (node:16-alpine)
//
// The inner repo carries its own git history, which the outer repo cannot
// commit (nested .git); this generator is the committed artifact instead.
// It is deterministic — fixed timestamps and identity — so the fixture's
// commit SHAs are stable across machines.

import { execFileSync } from "node:child_process";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "vulnerable-app");

const gitEnv = {
  ...process.env,
  GIT_AUTHOR_NAME: "fixture",
  GIT_AUTHOR_EMAIL: "fixture@rampscan.invalid",
  GIT_COMMITTER_NAME: "fixture",
  GIT_COMMITTER_EMAIL: "fixture@rampscan.invalid",
  GIT_AUTHOR_DATE: "2026-01-01T00:00:00Z",
  GIT_COMMITTER_DATE: "2026-01-01T00:00:00Z",
};

function git(...args) {
  return execFileSync("git", args, { cwd: root, env: gitEnv, encoding: "utf8" });
}

function write(rel, content) {
  const abs = join(root, rel);
  mkdirSync(dirname(abs), { recursive: true });
  writeFileSync(abs, content);
}

rmSync(root, { recursive: true, force: true });
mkdirSync(root, { recursive: true });
git("init", "-q", "-b", "main");

// ---- commit 1: the app, with faults 2–4 ------------------------------------
write(
  "package.json",
  JSON.stringify(
    {
      name: "vulnerable-app",
      version: "1.0.0",
      private: true,
      main: "src/index.js",
      dependencies: { lodash: "4.17.15" },
    },
    null,
    2,
  ) + "\n",
);
write(
  "package-lock.json",
  JSON.stringify(
    {
      name: "vulnerable-app",
      version: "1.0.0",
      lockfileVersion: 3,
      requires: true,
      packages: {
        "": {
          name: "vulnerable-app",
          version: "1.0.0",
          dependencies: { lodash: "4.17.15" },
        },
        "node_modules/lodash": {
          version: "4.17.15",
          resolved: "https://registry.npmjs.org/lodash/-/lodash-4.17.15.tgz",
          integrity:
            "sha512-8xOcRHvCjnocdS5cpwXQXVzmmh5e5+saE2QGoeQmbKmRS6J3VQppPOIt0MnmE+4xlZoumy0GPG0D0MVIQbNA1A==",
        },
      },
    },
    null,
    2,
  ) + "\n",
);
write(
  "src/index.js",
  `const merge = require("lodash/merge");

// Reachable use of the vulnerable symbol (lodash merge, GHSA-p6mc-m468-83gw):
// user-controlled JSON flows straight into merge().
function handleRequest(body) {
  const settings = {};
  merge(settings, JSON.parse(body)); // prototype pollution sink
  return settings;
}

module.exports = { handleRequest };
`,
);
write(
  ".github/workflows/ci.yml",
  `name: ci
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      # FAULT: action pinned to a mutable tag, not a commit SHA
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 22
      - run: npm ci
      - run: node -e "require('./src/index.js')"
      # FAULT: no provenance/attestation step anywhere in the workflow
`,
);
write(
  "Dockerfile",
  `# FAULT: EOL base image with known OS-level CVEs
FROM node:16-alpine
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY src ./src
CMD ["node", "src/index.js"]
`,
);
write("README.md", "# vulnerable-app\n\nPlanted-fault fixture for rampscan. Every fault here is deliberate.\n");
git("add", "-A");
git("commit", "-q", "-m", "initial app");

// ---- commit 2: fault 1, the secret enters history --------------------------
write(
  "config/.env",
  // Fake-but-well-formed AWS credentials: matches gitleaks' aws-access-key-id
  // pattern (AKIA + 16 uppercase alphanumerics). Not a real key. Deliberately
  // NOT AWS's documented example key (AKIAIOSFODNN7EXAMPLE) — gitleaks
  // allowlists that one, which would make the planted fault undetectable.
  `AWS_ACCESS_KEY_ID=<aws-key-shape-assembled-at-build-time>
AWS_SECRET_ACCESS_KEY=<aws-secret-shape-assembled-at-build-time>
`,
);
git("add", "-A");
git("commit", "-q", "-m", "add deployment config");

// ---- commit 3: the secret leaves the working tree but not history ----------
rmSync(join(root, "config"), { recursive: true });
git("add", "-A");
git("commit", "-q", "-m", "remove accidentally committed credentials");

const head = git("rev-parse", "HEAD").trim();
console.log(`fixtures/vulnerable-app built — HEAD ${head}`);
console.log(git("log", "--oneline"));
