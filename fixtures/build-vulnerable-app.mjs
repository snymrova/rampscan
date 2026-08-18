#!/usr/bin/env node
// Builds fixtures/vulnerable-app — the planted-fault toy repo (plan B4).
//
// Faults, planted deliberately:
//   1. a secret in git HISTORY but not at HEAD (added then removed — gitleaks
//      must scan history, not the working tree, to find it)
//   2. a known-vulnerable dependency (lodash 4.17.15 — GHSA-p6mc-m468-83gw,
//      prototype pollution) declared in package.json + package-lock.json AND
//      reachable: src/index.js requires lodash/merge from the package.json
//      main entry point — M4 must show the call path
//   3. an unpinned CI action (tag ref, not a commit SHA) and no provenance step
//   4. an EOL base image in the Dockerfile (node:16-alpine)
//   5. a route with no auth check in its call path (GET /health in
//      src/server.js; GET /settings passes through requireAuth — the contrast)
//
// And one planted NON-fault, the M4 not-affected demo:
//   6. a second known-vulnerable dependency (minimist 1.2.5 —
//      GHSA-xvch-5gv4-984h, CRITICAL prototype pollution) declared in
//      package.json + lockfile but never imported anywhere — the code graph
//      must prove it unreachable and emit a signed not-affected OpenVEX
//      instead of a violation
//
// The SAST edition of the same pair (the sast-reachability gate's demo):
//   7. dangerous code (eval) in src/render.js, REACHABLE: required from
//      src/index.js, the package.json main entry point — semgrep flags it,
//      the gate must show the call path (plus an md5 WARNING that rides
//      along as an observation without violating)
//   8. the same construct in src/legacy-tools.js, imported by NOTHING —
//      the graph must prove it unreachable, the gate marks it not_affected
//
// And the config plane:
//   9. an invalid OpenAPI document (openapi.yaml missing the required
//      `info` object) — spectral must reject it at error severity
//   (the Dockerfile and CI workflow above double as checkov's targets:
//    no USER, no HEALTHCHECK, unpinned action — failed baseline checks)
//
// The architecture-contract pair (plan L1 — rampscan.config.json declares
// intent, the contract gate checks the code against it):
//   10. a declared boundary broken: the contract says only src/server.js may
//       import src/billing, and src/render.js imports it directly — the gate
//       must name the offending import as the call path (server.js's own
//       import of billing is the allowed contrast)
//   11. a declared route-auth rule broken: the contract says every route must
//       reach an auth check, and GET /health (fault 5) does not — the same
//       unauthed route, now ALSO a violation of the repo's own declaration
//
// And the document family (plan N1b wave 1), which is the one place this
// fixture is deliberately WELL BEHAVED:
//   12. two declared documents that really exist (docs/access-control-policy.md
//       and docs/admin-guide.md) plus a published SECURITY.md — the three
//       document recipes need a repository where they reach `evidenced`, and
//       the broken cases (declared-but-missing, empty, undeclared) are unit
//       tests rather than planted faults, because each needs the fixture broken
//       in exactly one way
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
      dependencies: { lodash: "4.17.15", minimist: "1.2.5" },
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
          dependencies: { lodash: "4.17.15", minimist: "1.2.5" },
        },
        "node_modules/lodash": {
          version: "4.17.15",
          resolved: "https://registry.npmjs.org/lodash/-/lodash-4.17.15.tgz",
          integrity:
            "sha512-8xOcRHvCjnocdS5cpwXQXVzmmh5e5+saE2QGoeQmbKmRS6J3VQppPOIt0MnmE+4xlZoumy0GPG0D0MVIQbNA1A==",
        },
        "node_modules/minimist": {
          version: "1.2.5",
          resolved: "https://registry.npmjs.org/minimist/-/minimist-1.2.5.tgz",
          integrity:
            "sha512-FM9nNUYrRBAELZQT3xeZQ7fmMOBg6nWNmJKTcgsJeaLstP/UODVpGsr5OhXhhXg6f+qtJ8uiZ+PUxkDWcgIXLw==",
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
const { renderTemplate } = require("./render");

// Reachable use of the vulnerable symbol (lodash merge, GHSA-p6mc-m468-83gw):
// user-controlled JSON flows straight into merge().
function handleRequest(body) {
  const settings = {};
  merge(settings, JSON.parse(body)); // prototype pollution sink
  return renderTemplate("settings", settings);
}

module.exports = { handleRequest };
`,
);
write(
  "src/billing.js",
  `// The guarded module (fault 10): the contract in rampscan.config.json says
// only src/server.js may import this file. src/server.js does (allowed);
// src/render.js also does (the planted violation).
function formatInvoice(settings) {
  return { total: 0, currency: "USD", settings };
}

module.exports = { formatInvoice };
`,
);
write(
  "src/render.js",
  `const { createHash } = require("node:crypto");
// FAULT (10): imports the guarded billing module in violation of the declared
// boundary — the contract allows only src/server.js to do this.
const { formatInvoice } = require("./billing");

// FAULT: dynamic evaluation of a template string — code injection the moment
// any input reaches it. Planted REACHABLE: src/index.js (the package.json
// main entry point) requires this file, so the SAST gate must show the path.
function renderTemplate(template, context) {
  return eval("context." + template); // rampscan.dangerous-eval
}

// weak hash — a WARNING-severity observation that rides along without violating
function etagFor(content) {
  return createHash("md5").update(content).digest("hex");
}

// the boundary-breaking use: rendering reaches straight into billing
function renderInvoice(settings) {
  return JSON.stringify(formatInvoice(settings));
}

module.exports = { renderTemplate, etagFor, renderInvoice };
`,
);
write(
  "src/legacy-tools.js",
  `// FAULT PAIR (the not-affected demo, SAST edition): the same dangerous
// construct as src/render.js — but this file is imported by NOTHING. The
// code graph must prove it unreachable, and the sast-reachability gate must
// mark the hit not_affected instead of violated.
function runMigration(script) {
  return eval(script);
}

module.exports = { runMigration };
`,
);
write(
  "src/framework.js",
  `// Tiny express-shaped router — hand-rolled so the fixture's lockfile carries
// ONLY the two planted vulnerable dependencies, no framework noise.
const routes = [];
function register(method, path, handlers) {
  routes.push({ method, path, handlers });
}
module.exports = {
  get: (path, ...h) => register("GET", path, h),
  post: (path, ...h) => register("POST", path, h),
  routes,
};
`,
);
write(
  "src/auth.js",
  `function requireAuth(req) {
  if (!req.headers || !req.headers.authorization) {
    throw new Error("unauthenticated");
  }
}

module.exports = { requireAuth };
`,
);
write(
  "src/server.js",
  `const app = require("./framework");
const { requireAuth } = require("./auth");
const { handleRequest } = require("./index");
// the ALLOWED importer (fault 10's contrast): the contract permits exactly this
const { formatInvoice } = require("./billing");

// Authenticated: the auth check sits in the route's call path.
app.get("/settings", (req, res) => {
  requireAuth(req);
  res.end(JSON.stringify({ page: handleRequest(req.body), invoice: formatInvoice({}) }));
});

// FAULT: no auth check anywhere in this route's call path.
app.get("/health", (req, res) => {
  res.end("ok");
});
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
write(
  "openapi.yaml",
  `# FAULT: invalid OpenAPI document — the standard requires an \`info\` object;
# spectral (oas ruleset) must reject this at error severity.
openapi: 3.0.3
paths:
  /health:
    get:
      responses:
        "200":
          description: ok
`,
);
// The governed documents (N1b wave 1): declared, and — unlike almost
// everything else in this fixture — HONESTLY PRESENT. The three document-family
// recipes need a repository where they can reach `evidenced`, and the fixture
// that plants a fault in every other plane is the one that has to carry the
// passing case here; the missing, empty and undeclared cases are unit tests in
// packages/collectors/test/documents.test.ts, where a temp directory can be
// broken in one specific way at a time.
write(
  "docs/access-control-policy.md",
  `# Access control policy

Who may reach what in vulnerable-app, and on whose authority. Fixture content:
this document exists so a declaration can be satisfied honestly, and rampscan
reads its path, its size and its hash — never its argument.
`,
);
write(
  "docs/admin-guide.md",
  `# Administrator guide

Installing, configuring and operating vulnerable-app. Fixture content, present
for the same reason as the policy beside it.
`,
);
write(
  "SECURITY.md",
  `# Security policy

Report a vulnerability to security@vulnerable-app.invalid. In scope: this
repository. We answer within 5 working days.

Fixture content — the address is deliberately unroutable, which is exactly the
limb RA-05 (11)'s record leaves in its remainder: a committed channel is not a
monitored one.
`,
);
// The architecture contract (faults 10 and 11): the repo's OWN declared
// intent, which the code above deliberately breaks. No `graph` block — entry
// points stay inferred from package.json, which the J5 smoke pins on screen.
write(
  "rampscan.config.json",
  JSON.stringify(
    {
      contract: {
        rules: [
          {
            kind: "route-auth",
            id: "all-routes-authed",
            routes: "/*",
            description: "every route this service registers must require an authenticated caller",
          },
          {
            kind: "boundary",
            id: "billing-isolated",
            module: "src/billing",
            allowedImporters: ["src/server.js"],
            description: "billing logic may only be reached through the server layer",
          },
        ],
      },
      documents: [
        {
          id: "access-control-policy",
          kind: "access-control-policy",
          path: "docs/access-control-policy.md",
          description: "the policy governing who may reach what in this service",
        },
        {
          id: "admin-guide",
          kind: "system-documentation",
          path: "docs/admin-guide.md",
          description: "installation, configuration and operation for an administrator",
        },
      ],
    },
    null,
    2,
  ) + "\n",
);
write("README.md", "# vulnerable-app\n\nPlanted-fault fixture for rampscan. Every fault here is deliberate.\n");
git("add", "-A");
git("commit", "-q", "-m", "initial app");

// ---- commit 2: fault 1, the secret enters history --------------------------
// Split at a boundary no credential scanner reassembles; joined, byte-identical
// to the value this fixture has planted since it was written.
const PLANTED_KEY_ID = "AKIA" + "2jqw4kdlpz3xv7qh".toUpperCase();
const PLANTED_SECRET = ["e7Kp2mXzQ9Rt", "V4wYbN6cJ8hL", "3sD5fGaUqZ1o", "TiWv"].join("");
write(
  "config/.env",
  // Fake-but-well-formed AWS credentials: matches gitleaks' aws-access-key-id
  // pattern (AKIA + 16 uppercase alphanumerics). Not a real key. Deliberately
  // NOT AWS's documented example key (AKIAIOSFODNN7EXAMPLE) — gitleaks
  // allowlists that one, which would make the planted fault undetectable.
  //
  // Assembled rather than written as a literal, so that no blob in THIS
  // repository matches the pattern the fixture exists to plant. The bytes the
  // fixture receives are unchanged — its commit SHAs are load-bearing — and a
  // scanner pointed at rampscan itself no longer reports a finding that only
  // ever meant "the test data is working".
  `AWS_ACCESS_KEY_ID=${PLANTED_KEY_ID}
AWS_SECRET_ACCESS_KEY=${PLANTED_SECRET}
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
