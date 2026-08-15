// The second fixture repo (K1): a repository with HONEST GAPS.
//
// `vulnerable-app` is fully tooled — every collector finds something of its
// kind to look at, so every one of its board rows comes back evidenced or
// violated and the board has no empty cell anywhere. That made two shipped
// features untestable end to end: J3's "why is this empty?" hop (recorded at
// the time as "this fixture is fully tooled so its board has no unevidenced
// row to click") and now K1's guided empty states, whose whole subject is the
// empty cell.
//
// So this repo is deliberately unremarkable: a package with a lockfile, and
// nothing else. No Dockerfile, no CI workflow, no infrastructure definition,
// no API description, no server routes. Every collector that has nothing of
// its kind to look at skips HONESTLY and says so in the run record, which is
// exactly the sentence K1 renders under an empty row — a real skip reason
// produced by a real collector, never a fixture string typed to be found.
//
// Deterministic like its sibling: fixed identity and dates, so commit SHAs are
// stable across machines.

import { execFileSync } from "node:child_process";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "bare-app");

const gitEnv = {
  ...process.env,
  GIT_AUTHOR_NAME: "fixture",
  GIT_AUTHOR_EMAIL: "fixture@rampscan.invalid",
  GIT_COMMITTER_NAME: "fixture",
  GIT_COMMITTER_EMAIL: "fixture@rampscan.invalid",
  GIT_AUTHOR_DATE: "2026-01-02T00:00:00Z",
  GIT_COMMITTER_DATE: "2026-01-02T00:00:00Z",
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

write(
  "package.json",
  `${JSON.stringify(
    {
      name: "bare-app",
      version: "1.0.0",
      private: true,
      description: "a library with no pipeline, no container and no API surface",
      main: "index.js",
      license: "MIT",
      dependencies: {},
    },
    null,
    2,
  )}\n`,
);

// A real lockfile, so lockfile-pinned-deps has something true to say and the
// board is not uniformly empty — an all-empty repo would prove the renderer
// draws sentences, not that it draws them beside real answers.
write(
  "package-lock.json",
  `${JSON.stringify(
    {
      name: "bare-app",
      version: "1.0.0",
      lockfileVersion: 3,
      requires: true,
      packages: { "": { name: "bare-app", version: "1.0.0", license: "MIT" } },
    },
    null,
    2,
  )}\n`,
);

write(
  "index.js",
  `"use strict";

// Deliberately dull: no dynamic evaluation, no shell, no server. The point of
// this repository is what it does NOT contain.
function titleCase(input) {
  return String(input)
    .split(" ")
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
    .join(" ");
}

module.exports = { titleCase };
`,
);

write(
  "README.md",
  `# bare-app

A small library used as a scan fixture. It has no CI pipeline, no container
image, no infrastructure definitions and no HTTP surface — the collectors that
look for those find nothing and say so.
`,
);

git("add", "-A");
git("commit", "-q", "-m", "initial library");

const head = git("rev-parse", "HEAD").trim();
console.log(`bare-app built at ${root}`);
console.log(`HEAD ${head}`);
