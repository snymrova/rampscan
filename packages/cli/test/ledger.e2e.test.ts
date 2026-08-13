import { execFileSync } from "node:child_process";
import { appendFile, mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import { repoFacts } from "@rampscan/collectors";
import { createLocalLedger } from "@rampscan/ledger";
import { createProjector } from "@rampscan/projector";
import { DEFAULT_DATASET_PIN } from "@rampscan/dataset";
import { scan, verify } from "../src/index.js";
import type { ScanOutcome } from "../src/index.js";

// The M2 exit test (plan §M2 "done when"): two successive scans of the same
// repo with a touched file in between → the touched-path evidence dies of
// anchor-drift with the killing commit named, untouched evidence survives
// with its original signature, and `verify` passes on both old and new
// bundles. repo-facts only — no external tools, CI-safe.

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "../../..");

const gitEnv = {
  ...process.env,
  GIT_AUTHOR_NAME: "m2-test",
  GIT_AUTHOR_EMAIL: "m2@rampscan.invalid",
  GIT_COMMITTER_NAME: "m2-test",
  GIT_COMMITTER_EMAIL: "m2@rampscan.invalid",
};

let appRoot: string;
let ledgerDir: string;
let keysDir: string;
let commit2: string;
let scan1: ScanOutcome;
let scan2: ScanOutcome;

function git(cwd: string, ...args: string[]): string {
  return execFileSync("git", args, { cwd, env: gitEnv, encoding: "utf8" }).trim();
}

function record(outcome: ScanOutcome, kind: "appended" | "survived", recipeId: string) {
  return outcome.evidence![kind].find((r) => r.recipeId === recipeId);
}

async function runScan(now: Date): Promise<ScanOutcome> {
  return scan({
    path: appRoot,
    outDir: await mkdtemp(join(tmpdir(), "rampscan-m2-out-")),
    datasetDir: join(repoRoot, "docs/context/ramprules/derived"),
    datasetPin: DEFAULT_DATASET_PIN,
    recipesDir: join(repoRoot, "recipes/pipeline"),
    collectors: [repoFacts],
    ledgerDir,
    keysDir,
    now,
  });
}

beforeAll(async () => {
  const base = await mkdtemp(join(tmpdir(), "rampscan-m2-"));
  appRoot = join(base, "app");
  ledgerDir = join(base, "ledger");
  keysDir = join(base, "keys");
  await mkdir(join(appRoot, ".github", "workflows"), { recursive: true });

  await writeFile(
    join(appRoot, "package.json"),
    JSON.stringify({ name: "m2-app", version: "1.0.0" }, null, 2),
  );
  await writeFile(
    join(appRoot, "package-lock.json"),
    JSON.stringify({ name: "m2-app", version: "1.0.0", lockfileVersion: 3, packages: {} }, null, 2),
  );
  await writeFile(
    join(appRoot, ".github", "workflows", "ci.yml"),
    [
      "on: push",
      "jobs:",
      "  test:",
      "    runs-on: ubuntu-latest",
      "    steps:",
      `      - uses: actions/checkout@${"0".repeat(40)}`,
      "      - run: npm test",
    ].join("\n") + "\n",
  );
  git(appRoot, "init", "-q", "-b", "main");
  git(appRoot, "add", "-A");
  git(appRoot, "commit", "-qm", "app");

  scan1 = await runScan(new Date("2026-08-13T10:00:00Z"));

  // touch ONLY the workflow file — a comment changes the blob, not the checks
  await appendFile(join(appRoot, ".github", "workflows", "ci.yml"), "# touched\n");
  git(appRoot, "add", "-A");
  git(appRoot, "commit", "-qm", "touch workflow");
  commit2 = git(appRoot, "rev-parse", "HEAD");

  scan2 = await runScan(new Date("2026-08-13T11:00:00Z"));
});

describe("M2: ledger, signing, and honest death", () => {
  it("the first scan records signed evidence; nothing pre-exists to survive", () => {
    expect(scan1.evidence!.appended.length).toBeGreaterThan(0);
    expect(scan1.evidence!.survived).toHaveLength(0);
    expect(record(scan1, "appended", "lockfile-pinned-deps")).toBeDefined();
    expect(record(scan1, "appended", "ci-actions-pinned")).toBeDefined();
  });

  it("untouched evidence survives the second scan with its original digest", () => {
    const survivor = record(scan2, "survived", "lockfile-pinned-deps");
    expect(survivor).toBeDefined();
    expect(survivor!.digest).toBe(record(scan1, "appended", "lockfile-pinned-deps")!.digest);
    expect(record(scan2, "appended", "lockfile-pinned-deps")).toBeUndefined();
  });

  it("touched-path evidence is re-keyed: a new bundle, a new digest", () => {
    const rekeyed = record(scan2, "appended", "ci-actions-pinned");
    expect(rekeyed).toBeDefined();
    expect(rekeyed!.digest).not.toBe(record(scan1, "appended", "ci-actions-pinned")!.digest);
  });

  it("the projector declares the old evidence dead of anchor-drift, naming the killing commit", async () => {
    const projection = await createProjector().fold(createLocalLedger(ledgerDir));
    const rows = projection.rows.filter((r) => r.recipeId === "ci-actions-pinned");
    expect(rows).toHaveLength(2);

    const dead = rows.find((r) => r.status.state === "dead")!;
    expect(dead.bundleDigest).toBe(record(scan1, "appended", "ci-actions-pinned")!.digest);
    expect(dead.status).toEqual({ state: "dead", cause: "anchor-drift", killingCommit: commit2 });

    const live = rows.find((r) => r.status.state === "live")!;
    expect(live.bundleDigest).toBe(record(scan2, "appended", "ci-actions-pinned")!.digest);
  });

  it("survivors stay live with their original freshness — the clock did not reset", async () => {
    const projection = await createProjector().fold(createLocalLedger(ledgerDir));
    const row = projection.rows.find((r) => r.recipeId === "lockfile-pinned-deps")!;
    expect(row.status).toEqual({ state: "live" });
    expect(row.freshAsOf).toBe("2026-08-13T10:00:00.000Z");
  });

  it("verify passes on both the old (dead) and the new bundle — death is not corruption", async () => {
    for (const digest of [
      record(scan1, "appended", "ci-actions-pinned")!.digest,
      record(scan2, "appended", "ci-actions-pinned")!.digest,
      record(scan1, "appended", "lockfile-pinned-deps")!.digest,
    ]) {
      const report = await verify({ digest, ledgerDir, keysDir });
      expect(report.ok, report.lines.join("\n")).toBe(true);
    }
  });

  it("verify fails honestly on a digest the ledger never saw", async () => {
    const report = await verify({ digest: "f".repeat(64), ledgerDir, keysDir });
    expect(report.ok).toBe(false);
    expect(report.lines.join("\n")).toContain("no ledger entry");
  });
});
