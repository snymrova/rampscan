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
import { windowMsFor } from "@rampscan/scheduler";
import { canonicalJson } from "@rampscan/schema";
import type { Projection } from "@rampscan/core";
import { computeBoardAsOf, loadRecipes, scan, verify } from "../src/index.js";
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
let projectionAfterScan1: Projection;

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

  // capture what the board looked like right after the first scan — the
  // as-of exit test (I1b) must reproduce this byte-for-byte from the ledger
  projectionAfterScan1 = await createProjector({
    recipes: await loadRecipes(join(repoRoot, "recipes/pipeline")),
    windowMs: windowMsFor("b"),
    now: () => new Date("2026-08-13T10:30:00Z"),
  }).fold(createLocalLedger(ledgerDir));

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

describe("Phase I1 exit: point-in-time truth over the append-only record", () => {
  async function foldNow(asOf?: string): Promise<Projection> {
    return createProjector({
      recipes: await loadRecipes(join(repoRoot, "recipes/pipeline")),
      windowMs: windowMsFor("b"),
      now: () => new Date("2026-08-13T10:30:00Z"),
      ...(asOf !== undefined ? { asOf } : {}),
    }).fold(createLocalLedger(ledgerDir));
  }

  it("folding as-of an instant between the scans reproduces the first scan's projection byte-for-byte", async () => {
    const asOf = await foldNow("2026-08-13T10:30:00.000Z");
    expect(canonicalJson(asOf)).toBe(canonicalJson(projectionAfterScan1));
  });

  it("without as-of, the fold over both scans differs — the second scan really moved the board", async () => {
    const current = await foldNow();
    expect(canonicalJson(current)).not.toBe(canonicalJson(projectionAfterScan1));
  });

  // I3d: computeBoardAsOf is the one hand behind `rampscan board --as-of`
  // AND the console's /api/board/asof route — pinned here against the same
  // real two-scan ledger the I1b exit test uses, so both surfaces inherit
  // the byte-for-byte determinism proven above.
  it("computeBoardAsOf between the scans reproduces the first scan's registers and rollups (I3d)", async () => {
    const outcome = await computeBoardAsOf({
      ledgerDir,
      recipesDir: join(repoRoot, "recipes/pipeline"),
      asOf: "2026-08-13T10:30:00.000Z",
    });
    expect(canonicalJson(outcome.projection.registers)).toBe(
      canonicalJson(projectionAfterScan1.registers),
    );
    expect(canonicalJson(outcome.projection.controls)).toBe(
      canonicalJson(projectionAfterScan1.controls),
    );
    expect(canonicalJson(outcome.projection.ksis)).toBe(canonicalJson(projectionAfterScan1.ksis));
    // both scan instants enumerated, ascending — the selector's quick picks
    expect(outcome.scans).toHaveLength(2);
    expect(outcome.scans[0]! < outcome.scans[1]!).toBe(true);
    // a between-scans instant is honestly labeled as not a scan
    expect(outcome.asOfIsScan).toBe(false);
  });

  it("computeBoardAsOf at a scan instant includes that scan and says it is one (I3d)", async () => {
    const scansOnly = await computeBoardAsOf({
      ledgerDir,
      recipesDir: join(repoRoot, "recipes/pipeline"),
      asOf: (await computeBoardAsOf({
        ledgerDir,
        recipesDir: join(repoRoot, "recipes/pipeline"),
        asOf: "2026-08-13T10:30:00.000Z",
      })).scans[0]!,
    });
    expect(scansOnly.asOfIsScan).toBe(true);
    // the fold filter is inclusive: as-of AT the first scan's instant IS the
    // first scan's board
    expect(canonicalJson(scansOnly.projection.registers)).toBe(
      canonicalJson(projectionAfterScan1.registers),
    );
  });

  it("computeBoardAsOf before any scan folds an honestly empty world (I3d)", async () => {
    const outcome = await computeBoardAsOf({
      ledgerDir,
      recipesDir: join(repoRoot, "recipes/pipeline"),
      asOf: "2020-01-01T00:00:00.000Z",
    });
    // no repo had been scanned at that instant — no rows exist to show, and
    // the empty board is the answer, not an error
    expect(outcome.projection.registers).toHaveLength(0);
    expect(outcome.projection.controls).toHaveLength(0);
    expect(outcome.projection.ksis).toHaveLength(0);
  });

  it("control-register counts match an independent recount from the register rows", async () => {
    const projection = await foldNow();
    expect(projection.controls.length).toBeGreaterThan(0);
    expect(projection.ksis.length).toBeGreaterThan(0);
    for (const [rollups, ids] of [
      [projection.controls, (r: (typeof projection.registers)[number]) => r.controlIds],
      [projection.ksis, (r: (typeof projection.registers)[number]) => r.ksiIds],
    ] as const) {
      for (const rollup of rollups) {
        const mapped = projection.registers.filter(
          (row) => row.repo === rollup.repo && ids(row).includes(rollup.id),
        );
        expect(rollup.counts.total, `${rollup.id} total`).toBe(mapped.length);
        expect(rollup.recipeIds).toEqual(mapped.map((r) => r.recipeId).sort());
        for (const state of ["evidenced", "violated", "unevidenced", "notApplicable"] as const) {
          expect(rollup.counts[state], `${rollup.id} ${state}`).toBe(
            mapped.filter((r) => r.state === state).length,
          );
        }
      }
    }
  });
});
