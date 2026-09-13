import { execFileSync } from "node:child_process";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import { allCollectors, repoFacts } from "@rampscan/collectors";
import type { Projection } from "@rampscan/core";
import { DEFAULT_DATASET_PIN, loadKsiCatalogFromSlices } from "@rampscan/dataset";
import { createLocalLedger } from "@rampscan/ledger";
import { createProjector } from "@rampscan/projector";
import { mintComputedArtifact } from "../src/artifacts.js";
import { deriveCatalogMethods, loadRecipes } from "../src/recipes.js";
import { scan } from "../src/scan.js";
import { verify } from "../src/verify.js";

// THE R1 EXIT GATE, end to end:
//
//   "`frontier` prints a non-zero k / 5 for a KSI whose artifacts were authored
//    and computed; removing the authored file drops it back; byte-equal
//    `rebuild`; the suite green."
//
// One repository, one scan, repo-facts only (CI-safe). The repo declares an
// authored artifact 1 for a KSI its pipeline also evidences, so both halves of
// the plane meet on the same row — which is the arrangement the whole phase
// exists to produce.

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "../../..");
const RECIPES_DIR = join(repoRoot, "recipes/commit");
const DATASET_DIR = join(repoRoot, "docs/context/ramprules/derived");

const gitEnv = {
  ...process.env,
  GIT_AUTHOR_NAME: "r14-test",
  GIT_AUTHOR_EMAIL: "r14@rampscan.invalid",
  GIT_COMMITTER_NAME: "r14-test",
  GIT_COMMITTER_EMAIL: "r14@rampscan.invalid",
};

// a KSI repo-facts actually evidences in this fixture, so the authored body
// and a computed one meet on the SAME row — the arrangement the exit gate asks
// for, and the one that proves the two halves of the plane compose
const KSI = "KSI-CMT-VTD";
const ARTIFACT_PATH = "docs/ksi/cmt-vtd-1.md";
const BODY = "## Vulnerability tracking\n\nDependency updates are automated and tested on every merge.\n";

let base: string;
let appRoot: string;
let ledgerDir: string;
let keysDir: string;
let outDir: string;
let repo: string;

function git(...args: string[]): string {
  return execFileSync("git", args, { cwd: appRoot, env: gitEnv, encoding: "utf8" }).trim();
}

function runScan() {
  return scan({
    path: appRoot,
    outDir,
    datasetDir: DATASET_DIR,
    datasetPin: DEFAULT_DATASET_PIN,
    recipesDir: RECIPES_DIR,
    collectors: [repoFacts],
    ledgerDir,
    keysDir,
    trigger: "test",
  });
}

async function fold(): Promise<Projection> {
  const catalog = await loadKsiCatalogFromSlices(DATASET_DIR, DEFAULT_DATASET_PIN);
  const recipes = await loadRecipes(RECIPES_DIR);
  const projector = createProjector({
    recipes,
    methods: deriveCatalogMethods(
      recipes,
      allCollectors.map((c) => c.manifest),
    ),
    ksiIds: catalog.ksis.map((k) => k.id),
  });
  return projector.fold(createLocalLedger(ledgerDir));
}

async function artifactsOf(ksi: string) {
  const projection = await fold();
  return projection.methodRegisters.find((r) => r.repo === repo && r.ksi === ksi)!;
}

beforeAll(async () => {
  base = await mkdtemp(join(tmpdir(), "rampscan-r14-e2e-"));
  appRoot = join(base, "app");
  ledgerDir = join(base, "ledger");
  keysDir = join(base, "keys");
  outDir = join(base, "out");
  await mkdir(join(appRoot, "docs", "ksi"), { recursive: true });
  await mkdir(join(appRoot, ".github", "workflows"), { recursive: true });
  await writeFile(
    join(appRoot, "package.json"),
    JSON.stringify({ name: "r14-app", version: "1.0.0" }, null, 2),
  );
  await writeFile(
    join(appRoot, ".github", "workflows", "ci.yml"),
    ["on: push", "jobs:", "  t:", "    runs-on: ubuntu-latest", "    steps:", "      - run: npm test"].join("\n") + "\n",
  );
  await writeFile(join(appRoot, ARTIFACT_PATH), BODY);
  await writeFile(
    join(appRoot, "rampscan.config.json"),
    JSON.stringify(
      {
        artifacts: [
          {
            ksi: KSI,
            artifact: 1,
            path: ARTIFACT_PATH,
            description: "How vulnerabilities are tracked and remediated, and by which measures.",
          },
        ],
      },
      null,
      2,
    ),
  );
  git("init", "-q", "-b", "main");
  git("add", "-A");
  git("commit", "-qm", "app with a declared artifact");

  const outcome = await runScan();
  repo = outcome.result.repo;
}, 240_000);

describe("the authored source, end to end (R1.4)", () => {
  it("appends the declared body as a signed, commit-anchored artifact", async () => {
    const row = await artifactsOf(KSI);
    const cell = row.artifacts.find((a) => a.artifact === 1)!;
    expect(cell.present).toBe(true);
    expect(cell.body?.source).toBe("authored");
    expect(cell.body?.anchor).toEqual({ commit: git("rev-parse", "HEAD"), path: ARTIFACT_PATH });
    expect(cell.body?.validFrom).toBe(git("log", "-1", "--format=%cI"));

    const report = await verify({ digest: cell.body!.digest, ledgerDir, keysDir });
    expect(report.ok, report.lines.join("\n")).toBe(true);
    expect(report.lines.join("\n")).toContain(`${KSI} #1 — authored`);
  });

  it("does not re-append an unchanged body — its clock did not move", async () => {
    const before = await createLocalLedger(ledgerDir).list();
    const outcome = await runScan();
    expect(outcome.artifacts?.unchanged).toEqual([{ ksi: KSI, artifact: 1 }]);
    expect(outcome.artifacts?.appended).toEqual([]);
    const after = await createLocalLedger(ledgerDir).list();
    expect(after.length).toBeGreaterThanOrEqual(before.length); // the run record lands
    expect(
      after.filter((e) => e.bundle.predicate.timestamp !== undefined).length,
    ).toBeGreaterThan(0);
  });

  it("THE EXIT GATE: authored beside computed, and removing the file drops it back", async () => {
    // computed 4 beside the authored 1 — both halves of the plane on one row
    const projection = await fold();
    const minted = await mintComputedArtifact({
      repo,
      ksiId: KSI,
      artifact: 4,
      projection,
      offeringClass: "b",
      datasetDir: DATASET_DIR,
      datasetPin: DEFAULT_DATASET_PIN,
      ledgerDir,
      keysDir,
    });
    expect(minted.minted, "minted" in minted && !minted.minted ? minted.reason : "").toBe(true);

    const filled = await artifactsOf(KSI);
    expect(filled.artifactsPresent).toBeGreaterThanOrEqual(2);
    expect(filled.artifacts.find((a) => a.artifact === 1)!.body?.source).toBe("authored");
    expect(filled.artifacts.find((a) => a.artifact === 4)!.body?.source).toBe("computed");

    // now remove the authored file and re-scan: the declaration stands and
    // points at nothing, so the scan says so rather than passing over it
    await rm(join(appRoot, ARTIFACT_PATH));
    git("add", "-A");
    git("commit", "-qm", "remove the authored artifact");
    const outcome = await runScan();
    expect(outcome.artifacts?.problems).toEqual([
      { ksi: KSI, artifact: 1, path: ARTIFACT_PATH, reason: "no file at the declared path" },
    ]);
    expect(outcome.artifacts?.appended).toEqual([]);

    // …and the board drops it back. The `Artifact` has no withdrawal, so what
    // kills it is the scan's signed observation that the declaration no longer
    // resolves — and the empty cell carries that scan's own sentence.
    const dropped = await artifactsOf(KSI);
    const cell = dropped.artifacts.find((a) => a.artifact === 1)!;
    expect(cell.present).toBe(false);
    expect(cell.body).toBeUndefined();
    expect(cell.absent?.reason).toBe("no file at the declared path");
    expect(cell.absent?.path).toBe(ARTIFACT_PATH);
    expect(dropped.artifactsPresent).toBe(filled.artifactsPresent - 1);
    // the computed one is untouched: nothing was declared about it
    expect(dropped.artifacts.find((a) => a.artifact === 4)!.present).toBe(true);
  });

  it("restoring the file brings the slot back — a later observation un-kills it", async () => {
    await mkdir(join(appRoot, "docs", "ksi"), { recursive: true });
    await writeFile(join(appRoot, ARTIFACT_PATH), BODY);
    await writeFile(
      join(appRoot, "rampscan.config.json"),
      JSON.stringify(
        {
          artifacts: [
            {
              ksi: KSI,
              artifact: 1,
              path: ARTIFACT_PATH,
              description: "How vulnerabilities are tracked and remediated, and by which measures.",
            },
          ],
        },
        null,
        2,
      ),
    );
    git("add", "-A");
    git("commit", "-qm", "restore the authored artifact");

    const outcome = await runScan();
    expect(outcome.artifacts?.appended).toHaveLength(1);
    const row = await artifactsOf(KSI);
    const cell = row.artifacts.find((a) => a.artifact === 1)!;
    expect(cell.present).toBe(true);
    expect(cell.absent).toBeUndefined();
  });

  it("refuses a declaration for a KSI outside the pinned catalog", async () => {
    await writeFile(
      join(appRoot, "rampscan.config.json"),
      JSON.stringify(
        {
          artifacts: [
            {
              ksi: "KSI-NOT-REAL",
              artifact: 1,
              path: "docs/ksi/nope.md",
              description: "A declaration naming a KSI that does not exist at this pin.",
            },
          ],
        },
        null,
        2,
      ),
    );
    await mkdir(join(appRoot, "docs", "ksi"), { recursive: true });
    await writeFile(join(appRoot, "docs/ksi/nope.md"), "## Nope\n\nThis names no real slot.\n");
    git("add", "-A");
    git("commit", "-qm", "declare a KSI that does not exist");

    const outcome = await runScan();
    expect(outcome.artifacts?.appended).toEqual([]);
    expect(outcome.artifacts?.problems[0]!.reason).toContain("not in the pinned catalog");
  });
});
