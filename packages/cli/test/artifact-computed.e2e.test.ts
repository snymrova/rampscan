import { execFileSync } from "node:child_process";
import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import { repoFacts, allCollectors } from "@rampscan/collectors";
import type { Projection } from "@rampscan/core";
import { DEFAULT_DATASET_PIN, loadKsiCatalogFromSlices } from "@rampscan/dataset";
import { createLocalLedger } from "@rampscan/ledger";
import { createProjector } from "@rampscan/projector";
import { isArtifact } from "@rampscan/schema";
import { mintComputedArtifact } from "../src/artifacts.js";
import { deriveCatalogMethods, loadRecipes } from "../src/recipes.js";
import { scan } from "../src/scan.js";
import { verify } from "../src/verify.js";

// R1.2 exit test, over a REAL scanned world — repo-facts only, no external
// tools, CI-safe — because the thing under test is whether artifact 4 can be
// computed from the execution record a real run actually signed. A fixture
// journal would prove the renderer works and nothing about the seam.

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "../../..");
const RECIPES_DIR = join(repoRoot, "recipes/commit");
const DATASET_DIR = join(repoRoot, "docs/context/ramprules/derived");

const gitEnv = {
  ...process.env,
  GIT_AUTHOR_NAME: "r12-test",
  GIT_AUTHOR_EMAIL: "r12@rampscan.invalid",
  GIT_COMMITTER_NAME: "r12-test",
  GIT_COMMITTER_EMAIL: "r12@rampscan.invalid",
};

let appRoot: string;
let ledgerDir: string;
let keysDir: string;
let repo: string;
let projection: Projection;
/** a KSI this scan evidenced through an automated method — discovered, not assumed */
let evidencedKsi: string;
/** a KSI the catalog owes that nothing automated — the §13.4 refusal's case */
let unautomatedKsi: string;

async function fold(): Promise<Projection> {
  const catalog = await loadKsiCatalogFromSlices(DATASET_DIR, DEFAULT_DATASET_PIN);
  const projector = createProjector({
    recipes: await loadRecipes(RECIPES_DIR),
    methods: deriveCatalogMethods(
      await loadRecipes(RECIPES_DIR),
      allCollectors.map((c) => c.manifest),
    ),
    ksiIds: catalog.ksis.map((k) => k.id),
  });
  return projector.fold(createLocalLedger(ledgerDir));
}

beforeAll(async () => {
  const base = await mkdtemp(join(tmpdir(), "rampscan-r12-"));
  appRoot = join(base, "app");
  ledgerDir = join(base, "ledger");
  keysDir = join(base, "keys");
  await mkdir(join(appRoot, ".github", "workflows"), { recursive: true });
  await writeFile(
    join(appRoot, "package.json"),
    JSON.stringify({ name: "r12-app", version: "1.0.0" }, null, 2),
  );
  await writeFile(
    join(appRoot, ".github", "workflows", "ci.yml"),
    ["on: push", "jobs:", "  t:", "    runs-on: ubuntu-latest", "    steps:", "      - run: npm test"].join("\n") + "\n",
  );
  execFileSync("git", ["init", "-q", "-b", "main"], { cwd: appRoot, env: gitEnv });
  execFileSync("git", ["add", "-A"], { cwd: appRoot, env: gitEnv });
  execFileSync("git", ["commit", "-qm", "app"], { cwd: appRoot, env: gitEnv });

  await scan({
    path: appRoot,
    outDir: join(base, "out"),
    datasetDir: DATASET_DIR,
    datasetPin: DEFAULT_DATASET_PIN,
    recipesDir: RECIPES_DIR,
    collectors: [repoFacts],
    ledgerDir,
    keysDir,
    trigger: "test",
  });

  projection = await fold();
  const rows = projection.methodRegisters;
  repo = rows[0]!.repo;
  evidencedKsi = rows.find(
    (r) => r.automatedMethods > 0 && r.methods.some((m) => m.bundleDigest !== undefined),
  )!.ksi;
  unautomatedKsi = rows.find((r) => r.automatedMethods === 0)!.ksi;
}, 180_000);

describe("computed artifact 4 from the exec journal (R1.2)", () => {
  it("mints a body from the run this scan signed, and the slot fills", async () => {
    const minted = await mintComputedArtifact({
      repo,
      ksiId: evidencedKsi,
      artifact: 4,
      projection,
      datasetDir: DATASET_DIR,
      datasetPin: DEFAULT_DATASET_PIN,
      ledgerDir,
      keysDir,
    });
    expect(minted.minted, "minted" in minted && !minted.minted ? minted.reason : "").toBe(true);

    // it verifies offline like anything else in the ledger
    const digest = (minted as { digest: string }).digest;
    const report = await verify({ digest, ledgerDir, keysDir });
    expect(report.ok, report.lines.join("\n")).toBe(true);
    expect(report.lines.join("\n")).toContain(`${evidencedKsi} #4 — computed`);

    // and the statement carries what produced it
    const entry = (await createLocalLedger(ledgerDir).get(digest))!;
    expect(isArtifact(entry.bundle)).toBe(true);
    const predicate = (entry.bundle as { predicate: Record<string, unknown> }).predicate;
    const generator = predicate.generator as { journal_digest?: string; pins: Record<string, string> };
    expect(generator.journal_digest).toBeDefined();
    expect(generator.pins.run).toBeDefined();
    // the journal digest resolves to the run record in this same ledger
    const journal = await createLocalLedger(ledgerDir).get(generator.journal_digest!);
    expect(journal).toBeDefined();
    expect(String(predicate.body)).toContain("repo-facts");

    // the board moves, and the cell says where the bytes came from
    const after = await fold();
    const cell = after.methodRegisters
      .find((r) => r.repo === repo && r.ksi === evidencedKsi)!
      .artifacts.find((a) => a.artifact === 4)!;
    expect(cell.present).toBe(true);
    expect(cell.body?.source).toBe("computed");
  });

  it("refuses where nothing is automated, with the reason §13.4 requires", async () => {
    const minted = await mintComputedArtifact({
      repo,
      ksiId: unautomatedKsi,
      artifact: 4,
      projection,
      datasetDir: DATASET_DIR,
      datasetPin: DEFAULT_DATASET_PIN,
      ledgerDir,
      keysDir,
    });
    expect(minted.minted).toBe(false);
    expect((minted as { reason: string }).reason).toContain("rampscan does not write it");

    // and nothing was appended for it — a refusal writes no statement
    const entries = await createLocalLedger(ledgerDir).list();
    const bodies = entries.filter(
      (e) => isArtifact(e.bundle) && e.bundle.predicate.ksi_id === unautomatedKsi,
    );
    expect(bodies).toHaveLength(0);
  });

  it("is reproducible: the same fold mints byte-identical prose", async () => {
    const again = await mintComputedArtifact({
      repo,
      ksiId: evidencedKsi,
      artifact: 4,
      projection,
      datasetDir: DATASET_DIR,
      datasetPin: DEFAULT_DATASET_PIN,
      ledgerDir,
      keysDir,
    });
    expect(again.minted).toBe(true);
    const entries = (await createLocalLedger(ledgerDir).list()).filter(
      (e) => isArtifact(e.bundle) && e.bundle.predicate.ksi_id === evidencedKsi,
    );
    const digests = new Set(
      entries.map((e) => (e.bundle as { predicate: { body_digest: string } }).predicate.body_digest),
    );
    // two generations, one set of bytes — §13.5's clock restarted, the prose
    // did not change, and nothing claims to supersede itself
    expect(digests.size).toBe(1);
    expect((again as { supersedes?: string }).supersedes).toBeUndefined();
  });
});
