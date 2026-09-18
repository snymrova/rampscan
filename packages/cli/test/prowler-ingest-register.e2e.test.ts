import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { allCollectors } from "@rampscan/collectors";
import {
  DEFAULT_DATASET_PIN,
  loadKsiCatalog,
  loadLocalDataset,
  loadRuleRegister,
} from "@rampscan/dataset";
import { createLocalLedger } from "@rampscan/ledger";
import { createProjector } from "@rampscan/projector";
import { loadAdjudications } from "../src/adjudications.js";
import { buildFrontier } from "../src/frontier.js";
import { ingest } from "../src/ingest.js";
import { buildKsiRegister } from "../src/ksi-register.js";
import { deriveCatalogMethods, loadRecipes } from "../src/recipes.js";
import type { SdrCoverage } from "../src/sdr.js";
import { buildRejectionRegister } from "../src/submission.js";

// P3-5 (docs/RESEARCH-PROWLER-INGEST.md §5, §6): the register e2e.
//
// Q4.3's gate, restated for the fourth input: ingesting a Prowler scan raises
// a KSI's method count and its removal lowers it again. And §5's guarantee,
// which is new with P3 because P3 is the first change that could break it:
// what Prowler covers is a statement about RAMPSCAN'S evidence, not about
// the provider's submission. So the method registers move, and
// `rampscan submission`'s omission arithmetic — which KSIs the SDR leaves
// out — does not move by one row.

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const RECIPES_DIR = join(REPO_ROOT, "recipes/commit");
const DATASET_DIR = join(REPO_ROOT, "docs/context/ramprules/derived");
const RULES_FILE = join(REPO_ROOT, "docs/context/fedramp-rules/fedramp-consolidated-rules.json");
const ADJUDICATIONS_DIR = join(REPO_ROOT, "recipes/adjudications");
const SCAN = join(REPO_ROOT, "fixtures/ingest-prowler/prowler-output.ocsf.json");
const REPO = "fixtures/vulnerable-app";

async function ingestScan(ledgerDir: string, keysDir: string, exitCode = 0, log?: (l: string) => void) {
  return ingest({
    path: SCAN,
    repo: REPO,
    datasetDir: DATASET_DIR,
    rulesFile: RULES_FILE,
    datasetPin: DEFAULT_DATASET_PIN,
    ledgerDir,
    keysDir,
    cadence: "daily",
    exitCode,
    signerIdentity: "runner:prowler@synthetic-csp",
    repoRoot: REPO_ROOT,
    ...(log !== undefined ? { log } : {}),
  });
}

/** the `rampscan submission` KSI half over one ledger, the way main.ts builds it */
async function submissionOver(ledgerDir: string, sdr: SdrCoverage) {
  const catalog = await loadKsiCatalog({
    derivedDir: DATASET_DIR,
    rulesFile: RULES_FILE,
    pin: DEFAULT_DATASET_PIN,
  });
  const recipes = await loadRecipes(RECIPES_DIR);
  const methods = deriveCatalogMethods(recipes, allCollectors.map((c) => c.manifest));
  const projection = await createProjector({
    recipes,
    methods,
    ksiIds: catalog.ksis.map((k) => k.id),
    methodFloor: catalog.floors.b.minPerKsi,
    historyFloorMonths: catalog.historyFloors.b.months,
    machineWindow: catalog.windows.b,
    nonMachineWindow: catalog.nonMachineWindow,
  }).fold(createLocalLedger(ledgerDir));
  const dataset = await loadLocalDataset(DATASET_DIR, DEFAULT_DATASET_PIN);
  const ksis = buildKsiRegister({
    catalog,
    offeringClass: "b",
    methods,
    methodRegisters: projection.methodRegisters,
    frontier: buildFrontier({
      frontier: dataset.frontier(),
      adjudications: await loadAdjudications(ADJUDICATIONS_DIR),
      recipes,
      collectors: allCollectors,
      datasetVersion: dataset.version(),
      ksiReachedControls: dataset.ksiReachedControls(),
      upstreamRecipesFor: (controlId) => dataset.upstreamRecipesFor(controlId),
    }),
  });
  const view = await buildRejectionRegister({
    register: await loadRuleRegister(RULES_FILE, DEFAULT_DATASET_PIN),
    offeringClass: "b",
    ksis,
    sdr,
  });
  return { projection, ksis, section: view.sections.find((s) => s.section === "unaddressed-ksis")! };
}

describe("a Prowler scan on the board (P3-5)", () => {
  it("raises the method count, names what it could not see, and the removal lowers it", async () => {
    const withScan = await mkdtemp(join(tmpdir(), "rampscan-p35-with-"));
    const without = await mkdtemp(join(tmpdir(), "rampscan-p35-without-"));
    const lines: string[] = [];
    const outcome = await ingestScan(join(withScan, "ledger"), join(withScan, "keys"), 0, (l) =>
      lines.push(l),
    );

    // one bundle per (check, KSI), never per row: the fixture's 13
    // reported rows are six checks on eleven pairs, because
    // config_recorder_all_regions_enabled maps to six indicators (§2b)
    expect(outcome.appended).toHaveLength(11);
    const byMethod = new Map(outcome.appended.map((r) => [r.methodId, r.verdict]));
    expect(byMethod.get("aws-ingested:cloudfront_distributions_using_waf#KSI-CNA-RVP")).toBe("evidenced");
    // a MUTED fail still fails: a mutelist waives nothing here (P3-4)
    expect(byMethod.get("aws-ingested:iam_user_accesskey_unused#KSI-IAM-AAM")).toBe("violated");
    expect(byMethod.get("aws-ingested:iam_no_root_access_key#KSI-IAM-AAM")).toBe("evidenced");
    // the effective status decides, not the nested raw PASS (§10d)
    expect(byMethod.get("aws-ingested:cognito_user_pool_password_policy_lowercase#KSI-IAM-APM")).toBe(
      "violated",
    );
    for (const ksi of ["KSI-CMT-LMC", "KSI-CNA-EIS", "KSI-MLA-EVC", "KSI-MLA-LET", "KSI-PIY-GIV", "KSI-SVC-ACM"]) {
      expect(byMethod.get(`aws-ingested:config_recorder_all_regions_enabled#${ksi}`)).toBe("evidenced");
    }

    // the thirteen indicators nothing looked at: named, never minted
    expect(outcome.skipped).toHaveLength(13);
    expect(outcome.appended.some((r) => outcome.skipped.some((s) => r.methodId.endsWith(`#${s.ksi}`)))).toBe(
      false,
    );
    const log = lines.join("\n");
    expect(log).toContain("not recoverable from its output");
    expect(log).toMatch(/KSI-CNA-RVP coverage 2\/20 mapped AWS checks reported/);
    expect(log).toContain("no AWS call was executed by this appliance");

    // a record that answers every indicator except two the scan evidences
    const catalog = await loadKsiCatalog({
      derivedDir: DATASET_DIR,
      rulesFile: RULES_FILE,
      pin: DEFAULT_DATASET_PIN,
    });
    const answered = new Set(catalog.ksis.map((k) => k.id));
    answered.delete("KSI-CNA-RVP");
    answered.delete("KSI-IAM-AAM");
    const sdrMost: SdrCoverage = {
      path: "synthetic-sdr.json",
      ruleIds: new Set(),
      ksiIds: answered,
      statuses: new Map(),
      problems: [],
    };

    const withView = await submissionOver(join(withScan, "ledger"), sdrMost);
    const withoutView = await submissionOver(join(without, "ledger"), sdrMost);

    const methods = (v: typeof withView, ksi: string) =>
      v.projection.methodRegisters.find((r) => r.repo === REPO && r.ksi === ksi)?.methods.length ?? 0;
    for (const ksi of ["KSI-CNA-RVP", "KSI-IAM-AAM", "KSI-IAM-APM", "KSI-MLA-EVC"]) {
      expect(methods(withView, ksi), `${ksi} with the scan`).toBeGreaterThan(methods(withoutView, ksi));
    }
    // the removal: a ledger without the scan has no repo on the board at all
    expect(withoutView.projection.methodRegisters).toHaveLength(0);
    // and an uncovered indicator is exactly where it would be had Prowler never run
    expect(methods(withView, "KSI-CED-RAT")).toBe(methods(withoutView, "KSI-CED-RAT"));

    // §5: the omission arithmetic does not move. Prowler evidencing
    // KSI-CNA-RVP does not answer it in the provider's record.
    const omitted = (v: typeof withView) => v.section.rows.map((r) => [r.subject, r.rejection]);
    expect(omitted(withView)).toEqual(omitted(withoutView));
    expect(withView.section.rows.map((r) => r.subject).sort()).toEqual(["KSI-CNA-RVP", "KSI-IAM-AAM"]);
    const counts = (note: string | undefined) => note?.match(/(\d+) answered by the record, (\d+) omitted/)?.slice(1);
    expect(counts(withView.section.note)).toEqual(counts(withoutView.section.note));
  });

  it("a non-zero exit mints nothing and names every indicator", async () => {
    const work = await mkdtemp(join(tmpdir(), "rampscan-p35-exit1-"));
    const outcome = await ingestScan(join(work, "ledger"), join(work, "keys"), 1);
    expect(outcome.appended).toEqual([]);
    expect(outcome.skipped.length).toBeGreaterThan(13);
    expect(outcome.skipped.every((s) => s.exit_code === 1)).toBe(true);
  });

  it("refuses the file without the declared run facts — none is guessed", async () => {
    const work = await mkdtemp(join(tmpdir(), "rampscan-p35-bare-"));
    await expect(
      ingest({
        path: SCAN,
        repo: REPO,
        datasetDir: DATASET_DIR,
        rulesFile: RULES_FILE,
        datasetPin: DEFAULT_DATASET_PIN,
        ledgerDir: join(work, "ledger"),
        keysDir: join(work, "keys"),
        repoRoot: REPO_ROOT,
      }),
    ).rejects.toThrow(/--exit-code.*--signer.*--cadence/);
    // and the fixture is what it claims: an array, sniffed on content
    expect(Array.isArray(JSON.parse(await readFile(SCAN, "utf8")))).toBe(true);
  });
});
