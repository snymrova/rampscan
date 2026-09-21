import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { allCollectors } from "@rampscan/collectors";
import { DEFAULT_DATASET_PIN, loadKsiCatalog } from "@rampscan/dataset";
import { createLocalLedger } from "@rampscan/ledger";
import { createProjector, planeOfCell, reachOf } from "@rampscan/projector";
import { deriveCatalogMethods, loadRecipes } from "../src/recipes.js";
import { ingest } from "../src/ingest.js";
import { verify } from "../src/verify.js";

// The SARIF path end to end (docs/PLAN-REACH.md N2-2): a real semgrep log
// over fixtures/vulnerable-app and a real zizmor log over this repository's
// workflows become signed, verifiable ledger citizens whose methods sit on
// the COMMIT plane — beside the pipeline, never as a second plane — and whose
// verdicts are what rampscan's own assertion computed over the tool's rows.

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const FIXTURES = join(REPO_ROOT, "fixtures/ingest-sarif");
const DATASET_DIR = join(REPO_ROOT, "docs/context/ramprules/derived");
const RULES_FILE = join(REPO_ROOT, "docs/context/fedramp-rules/fedramp-consolidated-rules.json");
const REPO = "fixtures/vulnerable-app";

async function work(): Promise<{ ledgerDir: string; keysDir: string }> {
  const dir = await mkdtemp(join(tmpdir(), "rampscan-sarif-"));
  return { ledgerDir: join(dir, "ledger"), keysDir: join(dir, "keys") };
}

const base = {
  repo: REPO,
  datasetDir: DATASET_DIR,
  rulesFile: RULES_FILE,
  datasetPin: DEFAULT_DATASET_PIN,
  repoRoot: REPO_ROOT,
  exitCode: 0,
  signerIdentity: "runner:ci",
  cadence: "daily" as const,
  // neither fixture's tool wrote invocations[].endTimeUtc, so the run's
  // instant is declared — and declared the same way twice, the same bytes
  // are the same bundle
  timestamp: "2026-09-21T12:00:00Z",
};

describe("rampscan ingest <file.sarif>", () => {
  it("refuses a SARIF log without --tool, --exit-code, --signer and --cadence, naming each", async () => {
    const { ledgerDir, keysDir } = await work();
    await expect(
      ingest({
        repo: REPO,
        datasetDir: DATASET_DIR,
        rulesFile: RULES_FILE,
        datasetPin: DEFAULT_DATASET_PIN,
        repoRoot: REPO_ROOT,
        path: join(FIXTURES, "semgrep.sarif"),
        ledgerDir,
        keysDir,
      }),
    ).rejects.toThrow(/--tool <slug>.*--exit-code <n>.*--signer <identity>.*--cadence <cycle>/s);
  });

  it("refuses a log that records no invocation end time unless --timestamp declares the run's instant", async () => {
    const { ledgerDir, keysDir } = await work();
    await expect(
      ingest({ ...base, timestamp: undefined, path: join(FIXTURES, "semgrep.sarif"), tool: "semgrep-oss", ledgerDir, keysDir }),
    ).rejects.toThrow(/--timestamp <ISO 8601>/);
  });

  it("refuses a log whose tool version has no reviewed crosswalk, naming the ones that exist", async () => {
    const { ledgerDir, keysDir } = await work();
    await expect(
      ingest({ ...base, path: join(FIXTURES, "semgrep.sarif"), tool: "codeql", ledgerDir, keysDir }),
    ).rejects.toThrow(/no crosswalk for codeql.*sarif-semgrep-oss-1\.173\.0\.json, sarif-zizmor-1\.30\.1\.json/s);
  });

  it("mints signed, verifiable bundles on the commit plane, and the ladder counts them with the pipeline as one plane", async () => {
    const { ledgerDir, keysDir } = await work();
    const log: string[] = [];
    const outcome = await ingest({
      ...base,
      path: join(FIXTURES, "semgrep.sarif"),
      tool: "semgrep-oss",
      ledgerDir,
      keysDir,
      log: (l) => log.push(l),
    });
    expect(outcome.appended.map((r) => [r.methodId, r.verdict])).toEqual([
      ["aws-ingested:semgrep-oss/child-process-non-literal#KSI-PIY-RSD", "evidenced"],
      ["aws-ingested:semgrep-oss/dangerous-eval#KSI-PIY-RSD", "violated"],
      ["aws-ingested:semgrep-oss/weak-hash-algorithm#KSI-SVC-SIN", "evidenced"],
    ]);
    expect(outcome.skipped).toEqual([]);
    expect(log.some((l) => /reachability unknown/.test(l))).toBe(true);
    for (const record of outcome.appended) {
      const report = await verify({ digest: record.digest, ledgerDir, keysDir });
      expect(report.ok, record.methodId).toBe(true);
    }

    // the fold: the ingested cells carry the plane the submission declared,
    // and beside the pipeline's own SAST method on KSI-PIY-RSD they are ONE
    // plane — the ladder's distinct count does not move
    const catalog = await loadKsiCatalog({ derivedDir: DATASET_DIR, rulesFile: RULES_FILE, pin: DEFAULT_DATASET_PIN });
    const recipes = await loadRecipes(join(REPO_ROOT, "recipes/commit"));
    const methods = deriveCatalogMethods(recipes, allCollectors.map((c) => c.manifest));
    const projection = await createProjector({
      recipes,
      methods,
      ksiIds: catalog.ksis.map((k) => k.id),
      methodFloor: catalog.floors.b.minPerKsi,
      machineWindow: catalog.windows.b,
      nonMachineWindow: catalog.nonMachineWindow,
    }).fold(createLocalLedger(ledgerDir));
    const rsd = projection.methodRegisters.find((r) => r.repo === REPO && r.ksi === "KSI-PIY-RSD")!;
    const ingested = rsd.methods.filter((m) => m.source === "aws-ingested");
    expect(ingested).toHaveLength(2);
    for (const cell of ingested) {
      expect(cell.plane).toBe("commit");
      expect(planeOfCell(cell)).toBe("commit");
      expect(cell.automated).toBe(true);
      expect(cell.freshMet).toBe(true);
    }
    // a pipeline method on the same KSI, made fresh in memory: still one plane
    const withPipeline = {
      methods: [
        ...rsd.methods,
        { ...rsd.methods.find((m) => m.source === "pipeline")!, bundleDigest: "d", freshMet: true },
      ],
      methodFloor: 1,
    };
    const reach = reachOf(withPipeline, [{ plane: "pipeline", observes: ["x"], wired: ["x"] }]);
    expect(reach.distinctPlanes).toBe(1);
    expect(reach.rung).toBe("floor");
    expect(reach.next).toContain("one plane (commit)");
  });

  it("the zizmor log lands under five KSIs, one violated, and re-ingesting is unchanged", async () => {
    const { ledgerDir, keysDir } = await work();
    const first = await ingest({ ...base, repo: "snymrova/rampscan", path: join(FIXTURES, "zizmor.sarif"), tool: "zizmor", ledgerDir, keysDir });
    const violated = first.appended.filter((r) => r.verdict === "violated").map((r) => r.methodId);
    expect(violated).toEqual(["aws-ingested:zizmor/excessive-permissions#KSI-CNA-MAT"]);
    // the audits zizmor did not fire and does not declare it ran are named, not minted
    expect(first.skipped.length).toBe(41 - 5);
    expect(first.skipped.every((s) => /does not declare it ran/.test(s.reason))).toBe(true);
    const again = await ingest({ ...base, repo: "snymrova/rampscan", path: join(FIXTURES, "zizmor.sarif"), tool: "zizmor", ledgerDir, keysDir });
    expect(again.appended).toEqual([]);
    expect(again.unchanged.length).toBe(first.appended.length);
  });
});
