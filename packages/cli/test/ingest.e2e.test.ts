import { cp, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { DEFAULT_DATASET_PIN } from "@rampscan/dataset";
import { createLocalLedger } from "@rampscan/ledger";
import { isEvidenceBundle, methodOfIngestedBundle } from "@rampscan/schema";
import { ingest, loadSubmissions } from "../src/ingest.js";
import { verify } from "../src/verify.js";

// Q4.1 exit test: the synthetic evidence tree (fixtures/ingest-evidence-tree,
// shapes per docs/RESEARCH-PARAMIFY-PILOT.md §3, content ours) ingests into a
// ledger as signed, verifiable citizens — evidence-class labeled per G6,
// method derivable from each bundle alone, idempotent on re-ingest, and the
// whole batch refused before anything is signed when one submission is bad.
// Nothing here ever executes an AWS call: every byte was read from disk.

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const TREE = join(REPO_ROOT, "fixtures/ingest-evidence-tree");
const DATASET_DIR = join(REPO_ROOT, "docs/context/ramprules/derived");
const RULES_FILE = join(REPO_ROOT, "docs/context/fedramp-rules/fedramp-consolidated-rules.json");

const REPO = "synthetic-csp/offering";

async function work(): Promise<{ ledgerDir: string; keysDir: string }> {
  const dir = await mkdtemp(join(tmpdir(), "rampscan-q41-"));
  return { ledgerDir: join(dir, "ledger"), keysDir: join(dir, "keys") };
}

const base = {
  repo: REPO,
  datasetDir: DATASET_DIR,
      rulesFile: RULES_FILE,
  datasetPin: DEFAULT_DATASET_PIN,
};

describe("rampscan ingest — the evidence tree adapter", () => {
  it("ingests the fixture tree: three signed citizens, G6-labeled, methods derivable, idempotent", async () => {
    const { ledgerDir, keysDir } = await work();
    const outcome = await ingest({ ...base, path: TREE, ledgerDir, keysDir });

    expect(outcome.appended.map((r) => `${r.methodId} ${r.verdict}`).sort()).toEqual([
      "aws-ingested:KSI-CNA-RVP.sh#KSI-CNA-RVP evidenced",
      "aws-ingested:KSI-IAM-AAM.sh#KSI-IAM-AAM violated",
      "aws-ingested:KSI-SVC-SIN.sh#KSI-SVC-SIN evidenced",
    ]);
    expect(outcome.unchanged).toEqual([]);
    expect(outcome.skipped).toEqual([]);

    // every appended bundle is a regular evidence citizen: signed (verify
    // passes offline), evidence-class asserted, method a pure function of
    // the predicate
    const ledger = createLocalLedger(ledgerDir);
    const classes = new Map<string, string | undefined>();
    for (const record of outcome.appended) {
      const report = await verify({ digest: record.digest, ledgerDir, keysDir });
      expect(report.ok, report.lines.join("\n")).toBe(true);

      const entry = await ledger.get(record.digest);
      const bundle = entry!.bundle;
      if (!isEvidenceBundle(bundle)) throw new Error("ingest appended a non-evidence statement");
      expect(bundle.predicate.repo).toBe(REPO);
      expect(bundle.predicate.anchor_paths).toEqual([]);
      expect(methodOfIngestedBundle(bundle.predicate).id).toBe(record.methodId);
      classes.set(bundle.predicate.ksi_ids[0]!, bundle.predicate.evidence_class);
      // N0 rides through the adapter: the assertion's population is the
      // result rows the script emitted — and the assertion is the APPLIANCE's
      // evaluation of the manifest's clause over those rows (#147), not the
      // script's exit code
      expect(bundle.predicate.assertions[0]!.population).toBeGreaterThan(0);
      expect(bundle.predicate.assertions[0]!.detail).not.toMatch(/^exit \d/);
    }
    // the violated one names its offender: the NONCOMPLIANT principal, 1 of 2
    const aam = await ledger.get(
      outcome.appended.find((r) => r.methodId.endsWith("#KSI-IAM-AAM"))!.digest,
    );
    if (aam === undefined || !isEvidenceBundle(aam.bundle)) throw new Error("no bundle");
    expect(aam.bundle.predicate.assertions[0]).toMatchObject({
      passed: false,
      population: 2,
      offender_count: 1,
    });
    // the manifest's uniform class, and the per-entry override, both signed
    expect(classes.get("KSI-CNA-RVP")).toBe("process-generated");
    expect(classes.get("KSI-SVC-SIN")).toBe("point-in-time");
    expect(classes.get("KSI-IAM-AAM")).toBe("process-generated");

    // idempotent: the same tree again appends nothing — the original
    // signatures stand
    const again = await ingest({ ...base, path: TREE, ledgerDir, keysDir });
    expect(again.appended).toEqual([]);
    expect(again.unchanged.map((r) => r.digest).sort()).toEqual(
      outcome.appended.map((r) => r.digest).sort(),
    );
  });

  it("ingests a single native submission file", async () => {
    const { ledgerDir, keysDir } = await work();
    // the adapter's output IS the native contract — derive one from the
    // fixture tree and ingest it through the file path
    const {
      submissions: [submission],
    } = await loadSubmissions(TREE);
    const dir = await mkdtemp(join(tmpdir(), "rampscan-q41-file-"));
    const file = join(dir, "submission.json");
    await writeFile(file, JSON.stringify(submission, null, 2));

    const outcome = await ingest({ ...base, path: file, ledgerDir, keysDir });
    expect(outcome.appended).toHaveLength(1);
    expect(outcome.appended[0]!.methodId).toBe("aws-ingested:KSI-CNA-RVP.sh#KSI-CNA-RVP");
  });

  it("refuses the whole batch before signing when one KSI does not resolve", async () => {
    const { ledgerDir, keysDir } = await work();
    const copy = await mkdtemp(join(tmpdir(), "rampscan-q41-bad-"));
    await cp(TREE, copy, { recursive: true });
    const manifestPath = join(copy, "ingest-manifest.json");
    const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
    manifest.entries[0].ksi = "KSI-ZZZ-XXX";
    await writeFile(manifestPath, JSON.stringify(manifest, null, 2));
    // the bad KSI also needs its directory, or the tree walk refuses first —
    // this test is about the CATALOG refusal
    await cp(
      join(copy, "Evidence/cloud-native-architecture/KSI-CNA-RVP"),
      join(copy, "Evidence/cloud-native-architecture/KSI-ZZZ-XXX"),
      { recursive: true },
    );
    await cp(
      join(copy, "Evidence/cloud-native-architecture/KSI-ZZZ-XXX/KSI-CNA-RVP.json"),
      join(copy, "Evidence/cloud-native-architecture/KSI-ZZZ-XXX/KSI-ZZZ-XXX.json"),
    );

    await expect(ingest({ ...base, path: copy, ledgerDir, keysDir })).rejects.toThrow(
      /does not resolve in dataset/,
    );
    // nothing appended — validate-then-append means the good entries did not
    // half-land
    expect(await createLocalLedger(ledgerDir).list()).toEqual([]);
  });

  it("refuses a directory without the manifest, naming what the adapter needs", async () => {
    const { ledgerDir, keysDir } = await work();
    const empty = await mkdtemp(join(tmpdir(), "rampscan-q41-empty-"));
    await expect(ingest({ ...base, path: empty, ledgerDir, keysDir })).rejects.toThrow(
      /ingest-manifest\.json/,
    );
  });

  it("refuses a duplicate (recipe, KSI) within one batch", async () => {
    const { ledgerDir, keysDir } = await work();
    const copy = await mkdtemp(join(tmpdir(), "rampscan-q41-dup-"));
    await cp(TREE, copy, { recursive: true });
    const manifestPath = join(copy, "ingest-manifest.json");
    const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
    manifest.entries.push({ ...manifest.entries[0] });
    await writeFile(manifestPath, JSON.stringify(manifest, null, 2));

    await expect(ingest({ ...base, path: copy, ledgerDir, keysDir })).rejects.toThrow(
      /duplicate \(recipe, KSI\)/,
    );
    expect(await createLocalLedger(ledgerDir).list()).toEqual([]);
  });
});
