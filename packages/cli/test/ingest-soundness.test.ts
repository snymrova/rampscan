import { cp, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { DEFAULT_DATASET_PIN } from "@rampscan/dataset";
import { createLocalLedger } from "@rampscan/ledger";
import { isEvidenceBundle } from "@rampscan/schema";
import type { IngestManifest, IngestManifestEntry } from "@rampscan/schema";
import { ingest, loadSubmissions } from "../src/ingest.js";

// #147, the SECURITY.md class in the tree adapter: a script's exit code was
// read as its verdict, and the scripts that convention was read from exit 0
// after reading a non-compliant account — `s3_encryption_status.sh` at 0 %
// encrypted buckets, `guard_duty.sh` on "No GuardDuty detectors configured"
// (docs/RESEARCH-PARAMIFY-PILOT.md §8.1). Exit 0 proves the script finished
// READING; nothing about what it read. So:
//
//   - an entry with exit 0 and no assertion is a collected artifact, signed
//     into the ledger as `unevidenced` — never `evidenced`;
//   - an entry declaring structured assertions has them evaluated HERE, by
//     the appliance, over the result rows — the same evaluator every pipeline
//     recipe uses — and the verdict is what the rows say, whatever the exit;
//   - a non-zero exit is a failed run: the account was not seen, so there is
//     nothing to attest to and nothing to violate. The entry is skipped and
//     named, the way a skipped collector is, and never becomes a bundle.
//
// Every tree below is a copy of the synthetic fixture with its manifest
// rewritten; the result files are the fixture's own. Nothing executes AWS.

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const TREE = join(REPO_ROOT, "fixtures/ingest-evidence-tree");
const DATASET_DIR = join(REPO_ROOT, "docs/context/ramprules/derived");
const RULES_FILE = join(REPO_ROOT, "docs/context/fedramp-rules/fedramp-consolidated-rules.json");

const base = {
  repo: "synthetic-csp/offering",
  datasetDir: DATASET_DIR,
  rulesFile: RULES_FILE,
  datasetPin: DEFAULT_DATASET_PIN,
};

/** the fixture tree, with only the manifest's entries replaced */
async function treeWith(entries: IngestManifestEntry[]): Promise<{
  tree: string;
  ledgerDir: string;
  keysDir: string;
}> {
  const work = await mkdtemp(join(tmpdir(), "rampscan-147-"));
  const tree = join(work, "tree");
  await cp(TREE, tree, { recursive: true });
  const manifestPath = join(tree, "ingest-manifest.json");
  const manifest = JSON.parse(await readFile(manifestPath, "utf8")) as IngestManifest;
  await writeFile(manifestPath, JSON.stringify({ ...manifest, entries }, null, 2));
  return { tree, ledgerDir: join(work, "ledger"), keysDir: join(work, "keys") };
}

// the fixture's KSI-IAM-AAM rows: one COMPLIANT principal and one
// NONCOMPLIANT — the account a "0 = pass" convention reads as passing
const IAM = {
  ksi: "KSI-IAM-AAM",
  script: "KSI-IAM-AAM.sh",
  exit_code: 0,
  timestamp: "2026-09-10T14:03:00Z",
} satisfies IngestManifestEntry;

const EVERY_PRINCIPAL_COMPLIANT = {
  field: "status",
  op: "eq" as const,
  value: "COMPLIANT",
  description: "Every IAM principal the script inventoried reads COMPLIANT.",
};

describe("ingest tree adapter — exit 0 is collection, not compliance (#147)", () => {
  it("exit 0 with no assertion never reads evidenced: the bytes are collected, unevidenced", async () => {
    const { tree, ledgerDir, keysDir } = await treeWith([IAM]);
    const outcome = await ingest({ ...base, path: tree, ledgerDir, keysDir });

    expect(outcome.appended).toHaveLength(1);
    const record = outcome.appended[0]!;
    expect(record.verdict).not.toBe("evidenced");
    expect(record.verdict).toBe("unevidenced");

    // it IS a ledger citizen — the collected artifact, signed, is what a
    // later sufficiency judgment has to point at — carrying no assertion,
    // because nothing evaluated anything
    const entry = await createLocalLedger(ledgerDir).get(record.digest);
    if (entry === undefined || !isEvidenceBundle(entry.bundle)) throw new Error("no bundle");
    expect(entry.bundle.predicate.verdict).toBe("unevidenced");
    expect(entry.bundle.predicate.assertions).toEqual([]);
    expect(entry.bundle.subject.map((s) => s.name).sort()).toEqual([
      "Evidence/identity-and-access-management/KSI-IAM-AAM/KSI-IAM-AAM.csv",
      "Evidence/identity-and-access-management/KSI-IAM-AAM/KSI-IAM-AAM.json",
    ]);
  });

  it("a declared assertion is evaluated by the appliance over the rows, and exit 0 cannot outvote it", async () => {
    const { tree, ledgerDir, keysDir } = await treeWith([
      { ...IAM, assertions: [EVERY_PRINCIPAL_COMPLIANT] },
    ]);
    const outcome = await ingest({ ...base, path: tree, ledgerDir, keysDir });

    expect(outcome.appended.map((r) => r.verdict)).toEqual(["violated"]);
    const entry = await createLocalLedger(ledgerDir).get(outcome.appended[0]!.digest);
    if (entry === undefined || !isEvidenceBundle(entry.bundle)) throw new Error("no bundle");
    const [assertion] = entry.bundle.predicate.assertions;
    expect(assertion).toMatchObject({
      description: EVERY_PRINCIPAL_COMPLIANT.description,
      passed: false,
      // N0: the domain is the rows the script emitted, and the offender is named
      population: 2,
      offender_count: 1,
    });
    expect(assertion!.detail).toContain("1 of 2 row(s) fail status eq");
    expect(assertion!.detail).toContain("synthetic-legacy-svc");
  });

  it("a passing assertion over the rows earns evidenced — the only way the adapter says it", async () => {
    const { tree, ledgerDir, keysDir } = await treeWith([
      {
        ksi: "KSI-SVC-SIN",
        script: "KSI-SVC-SIN.sh",
        exit_code: 0,
        timestamp: "2026-09-10T14:01:30Z",
        assertions: [
          {
            field: "status",
            op: "eq",
            value: "ENCRYPTED",
            description: "Every storage resource the script inventoried is encrypted.",
          },
        ],
      },
    ]);
    const outcome = await ingest({ ...base, path: tree, ledgerDir, keysDir });
    expect(outcome.appended.map((r) => r.verdict)).toEqual(["evidenced"]);
    const entry = await createLocalLedger(ledgerDir).get(outcome.appended[0]!.digest);
    if (entry === undefined || !isEvidenceBundle(entry.bundle)) throw new Error("no bundle");
    expect(entry.bundle.predicate.assertions[0]).toMatchObject({ passed: true, population: 3 });
  });

  it("a non-zero exit is a failed run — skipped and named, never violated, never a bundle", async () => {
    const { tree, ledgerDir, keysDir } = await treeWith([
      { ...IAM, exit_code: 1, assertions: [EVERY_PRINCIPAL_COMPLIANT] },
      {
        ksi: "KSI-CNA-RVP",
        script: "KSI-CNA-RVP.sh",
        exit_code: 0,
        timestamp: "2026-09-10T14:00:00Z",
        assertions: [
          {
            field: "status",
            op: "eq",
            value: "PROTECTED",
            description: "Every edge resource the script inventoried is protected.",
          },
        ],
      },
    ]);
    const lines: string[] = [];
    const outcome = await ingest({
      ...base,
      path: tree,
      ledgerDir,
      keysDir,
      log: (l) => lines.push(l),
    });

    // the failed run is not in the ledger under any verdict — the rows it
    // would have been judged on were never read from the account
    expect(outcome.appended.map((r) => `${r.methodId} ${r.verdict}`)).toEqual([
      "aws-ingested:KSI-CNA-RVP.sh#KSI-CNA-RVP evidenced",
    ]);
    expect(outcome.skipped).toEqual([
      {
        ksi: "KSI-IAM-AAM",
        script: "KSI-IAM-AAM.sh",
        exit_code: 1,
        reason: expect.stringMatching(/exit 1.*failed run/),
      },
    ]);
    expect(lines.join("\n")).toMatch(/KSI-IAM-AAM\.sh.*skipped.*exit 1/);
    expect(await createLocalLedger(ledgerDir).list()).toHaveLength(1);
  });

  it("refuses an entry whose declared assertion has no rows of the shape it reads", async () => {
    const { tree, ledgerDir, keysDir } = await treeWith([
      { ...IAM, assertions: [EVERY_PRINCIPAL_COMPLIANT] },
    ]);
    // rows that are not objects have no fields to evaluate; that is a shape
    // the adapter refuses rather than a domain it evaluates as empty
    const resultPath = join(
      tree,
      "Evidence/identity-and-access-management/KSI-IAM-AAM/KSI-IAM-AAM.json",
    );
    await writeFile(resultPath, JSON.stringify({ results: ["COMPLIANT", "NONCOMPLIANT"] }));
    await expect(ingest({ ...base, path: tree, ledgerDir, keysDir })).rejects.toThrow(
      /results\[0\] is not an object/,
    );
    expect(await createLocalLedger(ledgerDir).list()).toEqual([]);
  });

  it("the adapter's output for a collected-only entry is a native submission with no assertions", async () => {
    const { tree } = await treeWith([IAM]);
    const { submissions, skipped } = await loadSubmissions(tree);
    expect(skipped).toEqual([]);
    expect(submissions).toHaveLength(1);
    expect(submissions[0]!.assertions).toEqual([]);
    // the run's own facts still travel: how to reproduce, and whose clock
    expect(submissions[0]!.reproduce).toContain("KSI-IAM-AAM.sh");
    expect(submissions[0]!.timestamp).toBe(IAM.timestamp);
  });
});
