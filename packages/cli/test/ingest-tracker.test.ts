import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { DEFAULT_DATASET_PIN, loadKsiCatalog } from "@rampscan/dataset";
import { createLocalLedger } from "@rampscan/ledger";
import { createProjector } from "@rampscan/projector";
import { IngestManifest } from "@rampscan/schema";
import { ingest, loadSubmissions } from "../src/ingest.js";

// N4-4 (docs/PLAN-REACH.md): the reviewing KSIs — after-action reports,
// procedure reviews, past-incident reviews, log reviews — reach the register
// through the tree adapter with a manifest an incident tracker's export can
// satisfy, and the manifest says whether a MACHINE produced the rows. A
// person's export declares `automated: false`: the rows are real, rampscan's
// assertions are evaluated over them, and the method counts as a method but
// never toward the FRC-CSX-VVK numerator — cover ≠ automate, kept where the
// temptation to conflate them is strongest.

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const TREE = join(REPO_ROOT, "fixtures/ingest-tracker");
const DATASET_DIR = join(REPO_ROOT, "docs/context/ramprules/derived");
const RULES_FILE = join(REPO_ROOT, "docs/context/fedramp-rules/fedramp-consolidated-rules.json");
const REPO = "synthetic-csp/offering";

async function work(): Promise<{ ledgerDir: string; keysDir: string }> {
  const dir = await mkdtemp(join(tmpdir(), "rampscan-tracker-"));
  return { ledgerDir: join(dir, "ledger"), keysDir: join(dir, "keys") };
}

describe("a tracker export through the tree adapter (N4-4)", () => {
  it("the manifest declares automated: false, and every submission carries it", async () => {
    const { submissions, skipped } = await loadSubmissions(TREE);
    expect(skipped).toEqual([]);
    expect(submissions.map((s) => [s.ksi, s.automated])).toEqual([
      ["KSI-INR-AAR", false],
      ["KSI-INR-RIR", false],
      ["KSI-INR-RPI", false],
      ["KSI-MLA-RVL", false],
    ]);
    // the assertions are rampscan's, evaluated over the exported rows at the
    // export's own clock — and every one passes on this fixture
    for (const s of submissions) {
      expect(s.assertions.length).toBeGreaterThan(0);
      expect(s.assertions.every((a) => a.passed), s.ksi).toBe(true);
      expect(s.evidence_class).toBe("point-in-time");
    }
  });

  it("ingests as four ledger citizens whose methods count, and never toward the automated floor", async () => {
    const { ledgerDir, keysDir } = await work();
    const outcome = await ingest({
      path: TREE,
      repo: REPO,
      datasetDir: DATASET_DIR,
      rulesFile: RULES_FILE,
      datasetPin: DEFAULT_DATASET_PIN,
      ledgerDir,
      keysDir,
    });
    expect(outcome.appended.map((r) => r.verdict)).toEqual(["evidenced", "evidenced", "evidenced", "evidenced"]);
    const catalog = await loadKsiCatalog({ derivedDir: DATASET_DIR, rulesFile: RULES_FILE, pin: DEFAULT_DATASET_PIN });
    const projection = await createProjector({
      methods: [],
      ksiIds: catalog.ksis.map((k) => k.id),
      methodFloor: catalog.floors.b.minPerKsi,
      machineWindow: catalog.windows.b,
      nonMachineWindow: catalog.nonMachineWindow,
    }).fold(createLocalLedger(ledgerDir));
    for (const ksi of ["KSI-INR-AAR", "KSI-INR-RIR", "KSI-INR-RPI", "KSI-MLA-RVL"]) {
      const row = projection.methodRegisters.find((r) => r.repo === REPO && r.ksi === ksi)!;
      expect(row.methods).toHaveLength(1);
      expect(row.methods[0]!.automated).toBe(false);
      expect(row.methods[0]!.clock).toBe("non-machine");
      expect(row.methods[0]!.state).toBe("evidenced");
      expect(row.automatedMethods).toBe(0);
      expect(row.floorMet).toBe(false); // covered, not automated: G2, no longer G1
      expect(row.gap).toBe("G2");
    }
  });

  it("an entry may override the manifest, and an undeclared manifest still reads true — nothing existing re-keys", () => {
    const base = {
      _type: "https://rampscan.dev/ingest-manifest/v1",
      signer_identity: "x",
      evidence_class: "process-generated",
      cadence: "daily",
      entries: [{ ksi: "KSI-INR-AAR", script: "s", exit_code: 0, timestamp: "2026-09-15T09:00:00Z" }],
    };
    expect(IngestManifest.parse(base).automated).toBeUndefined();
    expect(IngestManifest.parse({ ...base, automated: false }).automated).toBe(false);
    const overridden = IngestManifest.parse({
      ...base,
      automated: false,
      entries: [{ ...base.entries[0], automated: true }],
    });
    expect(overridden.entries[0]!.automated).toBe(true);
    expect(() => IngestManifest.parse({ ...base, automated: "yes" })).toThrow();
  });
});
