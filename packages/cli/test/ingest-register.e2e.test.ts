import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { allCollectors } from "@rampscan/collectors";
import { DEFAULT_DATASET_PIN, loadKsiCatalogFromSlices } from "@rampscan/dataset";
import { readProjectionSqlite } from "@rampscan/projector";
import { ingest } from "../src/ingest.js";
import { rebuild } from "../src/rebuild.js";
import { deriveCatalogMethods, loadRecipes } from "../src/recipes.js";

// Q4.3 / the Q4 PHASE exit gate (plan §4): "a fixture ingestion of a synthetic
// AWS result raises a KSI's method count on the board, and its removal lowers
// it; nothing in the appliance ever executed an AWS call."
//
// Q4.1 made the submission a signed ledger citizen; this is where citizenship
// starts counting. The fixture's three results land on KSI-CNA-RVP (evidenced),
// KSI-IAM-AAM (violated) and KSI-SVC-SIN (evidenced, declared point-in-time —
// the G6 specimen). The first two carry NO pipeline method at this pin, so
// their rows move from G1 "nothing evidences this" to a met automated floor.

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const RECIPES_DIR = join(REPO_ROOT, "recipes/commit");
const DATASET_DIR = join(REPO_ROOT, "docs/context/ramprules/derived");
const TREE = join(REPO_ROOT, "fixtures/ingest-evidence-tree");
const REPO = "fixtures/vulnerable-app";

async function foldInputs(work: string) {
  const catalog = await loadKsiCatalogFromSlices(DATASET_DIR, DEFAULT_DATASET_PIN);
  return {
    ledgerDir: join(work, "ledger"),
    recipesDir: RECIPES_DIR,
    dbPath: join(work, "projection.db"),
    methods: deriveCatalogMethods(
      await loadRecipes(RECIPES_DIR),
      allCollectors.map((c) => c.manifest),
    ),
    ksiIds: catalog.ksis.map((k) => k.id),
    methodFloor: catalog.floors.b.minPerKsi,
    machineWindow: catalog.windows.b,
    nonMachineWindow: catalog.nonMachineWindow,
  };
}

describe("ingested results count on the board (Q4.3)", () => {
  it("raises the method count, survives a rebuild, and keeps projection ≡ ledger", async () => {
    const work = await mkdtemp(join(tmpdir(), "rampscan-q43-"));
    const inputs = await foldInputs(work);
    const lines: string[] = [];

    const outcome = await ingest({
      path: TREE,
      repo: REPO,
      datasetDir: DATASET_DIR,
      datasetPin: DEFAULT_DATASET_PIN,
      ledgerDir: inputs.ledgerDir,
      keysDir: join(work, "keys"),
      log: (l) => lines.push(l),
    });
    expect(outcome.appended).toHaveLength(3);
    // the phase gate's own sentence, emitted by the command itself
    expect(lines.join("\n")).toContain("no AWS call was executed by this appliance");

    // rebuild twice: the second throws the projection away and recomputes, and
    // BOTH must read back identical to the fold. Before Q4.3 this mismatched —
    // an ingested row carried `commit: ""` and `introducingCommit: ""`, which
    // every store reads back as absent, so the projection failed its own proof.
    const first = await rebuild(inputs);
    expect(first.ok, first.lines.join("\n")).toBe(true);
    expect(first.lines.join("\n")).toContain("projection ≡ ledger");
    const second = await rebuild(inputs);
    expect(second.ok, second.lines.join("\n")).toBe(true);

    const projection = readProjectionSqlite(inputs.dbPath);
    const row = (ksi: string) =>
      projection.methodRegisters.find((r) => r.repo === REPO && r.ksi === ksi)!;

    // KSI-CNA-RVP carries no pipeline method at this pin: 0 → 1, and the floor
    // of 1 is MET by an ingested method, which is the whole point of Q4.3
    const rvp = row("KSI-CNA-RVP");
    expect(rvp.methods).toHaveLength(1);
    const rvpCell = rvp.methods[0]!;
    expect(rvpCell.methodId).toBe("aws-ingested:KSI-CNA-RVP.sh#KSI-CNA-RVP");
    expect(rvpCell.source).toBe("aws-ingested");
    expect(rvpCell.automated).toBe(true);
    expect(rvpCell.state).toBe("evidenced");
    expect(rvpCell.clock).toBe("machine");
    expect(rvp.automatedMethods).toBe(1);
    expect(rvp.floorMet).toBe(true);
    expect(rvp.gap).not.toBe("G1");
    expect(rvp.gap).not.toBe("G2");

    // a violated client result is still a method: the validation record exists,
    // and what it SAYS is G13's business (Q3.5), not the floor's
    const aam = row("KSI-IAM-AAM");
    expect(aam.methods).toHaveLength(1);
    expect(aam.methods[0]!.state).toBe("violated");
    expect(aam.automatedMethods).toBe(1);
    expect(aam.floorMet).toBe(true);
    expect(projection.vulnerabilities.some((v) => v.ksiIds.includes("KSI-IAM-AAM"))).toBe(true);

    // the G6 specimen: the SUBMITTER declared point-in-time, and the register
    // quotes that assertion rather than inferring one
    const sin = row("KSI-SVC-SIN");
    const sinCell = sin.methods.find((m) => m.source === "aws-ingested")!;
    expect(sinCell.evidenceClass).toBe("point-in-time");
    expect(sin.pointInTimeMethods).toBe(1);
    // it sits beside this KSI's pipeline methods — the register spans sources
    expect(sin.methods.length).toBeGreaterThan(1);
    expect([...new Set(sin.methods.map((m) => m.source))].sort()).toEqual([
      "aws-ingested",
      "pipeline",
    ]);

    // nothing of ours walked anything for an ingested method, so it declares no
    // collector and no scope — the interrogable fact is the signer identity
    expect(rvpCell.collector).toBeUndefined();
    expect(rvpCell.scope).toBeUndefined();
    expect(rvpCell.recipeId).toBe("KSI-CNA-RVP.sh"); // upstream's id, named
  });

  it("removing the ingestion lowers the count again", async () => {
    // The ledger is append-only, so "removal" is what the board says when the
    // ingestion is not in the ledger — the same fold inputs over a ledger
    // without it. Both halves of the phase gate, measured the same way.
    const withIngest = await mkdtemp(join(tmpdir(), "rampscan-q43-with-"));
    const without = await mkdtemp(join(tmpdir(), "rampscan-q43-without-"));
    const a = await foldInputs(withIngest);
    const b = await foldInputs(without);

    await ingest({
      path: TREE,
      repo: REPO,
      datasetDir: DATASET_DIR,
      datasetPin: DEFAULT_DATASET_PIN,
      ledgerDir: a.ledgerDir,
      keysDir: join(withIngest, "keys"),
    });
    await rebuild(a);
    await rebuild(b);

    const counted = (dbPath: string, ksi: string) =>
      readProjectionSqlite(dbPath).methodRegisters.find((r) => r.repo === REPO && r.ksi === ksi)
        ?.methods.length ?? 0;

    for (const ksi of ["KSI-CNA-RVP", "KSI-IAM-AAM", "KSI-SVC-SIN"]) {
      expect(counted(a.dbPath, ksi), `${ksi} with the ingestion`).toBeGreaterThan(
        counted(b.dbPath, ksi),
      );
    }
    // and with nothing ingested there is no repo on the board at all: an empty
    // ledger measures nothing, which is a different fact from measuring zero
    expect(readProjectionSqlite(b.dbPath).methodRegisters).toHaveLength(0);
  });
});
