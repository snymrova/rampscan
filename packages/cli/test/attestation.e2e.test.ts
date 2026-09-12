import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { allCollectors } from "@rampscan/collectors";
import { DEFAULT_DATASET_PIN, loadKsiCatalogFromSlices } from "@rampscan/dataset";
import { readProjectionSqlite } from "@rampscan/projector";
import { recordAttestation } from "../src/attestation.js";
import { rebuild } from "../src/rebuild.js";
import { deriveCatalogMethods, loadRecipes } from "../src/recipes.js";
import { verify } from "../src/verify.js";

// Q4.2 exit test (SPEC §12.9): a two-key attestation becomes a counted method.
// `KSI-CED-RAT` ("Reviewing All Training") is the honest specimen — the
// effectiveness of a training programme is acts-on-people, so no checkout walk
// and no AWS API call can reach it, and at this pin it carries NO pipeline
// method: 33 of the catalog's 46 KSIs don't. The register goes from G1 (nothing
// evidences this) to one non-machine method on VDR-TFR-NMV's 3-month clock,
// and a signed withdrawal takes it back — the phase exit gate's "raises a
// method count, and its removal lowers it", for the attestation leg.

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const RECIPES_DIR = join(REPO_ROOT, "recipes/commit");
const DATASET_DIR = join(REPO_ROOT, "docs/context/ramprules/derived");

const REPO = "fixtures/vulnerable-app";
const KSI = "KSI-CED-RAT";
// the fold instant, fixed so the clock arithmetic is deterministic
const FOLD_AT = new Date("2026-09-12T00:00:00.000Z");
// inside NMV's 3 months of FOLD_AT (threshold: 2026-06-12); STALE is not
const FRESH = new Date("2026-08-01T00:00:00.000Z");
const STALE = new Date("2026-05-01T00:00:00.000Z");

const STATEMENT =
  "Annual security awareness training completed by all personnel; the Q2 review " +
  "measured phishing-simulation failure rates against the prior period and the " +
  "curriculum was revised where they rose.";

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
    nonMachineWindow: catalog.nonMachineWindow,
    now: () => FOLD_AT,
  };
}

function rowFor(dbPath: string) {
  const projection = readProjectionSqlite(dbPath);
  return projection.methodRegisters.find((r) => r.repo === REPO && r.ksi === KSI)!;
}

describe("two-key attestation → a counted non-machine method", () => {
  it("raises the KSI's method count, lands on the NMV clock, and survives a rebuild", async () => {
    const work = await mkdtemp(join(tmpdir(), "rampscan-q42-"));
    const inputs = await foldInputs(work);

    // before: nothing evidences this KSI — G1, and no cells at all
    const before = await rebuild(inputs);
    expect(before.ok, before.lines.join("\n")).toBe(true);
    const emptyRow = readProjectionSqlite(inputs.dbPath).methodRegisters.find(
      (r) => r.ksi === KSI,
    );
    // with an empty ledger there is no scanned repo at all, so no row exists
    expect(emptyRow).toBeUndefined();

    const { digest } = await recordAttestation({
      repo: REPO,
      statementId: "security-awareness-training",
      ksiId: KSI,
      attestorRole: "head-of-people",
      statement: STATEMENT,
      action: "attested",
      proposedBy: "viewer@rampscan.local (pb:u1)",
      approvedBy: "approver@rampscan.local (pb:u2)",
      datasetDir: DATASET_DIR,
      datasetPin: DEFAULT_DATASET_PIN,
      ledgerDir: inputs.ledgerDir,
      keysDir: join(work, "keys"),
      now: FRESH,
    });

    // the signed event verifies offline like any evidence bundle, and names the
    // role the claim rests on beside the two identities that turned the keys
    const verification = await verify({
      digest,
      ledgerDir: inputs.ledgerDir,
      keysDir: join(work, "keys"),
    });
    expect(verification.ok, verification.lines.join("\n")).toBe(true);
    const text = verification.lines.join("\n");
    expect(text).toContain("security-awareness-training#KSI-CED-RAT → attested (head-of-people)");
    expect(text).toContain("proposed viewer@rampscan.local (pb:u1)");

    // rebuild twice — the second throws the projection away and recomputes;
    // the method must still be there, because it was never console state
    const first = await rebuild(inputs);
    expect(first.ok, first.lines.join("\n")).toBe(true);
    const second = await rebuild(inputs);
    expect(second.ok, second.lines.join("\n")).toBe(true);

    const row = rowFor(inputs.dbPath);
    expect(row).toBeDefined();
    expect(row.methods).toHaveLength(1);
    const cell = row.methods[0]!;
    expect(cell.methodId).toBe("attestation:security-awareness-training#KSI-CED-RAT");
    expect(cell.source).toBe("attestation");
    expect(cell.standing).toBe("narrative");
    expect(cell.bundleDigest).toBe(digest);
    // the event IS the evidence: its own timestamp is the instant the clock judges
    expect(cell.state).toBe("evidenced");
    expect(cell.freshAsOf).toBe(FRESH.toISOString());
    expect(cell.clock).toBe("non-machine");
    expect(cell.window).toEqual({ num: 3, unit: "months" });
    expect(cell.freshMet).toBe(true);
    // G6 labels a MACHINE process; a human statement asserts no evidence class
    expect(cell.evidenceClass).toBeUndefined();
    // G1 is over — something evidences this KSI now
    expect(row.gap).not.toBe("G1");

    // ...and the anti-gaming property: FRC-CSX-VVK counts AUTOMATED methods, so
    // the class floor is still unmet. Cover ≠ automate, structurally.
    expect(cell.automated).toBe(false);
    expect(row.automatedMethods).toBe(0);
    expect(row.floorMet).toBe(false);
  });

  it("a signed withdrawal lowers the count again — un-decided by deciding, never by deleting", async () => {
    const work = await mkdtemp(join(tmpdir(), "rampscan-q42-withdraw-"));
    const inputs = await foldInputs(work);
    const keysDir = join(work, "keys");
    const common = {
      repo: REPO,
      statementId: "security-awareness-training",
      ksiId: KSI,
      attestorRole: "head-of-people",
      statement: STATEMENT,
      proposedBy: "viewer@rampscan.local (pb:u1)",
      approvedBy: "approver@rampscan.local (pb:u2)",
      datasetDir: DATASET_DIR,
      datasetPin: DEFAULT_DATASET_PIN,
      ledgerDir: inputs.ledgerDir,
      keysDir,
    };

    const attested = await recordAttestation({ ...common, action: "attested", now: FRESH });
    await rebuild(inputs);
    expect(rowFor(inputs.dbPath).methods).toHaveLength(1);

    const withdrawn = await recordAttestation({
      ...common,
      action: "withdrawn",
      statement: "The Q2 review did not cover contractors; this claim is retracted pending re-run.",
      now: new Date("2026-09-01T00:00:00.000Z"),
    });
    await rebuild(inputs);
    const row = rowFor(inputs.dbPath);
    expect(row.methods).toHaveLength(0);
    expect(row.gap).toBe("G1");

    // both statements are still in the ledger and still verify: the history is
    // real, and the retraction is itself a signed, interrogable decision
    for (const digest of [attested.digest, withdrawn.digest]) {
      const v = await verify({ digest, ledgerDir: inputs.ledgerDir, keysDir });
      expect(v.ok, v.lines.join("\n")).toBe(true);
    }
  });

  it("an attestation nobody renewed inside 3 months has a lapsed clock — G3 once no floor outranks it", async () => {
    const work = await mkdtemp(join(tmpdir(), "rampscan-q42-stale-"));
    const inputs = await foldInputs(work);
    await recordAttestation({
      repo: REPO,
      statementId: "security-awareness-training",
      ksiId: KSI,
      attestorRole: "head-of-people",
      statement: STATEMENT,
      action: "attested",
      proposedBy: "viewer@rampscan.local (pb:u1)",
      approvedBy: "approver@rampscan.local (pb:u2)",
      datasetDir: DATASET_DIR,
      datasetPin: DEFAULT_DATASET_PIN,
      ledgerDir: inputs.ledgerDir,
      keysDir: join(work, "keys"),
      now: STALE,
    });
    await rebuild(inputs);
    const row = rowFor(inputs.dbPath);
    expect(row.methods[0]!.freshMet).toBe(false);
    expect(row.staleMethods).toBe(1);
    // At class b the automated floor of 1 is unmet and OUTRANKS the lapsed
    // clock: G2 is the worse fact, and the row says so (gap precedence
    // G1→G2→G3→…). The stale attestation is still counted in staleMethods —
    // masked as the row's headline, never lost.
    expect(row.gap).toBe("G2");

    // Where no automated floor is owed (class a), the lapsed clock is the
    // worst thing true about the row, and G3 surfaces — which is the whole
    // reason the attestation path sits on a clock at all.
    const classA = await rebuild({ ...inputs, methodFloor: null });
    expect(classA.ok, classA.lines.join("\n")).toBe(true);
    const unfloored = rowFor(inputs.dbPath);
    expect(unfloored.floorMet).toBeNull();
    expect(unfloored.gap).toBe("G3");
  });

  it("a renewal satisfies the same method rather than minting a second one", async () => {
    const work = await mkdtemp(join(tmpdir(), "rampscan-q42-renew-"));
    const inputs = await foldInputs(work);
    const common = {
      repo: REPO,
      statementId: "security-awareness-training",
      ksiId: KSI,
      attestorRole: "head-of-people",
      action: "attested" as const,
      proposedBy: "viewer@rampscan.local (pb:u1)",
      approvedBy: "approver@rampscan.local (pb:u2)",
      datasetDir: DATASET_DIR,
      datasetPin: DEFAULT_DATASET_PIN,
      ledgerDir: inputs.ledgerDir,
      keysDir: join(work, "keys"),
    };
    // the lapsed claim, then the renewal — a different post-holder, same mechanism
    await recordAttestation({ ...common, statement: STATEMENT, now: STALE });
    const renewal = await recordAttestation({
      ...common,
      attestorRole: "head-of-people",
      statement: `${STATEMENT} Re-reviewed for the current period, contractors included.`,
      now: FRESH,
    });
    await rebuild(inputs);
    const row = rowFor(inputs.dbPath);
    expect(row.methods).toHaveLength(1);
    expect(row.methods[0]!.freshMet).toBe(true);
    expect(row.methods[0]!.bundleDigest).toBe(renewal.digest);
    expect(row.gap).not.toBe("G3");
  });

  it("refuses an attestation for a KSI outside the pinned catalog", async () => {
    const work = await mkdtemp(join(tmpdir(), "rampscan-q42-bad-ksi-"));
    await expect(
      recordAttestation({
        repo: REPO,
        statementId: "x",
        ksiId: "KSI-NO-SUCH",
        attestorRole: "ciso",
        statement: "x",
        action: "attested",
        proposedBy: "a",
        approvedBy: "b",
        datasetDir: DATASET_DIR,
        datasetPin: DEFAULT_DATASET_PIN,
        ledgerDir: join(work, "ledger"),
        keysDir: join(work, "keys"),
      }),
    ).rejects.toThrow(/unknown KSI/);
  });

  it("refuses a blank statement, a blank role, and a statement id that would break the method id", async () => {
    const work = await mkdtemp(join(tmpdir(), "rampscan-q42-refusals-"));
    const base = {
      repo: REPO,
      statementId: "training-review",
      ksiId: KSI,
      attestorRole: "ciso",
      statement: "x",
      action: "attested" as const,
      proposedBy: "a",
      approvedBy: "b",
      datasetDir: DATASET_DIR,
      datasetPin: DEFAULT_DATASET_PIN,
      ledgerDir: join(work, "ledger"),
      keysDir: join(work, "keys"),
    };
    await expect(recordAttestation({ ...base, statement: "   " })).rejects.toThrow(
      /requires a statement/,
    );
    await expect(recordAttestation({ ...base, attestorRole: " " })).rejects.toThrow(
      /requires an attestor role/,
    );
    for (const statementId of ["two#parts", "a:b", "has space"]) {
      await expect(
        recordAttestation({ ...base, statementId }),
        statementId,
      ).rejects.toThrow(/not slug-shaped/);
    }
  });
});
