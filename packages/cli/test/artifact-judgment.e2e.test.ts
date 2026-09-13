import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { allCollectors } from "@rampscan/collectors";
import { DEFAULT_DATASET_PIN, loadKsiCatalogFromSlices } from "@rampscan/dataset";
import { readProjectionSqlite } from "@rampscan/projector";
import { recordArtifact } from "../src/artifacts.js";
import { recordArtifactJudgment } from "../src/artifact-judgment.js";
import { rebuild } from "../src/rebuild.js";
import { deriveCatalogMethods, loadRecipes } from "../src/recipes.js";
import { verify } from "../src/verify.js";

// Q3.3 exit test, amended by R1.1: an artifact BODY and the sufficiency
// judgment about it both survive `rampscan rebuild`, because both live in the
// LEDGER — the projection is thrown away and recomputed, and the cell comes
// back with the same bytes and the same approver identity. Never a checkbox:
// the only way this moves is a signed statement.
//
// What R1.1 changed here is what `present` means. Before the artifact plane a
// signed `sufficient` made a cell present with no prose behind it; now the
// body is the presence and the judgment says whether those bytes are enough.
// The last assertion below is the one that would have been impossible to write
// in Q3.3: the cell names the digest of the words it approved.

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const RECIPES_DIR = join(REPO_ROOT, "recipes/commit");
const DATASET_DIR = join(REPO_ROOT, "docs/context/ramprules/derived");

describe("two-key artifact judgment → rebuild survival", () => {
  it("records a signed judgment, folds it onto the checklist, and survives a projection rebuild", async () => {
    const work = await mkdtemp(join(tmpdir(), "rampscan-q33-"));
    const ledgerDir = join(work, "ledger");
    const keysDir = join(work, "keys");
    const dbPath = join(work, "projection.db");

    // the body first: R1.1's whole point is that there is something to judge
    const authored = await recordArtifact({
      repo: "fixtures/vulnerable-app",
      ksiId: "KSI-SCR-MIT",
      artifact: 4,
      source: "authored",
      body: "## Measurement accuracy\n\nThe pipeline resolves composite actions since #23.",
      anchor: { commit: "a".repeat(40), path: "docs/ksi/KSI-SCR-MIT-4.md" },
      datasetDir: DATASET_DIR,
      datasetPin: DEFAULT_DATASET_PIN,
      ledgerDir,
      keysDir,
    });

    const { digest } = await recordArtifactJudgment({
      repo: "fixtures/vulnerable-app",
      ksiId: "KSI-SCR-MIT",
      artifact: 4,
      action: "sufficient",
      justification: "the pipeline's measurement covers composite actions since #23",
      proposedBy: "viewer@rampscan.local (pb:u1)",
      approvedBy: "approver@rampscan.local (pb:u2)",
      datasetDir: DATASET_DIR,
      datasetPin: DEFAULT_DATASET_PIN,
      ledgerDir,
      keysDir,
    });

    // both signed statements verify offline like any evidence bundle
    const verification = await verify({ digest, ledgerDir, keysDir });
    expect(verification.ok, verification.lines.join("\n")).toBe(true);
    expect(verification.lines.join("\n")).toContain("KSI-SCR-MIT #4 → sufficient");
    const bodyCheck = await verify({ digest: authored.digest, ledgerDir, keysDir });
    expect(bodyCheck.ok, bodyCheck.lines.join("\n")).toBe(true);
    const bodyLines = bodyCheck.lines.join("\n");
    expect(bodyLines).toContain("KSI-SCR-MIT #4 — authored");
    expect(bodyLines).toContain("docs/ksi/KSI-SCR-MIT-4.md @ aaaaaaaaaaaa");
    expect(bodyLines).toContain("review   none on record"); // §13.2: printed, not assumed
    expect(bodyLines).toContain("VDR-TFR-NMV");

    // rebuild with the pivot's fold inputs, twice — the second run throws the
    // projection away and recomputes; the judgment must still be there,
    // because it was never console state
    const catalog = await loadKsiCatalogFromSlices(DATASET_DIR, DEFAULT_DATASET_PIN);
    const foldInputs = {
      ledgerDir,
      recipesDir: RECIPES_DIR,
      dbPath,
      methods: deriveCatalogMethods(
        await loadRecipes(RECIPES_DIR),
        allCollectors.map((c) => c.manifest),
      ),
      ksiIds: catalog.ksis.map((k) => k.id),
    };
    const first = await rebuild(foldInputs);
    expect(first.ok, first.lines.join("\n")).toBe(true);
    const second = await rebuild(foldInputs);
    expect(second.ok).toBe(true);

    const projection = readProjectionSqlite(dbPath);
    const row = projection.methodRegisters.find(
      (r) => r.repo === "fixtures/vulnerable-app" && r.ksi === "KSI-SCR-MIT",
    )!;
    expect(row).toBeDefined();
    const cell = row.artifacts.find((a) => a.artifact === 4)!;
    expect(cell.basis).toBe("judged");
    expect(cell.present).toBe(true);
    expect(cell.body?.digest).toBe(authored.digest);
    expect(cell.body?.bodyDigest).toBe(authored.bodyDigest);
    expect(cell.body?.source).toBe("authored");
    expect(cell.body?.anchor?.path).toBe("docs/ksi/KSI-SCR-MIT-4.md");
    expect(cell.judgment?.digest).toBe(digest);
    expect(cell.judgment?.approvedBy).toBe("approver@rampscan.local (pb:u2)");
    // the judgment names the bytes it approved, and those bytes are the ones
    // standing in the slot — the assertion Q3.3 had no way to write
    expect(cell.judgment?.bodyDigest).toBe(authored.bodyDigest);
    expect(cell.judgment?.appliesToLiveBody).toBe(true);
    // the computed artifacts stay empty: no evidence in this ledger, so 2 and
    // 5 are not even derivable — a judgment cannot green what the fold measures
    expect(row.artifacts.find((a) => a.artifact === 2)!.present).toBe(false);
    expect(row.artifacts.find((a) => a.artifact === 2)!.derivable).toBe(false);
    expect(row.artifacts.find((a) => a.artifact === 5)!.present).toBe(false);
    expect(row.artifactsPresent).toBe(1);
  });

  it("refuses to judge a slot with no body — there is nothing to name (§13.6)", async () => {
    const work = await mkdtemp(join(tmpdir(), "rampscan-r11-nobody-"));
    await expect(
      recordArtifactJudgment({
        repo: "fixtures/vulnerable-app",
        ksiId: "KSI-SCR-MIT",
        artifact: 1,
        action: "sufficient",
        justification: "it reads well enough",
        proposedBy: "a",
        approvedBy: "b",
        datasetDir: DATASET_DIR,
        datasetPin: DEFAULT_DATASET_PIN,
        ledgerDir: join(work, "ledger"),
        keysDir: join(work, "keys"),
      }),
    ).rejects.toThrow(/no artifact 1 body/);
  });

  it("refuses a judgment for a KSI outside the pinned catalog", async () => {
    const work = await mkdtemp(join(tmpdir(), "rampscan-q33-bad-"));
    await expect(
      recordArtifactJudgment({
        repo: "fixtures/vulnerable-app",
        ksiId: "KSI-NO-SUCH",
        artifact: 1,
        action: "sufficient",
        justification: "x",
        proposedBy: "a",
        approvedBy: "b",
        datasetDir: DATASET_DIR,
        datasetPin: DEFAULT_DATASET_PIN,
        ledgerDir: join(work, "ledger"),
        keysDir: join(work, "keys"),
      }),
    ).rejects.toThrow(/unknown KSI/);
  });

  it("refuses a judgment about the computed artifacts 2 and 5", async () => {
    const work = await mkdtemp(join(tmpdir(), "rampscan-q33-computed-"));
    for (const artifact of [2, 5]) {
      await expect(
        recordArtifactJudgment({
          repo: "fixtures/vulnerable-app",
          ksiId: "KSI-SCR-MIT",
          artifact,
          action: "sufficient",
          justification: "x",
          proposedBy: "a",
          approvedBy: "b",
          datasetDir: DATASET_DIR,
          datasetPin: DEFAULT_DATASET_PIN,
          ledgerDir: join(work, "ledger"),
          keysDir: join(work, "keys"),
        }),
        `artifact ${artifact}`,
      ).rejects.toThrow(/accepts no judgment/);
    }
  });
});
