import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { allCollectors } from "@rampscan/collectors";
import { DEFAULT_DATASET_PIN, loadKsiCatalogFromSlices } from "@rampscan/dataset";
import { readProjectionSqlite } from "@rampscan/projector";
import { recordArtifactJudgment } from "../src/artifact-judgment.js";
import { rebuild } from "../src/rebuild.js";
import { deriveCatalogMethods, loadRecipes } from "../src/recipes.js";
import { verify } from "../src/verify.js";

// Q3.3 exit test: an artifact-sufficiency judgment survives `rampscan
// rebuild` because it lives in the LEDGER — the projection is thrown away
// and recomputed, and the judged artifact is still present on the board's
// checklist, with the approver's identity riding in the signed event. Never
// a checkbox: the only way this bit flips is a signed statement.

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const RECIPES_DIR = join(REPO_ROOT, "recipes/commit");
const DATASET_DIR = join(REPO_ROOT, "docs/context/ramprules/derived");

describe("two-key artifact judgment → rebuild survival", () => {
  it("records a signed judgment, folds it onto the checklist, and survives a projection rebuild", async () => {
    const work = await mkdtemp(join(tmpdir(), "rampscan-q33-"));
    const ledgerDir = join(work, "ledger");
    const keysDir = join(work, "keys");
    const dbPath = join(work, "projection.db");

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

    // the signed event verifies offline like any evidence bundle
    const verification = await verify({ digest, ledgerDir, keysDir });
    expect(verification.ok, verification.lines.join("\n")).toBe(true);
    expect(verification.lines.join("\n")).toContain("KSI-SCR-MIT #4 → sufficient");

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
    expect(cell.judgment?.digest).toBe(digest);
    expect(cell.judgment?.approvedBy).toBe("approver@rampscan.local (pb:u2)");
    // the computed artifacts stay computed: no evidence in this ledger, so 2
    // and 5 are absent — a judgment cannot green what the fold measures
    expect(row.artifacts.find((a) => a.artifact === 2)!.present).toBe(false);
    expect(row.artifacts.find((a) => a.artifact === 5)!.present).toBe(false);
    expect(row.artifactsPresent).toBe(1);
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
