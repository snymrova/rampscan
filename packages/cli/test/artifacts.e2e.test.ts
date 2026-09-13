import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { allCollectors } from "@rampscan/collectors";
import { DEFAULT_DATASET_PIN, loadKsiCatalogFromSlices } from "@rampscan/dataset";
import { readProjectionSqlite } from "@rampscan/projector";
import { MAX_ARTIFACT_BODY_BYTES } from "@rampscan/schema";
import { recordArtifact } from "../src/artifacts.js";
import { rebuild } from "../src/rebuild.js";
import { deriveCatalogMethods, loadRecipes } from "../src/recipes.js";
import { verify } from "../src/verify.js";

// R1.1 exit test: an artifact body enters the ledger like every other
// statement, verifies offline, folds onto the board, and survives a rebuild —
// and the refusals of SPEC §13.2/§13.4 hold at the append rather than being
// discovered later by a document generator.

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const RECIPES_DIR = join(REPO_ROOT, "recipes/commit");
const DATASET_DIR = join(REPO_ROOT, "docs/context/ramprules/derived");
const REPO = "fixtures/vulnerable-app";

async function workspace(prefix: string) {
  const work = await mkdtemp(join(tmpdir(), prefix));
  return {
    ledgerDir: join(work, "ledger"),
    keysDir: join(work, "keys"),
    dbPath: join(work, "projection.db"),
  };
}

function base(ledgerDir: string, keysDir: string) {
  return {
    repo: REPO,
    datasetDir: DATASET_DIR,
    datasetPin: DEFAULT_DATASET_PIN,
    ledgerDir,
    keysDir,
  } as const;
}

async function foldOf(ledgerDir: string, dbPath: string) {
  const catalog = await loadKsiCatalogFromSlices(DATASET_DIR, DEFAULT_DATASET_PIN);
  const result = await rebuild({
    ledgerDir,
    recipesDir: RECIPES_DIR,
    dbPath,
    methods: deriveCatalogMethods(
      await loadRecipes(RECIPES_DIR),
      allCollectors.map((c) => c.manifest),
    ),
    ksiIds: catalog.ksis.map((k) => k.id),
  });
  expect(result.ok, result.lines.join("\n")).toBe(true);
  return readProjectionSqlite(dbPath);
}

describe("the artifact plane's write path (R1.1)", () => {
  it("appends a body, verifies it offline, and moves the KSI's k/5 off zero", async () => {
    const { ledgerDir, keysDir, dbPath } = await workspace("rampscan-r11-");
    const appended = await recordArtifact({
      ...base(ledgerDir, keysDir),
      ksiId: "KSI-SVC-SIN",
      artifact: 1,
      source: "authored",
      body: "## Service integrity\n\nEvery merge to main runs the pinned gate.",
      anchor: { commit: "c".repeat(40), path: "docs/ksi/KSI-SVC-SIN-1.md" },
      validFrom: "2026-09-01T00:00:00.000Z",
    });

    const verification = await verify({ digest: appended.digest, ledgerDir, keysDir });
    expect(verification.ok, verification.lines.join("\n")).toBe(true);

    const projection = await foldOf(ledgerDir, dbPath);
    const row = projection.methodRegisters.find(
      (r) => r.repo === REPO && r.ksi === "KSI-SVC-SIN",
    )!;
    expect(row.artifactsPresent).toBe(1);
    const cell = row.artifacts.find((a) => a.artifact === 1)!;
    expect(cell.body?.bodyDigest).toBe(appended.bodyDigest);
    expect(cell.body?.source).toBe("authored");
    expect(cell.body?.validFrom).toBe("2026-09-01T00:00:00.000Z");
  });

  it("records what a revision revises, read from the ledger rather than asked for", async () => {
    const { ledgerDir, keysDir, dbPath } = await workspace("rampscan-r11-rev-");
    const first = await recordArtifact({
      ...base(ledgerDir, keysDir),
      ksiId: "KSI-SVC-SIN",
      artifact: 1,
      source: "authored",
      body: "first statement",
      anchor: { commit: "c".repeat(40), path: "docs/ksi/KSI-SVC-SIN-1.md" },
    });
    expect(first.supersedes).toBeUndefined();

    const second = await recordArtifact({
      ...base(ledgerDir, keysDir),
      ksiId: "KSI-SVC-SIN",
      artifact: 1,
      source: "authored",
      body: "second statement, after the September review",
      anchor: { commit: "d".repeat(40), path: "docs/ksi/KSI-SVC-SIN-1.md" },
    });
    expect(second.supersedes).toBe(first.bodyDigest);

    // the fold takes the later one; the earlier statement is still in the
    // ledger, which is what "revises by writing again" means
    const projection = await foldOf(ledgerDir, dbPath);
    const cell = projection.methodRegisters
      .find((r) => r.repo === REPO && r.ksi === "KSI-SVC-SIN")!
      .artifacts.find((a) => a.artifact === 1)!;
    expect(cell.body?.bodyDigest).toBe(second.bodyDigest);
    expect(cell.body?.supersedes).toBe(first.bodyDigest);
  });

  it("re-signing identical bytes supersedes nothing — an artifact is not its own revision", async () => {
    const { ledgerDir, keysDir } = await workspace("rampscan-r11-same-");
    const args = {
      ...base(ledgerDir, keysDir),
      ksiId: "KSI-SVC-SIN",
      artifact: 1 as const,
      source: "authored" as const,
      body: "unchanged",
      anchor: { commit: "c".repeat(40), path: "docs/ksi/KSI-SVC-SIN-1.md" },
    };
    await recordArtifact(args);
    const again = await recordArtifact(args);
    expect(again.supersedes).toBeUndefined();
  });

  it("refuses to compute artifacts 1 and 3 at the append — §13.4, not a code review", async () => {
    const { ledgerDir, keysDir } = await workspace("rampscan-r11-computed-");
    for (const artifact of [1, 3] as const) {
      await expect(
        recordArtifact({
          ...base(ledgerDir, keysDir),
          ksiId: "KSI-SVC-SIN",
          artifact,
          source: "computed",
          body: "The provider implements the measures described below.",
          generator: { pins: { dataset: DEFAULT_DATASET_PIN }, tool_versions: {} },
        }),
        `artifact ${artifact}`,
      ).rejects.toThrow(/provider's own claim/);
    }
  });

  it("refuses a body longer than its own summary", async () => {
    const { ledgerDir, keysDir } = await workspace("rampscan-r11-long-");
    await expect(
      recordArtifact({
        ...base(ledgerDir, keysDir),
        ksiId: "KSI-SVC-SIN",
        artifact: 1,
        source: "authored",
        body: "x".repeat(MAX_ARTIFACT_BODY_BYTES + 1),
        anchor: { commit: "c".repeat(40), path: "docs/ksi/KSI-SVC-SIN-1.md" },
      }),
    ).rejects.toThrow(/short and simple high-level summaries/);
  });

  it("refuses an authored body with no anchor — it could never die by drift", async () => {
    const { ledgerDir, keysDir } = await workspace("rampscan-r11-anchor-");
    await expect(
      recordArtifact({
        ...base(ledgerDir, keysDir),
        ksiId: "KSI-SVC-SIN",
        artifact: 1,
        source: "authored",
        body: "a statement with no file behind it",
      }),
    ).rejects.toThrow(/anchor drift/);
  });

  it("refuses a blank body and an unknown KSI", async () => {
    const { ledgerDir, keysDir } = await workspace("rampscan-r11-blank-");
    await expect(
      recordArtifact({
        ...base(ledgerDir, keysDir),
        ksiId: "KSI-SVC-SIN",
        artifact: 1,
        source: "authored",
        body: "   \n  ",
        anchor: { commit: "c".repeat(40), path: "docs/ksi/KSI-SVC-SIN-1.md" },
      }),
    ).rejects.toThrow(/an absence is recorded with a reason/);
    await expect(
      recordArtifact({
        ...base(ledgerDir, keysDir),
        ksiId: "KSI-NO-SUCH",
        artifact: 1,
        source: "authored",
        body: "for a KSI that does not exist",
        anchor: { commit: "c".repeat(40), path: "docs/ksi/x.md" },
      }),
    ).rejects.toThrow(/unknown KSI/);
  });
});
