import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { DEFAULT_DATASET_PIN } from "@rampscan/dataset";
import { readProjectionSqlite } from "@rampscan/projector";
import { rebuild } from "../src/rebuild.js";
import { recordScoping } from "../src/scoping.js";
import { verify } from "../src/verify.js";

// M3 exit test (plan Phase E): a notApplicable survives `rampscan rebuild`
// because it lives in the LEDGER — the projection is thrown away and
// recomputed, and the register still says notApplicable, with the approver's
// identity riding in the signed event. Also proves rebuild's equality check:
// fold → store → read-back → byte equality.

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const RECIPES_DIR = join(REPO_ROOT, "recipes/pipeline");
const DATASET_DIR = join(REPO_ROOT, "docs/context/ramprules/derived");

describe("two-key scoping → rebuild survival", () => {
  it("records a signed scoping event, folds it to notApplicable, and survives a projection rebuild", async () => {
    const work = await mkdtemp(join(tmpdir(), "rampscan-m3-"));
    const ledgerDir = join(work, "ledger");
    const keysDir = join(work, "keys");
    const dbPath = join(work, "projection.db");

    const { digest } = await recordScoping({
      repo: "fixtures/vulnerable-app",
      recipeId: "container-runs-nonroot",
      justification: "fixture repo ships no production container image",
      proposedBy: "viewer@rampscan.local (pb:u1)",
      approvedBy: "approver@rampscan.local (pb:u2)",
      recipesDir: RECIPES_DIR,
      datasetDir: DATASET_DIR,
      datasetPin: DEFAULT_DATASET_PIN,
      ledgerDir,
      keysDir,
    });

    // the signed event verifies offline like any evidence bundle
    const verification = await verify({ digest, ledgerDir, keysDir });
    expect(verification.ok, verification.lines.join("\n")).toBe(true);

    // rebuild #1: projection written from the ledger and proven equal
    const first = await rebuild({ ledgerDir, recipesDir: RECIPES_DIR, dbPath });
    expect(first.ok, first.lines.join("\n")).toBe(true);

    // rebuild #2 = throw the projection away and recompute — the scoping must
    // still be there, because it was never console state
    const second = await rebuild({ ledgerDir, recipesDir: RECIPES_DIR, dbPath });
    expect(second.ok).toBe(true);

    const projection = readProjectionSqlite(dbPath);
    const row = projection.registers.find((r) => r.recipeId === "container-runs-nonroot")!;
    expect(row.state).toBe("notApplicable");
    expect(row.scoping?.digest).toBe(digest);
    expect(row.scoping?.approvedBy).toBe("approver@rampscan.local (pb:u2)");

    // the join keeps the honest default: every other catalog recipe is
    // visible as unevidenced for this repo — nothing hides
    const others = projection.registers.filter((r) => r.recipeId !== "container-runs-nonroot");
    expect(others.length).toBeGreaterThan(5);
    expect(others.every((r) => r.state === "unevidenced")).toBe(true);

    // and it is drift: the scoped event is on the record
    expect(projection.drift.map((d) => d.kind)).toContain("scoped");
  });

  it("refuses a scoping for a recipe outside the catalog", async () => {
    const work = await mkdtemp(join(tmpdir(), "rampscan-m3-bad-"));
    await expect(
      recordScoping({
        repo: "fixtures/vulnerable-app",
        recipeId: "no-such-recipe",
        justification: "x",
        proposedBy: "a",
        approvedBy: "b",
        recipesDir: RECIPES_DIR,
        datasetDir: DATASET_DIR,
        datasetPin: DEFAULT_DATASET_PIN,
        ledgerDir: join(work, "ledger"),
        keysDir: join(work, "keys"),
      }),
    ).rejects.toThrow(/unknown recipe/);
  });
});
