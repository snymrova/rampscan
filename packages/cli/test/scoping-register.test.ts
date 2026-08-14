import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { toScopingEvent } from "@rampscan/core";
import { DEFAULT_DATASET_PIN } from "@rampscan/dataset";
import { createLocalLedger } from "@rampscan/ledger";
import { computeScopingRegister } from "../src/scoping-register.js";
import type { ScopingProposalInput } from "../src/scoping-register.js";
import { recordScoping } from "../src/scoping.js";

// The scoping register (plan I3c): approved decisions come from the LEDGER
// (signed events, each re-verified), rejected/pending from the proposals
// collection — and the two are cross-checked, never merged blindly. These
// tests pin every signature status and every honesty flag the register can
// emit, against a real ledger and real keys.

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const RECIPES_DIR = join(REPO_ROOT, "recipes/pipeline");
const DATASET_DIR = join(REPO_ROOT, "docs/context/ramprules/derived");

const REPO = "fixtures/vulnerable-app";

function proposal(overrides: Partial<ScopingProposalInput>): ScopingProposalInput {
  return {
    id: "p1",
    repo: REPO,
    recipe_id: "container-runs-nonroot",
    justification: "fixture repo ships no production container image",
    status: "pending",
    proposed_by: "viewer@rampscan.local (pb:u1)",
    decided_by: "",
    scoping_digest: "",
    created: "2026-08-14T10:00:00.000Z",
    updated: "2026-08-14T10:00:00.000Z",
    ...overrides,
  };
}

async function scopedWorld(): Promise<{ ledgerDir: string; keysDir: string; digest: string }> {
  const work = await mkdtemp(join(tmpdir(), "rampscan-i3c-"));
  const ledgerDir = join(work, "ledger");
  const keysDir = join(work, "keys");
  const { digest } = await recordScoping({
    repo: REPO,
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
  return { ledgerDir, keysDir, digest };
}

describe("computeScopingRegister", () => {
  it("lifts an approved decision from the signed ledger event and verifies it", async () => {
    const { ledgerDir, keysDir, digest } = await scopedWorld();
    const register = await computeScopingRegister({
      ledgerDir,
      keysDir,
      recipesDir: RECIPES_DIR,
      proposals: [
        proposal({
          status: "approved",
          decided_by: "approver@rampscan.local (pb:u2)",
          scoping_digest: digest,
        }),
      ],
    });

    expect(register.counts).toEqual({ approved: 1, rejected: 0, pending: 0 });
    const row = register.rows[0]!;
    expect(row.decision).toBe("approved");
    expect(row.signature).toBe("verified");
    expect(row.digest).toBe(digest);
    // the SIGNED predicate is the record: identities, justification, scope
    expect(row.decidedBy).toBe("approver@rampscan.local (pb:u2)");
    expect(row.proposedBy).toBe("viewer@rampscan.local (pb:u1)");
    expect(row.justification).toBe("fixture repo ships no production container image");
    expect(row.ksiIds.length).toBeGreaterThan(0);
    expect(row.controlIds.length).toBeGreaterThan(0);
    expect(row.problems).toEqual([]);
  });

  it("reports `failed` when the envelope does not verify against the serving key", async () => {
    const { ledgerDir, digest } = await scopedWorld();
    // a different keys dir = a different (freshly generated) keypair — the
    // recorded envelope cannot verify against it
    const wrongKeys = join(await mkdtemp(join(tmpdir(), "rampscan-i3c-wrongkey-")), "keys");
    const register = await computeScopingRegister({
      ledgerDir,
      keysDir: wrongKeys,
      recipesDir: RECIPES_DIR,
      proposals: [],
    });
    const row = register.rows.find((r) => r.digest === digest)!;
    expect(row.signature).toBe("failed");
    expect(row.problems.some((p) => p.includes("does not verify"))).toBe(true);
  });

  it("reports `unsigned` for a scoping event appended without an envelope", async () => {
    const work = await mkdtemp(join(tmpdir(), "rampscan-i3c-unsigned-"));
    const ledgerDir = join(work, "ledger");
    const statement = toScopingEvent(
      { id: "codeowners-defined", ksi_ids: ["KSI-X"], control_ids: ["cm-1"] },
      {
        repo: REPO,
        justification: "appended unsigned on purpose",
        proposedBy: "a",
        approvedBy: "b",
        datasetVersion: "test",
        timestamp: "2026-08-14T09:00:00.000Z",
      },
    );
    await createLocalLedger(ledgerDir).append(statement);
    const register = await computeScopingRegister({
      ledgerDir,
      keysDir: join(work, "keys"),
      recipesDir: RECIPES_DIR,
      proposals: [],
    });
    expect(register.rows[0]!.signature).toBe("unsigned");
    expect(register.rows[0]!.problems.some((p) => p.includes("without a signature"))).toBe(true);
  });

  it("flags a ledger event with no matching proposal row instead of hiding the gap", async () => {
    const { ledgerDir, keysDir } = await scopedWorld();
    const register = await computeScopingRegister({
      ledgerDir,
      keysDir,
      recipesDir: RECIPES_DIR,
      proposals: [],
    });
    expect(register.rows[0]!.signature).toBe("verified");
    expect(register.rows[0]!.problems.some((p) => p.includes("no matching proposal row"))).toBe(
      true,
    );
  });

  it("keeps rejected proposals on the register — the honest record of a declined scope-out", async () => {
    const { ledgerDir, keysDir } = await scopedWorld();
    const register = await computeScopingRegister({
      ledgerDir,
      keysDir,
      recipesDir: RECIPES_DIR,
      proposals: [
        proposal({
          id: "p-rej",
          recipe_id: "codeowners-defined",
          justification: "we do not need code owners",
          status: "rejected",
          decided_by: "approver@rampscan.local (pb:u2)",
          updated: "2026-08-14T11:00:00.000Z",
        }),
      ],
    });

    expect(register.counts.rejected).toBe(1);
    const row = register.rows.find((r) => r.decision === "rejected")!;
    expect(row.recipeId).toBe("codeowners-defined");
    expect(row.justification).toBe("we do not need code owners");
    expect(row.decidedBy).toBe("approver@rampscan.local (pb:u2)");
    // a rejection never touches the ledger: no digest, no signature status
    expect(row.digest).toBeUndefined();
    expect(row.signature).toBeUndefined();
    // the scope it declined to remove comes from the catalog
    expect(row.controlIds.length).toBeGreaterThan(0);
    // rejected rows sort by their decision time — newer than the scoping event
    expect(register.rows[0]!.decision).toBe("rejected");
  });

  it("surfaces an approved claim the ledger cannot back as `missing`, loudly", async () => {
    const { ledgerDir, keysDir } = await scopedWorld();
    const register = await computeScopingRegister({
      ledgerDir,
      keysDir,
      recipesDir: RECIPES_DIR,
      proposals: [
        proposal({
          id: "p-orphan",
          recipe_id: "codeowners-defined",
          status: "approved",
          decided_by: "approver@rampscan.local (pb:u2)",
          scoping_digest: "0".repeat(64),
        }),
        proposal({
          id: "p-orphan-nodigest",
          recipe_id: "lockfile-pinned-deps",
          status: "approved",
          decided_by: "approver@rampscan.local (pb:u2)",
        }),
      ],
    });

    const orphan = register.rows.find((r) => r.recipeId === "codeowners-defined")!;
    expect(orphan.signature).toBe("missing");
    expect(orphan.problems.some((p) => p.includes("no scoping event at"))).toBe(true);
    const noDigest = register.rows.find((r) => r.recipeId === "lockfile-pinned-deps")!;
    expect(noDigest.signature).toBe("missing");
    expect(noDigest.problems.some((p) => p.includes("records no ledger digest"))).toBe(true);
    // both still count as approved decisions — the claim is on the record
    expect(register.counts.approved).toBe(3);
  });

  it("names a proposal whose recipe left the catalog instead of guessing its scope", async () => {
    const { ledgerDir, keysDir } = await scopedWorld();
    const register = await computeScopingRegister({
      ledgerDir,
      keysDir,
      recipesDir: RECIPES_DIR,
      proposals: [
        proposal({ id: "p-gone", recipe_id: "no-such-recipe", status: "pending" }),
      ],
    });
    const row = register.rows.find((r) => r.recipeId === "no-such-recipe")!;
    expect(row.ksiIds).toEqual([]);
    expect(row.controlIds).toEqual([]);
    expect(row.problems.some((p) => p.includes("not in the catalog"))).toBe(true);
    expect(register.counts.pending).toBe(1);
  });
});
