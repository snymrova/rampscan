import { execFileSync, spawn, type ChildProcess } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { LedgerEntry } from "@rampscan/core";
import type { EvidenceBundle } from "@rampscan/schema";
import {
  PocketBaseAdmin,
  foldEntries,
  readProjectionPocketBase,
  writeProjectionPocketBase,
} from "../src/index.js";

// PocketBase round trip (plan M3 E1), gated on the vendored binary: run
// `pnpm fetch-pocketbase` to enable. Proves the writer's contract — drop-and-
// refill lands the whole projection, reads back identically, and projection
// collections reject writes from anyone but the projector's superuser.

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const PB_BIN = join(ROOT, "console/pocketbase/bin/pocketbase");
const HAVE_PB = existsSync(PB_BIN);

const PORT = 8097; // test-only port, away from the serve default 8090
const URL = `http://127.0.0.1:${PORT}`;
const EMAIL = "projector@rampscan.local";
const PASSWORD = "test-superuser-pass-1";

let child: ChildProcess | undefined;

function evidenceEntry(recipe: string, timestamp: string): LedgerEntry {
  const bundle: EvidenceBundle = {
    _type: "https://in-toto.io/Statement/v1",
    subject: [{ name: "x", digest: { sha256: "e".repeat(64) } }],
    predicateType: "https://rampscan.dev/evidence/v1",
    predicate: {
      recipe_id: recipe,
      ksi_ids: ["KSI-SCR-MIT"],
      control_ids: ["si-7.1"],
      verdict: "evidenced",
      repo: "fixtures/app",
      commit: "1".repeat(40),
      anchor_paths: [{ path: "f", contentHash: "a".repeat(64) }],
      dataset_version: "2026.07.14.01",
      tool_versions: { "repo-facts": "0.1.0" },
      assertions: [{ description: "check", passed: true }],
      cadence: "continuous",
      run_id: `run-${timestamp}`,
      timestamp,
    },
  };
  return {
    digest: `pbtest-${recipe}`,
    bundle,
    envelope: { payload: "cGF5bG9hZA==", payloadType: "application/vnd.in-toto+json", signatures: [{ keyid: "k", sig: "s" }] },
    appendedAt: timestamp,
  };
}

describe.skipIf(!HAVE_PB)("pocketbase projection store", () => {
  beforeAll(async () => {
    const dataDir = await mkdtemp(join(tmpdir(), "rampscan-pb-"));
    execFileSync(PB_BIN, ["superuser", "upsert", EMAIL, PASSWORD, "--dir", dataDir], { stdio: "pipe" });
    child = spawn(PB_BIN, ["serve", `--http=127.0.0.1:${PORT}`, "--dir", dataDir], { stdio: "pipe" });
    const pb = new PocketBaseAdmin(URL);
    for (let i = 0; i < 100; i++) {
      if (await pb.health()) return;
      await new Promise((r) => setTimeout(r, 100));
    }
    throw new Error("pocketbase did not come up");
  }, 20_000);

  afterAll(() => {
    child?.kill("SIGTERM");
  });

  it("write → read returns the identical projection; a second write replaces, never merges", async () => {
    const pb = new PocketBaseAdmin(URL);
    await pb.auth(EMAIL, PASSWORD);

    const entries = [
      evidenceEntry("lockfile-pinned-deps", "2026-08-01T00:00:00.000Z"),
      evidenceEntry("sbom-exists-and-fresh", "2026-08-02T00:00:00.000Z"),
    ];
    const projection = foldEntries(entries, "2026-08-03T00:00:00.000Z");
    const settings = { certClass: "b" as const, reproduceCommand: "pnpm rampscan scan <path>" };

    await writeProjectionPocketBase(projection, entries, pb, settings);
    await writeProjectionPocketBase(projection, entries, pb, settings); // drop-and-refill, not append
    expect(await readProjectionPocketBase(pb)).toEqual(projection);

    const bundles = await pb.listAll("bundles");
    expect(bundles).toHaveLength(2);
    expect((bundles[0] as any).envelope.signatures).toHaveLength(1);
  });

  it("projection collections reject writes that are not the projector's — rule 1 enforced", async () => {
    const anonymous = new PocketBaseAdmin(URL); // no auth() — not the projector
    await expect(
      anonymous.create("registers", { repo: "x", recipe_id: "y", state: "evidenced" }),
    ).rejects.toThrow(/HTTP 4/);
  });
});
