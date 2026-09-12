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

function evidenceEntry(recipe: string, timestamp: string, violated = false): LedgerEntry {
  const bundle: EvidenceBundle = {
    _type: "https://in-toto.io/Statement/v1",
    subject: [{ name: "x", digest: { sha256: "e".repeat(64) } }],
    predicateType: "https://rampscan.dev/evidence/v1",
    predicate: {
      recipe_id: recipe,
      ksi_ids: ["KSI-SCR-MIT"],
      control_ids: ["si-7.1"],
      verdict: violated ? "violated" : "evidenced",
      repo: "fixtures/app",
      commit: "1".repeat(40),
      anchor_paths: [{ path: "f", contentHash: "a".repeat(64) }],
      dataset_version: "2026.07.14.01",
      tool_versions: { "repo-facts": "0.1.0" },
      assertions: violated
        ? [
            {
              description: "check",
              passed: false,
              detail: "1 of 1 row(s) fail",
              offenders: [{ file: "bad.ts", line: 2, check: "b" }],
              offender_count: 1,
            },
          ]
        : [{ description: "check", passed: true }],
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
      // a violated cell whose register row carries fix pointers + the streak (I2c)
      evidenceEntry("no-secrets-in-history", "2026-08-02T01:00:00.000Z", true),
    ];
    const projection = foldEntries(entries, "2026-08-03T00:00:00.000Z");
    expect(
      projection.registers.find((r) => r.recipeId === "no-secrets-in-history")!.pointers,
    ).toBeDefined();
    const settings = { certClass: "b" as const, reproduceCommand: "pnpm rampscan scan <path>" };

    await writeProjectionPocketBase(projection, entries, pb, settings);
    await writeProjectionPocketBase(projection, entries, pb, settings); // drop-and-refill, not append
    expect(await readProjectionPocketBase(pb)).toEqual(projection);

    const bundles = await pb.listAll("bundles");
    expect(bundles).toHaveLength(3);
    expect((bundles[0] as any).envelope.signatures).toHaveLength(1);
  });

  // Q4.3: an ingested result has NO commit anchor (SPEC §12.8), so its register
  // row omits `commit` and its vulnerability record carries an empty one. Both
  // must survive this store, whose `commit_sha` on vulnerabilities is a REQUIRED
  // field — exactly the kind of place an empty value is silently rejected.
  it("an ingested result with no commit anchor round-trips, violated episode included", async () => {
    const pb = new PocketBaseAdmin(URL);
    await pb.auth(EMAIL, PASSWORD);

    const ingested = (ksi: string, violated: boolean, timestamp: string): LedgerEntry => ({
      digest: `pbtest-ing-${ksi}`,
      appendedAt: timestamp,
      bundle: {
        _type: "https://in-toto.io/Statement/v1",
        subject: [{ name: "out.json", digest: { sha256: "f".repeat(64) } }],
        predicateType: "https://rampscan.dev/evidence/v1",
        predicate: {
          recipe_id: `${ksi}.sh`,
          method_id: `aws-ingested:${ksi}.sh#${ksi}`,
          evidence_class: "process-generated",
          ingest: { signer_identity: "ops@client.example", ingest_digest: "a".repeat(64) },
          ksi_ids: [ksi],
          control_ids: [],
          verdict: violated ? "violated" : "evidenced",
          repo: "fixtures/app",
          commit: "",
          anchor_paths: [],
          dataset_version: "2026.07.14.01",
          tool_versions: {},
          assertions: [{ description: "check", passed: !violated, population: 0 }],
          cadence: "monthly",
          run_id: `ingest:${ksi}`,
          timestamp,
        },
      } as EvidenceBundle,
    });

    const entries = [
      ingested("KSI-CNA-RVP", false, "2026-08-01T00:00:00.000Z"),
      ingested("KSI-IAM-AAM", true, "2026-08-01T01:00:00.000Z"),
    ];
    const projection = foldEntries(entries, "2026-08-03T00:00:00.000Z");
    // the row says nothing about a commit, because there is none to name
    const row = projection.registers.find((r) => r.recipeId === "KSI-IAM-AAM.sh")!;
    expect(row.commit).toBeUndefined();
    expect(row.introducingCommit).toBeUndefined();
    // the violated ingestion still opens an episode, whose commit IS empty
    expect(projection.vulnerabilities).toHaveLength(1);
    expect(projection.vulnerabilities[0]!.commit).toBe("");
    // "0 of 0" is a measurement: population 0 must survive too, not read as absent
    expect(row.population).toBe(0);

    const settings = { certClass: "b" as const, reproduceCommand: "pnpm rampscan scan <path>" };
    await writeProjectionPocketBase(projection, entries, pb, settings);
    expect(await readProjectionPocketBase(pb)).toEqual(projection);
  });

  it("ensureCollection grows an existing collection additively — a new spec field reaches old deployments", async () => {
    const pb = new PocketBaseAdmin(URL);
    await pb.auth(EMAIL, PASSWORD);
    const rules = { listRule: null, viewRule: null, createRule: null, updateRule: null, deleteRule: null };
    const reduced = {
      name: "sync_probe",
      type: "base" as const,
      fields: [{ name: "a", type: "text", required: true }],
      ...rules,
    };
    await pb.ensureCollection(reduced);
    // the spec grew a field (the I2c situation: registers gained pointers)
    await pb.ensureCollection({
      ...reduced,
      fields: [...reduced.fields, { name: "b", type: "text", required: false }],
    });
    await pb.create("sync_probe", { a: "x", b: "kept" });
    const rows = await pb.listAll("sync_probe");
    expect((rows[0] as any).b).toBe("kept"); // without the sync, PB silently drops unknown fields
  });

  it("ensureCollection relaxes a field the spec made optional — and only that direction (Q4.3)", async () => {
    const pb = new PocketBaseAdmin(URL);
    await pb.auth(EMAIL, PASSWORD);
    const rules = { listRule: null, viewRule: null, createRule: null, updateRule: null, deleteRule: null };
    const strict = {
      name: "relax_probe",
      type: "base" as const,
      fields: [
        { name: "keep_required", type: "text", required: true },
        { name: "was_required", type: "text", required: true },
      ],
      ...rules,
    };
    await pb.ensureCollection(strict);
    // the deployment exists with both fields required — an empty value is refused
    await expect(
      pb.create("relax_probe", { keep_required: "x", was_required: "" }),
    ).rejects.toThrow(/validation_required/);

    // the spec relaxes one of them, exactly as `vulnerabilities.commit_sha` was
    await pb.ensureCollection({
      ...strict,
      fields: [
        { name: "keep_required", type: "text", required: true },
        { name: "was_required", type: "text", required: false },
      ],
    });
    await pb.create("relax_probe", { keep_required: "x", was_required: "" });
    const rows = await pb.listAll("relax_probe");
    expect(rows).toHaveLength(1);
    expect((rows[0] as any).was_required).toBe("");
    // the field the spec still requires is untouched: relaxing is not a licence
    // to loosen everything, and tightening/retyping stays a hand-written migration
    await expect(
      pb.create("relax_probe", { keep_required: "", was_required: "" }),
    ).rejects.toThrow(/validation_required/);
  });

  it("projection collections reject writes that are not the projector's — rule 1 enforced", async () => {
    const anonymous = new PocketBaseAdmin(URL); // no auth() — not the projector
    await expect(
      anonymous.create("registers", { repo: "x", recipe_id: "y", state: "evidenced" }),
    ).rejects.toThrow(/HTTP 4/);
  });
});
