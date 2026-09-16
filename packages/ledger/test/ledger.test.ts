import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import type { EvidenceBundle } from "@rampscan/schema";
import { bundleDigest, createLocalLedger } from "../src/index.js";

// The append-only property is enforced by the adapter, not by discipline —
// so the tests include one that tries to cheat and fails (plan M2 exit).

function makeBundle(overrides: { recipe?: string; verdict?: "evidenced" | "violated"; hash?: string; timestamp?: string } = {}): EvidenceBundle {
  const hash = overrides.hash ?? "a".repeat(64);
  return {
    _type: "https://in-toto.io/Statement/v1",
    subject: [{ name: "package.json", digest: { sha256: hash } }],
    predicateType: "https://rampscan.dev/evidence/v1",
    predicate: {
      recipe_id: overrides.recipe ?? "lockfile-pinned-deps",
      ksi_ids: ["KSI-SCR-MIT"],
      control_ids: ["si-7.1"],
      verdict: overrides.verdict ?? "evidenced",
      repo: "fixtures/app",
      commit: "c".repeat(40),
      anchor_paths: [{ path: "package.json", contentHash: hash }],
      dataset_version: "2026.07.14.01",
      tool_versions: { "repo-facts": "0.1.0" },
      assertions: [{ description: "lockfile present", passed: true }],
      cadence: "continuous",
      run_id: "run-test",
      timestamp: overrides.timestamp ?? "2026-08-13T00:00:00.000Z",
    },
  };
}

async function tempLedgerDir(): Promise<string> {
  return mkdtemp(join(tmpdir(), "rampscan-ledger-"));
}

describe("local ledger", () => {
  it("stores scoping events beside evidence — one ledger, two statement kinds (M3)", async () => {
    const ledger = createLocalLedger(await tempLedgerDir());
    const scoping = {
      _type: "https://in-toto.io/Statement/v1" as const,
      subject: [{ name: "justification.txt", digest: { sha256: "b".repeat(64) } }],
      predicateType: "https://rampscan.dev/scoping/v1" as const,
      predicate: {
        action: "notApplicable" as const,
        recipe_id: "container-runs-nonroot",
        ksi_ids: ["KSI-CNA-CIC"],
        control_ids: ["cm-2.2"],
        repo: "fixtures/app",
        justification: "no container ships from this repo",
        proposed_by: "viewer@rampscan.local (pb:u1)",
        approved_by: "approver@rampscan.local (pb:u2)",
        dataset_version: "2026.07.14.01",
        timestamp: "2026-08-13T01:00:00.000Z",
      },
    };
    await ledger.append(makeBundle());
    const digest = await ledger.append(scoping);
    const entry = await ledger.get(digest);
    expect(entry!.bundle).toEqual(scoping);
    // the index records the action as the verdict column, so filters stay uniform
    const scoped = await ledger.list({ verdict: "notApplicable" as never });
    expect(scoped.map((e) => e.digest)).toEqual([digest]);
    expect(await ledger.list()).toHaveLength(2);
  });

  it("append → get round-trips the bundle and its envelope, keyed by content digest", async () => {
    const ledger = createLocalLedger(await tempLedgerDir());
    const bundle = makeBundle();
    const envelope = { payload: "cGF5bG9hZA==", payloadType: "application/vnd.in-toto+json", signatures: [{ keyid: "k", sig: "s" }] };
    const digest = await ledger.append(bundle, envelope);
    expect(digest).toBe(bundleDigest(bundle));

    const entry = await ledger.get(digest);
    expect(entry).toBeDefined();
    expect(entry!.bundle).toEqual(bundle);
    expect(entry!.envelope).toEqual(envelope);
    expect(Date.parse(entry!.appendedAt)).not.toBeNaN();
  });

  it("appending identical content is idempotent — same digest, no rewrite", async () => {
    const dir = await tempLedgerDir();
    const ledger = createLocalLedger(dir);
    const bundle = makeBundle();
    const d1 = await ledger.append(bundle);
    const d2 = await ledger.append(bundle);
    expect(d2).toBe(d1);
    const index = await readFile(join(dir, "index.jsonl"), "utf8");
    expect(index.trim().split("\n")).toHaveLength(1); // no duplicate index rows
  });

  it("different content gets a different address — history is never overwritten", async () => {
    const ledger = createLocalLedger(await tempLedgerDir());
    const v1 = makeBundle({ hash: "a".repeat(64) });
    const v2 = makeBundle({ hash: "b".repeat(64) });
    const d1 = await ledger.append(v1);
    const d2 = await ledger.append(v2);
    expect(d2).not.toBe(d1);
    expect((await ledger.get(d1))!.bundle).toEqual(v1); // the original is intact
  });

  it("cheating is detected: an object file tampered on disk fails get()", async () => {
    const dir = await tempLedgerDir();
    const ledger = createLocalLedger(dir);
    const digest = await ledger.append(makeBundle());

    const objectPath = join(dir, "objects", `${digest}.json`);
    // the adapter chmods objects read-only; a direct overwrite must fail …
    await expect(writeFile(objectPath, "{}")).rejects.toThrow();
    // … and even a forced rewrite (chmod back, as an attacker with fs access
    // could) is caught, because get() re-hashes what it reads
    const { chmod } = await import("node:fs/promises");
    await chmod(objectPath, 0o644);
    await writeFile(objectPath, JSON.stringify(makeBundle({ verdict: "violated" })));
    await expect(ledger.get(digest)).rejects.toThrow(/integrity violation/);
  });

  // #142 — list() reads each object once per process. The ledger is
  // append-only, so a verified object stays true for the life of the process;
  // what can change is the index's TAIL, and only by growing. The watermark
  // is the byte count consumed, and a shorter index is a rewrite.
  describe("list() reads the index past its watermark and each object once (#142)", () => {
    it("sees an append made by another instance — the tail past the watermark", async () => {
      const dir = await tempLedgerDir();
      const reader = createLocalLedger(dir);
      const writer = createLocalLedger(dir);
      await writer.append(makeBundle({ hash: "a".repeat(64) }));
      expect(await reader.list()).toHaveLength(1);
      const d2 = await writer.append(makeBundle({ hash: "b".repeat(64) }));
      const after = await reader.list();
      expect(after.map((e) => e.digest)).toContain(d2);
      expect(after).toHaveLength(2);
    });

    it("the same instance sees its own append, and the earlier entry is the same object", async () => {
      const ledger = createLocalLedger(await tempLedgerDir());
      const d1 = await ledger.append(makeBundle({ hash: "a".repeat(64) }));
      const [first] = await ledger.list();
      await ledger.append(makeBundle({ hash: "b".repeat(64) }));
      const again = await ledger.list();
      expect(again).toHaveLength(2);
      expect(again.find((e) => e.digest === d1)).toBe(first); // verified once, served again
    });

    it("an object tampered before the first read is caught by list(), not only get()", async () => {
      const dir = await tempLedgerDir();
      const ledger = createLocalLedger(dir);
      const digest = await ledger.append(makeBundle());
      const objectPath = join(dir, "objects", `${digest}.json`);
      const { chmod } = await import("node:fs/promises");
      await chmod(objectPath, 0o644);
      await writeFile(objectPath, JSON.stringify(makeBundle({ verdict: "violated" })));
      await expect(ledger.list()).rejects.toThrow(/integrity violation/);
    });

    it("an index that shrank is refused as a rewrite, never served as a shorter history", async () => {
      const dir = await tempLedgerDir();
      const ledger = createLocalLedger(dir);
      await ledger.append(makeBundle({ hash: "a".repeat(64) }));
      await ledger.append(makeBundle({ hash: "b".repeat(64) }));
      expect(await ledger.list()).toHaveLength(2);
      const indexPath = join(dir, "index.jsonl");
      const [firstLine] = (await readFile(indexPath, "utf8")).split("\n");
      await writeFile(indexPath, firstLine + "\n");
      await expect(ledger.list()).rejects.toThrow(/integrity violation.*index/);
    });

    it("a trailing line still being written is held until its newline arrives", async () => {
      const dir = await tempLedgerDir();
      const ledger = createLocalLedger(dir);
      const d1 = await ledger.append(makeBundle({ hash: "a".repeat(64) }));
      expect(await ledger.list()).toHaveLength(1);
      // a second append, torn: the object is on disk, the index row has no newline yet
      const writer = createLocalLedger(dir);
      const d2 = await writer.append(makeBundle({ hash: "b".repeat(64) }));
      const indexPath = join(dir, "index.jsonl");
      const full = await readFile(indexPath, "utf8");
      const lines = full.split("\n").filter((l) => l.length > 0);
      const torn = lines[1]!.slice(0, 40);
      await writeFile(indexPath, lines[0] + "\n" + torn);
      expect((await ledger.list()).map((e) => e.digest)).toEqual([d1]);
      // the rest of the line lands; the row is now whole and served
      const { appendFile } = await import("node:fs/promises");
      await appendFile(indexPath, lines[1]!.slice(40) + "\n");
      expect((await ledger.list()).map((e) => e.digest)).toEqual([d1, d2]);
    });

    it("get() still reads and re-hashes from disk every time — the verifying read", async () => {
      const dir = await tempLedgerDir();
      const ledger = createLocalLedger(dir);
      const digest = await ledger.append(makeBundle());
      expect(await ledger.list()).toHaveLength(1); // loaded and cached for list()
      const objectPath = join(dir, "objects", `${digest}.json`);
      const { chmod } = await import("node:fs/promises");
      await chmod(objectPath, 0o644);
      await writeFile(objectPath, JSON.stringify(makeBundle({ verdict: "violated" })));
      await expect(ledger.get(digest)).rejects.toThrow(/integrity violation/);
    });
  });

  it("list() filters by recipe, repo, verdict, and since", async () => {
    const ledger = createLocalLedger(await tempLedgerDir());
    await ledger.append(makeBundle({ recipe: "r-one", timestamp: "2026-08-01T00:00:00.000Z" }));
    await ledger.append(makeBundle({ recipe: "r-two", verdict: "violated", hash: "d".repeat(64), timestamp: "2026-08-10T00:00:00.000Z" }));

    expect(await ledger.list({ recipeId: "r-one" })).toHaveLength(1);
    expect(await ledger.list({ verdict: "violated" })).toHaveLength(1);
    expect(await ledger.list({ since: "2026-08-05T00:00:00.000Z" })).toHaveLength(1);
    expect(await ledger.list({ repo: "someone-else/repo" })).toHaveLength(0);
    expect(await ledger.list()).toHaveLength(2);
  });
});
