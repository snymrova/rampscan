import { createHash } from "node:crypto";
import {
  appendFile,
  chmod,
  mkdir,
  readFile,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";
import { EvidenceBundle, canonicalJson } from "@rampscan/schema";
import type {
  Digest,
  LedgerEntry,
  LedgerQuery,
  LedgerStore,
  SignedEnvelope,
} from "@rampscan/core";

// Local LedgerStore (plan M2): a content-addressed append-only directory.
//
//   <dir>/objects/<sha256>.json           canonical statement bytes — the
//                                         file's own hash IS its address
//   <dir>/objects/<sha256>.envelope.json  the DSSE envelope over it
//   <dir>/index.jsonl                     one line per append, cheap fields
//                                         only, for list() without loading
//                                         every object
//
// No deletes, no rewrites — enforced by the adapter, not by discipline:
// objects are written with the exclusive flag then chmod'd read-only, the
// only write to the index is an append, and get() re-hashes what it reads so
// out-of-band tampering is detected, never served.

export function bundleDigest(bundle: EvidenceBundle): Digest {
  return createHash("sha256").update(canonicalJson(bundle)).digest("hex");
}

interface IndexRow {
  digest: Digest;
  appended_at: string;
  recipe_id: string;
  repo: string;
  commit: string;
  verdict: string;
  timestamp: string;
}

export function createLocalLedger(dir: string): LedgerStore {
  const objectsDir = join(dir, "objects");
  const indexPath = join(dir, "index.jsonl");

  async function readIndex(): Promise<IndexRow[]> {
    let raw: string;
    try {
      raw = await readFile(indexPath, "utf8");
    } catch {
      return [];
    }
    return raw
      .split("\n")
      .filter((line) => line.trim().length > 0)
      .map((line) => JSON.parse(line) as IndexRow);
  }

  async function loadBundle(digest: Digest): Promise<EvidenceBundle> {
    const path = join(objectsDir, `${digest}.json`);
    const bytes = await readFile(path, "utf8");
    const actual = createHash("sha256").update(bytes).digest("hex");
    if (actual !== digest) {
      throw new Error(
        `ledger integrity violation: object ${digest} hashes to ${actual} — the file was modified out of band`,
      );
    }
    return EvidenceBundle.parse(JSON.parse(bytes));
  }

  async function loadEnvelope(digest: Digest): Promise<SignedEnvelope | undefined> {
    try {
      return JSON.parse(
        await readFile(join(objectsDir, `${digest}.envelope.json`), "utf8"),
      ) as SignedEnvelope;
    } catch {
      return undefined;
    }
  }

  return {
    async append(bundle, envelope): Promise<Digest> {
      const parsed = EvidenceBundle.parse(bundle);
      const bytes = canonicalJson(parsed);
      const digest = createHash("sha256").update(bytes).digest("hex");
      await mkdir(objectsDir, { recursive: true });

      const objectPath = join(objectsDir, `${digest}.json`);
      try {
        await writeFile(objectPath, bytes, { flag: "wx" });
        await chmod(objectPath, 0o444);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
        // same content, same address — idempotent, and nothing was rewritten
        return digest;
      }

      if (envelope) {
        const envPath = join(objectsDir, `${digest}.envelope.json`);
        await writeFile(envPath, JSON.stringify(envelope, null, 2), { flag: "wx" });
        await chmod(envPath, 0o444);
      }

      const row: IndexRow = {
        digest,
        appended_at: new Date().toISOString(),
        recipe_id: parsed.predicate.recipe_id,
        repo: parsed.predicate.repo,
        commit: parsed.predicate.commit,
        verdict: parsed.predicate.verdict,
        timestamp: parsed.predicate.timestamp,
      };
      await appendFile(indexPath, JSON.stringify(row) + "\n");
      return digest;
    },

    async get(digest): Promise<LedgerEntry | undefined> {
      const index = await readIndex();
      const row = index.find((r) => r.digest === digest);
      if (!row) return undefined;
      const bundle = await loadBundle(digest);
      const envelope = await loadEnvelope(digest);
      const entry: LedgerEntry = { digest, bundle, appendedAt: row.appended_at };
      if (envelope) entry.envelope = envelope;
      return entry;
    },

    async list(query?: LedgerQuery): Promise<LedgerEntry[]> {
      const index = await readIndex();
      const matches = index.filter(
        (r) =>
          (query?.recipeId === undefined || r.recipe_id === query.recipeId) &&
          (query?.repo === undefined || r.repo === query.repo) &&
          (query?.commit === undefined || r.commit === query.commit) &&
          (query?.verdict === undefined || r.verdict === query.verdict) &&
          (query?.since === undefined || r.timestamp >= query.since),
      );
      return Promise.all(
        matches.map(async (r) => {
          const bundle = await loadBundle(r.digest);
          const envelope = await loadEnvelope(r.digest);
          const entry: LedgerEntry = {
            digest: r.digest,
            bundle,
            appendedAt: r.appended_at,
          };
          if (envelope) entry.envelope = envelope;
          return entry;
        }),
      );
    },
  };
}
