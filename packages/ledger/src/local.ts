import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import {
  appendFile,
  chmod,
  mkdir,
  open,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";
import { setImmediate as yieldToLoop } from "node:timers/promises";
import {
  LedgerStatement,
  canonicalJson,
  isArtifact,
  isArtifactDeclarations,
  isArtifactJudgment,
  isAttestation,
  isEvidenceBundle,
  isScanRun,
  isScopingEvent,
} from "@rampscan/schema";
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
// only write to the index is an append, and every read from disk re-hashes
// what it reads so out-of-band tampering is detected, never served.
//
// Reading is the cost (#142). The fold is a function of the whole ledger, and
// the whole ledger is two small files per statement: measured at 60k
// statements, list() took 14.6 s of which the fold took 0.7 s, and 3.1 s of
// every 4.1 s was the two file opens — the threadpool hop that a parallel
// readFile pays per tiny file (8.6× the cost of a synchronous read of the
// same bytes). So an instance reads each object ONCE, synchronously,
// verifies it, and keeps it: the ledger is append-only, so a verified object
// stays true for as long as the process does. What can change underneath is
// the index, and only by growing — the watermark is the byte count consumed,
// list() reads the tail past it, and an index shorter than the watermark is
// a rewrite, refused. `get()` stays the verifying read: disk, every time.

export function bundleDigest(bundle: LedgerStatement): Digest {
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

/** Objects verified between two yields to the event loop — a long first read
 *  under `serve` must not hold the request loop for its whole length. */
const LOADS_PER_YIELD = 512;

export function createLocalLedger(dir: string): LedgerStore {
  const objectsDir = join(dir, "objects");
  const indexPath = join(dir, "index.jsonl");

  // The index as consumed so far: `rows` holds every whole line, `consumed`
  // the bytes those lines (and `partial`) span, `partial` a trailing line an
  // appender has begun and not yet ended with its newline — held, not parsed,
  // until the rest of it lands.
  const rows: IndexRow[] = [];
  let consumed = 0;
  let partial: Buffer = Buffer.alloc(0);
  // Every statement list() has verified from disk in this process, by digest.
  const loaded = new Map<Digest, LedgerEntry>();

  async function readIndex(): Promise<IndexRow[]> {
    let handle: Awaited<ReturnType<typeof open>>;
    try {
      handle = await open(indexPath, "r");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      if (consumed > 0) {
        throw new Error(
          `ledger integrity violation: index.jsonl is gone after ${consumed} bytes of it were read — the index was removed out of band`,
        );
      }
      return rows;
    }
    try {
      const { size } = await handle.stat();
      if (size < consumed) {
        throw new Error(
          `ledger integrity violation: index.jsonl shrank from ${consumed} to ${size} bytes — the index was rewritten out of band`,
        );
      }
      if (size === consumed) return rows;
      const tail = Buffer.alloc(size - consumed);
      await handle.read(tail, 0, tail.length, consumed);
      consumed = size;
      const bytes = Buffer.concat([partial, tail]);
      // split on the newline byte, never inside a character: 0x0A cannot occur
      // within a multi-byte UTF-8 sequence, so a torn read is torn at a byte
      // boundary the decoder below never sees
      const lastNewline = bytes.lastIndexOf(0x0a);
      partial = lastNewline === -1 ? bytes : bytes.subarray(lastNewline + 1);
      if (lastNewline === -1) return rows;
      for (const line of bytes.subarray(0, lastNewline).toString("utf8").split("\n")) {
        if (line.trim().length === 0) continue;
        rows.push(JSON.parse(line) as IndexRow);
      }
      return rows;
    } finally {
      await handle.close();
    }
  }

  // One statement and its envelope from disk, re-hashed: the only way bytes
  // enter this process, for get() and for the first read of list().
  function readEntry(row: IndexRow): LedgerEntry {
    const bytes = readFileSync(join(objectsDir, `${row.digest}.json`), "utf8");
    const actual = createHash("sha256").update(bytes).digest("hex");
    if (actual !== row.digest) {
      throw new Error(
        `ledger integrity violation: object ${row.digest} hashes to ${actual} — the file was modified out of band`,
      );
    }
    const entry: LedgerEntry = {
      digest: row.digest,
      bundle: LedgerStatement.parse(JSON.parse(bytes)),
      appendedAt: row.appended_at,
    };
    try {
      entry.envelope = JSON.parse(
        readFileSync(join(objectsDir, `${row.digest}.envelope.json`), "utf8"),
      ) as SignedEnvelope;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
    return entry;
  }

  return {
    async append(bundle, envelope): Promise<Digest> {
      const parsed = LedgerStatement.parse(bundle);
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

      // Each statement kind fills the index slots it honestly has: a scoping
      // event carries no commit anchor and no verdict (its action goes in the
      // verdict slot so list() filters keep working uniformly), an artifact
      // judgment (Q3.3) and an attestation (Q4.2) likewise name no recipe and
      // no commit — their actions ride the verdict slot the same way — and a
      // run record (J1) is about a whole scan rather than one recipe, so its
      // recipe_id and verdict stay EMPTY rather than being invented. That is
      // what keeps `list({ recipeId })` from ever handing a run record to the
      // evidence chain that asked for a recipe's bundles.
      //
      // An artifact (R1.1) names no recipe and has no action, so both stay
      // empty; its commit slot is filled ONLY from an authored body's anchor,
      // where a commit is a fact the statement already carries. A computed,
      // attested or assessed body has no anchor and gets no commit — §13.2's
      // "absent means absent" reaches the index too, because a commit invented
      // here is a commit `list({ commit })` would hand back as evidence that
      // this body describes that tree. A declaration observation (R1.4) DOES
      // fill it: it is a claim about a tree, made at the commit it names.
      const row: IndexRow = {
        digest,
        appended_at: new Date().toISOString(),
        recipe_id:
          isEvidenceBundle(parsed) || isScopingEvent(parsed) ? parsed.predicate.recipe_id : "",
        repo: parsed.predicate.repo,
        commit: isEvidenceBundle(parsed) || isScanRun(parsed) || isArtifactDeclarations(parsed)
          ? parsed.predicate.commit
          : isArtifact(parsed)
            ? (parsed.predicate.anchor?.commit ?? "")
            : "",
        verdict: isEvidenceBundle(parsed)
          ? parsed.predicate.verdict
          : isScopingEvent(parsed) || isArtifactJudgment(parsed) || isAttestation(parsed)
            ? parsed.predicate.action
            : "",
        timestamp: parsed.predicate.timestamp,
      };
      await appendFile(indexPath, JSON.stringify(row) + "\n");
      return digest;
    },

    async get(digest): Promise<LedgerEntry | undefined> {
      const index = await readIndex();
      const row = index.find((r) => r.digest === digest);
      if (!row) return undefined;
      // never from `loaded`: `verify` and the tamper tests read this path, and
      // what they want to know is what is on disk NOW
      return readEntry(row);
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
      const entries: LedgerEntry[] = [];
      let reads = 0;
      for (const row of matches) {
        let entry = loaded.get(row.digest);
        if (entry === undefined) {
          entry = readEntry(row);
          loaded.set(row.digest, entry);
          if (++reads % LOADS_PER_YIELD === 0) await yieldToLoop();
        }
        entries.push(entry);
      }
      return entries;
    },
  };
}
