import { createHash } from "node:crypto";
import { readFile, readdir, stat } from "node:fs/promises";
import { basename, join, relative } from "node:path";
import { z } from "zod";
import { evaluateAssertions, toIngestedBundle } from "@rampscan/core";
import type { Digest, ObservationRows } from "@rampscan/core";
import { loadKsiCatalog } from "@rampscan/dataset";
import { bundleDigest, createLocalLedger } from "@rampscan/ledger";
import type {
  IngestManifest,
  IngestManifestEntry,
  IngestSubmission,
  Verdict,
} from "@rampscan/schema";
import {
  IngestManifest as IngestManifestSchema,
  IngestSubmission as IngestSubmissionSchema,
  methodId,
  submissionVerdict,
} from "@rampscan/schema";
import { createLocalSigner } from "@rampscan/signer";

// `rampscan ingest <path>` (SPEC §12.8, plan Q4.1): client-run signed results
// become ledger citizens. Two input shapes, one contract:
//
//   a FILE       one native IngestSubmission document
//   a DIRECTORY  an Evidence/<family>/<KSI-ID>/ tree plus the client-authored
//                ingest-manifest.json — the adapter that meets clients where
//                they already are (docs/RESEARCH-PARAMIFY-PILOT.md §3). The
//                adapter's OUTPUT is native submissions, so the digest
//                discipline is identical on both paths.
//
// Validate-then-append: every submission is checked against the contract and
// the pinned catalog BEFORE anything is signed — one bad submission refuses
// the whole batch, the artifact-judgment pattern applied to evidence. The
// no-execution boundary holds throughout: nothing here calls AWS; this
// command reads files the client produced and hands over.

export const INGEST_MANIFEST_FILENAME = "ingest-manifest.json";

/** the per-KSI result file's one structural obligation: a `results` array */
const TreeResultFile = z.looseObject({
  results: z.array(z.unknown()),
});

export interface IngestRecord {
  methodId: string;
  verdict: Verdict;
  digest: Digest;
}

/**
 * A tree entry the adapter did not turn into a submission (#147): the run
 * failed, so the account was never read and there is nothing to attest to —
 * named the way a skipped collector is, and absent from the ledger.
 */
export interface SkippedEntry {
  ksi: string;
  script: string;
  exit_code: number;
  reason: string;
}

export interface IngestOutcome {
  /** newly signed and appended */
  appended: IngestRecord[];
  /** already in the ledger byte-for-byte — nothing re-signed */
  unchanged: IngestRecord[];
  /** tree entries whose run failed — never a bundle under any verdict */
  skipped: SkippedEntry[];
}

export interface LoadedSubmissions {
  submissions: IngestSubmission[];
  skipped: SkippedEntry[];
}

export interface IngestOptions {
  /** a submission file, or an evidence-tree directory holding ingest-manifest.json */
  path: string;
  /** the offering/repo whose register this evidence joins — never guessed */
  repo: string;
  datasetDir: string;
  /** the canonical rules JSON, loaded beside the slices and cross-checked (R0.2) */
  rulesFile: string;
  datasetPin: string;
  ledgerDir: string;
  keysDir: string;
  log?: (line: string) => void;
}

async function sha256File(path: string): Promise<string> {
  return createHash("sha256").update(await readFile(path)).digest("hex");
}

/** every directory under `root` whose basename is exactly `name` */
async function findDirs(root: string, name: string): Promise<string[]> {
  const hits: string[] = [];
  async function walk(dir: string): Promise<void> {
    for (const entry of await readdir(dir, { withFileTypes: true })) {
      if (!entry.isDirectory()) continue;
      const full = join(dir, entry.name);
      if (entry.name === name) hits.push(full);
      await walk(full);
    }
  }
  await walk(root);
  return hits;
}

/** the failed-run reason, as the outcome and the log both spell it */
function failedRunReason(entry: IngestManifestEntry): string {
  return (
    `exit ${entry.exit_code} is a failed run — the script could not read the account, ` +
    `so there is nothing to attest to and nothing to violate; skipped, not signed`
  );
}

/**
 * The tree adapter: one manifest entry → one native submission. The tree
 * carries the outputs (the per-KSI JSON results file, the CSV beside it);
 * the manifest carries the facts the tree does not — signer identity,
 * evidence class, cadence, and per entry the script, exit code, timestamp
 * and assertions. The exit code is read for what the scripts mean by it
 * (#147, docs/RESEARCH-PARAMIFY-PILOT.md §8.1): 0 is a script that finished
 * reading, and the caller has already set aside anything else as a failed
 * run. What the rows SAY is decided here — the entry's structured assertions
 * evaluated by the appliance over `results`, with `population` the rows the
 * script emitted so a pass over nothing stays distinguishable from a pass
 * over 412 resources (N0). No assertions means no evaluation: the submission
 * carries none, and the verdict it computes to is `unevidenced`.
 */
async function entryToSubmission(
  treeDir: string,
  entry: IngestManifestEntry,
  manifest: IngestManifest,
): Promise<IngestSubmission> {
  const dirs = await findDirs(treeDir, entry.ksi);
  if (dirs.length === 0) {
    throw new Error(
      `manifest entry ${entry.ksi}: no directory named ${entry.ksi} under ${treeDir} — ` +
        `the tree convention is Evidence/<family>/<KSI-ID>/`,
    );
  }
  if (dirs.length > 1) {
    throw new Error(
      `manifest entry ${entry.ksi}: ${dirs.length} directories named ${entry.ksi} under ${treeDir} — ` +
        `the adapter refuses to guess which one the manifest means`,
    );
  }
  const dir = dirs[0]!;

  const resultPath = join(dir, `${entry.ksi}.json`);
  let resultRaw: string;
  try {
    resultRaw = await readFile(resultPath, "utf8");
  } catch {
    throw new Error(
      `manifest entry ${entry.ksi}: ${resultPath} is missing — a result without its ` +
        `results file has nothing to attest to`,
    );
  }
  const parsed = TreeResultFile.safeParse(JSON.parse(resultRaw));
  if (!parsed.success) {
    throw new Error(
      `manifest entry ${entry.ksi}: ${basename(resultPath)} does not carry a "results" array`,
    );
  }

  const artifacts: IngestSubmission["artifacts"] = [
    { name: relative(treeDir, resultPath), sha256: await sha256File(resultPath) },
  ];
  const csvPath = join(dir, `${entry.ksi}.csv`);
  try {
    await stat(csvPath);
    artifacts.push({ name: relative(treeDir, csvPath), sha256: await sha256File(csvPath) });
  } catch {
    // the CSV is the ecosystem's convention, not the contract's obligation —
    // absent means absent, never an invented digest
  }

  // the rows are the evaluator's domain. A row that is not an object has no
  // fields to read, so an assertion over it would pass or fail on a shape
  // accident; refused, like a results file with no `results` at all
  const declared = entry.assertions ?? [];
  const rows: ObservationRows = [];
  if (declared.length > 0) {
    parsed.data.results.forEach((row, i) => {
      if (row === null || typeof row !== "object" || Array.isArray(row)) {
        throw new Error(
          `manifest entry ${entry.ksi}: ${basename(resultPath)} results[${i}] is not an object, ` +
            `so the declared assertions have no fields to read`,
        );
      }
      rows.push(row as Record<string, unknown>);
    });
  }
  // `now` for max_age_days is the run's own clock: the assertion is about the
  // account as the script saw it, not as of the day someone ingested the tree
  const assertions = evaluateAssertions(declared, rows, new Date(entry.timestamp));

  return {
    _type: "https://rampscan.dev/ingest-submission/v1",
    recipe_id: entry.script,
    ksi: entry.ksi,
    evidence_class: entry.evidence_class ?? manifest.evidence_class,
    cadence: manifest.cadence,
    artifacts,
    assertions,
    timestamp: entry.timestamp,
    signer_identity: manifest.signer_identity,
    reproduce: `${entry.script} <profile> <region> <output_dir> <output_csv>`,
  };
}

/** parse the input into native submissions — the two shapes, one output */
export async function loadSubmissions(path: string): Promise<LoadedSubmissions> {
  const info = await stat(path);
  if (info.isFile()) {
    const raw = JSON.parse(await readFile(path, "utf8")) as unknown;
    try {
      return { submissions: [IngestSubmissionSchema.parse(raw)], skipped: [] };
    } catch (cause) {
      throw new Error(`${path} does not match the ingestion contract (SPEC §12.8)`, { cause });
    }
  }

  const manifestPath = join(path, INGEST_MANIFEST_FILENAME);
  let manifestRaw: string;
  try {
    manifestRaw = await readFile(manifestPath, "utf8");
  } catch {
    throw new Error(
      `${path} is a directory but holds no ${INGEST_MANIFEST_FILENAME} — the tree adapter ` +
        `needs the client-authored manifest (signer identity, evidence class, cadence, ` +
        `per-entry script/exit code/timestamp); a single submission is ingested as a file`,
    );
  }
  let manifest;
  try {
    manifest = IngestManifestSchema.parse(JSON.parse(manifestRaw));
  } catch (cause) {
    throw new Error(`${manifestPath} does not match the ingest manifest contract (SPEC §12.8)`, {
      cause,
    });
  }

  const submissions: IngestSubmission[] = [];
  const skipped: SkippedEntry[] = [];
  for (const entry of manifest.entries) {
    // a failed run is set aside BEFORE the tree is read for it: its results
    // file may be partial or missing, and either way the account was not
    // seen — nothing here is evidence, and nothing here is a violation
    if (entry.exit_code !== 0) {
      skipped.push({
        ksi: entry.ksi,
        script: entry.script,
        exit_code: entry.exit_code,
        reason: failedRunReason(entry),
      });
      continue;
    }
    submissions.push(await entryToSubmission(path, entry, manifest));
  }
  return { submissions, skipped };
}

export async function ingest(options: IngestOptions): Promise<IngestOutcome> {
  const log = options.log ?? (() => {});
  const { submissions, skipped } = await loadSubmissions(options.path);
  for (const s of skipped) log(`${s.script}#${s.ksi} → skipped: ${s.reason}`);

  // Refusal before append: unknown KSIs and in-batch duplicates are collected
  // and reported TOGETHER, and nothing is signed while any stand — a batch
  // that half-landed is a ledger that says something no one decided.
  const catalog = await loadKsiCatalog({
    derivedDir: options.datasetDir,
    rulesFile: options.rulesFile,
    pin: options.datasetPin,
  });
  const known = new Set(catalog.ksis.map((k) => k.id));
  const problems: string[] = [];
  const seen = new Set<string>();
  for (const submission of submissions) {
    if (!known.has(submission.ksi)) {
      problems.push(
        `${submission.recipe_id}: KSI "${submission.ksi}" does not resolve in dataset ${catalog.datasetVersion}`,
      );
    }
    const key = `${submission.recipe_id}#${submission.ksi}`;
    if (seen.has(key)) {
      problems.push(
        `duplicate (recipe, KSI) in one batch: ${key} — two results for one method in a single ` +
          `handoff is a contradiction, not a refresh`,
      );
    }
    seen.add(key);
  }
  if (problems.length > 0) {
    throw new Error(
      `ingestion refused — nothing appended:\n${problems.map((p) => `  ${p}`).join("\n")}`,
    );
  }

  const ledger = createLocalLedger(options.ledgerDir);
  const signer = createLocalSigner(options.keysDir, { log });
  const appended: IngestRecord[] = [];
  const unchanged: IngestRecord[] = [];
  for (const submission of submissions) {
    const bundle = toIngestedBundle(submission, {
      repo: options.repo,
      datasetVersion: catalog.datasetVersion,
    });
    const digest = bundleDigest(bundle);
    const record: IngestRecord = {
      methodId: methodId("aws-ingested", submission.recipe_id, submission.ksi),
      verdict: submissionVerdict(submission),
      digest,
    };
    if ((await ledger.get(digest)) !== undefined) {
      // byte-for-byte the same submission — the original signature stands
      unchanged.push(record);
      log(`${record.methodId} → ${record.verdict} (already in the ledger, unchanged)`);
      continue;
    }
    const envelope = await signer.sign(bundle);
    await ledger.append(bundle, envelope);
    appended.push(record);
    log(`${record.methodId} → ${record.verdict} (${digest.slice(0, 12)}…)`);
  }
  log(
    `ingest: ${appended.length} bundle(s) appended, ${unchanged.length} unchanged, ` +
      `${skipped.length} skipped (failed runs) — no AWS call was executed by this appliance`,
  );
  return { appended, unchanged, skipped };
}
