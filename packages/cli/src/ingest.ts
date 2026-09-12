import { createHash } from "node:crypto";
import { readFile, readdir, stat } from "node:fs/promises";
import { basename, join, relative } from "node:path";
import { z } from "zod";
import { toIngestedBundle } from "@rampscan/core";
import type { Digest } from "@rampscan/core";
import { loadKsiCatalogFromSlices } from "@rampscan/dataset";
import { bundleDigest, createLocalLedger } from "@rampscan/ledger";
import type { IngestManifest, IngestManifestEntry, IngestSubmission } from "@rampscan/schema";
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
  verdict: "evidenced" | "violated";
  digest: Digest;
}

export interface IngestOutcome {
  /** newly signed and appended */
  appended: IngestRecord[];
  /** already in the ledger byte-for-byte — nothing re-signed */
  unchanged: IngestRecord[];
}

export interface IngestOptions {
  /** a submission file, or an evidence-tree directory holding ingest-manifest.json */
  path: string;
  /** the offering/repo whose register this evidence joins — never guessed */
  repo: string;
  datasetDir: string;
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

/**
 * The tree adapter: one manifest entry → one native submission. The tree
 * carries the outputs (the per-KSI JSON results file, the CSV beside it);
 * the manifest carries the facts the tree does not — signer identity,
 * evidence class, cadence, and per entry the script, exit code, and
 * timestamp from the orchestrator's own run log. The exit code becomes the
 * single assertion (their orchestration's own convention: exit code IS the
 * validation outcome), with `population` set to the result rows the script
 * emitted so a pass over nothing stays distinguishable from a pass over 412
 * resources (N0).
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

  return {
    _type: "https://rampscan.dev/ingest-submission/v1",
    recipe_id: entry.script,
    ksi: entry.ksi,
    evidence_class: entry.evidence_class ?? manifest.evidence_class,
    cadence: manifest.cadence,
    artifacts,
    assertions: [
      {
        description: `${entry.script} validation (exit code)`,
        passed: entry.exit_code === 0,
        detail: `exit ${entry.exit_code}`,
        population: parsed.data.results.length,
      },
    ],
    timestamp: entry.timestamp,
    signer_identity: manifest.signer_identity,
    reproduce: `${entry.script} <profile> <region> <output_dir> <output_csv>`,
  };
}

/** parse the input into native submissions — the two shapes, one output */
export async function loadSubmissions(path: string): Promise<IngestSubmission[]> {
  const info = await stat(path);
  if (info.isFile()) {
    const raw = JSON.parse(await readFile(path, "utf8")) as unknown;
    try {
      return [IngestSubmissionSchema.parse(raw)];
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
  for (const entry of manifest.entries) {
    submissions.push(await entryToSubmission(path, entry, manifest));
  }
  return submissions;
}

export async function ingest(options: IngestOptions): Promise<IngestOutcome> {
  const log = options.log ?? (() => {});
  const submissions = await loadSubmissions(options.path);

  // Refusal before append: unknown KSIs and in-batch duplicates are collected
  // and reported TOGETHER, and nothing is signed while any stand — a batch
  // that half-landed is a ledger that says something no one decided.
  const catalog = await loadKsiCatalogFromSlices(options.datasetDir, options.datasetPin);
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
    `ingest: ${appended.length} bundle(s) appended, ${unchanged.length} unchanged — ` +
      `no AWS call was executed by this appliance`,
  );
  return { appended, unchanged };
}
