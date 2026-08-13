import { randomBytes } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import {
  buildScanResult,
  createLocalRepoSource,
  createLocalRunner,
  sameEvidence,
  toEvidenceBundle,
} from "@rampscan/core";
import type { Collector, Digest, LedgerEntry, RunResult } from "@rampscan/core";
import { loadLocalDataset } from "@rampscan/dataset";
import { createLocalLedger } from "@rampscan/ledger";
import { createLocalSigner } from "@rampscan/signer";
import { ScanResult, isEvidenceBundle } from "@rampscan/schema";
import type { PipelineRecipe } from "@rampscan/schema";
import { loadRecipes, validateRecipeIds } from "./recipes.js";

// `rampscan scan <path>` orchestration (plan C5): pin workspace → load pinned
// dataset + recipes → run collectors in order → join → scan-result.json.
// As of M2 the output stops being a JSON file and becomes a record: each
// evidenced/violated row is signed and appended to the ledger — unless the
// identical evidence is already there, in which case it survives with its
// original signature (that survival is what makes anchor death meaningful).

export interface ScanOptions {
  /** path to the checkout to scan */
  path: string;
  /** output dir; artifacts/ and scan-result.json land here */
  outDir: string;
  datasetDir: string;
  datasetPin: string;
  recipesDir: string;
  collectors: Collector[];
  /** append-only evidence ledger dir; omit to skip recording (M1 behavior) */
  ledgerDir?: string;
  /** signing keypair dir; required when ledgerDir is set */
  keysDir?: string;
  /** the run's single clock — defaults to now */
  now?: Date;
  log?: (line: string) => void;
}

export interface EvidenceRecord {
  recipeId: string;
  digest: Digest;
}

export interface ScanOutcome {
  result: ScanResult;
  resultPath: string;
  /** ledger writes, when a ledger was configured */
  evidence?: {
    appended: EvidenceRecord[];
    /** already in the ledger with identical evidence — original signature stands */
    survived: EvidenceRecord[];
  };
}

function latestEntry(entries: LedgerEntry[]): LedgerEntry | undefined {
  return [...entries].sort((a, b) => {
    const t = a.bundle.predicate.timestamp.localeCompare(b.bundle.predicate.timestamp);
    return t !== 0 ? t : a.appendedAt.localeCompare(b.appendedAt);
  }).at(-1);
}

export async function scan(options: ScanOptions): Promise<ScanOutcome> {
  const log = options.log ?? (() => {});
  const now = options.now ?? new Date();
  const runId = `run-${now.toISOString().replaceAll(/[:.]/g, "-")}-${randomBytes(3).toString("hex")}`;

  const workspace = await createLocalRepoSource().fetch({ repo: options.path });
  log(`workspace ${workspace.root} @ ${workspace.commit.slice(0, 12)}`);

  const dataset = await loadLocalDataset(options.datasetDir, options.datasetPin);
  const recipes = await loadRecipes(options.recipesDir);
  const problems = validateRecipeIds(recipes, dataset);
  if (problems.length > 0) {
    throw new Error(`recipe validation against dataset ${dataset.version()} failed:\n  ${problems.join("\n  ")}`);
  }
  log(`${recipes.length} recipes validated against dataset ${dataset.version()}`);

  const outDir = resolve(options.outDir);
  const artifactDir = join(outDir, "artifacts");
  await mkdir(artifactDir, { recursive: true });

  const inputs = new Map<string, string>();
  const runner = createLocalRunner({
    collectors: options.collectors,
    artifactDir,
    inputs,
    runId,
  });

  const runs = new Map<string, RunResult>();
  for (const collector of options.collectors) {
    const name = collector.manifest.name;
    log(`collector ${name} …`);
    try {
      const result = await runner.run(collector.manifest, workspace);
      runs.set(name, result);
      log(
        result.skipped
          ? `collector ${name} skipped: ${result.skipped.reason}`
          : `collector ${name} done (${result.findings.length} findings, tool ${result.toolVersion})`,
      );
    } catch (error) {
      // a crashed wrapper must be visible, not fatal to the whole run
      const reason = `collector crashed: ${error instanceof Error ? error.message : String(error)}`;
      runs.set(name, {
        findings: [],
        artifacts: [],
        observations: {},
        anchors: {},
        toolVersion: "error",
        exitCode: -1,
        skipped: { reason },
      });
      log(`collector ${name} CRASHED — recorded as skipped: ${reason}`);
    }
  }

  const result = ScanResult.parse(
    buildScanResult({
      recipes,
      runs,
      workspace,
      datasetVersion: dataset.version(),
      runId,
      now,
    }),
  );

  const resultPath = join(outDir, "scan-result.json");
  await writeFile(resultPath, JSON.stringify(result, null, 2) + "\n");

  if (options.ledgerDir === undefined) return { result, resultPath };
  if (options.keysDir === undefined) {
    throw new Error("ledgerDir is set but keysDir is not — evidence is only recorded signed");
  }

  const ledger = createLocalLedger(options.ledgerDir);
  const signer = createLocalSigner(options.keysDir, { log });
  const recipeById = new Map<string, PipelineRecipe>(recipes.map((r) => [r.id, r]));
  const appended: EvidenceRecord[] = [];
  const survived: EvidenceRecord[] = [];

  for (const row of result.recipes) {
    const recipe = recipeById.get(row.recipe_id)!;
    const bundle = toEvidenceBundle(recipe, row, {
      repo: workspace.repo,
      commit: workspace.commit,
      datasetVersion: dataset.version(),
      toolVersion: runs.get(row.collector)?.toolVersion ?? "unknown",
      runId,
      timestamp: now.toISOString(),
    });
    if (!bundle) {
      if (row.verdict !== "unevidenced") {
        log(`recipe ${row.recipe_id}: ${row.verdict} but nothing to attest to — NOT recorded`);
      }
      continue;
    }

    const prior = latestEntry(
      await ledger.list({ recipeId: row.recipe_id, repo: workspace.repo }),
    );
    if (prior && isEvidenceBundle(prior.bundle) && sameEvidence(prior.bundle, bundle)) {
      survived.push({ recipeId: row.recipe_id, digest: prior.digest });
      continue;
    }
    const envelope = await signer.sign(bundle);
    const digest = await ledger.append(bundle, envelope);
    appended.push({ recipeId: row.recipe_id, digest });
  }

  log(
    `ledger: ${appended.length} bundle(s) appended, ${survived.length} survived unchanged, ` +
      `${result.summary.unevidenced} recipe(s) unevidenced (never recorded)`,
  );
  return { result, resultPath, evidence: { appended, survived } };
}
