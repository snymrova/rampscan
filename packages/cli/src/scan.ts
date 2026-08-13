import { createHash, randomBytes } from "node:crypto";
import { copyFile, mkdir, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { OPENVEX_ARTIFACT, loadToolManifest } from "@rampscan/collectors";
import {
  buildScanResult,
  createCachingRunner,
  createLocalRepoSource,
  createLocalRunner,
  sameEvidence,
  toEvidenceBundle,
} from "@rampscan/core";
import type {
  CacheMode,
  CacheOutcome,
  Collector,
  Digest,
  LedgerEntry,
  RunResult,
} from "@rampscan/core";
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
  /**
   * The scan cache (M5 G2). "incremental" reuses collector results whose
   * cacheScope is clean by content hash; "full" bypasses reads but refreshes
   * every entry. Omit for the uncached M1–M4 behavior.
   */
  cache?: { dir: string; mode: CacheMode };
  /**
   * Identical evidence normally survives with its original signature — but
   * the MVX clock reads the bundle timestamp, so a daemon re-verifying on
   * cadence must eventually mint a fresh attestation or watch true evidence
   * "expire". When set, identical evidence older than this is re-signed and
   * appended (the prior bundle dies `superseded` — an honest record of the
   * re-verification). Unset → M2 behavior: identical evidence always survives.
   */
  refreshOlderThanMs?: number;
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
    /** identical evidence past refreshOlderThanMs — re-signed with a fresh timestamp */
    refreshed: EvidenceRecord[];
  };
  /** per-collector cache outcomes, when a cache was configured */
  cache?: Record<string, CacheOutcome>;
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

  // the repo's ledger identity is the RESOLVED path — `scan .` and a daemon
  // watching the absolute path must agree on which evidence is whose
  const workspace = await createLocalRepoSource().fetch({ repo: resolve(options.path) });
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
  const localRunner = createLocalRunner({
    collectors: options.collectors,
    artifactDir,
    inputs,
    runId,
  });

  const cacheOutcomes: Record<string, CacheOutcome> = {};
  let runner = localRunner;
  if (options.cache) {
    // the pinned tools.json content salts every key: re-pinning a tool image
    // invalidates the cache even though the manifest still says resolved-at-run
    const keySalt = createHash("sha256")
      .update(JSON.stringify(await loadToolManifest()))
      .digest("hex");
    runner = createCachingRunner(localRunner, {
      dir: options.cache.dir,
      mode: options.cache.mode,
      artifactDir,
      inputs,
      keySalt,
      onOutcome: (collector, outcome) => {
        cacheOutcomes[collector] = outcome;
      },
      log,
    });
    log(`scan cache: ${options.cache.mode} mode at ${options.cache.dir}`);
  }

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

  // the VEX export lands in exports/ (plan §M4): the signed bundle attests
  // to the artifact by digest; this copy is the hand-to-an-assessor file
  const vexSource = inputs.get(OPENVEX_ARTIFACT);
  if (vexSource !== undefined) {
    const exportsDir = join(outDir, "exports");
    await mkdir(exportsDir, { recursive: true });
    await copyFile(vexSource, join(exportsDir, OPENVEX_ARTIFACT));
    log(`OpenVEX export → ${join(exportsDir, OPENVEX_ARTIFACT)}`);
  }

  const outcome: ScanOutcome = { result, resultPath };
  if (options.cache) outcome.cache = cacheOutcomes;

  if (options.ledgerDir === undefined) return outcome;
  if (options.keysDir === undefined) {
    throw new Error("ledgerDir is set but keysDir is not — evidence is only recorded signed");
  }

  const ledger = createLocalLedger(options.ledgerDir);
  const signer = createLocalSigner(options.keysDir, { log });
  const recipeById = new Map<string, PipelineRecipe>(recipes.map((r) => [r.id, r]));
  const appended: EvidenceRecord[] = [];
  const survived: EvidenceRecord[] = [];
  const refreshed: EvidenceRecord[] = [];

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
      const priorAgeMs = now.getTime() - Date.parse(prior.bundle.predicate.timestamp);
      if (options.refreshOlderThanMs === undefined || priorAgeMs < options.refreshOlderThanMs) {
        survived.push({ recipeId: row.recipe_id, digest: prior.digest });
        continue;
      }
      // identical but aging: mint a fresh attestation so the MVX clock
      // records the re-verification (the prior bundle dies `superseded`)
      const envelope = await signer.sign(bundle);
      const digest = await ledger.append(bundle, envelope);
      refreshed.push({ recipeId: row.recipe_id, digest });
      continue;
    }
    const envelope = await signer.sign(bundle);
    const digest = await ledger.append(bundle, envelope);
    appended.push({ recipeId: row.recipe_id, digest });
  }

  log(
    `ledger: ${appended.length} bundle(s) appended, ${refreshed.length} refreshed (re-signed), ` +
      `${survived.length} survived unchanged, ` +
      `${result.summary.unevidenced} recipe(s) unevidenced (never recorded)`,
  );
  outcome.evidence = { appended, survived, refreshed };
  return outcome;
}
