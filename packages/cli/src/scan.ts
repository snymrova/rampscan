import { createHash, randomBytes } from "node:crypto";
import { copyFile, mkdir, readFile, stat, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import {
  OPENVEX_ARTIFACT,
  cacheKeySalt,
  createJournaledRunner,
  loadToolManifest,
} from "@rampscan/collectors";
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
import {
  IN_TOTO_STATEMENT_TYPE,
  RAMPSCAN_SCAN_RUN_TYPE,
  ScanResult,
  ScanRun,
  isEvidenceBundle,
} from "@rampscan/schema";
import type {
  CacheRecord,
  CollectorRun,
  PipelineRecipe,
  ScanRunTrigger,
  Subject,
} from "@rampscan/schema";
import { buildRepoModel, REPO_MODEL_ARTIFACT, serializeRepoModel } from "./model.js";
import { loadRecipes, validateRecipeIds } from "./recipes.js";
import { buildToolMap } from "./tools.js";

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
  /** what caused this scan (J1) — recorded in the signed run record */
  trigger?: ScanRunTrigger;
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
  /** the signed run record (J1), when a ledger was configured */
  run?: { digest: Digest; collectors: number; skipped: number };
  /**
   * The repo model (L2), when a ledger was configured — a derivation of the
   * ledger AFTER this scan's evidence landed, written as a run artifact and
   * attested by the run record's subject list. Absent with no ledger, because
   * there is nothing to derive it from.
   */
  model?: { path: string; sha256: string; nodes: number; links: number };
}

/**
 * The run record's collector rows (J1): the runner's OWN observations of how
 * each collector went, never re-derived from the scan result. Every collector
 * that was dispatched appears — ran, cache-hit, skipped, or crashed alike. A
 * manifest of "what happened" that quietly omitted the tools which did not
 * run would be the screenshot folder this product exists to replace, and the
 * unevidenced cells are exactly the ones an operator opens this record for.
 */
async function buildCollectorRuns(
  collectors: Collector[],
  runs: Map<string, RunResult>,
  cacheRecords: Map<string, CacheRecord>,
  artifactDir: string,
): Promise<CollectorRun[]> {
  const rows: CollectorRun[] = [];
  for (const collector of collectors) {
    const name = collector.manifest.name;
    const run = runs.get(name);
    if (!run) continue;
    const artifacts: CollectorRun["artifacts"] = [];
    for (const artifact of run.artifacts) {
      const entry: CollectorRun["artifacts"][number] = {
        name: artifact.name,
        sha256: artifact.sha256,
      };
      try {
        entry.bytes = (await stat(join(artifactDir, artifact.path))).size;
      } catch {
        // the file is not on disk (an out dir moved, a later run's cleanup):
        // the digest still names it exactly, and a size is not invented
      }
      artifacts.push(entry);
    }
    const row: CollectorRun = {
      collector: name,
      tool_version: run.toolVersion,
      // 0 when nothing wrapped the runner (a bare unit-test runner) — the
      // record says zero rather than pretending to a measurement
      duration_ms: run.telemetry?.durationMs ?? 0,
      exit_code: run.exitCode,
      findings: run.findings.length,
      tools: run.telemetry?.tools ?? [],
      invocations: run.telemetry?.invocations ?? [],
      artifacts,
      cache: cacheRecords.get(name) ?? { state: "none" },
    };
    // what this collector ate (J5): the chain's link from a gate that spawns
    // nothing back to the tool whose output it judged
    if (collector.manifest.inputs && collector.manifest.inputs.length > 0) {
      row.consumes = [...collector.manifest.inputs];
    }
    if (run.skipped) row.skip_reason = run.skipped.reason;
    rows.push(row);
  }
  return rows;
}

/**
 * What the run record attests to: every artifact the run produced, plus
 * scan-result.json — which also guarantees a subject exists at all when no
 * tool resolved and the run produced nothing else. Sorted, so the same run
 * always canonicalizes the same way.
 *
 * `extra` carries the run's OWN derivations (L2's repo-model.json): artifacts
 * of the scan rather than of any one collector, which is why they arrive here
 * rather than through a collector row.
 */
async function runSubjects(
  resultPath: string,
  runs: Map<string, RunResult>,
  extra: Subject[] = [],
): Promise<Subject[]> {
  const byName = new Map<string, Subject>();
  byName.set("scan-result.json", {
    name: "scan-result.json",
    digest: { sha256: createHash("sha256").update(await readFile(resultPath)).digest("hex") },
  });
  for (const run of runs.values()) {
    for (const artifact of run.artifacts) {
      byName.set(artifact.name, { name: artifact.name, digest: { sha256: artifact.sha256 } });
    }
  }
  for (const subject of extra) byName.set(subject.name, subject);
  return [...byName.values()].sort((a, b) => a.name.localeCompare(b.name));
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
  // The journaling decorator sits INSIDE the cache: a cache hit spawns
  // nothing, so it must record nothing this run — the telemetry rides the
  // cached RunResult instead, and `cache.state` is what tells a reader which
  // run those invocations belong to.
  const localRunner = createJournaledRunner(
    createLocalRunner({
      collectors: options.collectors,
      artifactDir,
      inputs,
      runId,
    }),
    // paths this run owns: argv tokens under them are safe to record verbatim
    // in a permanent statement; everything else must earn its way past the
    // allowlist. workspace.root is added per collector by the decorator.
    { safeRoots: [outDir, artifactDir, ...(options.cache ? [options.cache.dir] : [])] },
  );

  const cacheOutcomes: Record<string, CacheOutcome> = {};
  const cacheRecords = new Map<string, CacheRecord>();
  let runner = localRunner;
  if (options.cache) {
    // the pinned tools.json content and the vendored semgrep ruleset salt
    // every key: re-pinning an image or editing a rule invalidates the cache
    // even though the manifest still says resolved-at-run
    const keySalt = await cacheKeySalt();
    runner = createCachingRunner(localRunner, {
      dir: options.cache.dir,
      mode: options.cache.mode,
      artifactDir,
      inputs,
      keySalt,
      onOutcome: (collector, outcome, detail) => {
        cacheOutcomes[collector] = outcome;
        cacheRecords.set(collector, {
          state: outcome,
          ...(detail ? { key: detail.key, scope: detail.scope } : {}),
        });
      },
      log,
    });
    log(`scan cache: ${options.cache.mode} mode at ${options.cache.dir}`);
  }

  const runs = new Map<string, RunResult>();
  const startedAt = new Date().toISOString();
  const startedAtMs = Date.now();
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

  // The repo model (L2), derived HERE — after this scan's evidence is in the
  // ledger and before the run record is written. The order is the whole point:
  // the model is a fold derivative, so it must see this scan's bundles, and
  // the run record must be able to attest the bytes by digest. (The run record
  // itself is appended after, so the model never describes the statement that
  // names it — which is fine: runs are not nodes in this model.)
  const model = buildRepoModel({
    entries: await ledger.list(),
    recipes,
    dataset,
    toolMap: buildToolMap({
      recipes,
      collectors: options.collectors,
      toolManifest: await loadToolManifest(),
    }),
  });
  const modelBytes = serializeRepoModel(model);
  const modelDir = join(artifactDir, "model");
  await mkdir(modelDir, { recursive: true });
  const modelPath = join(modelDir, REPO_MODEL_ARTIFACT);
  await writeFile(modelPath, modelBytes);
  const modelSha256 = createHash("sha256").update(modelBytes).digest("hex");
  outcome.model = {
    path: modelPath,
    sha256: modelSha256,
    nodes: model.nodes.length,
    links: model.links.length,
  };
  log(
    `repo model: ${model.nodes.length} node(s), ${model.links.length} link(s)` +
      `${model.problems.length > 0 ? `, ${model.problems.length} problem(s)` : ""} → ${modelPath}`,
  );

  // The run record (J1), always appended — one per scan, never deduplicated.
  // A run is unique by construction (its durations and clock), and the record
  // of WHAT RAN is precisely the thing that must not be deduplicated away:
  // two identical-looking scans a week apart are two facts, not one.
  const collectorRuns = await buildCollectorRuns(
    options.collectors,
    runs,
    cacheRecords,
    artifactDir,
  );
  const runRecord = ScanRun.parse({
    _type: IN_TOTO_STATEMENT_TYPE,
    subject: await runSubjects(resultPath, runs, [
      { name: REPO_MODEL_ARTIFACT, digest: { sha256: modelSha256 } },
    ]),
    predicateType: RAMPSCAN_SCAN_RUN_TYPE,
    predicate: {
      run_id: runId,
      repo: workspace.repo,
      commit: workspace.commit,
      trigger: options.trigger ?? "manual",
      started_at: startedAt,
      duration_ms: Date.now() - startedAtMs,
      dataset_version: dataset.version(),
      collectors: collectorRuns,
      // the same instant every bundle of this scan carries, so the fold and
      // the as-of selector treat the run and its evidence as one event
      timestamp: now.toISOString(),
    },
  });
  const runDigest = await ledger.append(runRecord, await signer.sign(runRecord));
  const skippedCount = collectorRuns.filter((c) => c.skip_reason !== undefined).length;
  log(
    `run record: ${runDigest.slice(0, 12)}… — ${collectorRuns.length} collector(s), ` +
      `${skippedCount} skipped (verify it like any bundle: rampscan verify ${runDigest.slice(0, 12)}…)`,
  );
  outcome.run = { digest: runDigest, collectors: collectorRuns.length, skipped: skippedCount };
  return outcome;
}
