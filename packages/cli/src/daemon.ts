import { appendFile, mkdir, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { createLocalRepoSource } from "@rampscan/core";
import type { CertClass, Collector } from "@rampscan/core";
import { createLocalLedger } from "@rampscan/ledger";
import { createProjector } from "@rampscan/projector";
import {
  DEFAULT_SCAN_AT_FRACTION,
  createLocalScheduler,
  describeEvent,
  diffScanResults,
  windowMsFor,
} from "@rampscan/scheduler";
import type {
  LocalScheduler,
  SchedulerAssessment,
  SchedulerEvent,
  ScanComparison,
} from "@rampscan/scheduler";
import type { ScanResult } from "@rampscan/schema";
import { loadRecipes } from "./recipes.js";
import { scan } from "./scan.js";

// `rampscan daemon <path>` (plan G1+G2): the clock runs itself. A tick loop
// assesses the live evidence for the target on every check interval, warns
// on nearing-expiry bundles BEFORE the MVX window closes, and re-scans when
// the cadence math (or a moved HEAD) says so. Scans are incremental — the
// content-hash cache — except every Nth, which bypasses the cache entirely
// and diffs its joined result against the last incremental result at the
// same commit: the cache verifies itself, and any divergence (poisoned
// entry, advisory published since, tool drift) is alerted, never absorbed.

export type DaemonEvent =
  | SchedulerEvent
  | { kind: "divergence"; repo: string; comparison: ScanComparison; reportPath: string }
  | { kind: "cache-verified"; repo: string; recipeCount: number }
  | {
      kind: "scan-recorded";
      repo: string;
      mode: "incremental" | "full";
      commit: string;
      appended: number;
      refreshed: number;
      survived: number;
      cacheHits: number;
    };

export interface DaemonOptions {
  /** path to the checkout to keep evidenced */
  path: string;
  outDir: string;
  ledgerDir: string;
  keysDir: string;
  datasetDir: string;
  datasetPin: string;
  recipesDir: string;
  collectors: Collector[];
  certClass: CertClass;
  /** scan cache dir (the incremental dirty-set store) */
  cacheDir: string;
  /** how often the loop re-checks the clock (default 5 minutes) */
  checkIntervalMs?: number;
  /** every Nth scan runs with the cache bypassed and diffs the result (default 6) */
  fullEvery?: number;
  scanAtFraction?: number;
  warnAtFraction?: number;
  /** MVX window override per class — tests only */
  windowMs?: Partial<Record<CertClass, number>>;
  /** injectable clock — tests only */
  clock?: () => number;
  onEvent?(event: DaemonEvent): void;
  log?(line: string): void;
}

export interface DaemonHandle {
  scheduler: LocalScheduler;
  /** scans run so far (incremental + full) */
  scanCount(): number;
  stop(): void;
}

export function describeDaemonEvent(event: DaemonEvent): string {
  switch (event.kind) {
    case "divergence": {
      const heads = event.comparison.divergences
        .map((d) => `${d.recipeId} (${d.field})`)
        .join(", ");
      return `CACHE DIVERGENCE — full scan disagrees with the incremental result: ${heads} — report: ${event.reportPath}`;
    }
    case "cache-verified":
      return `full scan verified the cache — ${event.recipeCount} recipe verdicts identical`;
    case "scan-recorded":
      return (
        `scan recorded (${event.mode}) @ ${event.commit.slice(0, 12)}: ` +
        `${event.appended} appended, ${event.refreshed} refreshed, ${event.survived} survived, ` +
        `${event.cacheHits} collector(s) from cache`
      );
    default:
      return describeEvent(event);
  }
}

export async function startDaemon(options: DaemonOptions): Promise<DaemonHandle> {
  const log = options.log ?? (() => {});
  const clock = options.clock ?? Date.now;
  const fullEvery = options.fullEvery ?? 6;
  const repoPath = resolve(options.path);
  const outDir = resolve(options.outDir);
  await mkdir(outDir, { recursive: true });
  const eventsPath = join(outDir, "daemon-events.jsonl");

  const recipes = await loadRecipes(options.recipesDir);
  const windowMs = options.windowMs?.[options.certClass] ?? windowMsFor(options.certClass);
  const projector = createProjector({ recipes, windowMs });
  const repoSource = createLocalRepoSource();

  const scanAtFraction = options.scanAtFraction ?? DEFAULT_SCAN_AT_FRACTION;
  const refreshOlderThanMs = windowMs * scanAtFraction;

  let scans = 0;
  let lastIncremental: ScanResult | undefined;

  let eventWrites = Promise.resolve();
  const emit = (event: DaemonEvent): void => {
    log(describeDaemonEvent(event));
    const line = JSON.stringify({ at: new Date(clock()).toISOString(), ...event }) + "\n";
    eventWrites = eventWrites.then(() => appendFile(eventsPath, line)).catch(() => {});
    options.onEvent?.(event);
  };

  async function assess(): Promise<SchedulerAssessment> {
    const projection = await projector.fold(createLocalLedger(options.ledgerDir));
    const live = projection.registers.filter(
      (row) =>
        row.repo === repoPath &&
        row.bundleDigest !== undefined &&
        row.freshAsOf !== undefined,
    );
    const rows = live.map((row) => ({
      recipeId: row.recipeId,
      bundleDigest: row.bundleDigest!,
      freshAsOf: row.freshAsOf!,
    }));
    const newest = [...live].sort((a, b) => a.freshAsOf!.localeCompare(b.freshAsOf!)).at(-1);
    const assessment: SchedulerAssessment = { rows };
    if (newest?.commit !== undefined) assessment.lastCommit = newest.commit;
    return assessment;
  }

  async function runScan(): Promise<void> {
    scans += 1;
    const mode: "incremental" | "full" = scans % fullEvery === 0 ? "full" : "incremental";
    const outcome = await scan({
      path: repoPath,
      outDir,
      datasetDir: options.datasetDir,
      datasetPin: options.datasetPin,
      recipesDir: options.recipesDir,
      collectors: options.collectors,
      ledgerDir: options.ledgerDir,
      keysDir: options.keysDir,
      cache: { dir: options.cacheDir, mode },
      refreshOlderThanMs,
      now: new Date(clock()),
      log,
    });

    const cacheHits = Object.values(outcome.cache ?? {}).filter((o) => o === "hit").length;
    emit({
      kind: "scan-recorded",
      repo: repoPath,
      mode,
      commit: outcome.result.commit,
      appended: outcome.evidence?.appended.length ?? 0,
      refreshed: outcome.evidence?.refreshed.length ?? 0,
      survived: outcome.evidence?.survived.length ?? 0,
      cacheHits,
    });

    if (mode === "incremental") {
      lastIncremental = outcome.result;
      return;
    }
    // the scheduled full scan verifies the cache — only comparable when the
    // last incremental result exists and saw the same commit
    if (lastIncremental && lastIncremental.commit === outcome.result.commit) {
      const comparison = diffScanResults(outcome.result, lastIncremental);
      if (comparison.divergences.length > 0) {
        const reportPath = join(outDir, "divergence-report.json");
        await writeFile(
          reportPath,
          JSON.stringify(
            {
              at: new Date(clock()).toISOString(),
              repo: repoPath,
              commit: outcome.result.commit,
              full_run: outcome.result.run_id,
              incremental_run: lastIncremental.run_id,
              ...comparison,
            },
            null,
            2,
          ) + "\n",
        );
        emit({ kind: "divergence", repo: repoPath, comparison, reportPath });
      } else {
        emit({ kind: "cache-verified", repo: repoPath, recipeCount: outcome.result.recipes.length });
      }
    }
    // the full scan refreshed every cache entry — future incrementals diff
    // against it, so it becomes the comparison base too
    lastIncremental = outcome.result;
  }

  const schedulerOptions: Parameters<typeof createLocalScheduler>[0] = {
    assess: () => assess(),
    scan: () => runScan(),
    head: async (target) => (await repoSource.fetch(target)).commit,
    onEvent: emit,
    clock,
  };
  if (options.checkIntervalMs !== undefined)
    schedulerOptions.checkIntervalMs = options.checkIntervalMs;
  if (options.windowMs !== undefined) schedulerOptions.windowMs = options.windowMs;
  if (options.scanAtFraction !== undefined)
    schedulerOptions.scanAtFraction = options.scanAtFraction;
  if (options.warnAtFraction !== undefined)
    schedulerOptions.warnAtFraction = options.warnAtFraction;

  const scheduler = createLocalScheduler(schedulerOptions);
  await scheduler.ensureCadence(options.certClass, { repo: repoPath });

  return {
    scheduler,
    scanCount: () => scans,
    stop: () => scheduler.stop(),
  };
}
