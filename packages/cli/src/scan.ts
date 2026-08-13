import { randomBytes } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import {
  buildScanResult,
  createLocalRepoSource,
  createLocalRunner,
} from "@rampscan/core";
import type { Collector, RunResult } from "@rampscan/core";
import { loadLocalDataset } from "@rampscan/dataset";
import { ScanResult } from "@rampscan/schema";
import { loadRecipes, validateRecipeIds } from "./recipes.js";

// `rampscan scan <path>` orchestration (plan C5): pin workspace → load pinned
// dataset + recipes → run collectors in order → join → scan-result.json.

export interface ScanOptions {
  /** path to the checkout to scan */
  path: string;
  /** output dir; artifacts/ and scan-result.json land here */
  outDir: string;
  datasetDir: string;
  datasetPin: string;
  recipesDir: string;
  collectors: Collector[];
  /** the run's single clock — defaults to now */
  now?: Date;
  log?: (line: string) => void;
}

export interface ScanOutcome {
  result: ScanResult;
  resultPath: string;
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
  return { result, resultPath };
}
