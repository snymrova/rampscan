#!/usr/bin/env node
import { parseArgs } from "node:util";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { allCollectors } from "@rampscan/collectors";
import { DEFAULT_DATASET_PIN } from "@rampscan/dataset";
import { scan } from "./scan.js";
import { renderSummary } from "./summary.js";

// rampscan CLI — M1 surface: `rampscan scan <path>`.
// Run from the repo: `pnpm rampscan scan <path>`.

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");

function usage(): never {
  console.error(
    [
      "usage: rampscan scan <path> [options]",
      "",
      "options:",
      "  --out <dir>       output directory (default: ./rampscan-out)",
      "  --dataset <dir>   ramprules derived-slice dir (default: docs/context/ramprules/derived)",
      "  --pin <version>   dataset version pin (default: " + DEFAULT_DATASET_PIN + ")",
      "  --recipes <dir>   pipeline recipe dir (default: recipes/pipeline)",
      "  --no-color        plain output",
    ].join("\n"),
  );
  process.exit(2);
}

async function main(): Promise<void> {
  const { values, positionals } = parseArgs({
    args: process.argv.slice(2),
    allowPositionals: true,
    options: {
      out: { type: "string" },
      dataset: { type: "string" },
      pin: { type: "string" },
      recipes: { type: "string" },
      "no-color": { type: "boolean" },
    },
  });

  const [command, target] = positionals;
  if (command !== "scan" || !target) usage();

  const { result, resultPath } = await scan({
    path: target,
    outDir: values.out ?? "./rampscan-out",
    datasetDir: values.dataset ?? join(REPO_ROOT, "docs/context/ramprules/derived"),
    datasetPin: values.pin ?? DEFAULT_DATASET_PIN,
    recipesDir: values.recipes ?? join(REPO_ROOT, "recipes/pipeline"),
    collectors: allCollectors,
    log: (line) => console.error(`· ${line}`),
  });

  const useColor = values["no-color"] ? false : (process.stdout.isTTY ?? false);
  console.log(renderSummary(result, useColor));
  console.log(`\nscan-result: ${resultPath}`);
  // violations are a result, not a crash — reserve nonzero exits for failures
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
});
