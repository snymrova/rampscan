#!/usr/bin/env node
import { parseArgs } from "node:util";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { allCollectors } from "@rampscan/collectors";
import { DEFAULT_DATASET_PIN } from "@rampscan/dataset";
import { createLocalLedger } from "@rampscan/ledger";
import { createProjector, writeProjectionSqlite } from "@rampscan/projector";
import { renderBoard } from "./board.js";
import { scan } from "./scan.js";
import { renderSummary } from "./summary.js";
import { verify } from "./verify.js";

// rampscan CLI — M2 surface:
//   rampscan scan <path>     scan, join, sign, append to the ledger
//   rampscan verify <digest> offline check of one bundle
//   rampscan board           the projection: live and dead evidence
// Run from the repo: `pnpm rampscan <command>`.

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");

function usage(): never {
  console.error(
    [
      "usage: rampscan <command> [options]",
      "",
      "commands:",
      "  scan <path>       scan a checkout; sign and record evidence",
      "  verify <digest>   verify one ledger bundle offline (content + signature)",
      "  board             show the projection: live evidence and the graveyard",
      "",
      "options:",
      "  --out <dir>       scan output directory (default: ./rampscan-out)",
      "  --ledger <dir>    append-only evidence ledger (default: ./rampscan-ledger)",
      "  --keys <dir>      signing keypair dir (default: ./rampscan-keys)",
      "  --db <path>       board: also write the projection to this SQLite file",
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
      ledger: { type: "string" },
      keys: { type: "string" },
      db: { type: "string" },
      dataset: { type: "string" },
      pin: { type: "string" },
      recipes: { type: "string" },
      "no-color": { type: "boolean" },
    },
  });

  const [command, target] = positionals;
  const ledgerDir = values.ledger ?? "./rampscan-ledger";
  const keysDir = values.keys ?? "./rampscan-keys";
  const useColor = values["no-color"] ? false : (process.stdout.isTTY ?? false);

  switch (command) {
    case "scan": {
      if (!target) usage();
      const { result, resultPath } = await scan({
        path: target,
        outDir: values.out ?? "./rampscan-out",
        datasetDir: values.dataset ?? join(REPO_ROOT, "docs/context/ramprules/derived"),
        datasetPin: values.pin ?? DEFAULT_DATASET_PIN,
        recipesDir: values.recipes ?? join(REPO_ROOT, "recipes/pipeline"),
        collectors: allCollectors,
        ledgerDir,
        keysDir,
        log: (line) => console.error(`· ${line}`),
      });
      console.log(renderSummary(result, useColor));
      console.log(`\nscan-result: ${resultPath}`);
      // violations are a result, not a crash — reserve nonzero exits for failures
      return;
    }

    case "verify": {
      if (!target) usage();
      const report = await verify({ digest: target, ledgerDir, keysDir });
      console.log(report.lines.join("\n"));
      if (!report.ok) process.exit(1);
      return;
    }

    case "board": {
      const projection = await createProjector().fold(createLocalLedger(ledgerDir));
      if (values.db) {
        await writeProjectionSqlite(projection, values.db);
        console.error(`· projection written to ${values.db}`);
      }
      console.log(renderBoard(projection, useColor));
      return;
    }

    default:
      usage();
  }
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
});
