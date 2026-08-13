#!/usr/bin/env node
import { parseArgs } from "node:util";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { allCollectors } from "@rampscan/collectors";
import { DEFAULT_DATASET_PIN } from "@rampscan/dataset";
import { createLocalLedger } from "@rampscan/ledger";
import { createProjector } from "@rampscan/projector";
import type { CertClass } from "@rampscan/core";
import { renderBoard } from "./board.js";
import { rebuild } from "./rebuild.js";
import { loadRecipes } from "./recipes.js";
import { scan } from "./scan.js";
import { serve } from "./serve.js";
import { renderSummary } from "./summary.js";
import { verify } from "./verify.js";

// rampscan CLI — M3 surface:
//   rampscan scan <path>     scan, join, sign, append to the ledger
//   rampscan verify <digest> offline check of one bundle
//   rampscan board           the projection as text: registers + graveyard
//   rampscan rebuild         projection stores from the ledger, with proof
//   rampscan serve           PocketBase + the Next.js console, locally
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
      "  board             show the projection: registers, live evidence, graveyard",
      "  rebuild           rebuild projection stores from the ledger and PROVE projection ≡ ledger",
      "  serve             start PocketBase + the Next.js console (the visual board)",
      "",
      "options:",
      "  --out <dir>       scan output directory (default: ./rampscan-out)",
      "  --ledger <dir>    append-only evidence ledger (default: ./rampscan-ledger)",
      "  --keys <dir>      signing keypair dir (default: ./rampscan-keys)",
      "  --db <path>       board/rebuild: SQLite projection path (default: ./rampscan-projection.db for rebuild)",
      "  --dataset <dir>   ramprules derived-slice dir (default: docs/context/ramprules/derived)",
      "  --pin <version>   dataset version pin (default: " + DEFAULT_DATASET_PIN + ")",
      "  --recipes <dir>   pipeline recipe dir (default: recipes/pipeline)",
      "  --class <b|c>     target cert class → MVX window (b=7d, c=3d; default: b)",
      "  --pb-port <n>     serve: PocketBase port (default: 8090)",
      "  --web-port <n>    serve: console port (default: 3000)",
      "  --no-web          serve: PocketBase + projector only, no Next.js",
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
      class: { type: "string" },
      "pb-port": { type: "string" },
      "web-port": { type: "string" },
      "no-web": { type: "boolean" },
      "no-color": { type: "boolean" },
    },
  });

  const [command, target] = positionals;
  const ledgerDir = values.ledger ?? "./rampscan-ledger";
  const keysDir = values.keys ?? "./rampscan-keys";
  const datasetDir = values.dataset ?? join(REPO_ROOT, "docs/context/ramprules/derived");
  const datasetPin = values.pin ?? DEFAULT_DATASET_PIN;
  const recipesDir = values.recipes ?? join(REPO_ROOT, "recipes/pipeline");
  const useColor = values["no-color"] ? false : (process.stdout.isTTY ?? false);
  const certClass = (values.class ?? "b") as CertClass;
  if (certClass !== "b" && certClass !== "c") usage();

  switch (command) {
    case "scan": {
      if (!target) usage();
      const { result, resultPath } = await scan({
        path: target,
        outDir: values.out ?? "./rampscan-out",
        datasetDir,
        datasetPin,
        recipesDir,
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
      const recipes = await loadRecipes(recipesDir);
      const projection = await createProjector({ recipes }).fold(createLocalLedger(ledgerDir));
      console.log(renderBoard(projection, useColor));
      return;
    }

    case "rebuild": {
      // PocketBase needs no flag here: `rampscan serve` re-projects it on every ledger append
      const report = await rebuild({
        ledgerDir,
        recipesDir,
        dbPath: values.db ?? "./rampscan-projection.db",
      });
      console.log(report.lines.join("\n"));
      if (!report.ok) process.exit(1);
      return;
    }

    case "serve": {
      await serve({
        repoRoot: REPO_ROOT,
        ledgerDir: resolve(ledgerDir),
        keysDir: resolve(keysDir),
        recipesDir: resolve(recipesDir),
        datasetDir: resolve(datasetDir),
        datasetPin,
        certClass,
        pbPort: Number(values["pb-port"] ?? 8090),
        webPort: Number(values["web-port"] ?? 3000),
        web: !values["no-web"],
        log: (line) => console.error(`· ${line}`),
      });
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
