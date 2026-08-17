#!/usr/bin/env node
import { parseArgs } from "node:util";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { allCollectors, loadToolManifest } from "@rampscan/collectors";
import { DEFAULT_DATASET_PIN, loadLocalDataset } from "@rampscan/dataset";
import { createLocalLedger } from "@rampscan/ledger";
import { createProjector } from "@rampscan/projector";
import type { CertClass } from "@rampscan/core";
import { windowMsFor } from "@rampscan/scheduler";
import { renderBoard, renderBoardDiff } from "./board.js";
import { computeBoardAsOf } from "./board-asof.js";
import { computeBoardDiff } from "./board-diff.js";
import { loadAdjudications } from "./adjudications.js";
import { check, renderCheck } from "./check.js";
import { buildFrontier, renderFrontier, unreviewedControls } from "./frontier.js";
import { startDaemon } from "./daemon.js";
import { computeRepoModel, renderRepoModel, serializeRepoModel } from "./model.js";
import { rebuild } from "./rebuild.js";
import { loadRecipes } from "./recipes.js";
import { report } from "./report.js";
import { scan } from "./scan.js";
import { serve } from "./serve.js";
import { renderSummary } from "./summary.js";
import { buildToolMap, renderToolMap, toolMapProblems } from "./tools.js";
import { verify } from "./verify.js";

// rampscan CLI — M5 surface:
//   rampscan scan <path>     scan, join, sign, append to the ledger
//   rampscan check <path>    the working-tree DRY RUN (L3a): what a scan would
//                            conclude before you commit — nothing signed,
//                            nothing appended, exits nonzero on a would-be
//                            violation so a hook or CI job can gate on it
//   rampscan verify <digest> offline check of one bundle
//   rampscan board           the projection as text: registers + graveyard
//   rampscan rebuild         projection stores from the ledger, with proof
//   rampscan serve           PocketBase + the Next.js console, locally
//   rampscan daemon <path>   the clock runs itself: cadence re-scans,
//                            near-expiry warnings, cache self-verification
//   rampscan report          FRONTIER-PIPELINE.md from a real run
//   rampscan tools           the static map: recipe ↔ collector ↔ tool ↔ image
//   rampscan model           the repo model: the ledger's world as typed nodes
//                            and links (`--json` reproduces the scan artifact)
//   rampscan frontier        the commit plane's answer to ramprules' automation
//                            frontier: catalog × adjudications × the pinned frontier
// Run from the repo: `pnpm rampscan <command>`.

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");

function usage(): never {
  console.error(
    [
      "usage: rampscan <command> [options]",
      "",
      "commands:",
      "  scan <path>       scan a checkout; sign and record evidence",
      "  check <path>      DRY RUN over the WORKING TREE: what a scan would conclude if you",
      "                    committed now — the pure gates only, nothing signed, nothing appended,",
      "                    no artifact kept. Exits 1 on a would-be violation (pre-commit / CI gate)",
      "  verify <digest>   verify one ledger bundle offline (content + signature)",
      "  board             show the projection: registers, live evidence, graveyard (--json for the fold)",
      "  board --as-of <iso>  the same projection at a past instant, refolded from the ledger",
      "  board --since previous|<iso>  what moved since a prior scan's board (I2d)",
      "  rebuild           rebuild projection stores from the ledger and PROVE projection ≡ ledger",
      "  serve             start PocketBase + the Next.js console (the visual board)",
      "  daemon <path>     keep the target evidenced on cadence: incremental re-scans,",
      "                    near-expiry warnings, scheduled full-scan cache verification",
      "  report            generate docs/FRONTIER-PIPELINE.md from the last scan result",
      "  tools             the static map: which collector answers which recipe, with which",
      "                    tool and pinned image (doctor: can it run · tools: who feeds whom)",
      "  model             the repo model: repos, recipes, controls, KSIs, collectors, tools,",
      "                    contract rules and the walked graph, as typed nodes and links.",
      "                    `--json` prints the artifact a scan attests, byte-for-byte",
      "  frontier          the commit plane's coverage of ramprules' uncovered controls:",
      "                    catalog × adjudications × the pinned frontier, nothing probed. Exits 1",
      "                    on a broken link; --strict also exits 1 on any unreviewed control",
      "",
      "options:",
      "  --out <dir>       scan/daemon output directory (default: ./rampscan-out);",
      "                    serve tails <out>/daemon-events.jsonl into the console",
      "  --ledger <dir>    append-only evidence ledger (default: ./rampscan-ledger)",
      "  --keys <dir>      signing keypair dir (default: ./rampscan-keys)",
      "  --db <path>       board/rebuild: SQLite projection path (default: ./rampscan-projection.db for rebuild)",
      "  --dataset <dir>   ramprules derived-slice dir (default: docs/context/ramprules/derived)",
      "  --pin <version>   dataset version pin (default: " + DEFAULT_DATASET_PIN + ")",
      "  --recipes <dir>   pipeline recipe dir (default: recipes/pipeline)",
      "  --adjudications <dir>  frontier: per-control disposition dir (default: recipes/adjudications)",
      "  --strict          frontier: exit 1 on a pipeline-unreviewed control, not only a broken link",
      "  --class <b|c>     target cert class → MVX window (b=7d, c=3d; default: b)",
      "  --as-of <iso>     board: fold only statements at or before this instant (I1b)",
      "  --since <v>       board: lead with the diff against a baseline board — `previous`",
      "                    (the scan before the current one) or an ISO instant (I2d)",
      "  --pb-port <n>     serve: PocketBase port (default: 8090)",
      "  --web-port <n>    serve: console port (default: 3000)",
      "  --no-web          serve: PocketBase + projector only, no Next.js",
      "  --pb-data <dir>   serve: PocketBase data dir (default: console/pocketbase/data)",
      "  --cache <dir>     daemon: scan cache dir (default: ./rampscan-cache)",
      "  --check-interval <s>  daemon: clock check interval in seconds (default: 300)",
      "  --full-every <n>  daemon: every Nth scan bypasses the cache and verifies it (default: 6)",
      "  --result <path>   report: scan result to report from (default: ./rampscan-out/scan-result.json)",
      "  --report-out <path>  report: output file (default: docs/FRONTIER-PIPELINE.md)",
      "  --json            board/check/tools/model: the JSON instead of the text reading (for `model`,",
      "                    the canonical bytes a scan's run record attests)",
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
      adjudications: { type: "string" },
      strict: { type: "boolean" },
      class: { type: "string" },
      "as-of": { type: "string" },
      since: { type: "string" },
      "pb-port": { type: "string" },
      "web-port": { type: "string" },
      "no-web": { type: "boolean" },
      "pb-data": { type: "string" },
      cache: { type: "string" },
      "check-interval": { type: "string" },
      "full-every": { type: "string" },
      result: { type: "string" },
      "report-out": { type: "string" },
      json: { type: "boolean" },
      "no-color": { type: "boolean" },
    },
  });

  const [command, target] = positionals;
  const ledgerDir = values.ledger ?? "./rampscan-ledger";
  const keysDir = values.keys ?? "./rampscan-keys";
  const datasetDir = values.dataset ?? join(REPO_ROOT, "docs/context/ramprules/derived");
  const datasetPin = values.pin ?? DEFAULT_DATASET_PIN;
  const recipesDir = values.recipes ?? join(REPO_ROOT, "recipes/pipeline");
  const adjudicationsDir = values.adjudications ?? join(REPO_ROOT, "recipes/adjudications");
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
        trigger: "manual",
        log: (line) => console.error(`· ${line}`),
      });
      console.log(renderSummary(result, useColor));
      console.log(`\nscan-result: ${resultPath}`);
      // violations are a result, not a crash — reserve nonzero exits for failures
      return;
    }

    case "check": {
      if (!target) usage();
      // The dry run (L3a). The ledger is passed READ-ONLY, for the board
      // comparison that tells "I broke this" from "this was already broken";
      // no signer is constructed here at all, because there is nothing to sign.
      const outcome = await check({
        path: target,
        datasetDir,
        datasetPin,
        recipesDir,
        collectors: allCollectors,
        ledgerDir,
        certClass,
        log: (line) => console.error(`· ${line}`),
      });
      if (values.json) console.log(JSON.stringify(outcome, null, 2));
      else console.log(renderCheck(outcome, useColor));
      // The one place in this CLI where a violation IS a nonzero exit, and the
      // difference from `scan` is deliberate: a scan RECORDS a fact, so a
      // violation is a true result and not a failure, while `check` is a
      // question the caller asked before committing — its exit code is the
      // answer, which is what makes it usable as a pre-commit hook or a CI gate.
      if (outcome.wouldViolate) process.exit(1);
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
      const asOf = values["as-of"];
      if (asOf !== undefined && Number.isNaN(Date.parse(asOf))) {
        console.error(`--as-of is not a parseable instant: ${asOf}`);
        process.exit(2);
      }
      const since = values.since;
      if (since !== undefined && since !== "previous" && Number.isNaN(Date.parse(since))) {
        console.error(`--since is not \`previous\` or a parseable instant: ${since}`);
        process.exit(2);
      }
      const asOfIso = asOf !== undefined ? new Date(asOf).toISOString() : undefined;
      if (since !== undefined) {
        // the diff leads (I2d): what moved since the baseline, then the board
        const outcome = await computeBoardDiff({
          ledgerDir,
          recipesDir,
          since: since === "previous" ? since : new Date(since).toISOString(),
          ...(asOfIso !== undefined ? { asOf: asOfIso } : {}),
        });
        console.log(renderBoardDiff(outcome, useColor));
        console.log("");
      }
      if (asOfIso !== undefined) {
        // the same hand the console's as-of route calls (I3d) — terminal and
        // browser can never disagree about what the past board looked like
        const outcome = await computeBoardAsOf({ ledgerDir, recipesDir, asOf: asOfIso });
        // `--json` emits the PROJECTION, not a summary of it (L3c): the text
        // reading and the JSON are two renderings of one fold, so a script and
        // an operator cannot come to different conclusions about the same board
        if (values.json) {
          console.log(JSON.stringify(outcome.projection, null, 2));
          return;
        }
        console.log(
          `AS OF ${asOfIso} — refolded from ledger statements at or before this instant` +
            `${outcome.asOfIsScan ? " (a scan instant)" : ""}\n`,
        );
        console.log(renderBoard(outcome.projection, useColor));
        return;
      }
      const projector = createProjector({ recipes, windowMs: windowMsFor(certClass) });
      const projection = await projector.fold(createLocalLedger(ledgerDir));
      if (values.json) console.log(JSON.stringify(projection, null, 2));
      else console.log(renderBoard(projection, useColor));
      return;
    }

    case "rebuild": {
      // PocketBase needs no flag here: `rampscan serve` re-projects it on every ledger append
      const report = await rebuild({
        ledgerDir,
        recipesDir,
        dbPath: values.db ?? "./rampscan-projection.db",
        windowMs: windowMsFor(certClass),
      });
      console.log(report.lines.join("\n"));
      if (!report.ok) process.exit(1);
      return;
    }

    case "daemon": {
      if (!target) usage();
      const handle = await startDaemon({
        path: target,
        outDir: values.out ?? "./rampscan-out",
        ledgerDir,
        keysDir,
        datasetDir,
        datasetPin,
        recipesDir,
        collectors: allCollectors,
        certClass,
        cacheDir: values.cache ?? "./rampscan-cache",
        checkIntervalMs: Number(values["check-interval"] ?? 300) * 1000,
        fullEvery: Number(values["full-every"] ?? 6),
        log: (line) => console.error(`· ${new Date().toISOString()} ${line}`),
      });
      console.error(
        `· daemon watching ${target} (class ${certClass}) — ctrl-c to stop`,
      );
      await new Promise<void>((resolvePromise) => {
        const shutdown = () => {
          handle.stop();
          console.error(`· daemon stopped after ${handle.scanCount()} scan(s)`);
          resolvePromise();
        };
        process.once("SIGINT", shutdown);
        process.once("SIGTERM", shutdown);
      });
      return;
    }

    case "report": {
      const outcome = await report({
        resultPath: values.result ?? join(values.out ?? "./rampscan-out", "scan-result.json"),
        outPath: values["report-out"] ?? join(REPO_ROOT, "docs/FRONTIER-PIPELINE.md"),
      });
      console.log(outcome.lines.join("\n"));
      return;
    }

    case "tools": {
      // pure derivation — catalog + manifests + tools.json, nothing probed
      const map = buildToolMap({
        recipes: await loadRecipes(recipesDir),
        collectors: allCollectors,
        toolManifest: await loadToolManifest(),
      });
      if (values.json) {
        console.log(JSON.stringify(map, null, 2));
      } else {
        console.log(renderToolMap(map, useColor));
      }
      const problems = toolMapProblems(map);
      if (problems.length > 0) {
        console.error(
          `\n${problems.length} broken link(s) in the map:\n` +
            problems.map((p) => `  - ${p}`).join("\n"),
        );
        process.exit(1);
      }
      return;
    }

    case "frontier": {
      // ground rule 9's enforcement (N1a-T2): coverage is computed, never
      // typed. A pure derivation in the shape of `tools` and `model` — catalog
      // × adjudications × the pinned frontier, nothing probed, nothing
      // written, non-zero exit on a broken link.
      const dataset = await loadLocalDataset(datasetDir, datasetPin);
      const map = buildFrontier({
        frontier: dataset.frontier(),
        adjudications: await loadAdjudications(adjudicationsDir),
        recipes: await loadRecipes(recipesDir),
        collectors: allCollectors,
        datasetVersion: dataset.version(),
        ksiReachedControls: dataset.ksiReachedControls(),
      });
      if (values.json) console.log(JSON.stringify(map, null, 2));
      else console.log(renderFrontier(map, useColor));
      if (map.problems.length > 0) {
        console.error(
          `\n${map.problems.length} broken link(s) in the adjudication overlay:\n` +
            map.problems.map((p) => `  - ${p}`).join("\n"),
        );
        process.exit(1);
      }
      // The strict gate (N0 decision 3): once N1a has adjudicated the frontier,
      // this becomes the CI invocation, so the set cannot silently regrow. It
      // is a flag rather than the default only until that day — a command red
      // from its first run teaches people to ignore it.
      const unreviewed = unreviewedControls(map);
      if (values.strict && unreviewed.length > 0) {
        console.error(
          `\n${unreviewed.length} control(s) unreviewed from the commit plane:\n  ` +
            unreviewed.join(", "),
        );
        process.exit(1);
      }
      return;
    }

    case "model": {
      // a derivation, like `tools` — no scan needed, nothing probed, nothing
      // written. `--json` emits the artifact's exact bytes, so
      // `rampscan model --json` and the repo-model.json a scan attested are
      // the same file whenever the ledger has not moved.
      const model = await computeRepoModel({
        ledgerDir,
        recipesDir,
        dataset: await loadLocalDataset(datasetDir, datasetPin),
        toolMap: buildToolMap({
          recipes: await loadRecipes(recipesDir),
          collectors: allCollectors,
          toolManifest: await loadToolManifest(),
        }),
      });
      if (values.json) process.stdout.write(serializeRepoModel(model));
      else console.log(renderRepoModel(model, useColor));
      if (model.problems.length > 0) {
        console.error(
          `\n${model.problems.length} problem(s) the model could not state:\n` +
            model.problems.map((p) => `  - ${p}`).join("\n"),
        );
        process.exit(1);
      }
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
        outDir: resolve(values.out ?? "./rampscan-out"),
        certClass,
        pbPort: Number(values["pb-port"] ?? 8090),
        webPort: Number(values["web-port"] ?? 3000),
        web: !values["no-web"],
        ...(values["pb-data"] !== undefined ? { pbDataDir: resolve(values["pb-data"]) } : {}),
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
