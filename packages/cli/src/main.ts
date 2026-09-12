#!/usr/bin/env node
import { parseArgs } from "node:util";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { allCollectors, loadToolManifest } from "@rampscan/collectors";
import {
  DEFAULT_DATASET_PIN,
  DEFAULT_OVERLAY_PINS,
  OFFERING_CLASSES,
  loadKsiCatalogFromRules,
  loadKsiCatalogFromSlices,
  loadLocalDataset,
  type OfferingClass,
} from "@rampscan/dataset";
import { createLocalLedger } from "@rampscan/ledger";
import { createProjector } from "@rampscan/projector";
import type { CertClass } from "@rampscan/core";
import { windowMsFor } from "@rampscan/scheduler";
import { renderBoard, renderBoardDiff } from "./board.js";
import { computeBoardAsOf } from "./board-asof.js";
import { computeBoardDiff } from "./board-diff.js";
import { loadAdjudications } from "./adjudications.js";
import { check, renderCheck } from "./check.js";
import { ingest } from "./ingest.js";
import { renderCheckComment } from "./check-comment.js";
import { buildFrontier, renderFrontier, unreviewedControls } from "./frontier.js";
import { buildGapRegister, renderGapRegister } from "./gaps.js";
import { renderFedrampExports, writeFedrampExports } from "./fedramp-run.js";
import { checkConformance, renderConformance } from "./fedramp-conformance.js";
import { loadOffering } from "./offering.js";
import { buildKsiRegister, renderKsiRegister } from "./ksi-register.js";
import { startDaemon } from "./daemon.js";
import { computeRepoModel, renderRepoModel, serializeRepoModel } from "./model.js";
import { renderOwed, renderOwedKsi } from "./owed.js";
import { rebuild } from "./rebuild.js";
import { deriveCatalogMethods, loadRecipes } from "./recipes.js";
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
      "  ingest <path>     append CLIENT-RUN signed results as ledger citizens (SPEC §12.8):",
      "                    a submission file, or an Evidence/ tree with ingest-manifest.json.",
      "                    Requires --repo; validates against the pinned catalog; refuses the",
      "                    whole batch before signing anything. Never executes an AWS call",
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
      "  frontier          the KSI register (SPEC §12.5): one row per KSI — methods against the",
      "                    class floor, freshest evidence against the window, worst gap class —",
      "                    plus the G8 adjudication queue by leverage. Exits 1 on a broken link;",
      "                    --strict also exits 1 on any unreviewed control",
      "  frontier --by-controls  the legacy control view, unchanged: catalog × adjudications ×",
      "                    the pinned frontier (ground rule 1 — both denominators stay printable)",
      "  exports           the two FedRAMP schema-target exports (plan Q5): a Certification",
      "                    Package Overview (FRC-CSO-PKG) and an Ongoing Certification Report",
      "                    (CCM-OCR-AVL) as JSON valid against the PINNED FedRAMP schemas —",
      "                    the scanned repo's declared `offering` block joined to the fold.",
      "                    Lands in <out>/exports/. Exits 1 on a nonconforming document",
      "                    (FRC-CSO-JSN); every document carries its own conformance verdict",
      "  conformance [path]  the package conformance check (plan Q5.2 — G10, FRC-CSO-JSN):",
      "                    certification JSON on disk validated against the PINNED FedRAMP",
      "                    schemas — rampscan's own exports or a document another tool wrote.",
      "                    Defaults to <out>/exports/; takes a file or a directory. Also checks",
      "                    each document's own conformance stamp AGAINST a fresh validation, so",
      "                    a file claiming a verdict it no longer earns fails. Exits 1 on any",
      "                    violation, disagreement, or unresolvable schema — never a skip",
      "  gaps              the gap register as a computation (plan Q3 exit): every G1–G6, G8,",
      "                    G13 row, each citing its rule id and the evidence digest where",
      "                    evidence exists to cite. Accepts --class a|b|c|d like frontier",
      "  owed [ksi-id]     the owed side (SPEC §12): what any (KSI, class) pair owes — statement,",
      "                    method floor, validation window, artifact count — every number read",
      "                    from the pinned JSON. Accepts --class a|b|c|d (reporting is a what-if;",
      "                    the scheduler still refuses d). --rules <file> loads the canonical",
      "                    fedramp-consolidated-rules.json instead of the ramprules slices",
      "",
      "options:",
      "  --out <dir>       scan/daemon output directory (default: ./rampscan-out);",
      "                    serve tails <out>/daemon-events.jsonl into the console",
      "  --ledger <dir>    append-only evidence ledger (default: ./rampscan-ledger)",
      "  --keys <dir>      signing keypair dir (default: ./rampscan-keys)",
      "  --db <path>       board/rebuild: SQLite projection path (default: ./rampscan-projection.db for rebuild)",
      "  --dataset <dir>   ramprules derived-slice dir (default: docs/context/ramprules/derived)",
      "  --pin <version>   dataset version pin (default: " + DEFAULT_DATASET_PIN + ")",
      "  --recipes <dir>   commit-plane recipe dir (default: recipes/commit)",
      "  --adjudications <dir>  frontier: per-control disposition dir (default: recipes/adjudications)",
      "  --repo <name>     ingest: the offering/repo whose register the evidence joins (required —",
      "                    the row key is never guessed)",
      "  --strict          frontier: exit 1 on a pipeline-unreviewed control, not only a broken link",
      "  --class <b|c>     target cert class → MVX window (b=7d, c=3d; default: b).",
      "                    owed, frontier, gaps and exports: also accept a and d — reporting",
      "                    is a what-if",
      "                    against that class's floors (SPEC §12.3/§12.5); the scheduler still",
      "                    refuses d",
      "  --rules <file>    owed: load the canonical fedramp-consolidated-rules.json (Path B",
      "                    of the dual-source contract) instead of the ramprules slices",
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
      "  --markdown        check: the pull-request comment (N2a) instead of the text reading —",
      "                    EMPTY when nothing would be violated, because a clean run gets no comment",
      "  --run-url <url>   check --markdown: the CI run to link in the comment footer",
      "  --baseline-ref <ref>  check: a git ref whose TREE is dry-run as the baseline, so the",
      "                    comment can tell a violation this tree introduced from one it inherited.",
      "                    A pull request's base commit is the intended argument. Without it the",
      "                    board is the baseline, and with no ledger there is none at all",
      "  --schema <file>   conformance: force a pinned FedRAMP schema instead of resolving",
      "                    one per document from its stamp or its filename",
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
      rules: { type: "string" },
      adjudications: { type: "string" },
      repo: { type: "string" },
      strict: { type: "boolean" },
      "by-controls": { type: "boolean" },
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
      markdown: { type: "boolean" },
      "run-url": { type: "string" },
      "baseline-ref": { type: "string" },
      schema: { type: "string" },
      "no-color": { type: "boolean" },
    },
  });

  const [command, target] = positionals;
  const ledgerDir = values.ledger ?? "./rampscan-ledger";
  const keysDir = values.keys ?? "./rampscan-keys";
  const datasetDir = values.dataset ?? join(REPO_ROOT, "docs/context/ramprules/derived");
  const datasetPin = values.pin ?? DEFAULT_DATASET_PIN;
  const recipesDir = values.recipes ?? join(REPO_ROOT, "recipes/commit");
  const adjudicationsDir = values.adjudications ?? join(REPO_ROOT, "recipes/adjudications");
  const useColor = values["no-color"] ? false : (process.stdout.isTTY ?? false);
  const certClass = (values.class ?? "b") as CertClass;
  // `owed` and `frontier` report against all four classes (SPEC §12.3/§12.5
  // — a what-if, not a schedule); every other consumer of --class drives the
  // scheduler, whose refusal of a and d stands until §11 q6 is settled.
  if (
    command !== "owed" &&
    command !== "frontier" &&
    command !== "gaps" &&
    command !== "exports" &&
    certClass !== "b" &&
    certClass !== "c"
  ) {
    usage();
  }

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
        ...(values["baseline-ref"] !== undefined
          ? { baselineRef: values["baseline-ref"] }
          : {}),
        certClass,
        log: (line) => console.error(`· ${line}`),
      });
      if (values.json) console.log(JSON.stringify(outcome, null, 2));
      else if (values.markdown) {
        // The comment or nothing. An empty stdout is the signal the action
        // reads for "no comment belongs on this pull request" — it is not a
        // failure to render, it is the rendering of a clean tree.
        const body = renderCheckComment(outcome, {
          ...(values["run-url"] !== undefined ? { runUrl: values["run-url"] } : {}),
        });
        if (body !== undefined) console.log(body);
      } else console.log(renderCheck(outcome, useColor));
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

    case "ingest": {
      if (!target) usage();
      if (values.repo === undefined) {
        console.error("ingest requires --repo <name> — the register's row key is never guessed");
        process.exit(2);
      }
      await ingest({
        path: target,
        repo: values.repo,
        datasetDir,
        datasetPin,
        ledgerDir,
        keysDir,
        log: (line) => console.log(line),
      });
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
      const rebuildCatalog = await loadKsiCatalogFromSlices(datasetDir, datasetPin);
      const report = await rebuild({
        ledgerDir,
        recipesDir,
        dbPath: values.db ?? "./rampscan-projection.db",
        windowMs: windowMsFor(certClass),
        // the pivot's fold inputs (Q2), same as serve — so the byte-equality
        // proof covers the method register rather than an empty one
        methods: deriveCatalogMethods(
          await loadRecipes(recipesDir),
          allCollectors.map((c) => c.manifest),
        ),
        ksiIds: rebuildCatalog.ksis.map((k) => k.id),
        methodFloor: rebuildCatalog.floors[certClass].minPerKsi,
        historyFloorMonths: rebuildCatalog.historyFloors[certClass].months,
        machineWindow: rebuildCatalog.windows[certClass],
        nonMachineWindow: rebuildCatalog.nonMachineWindow,
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
        // awaited, not fired: the process exits on the next turn and the last
        // events append is still in flight until stop() drains it
        const shutdown = (): void => {
          void handle.stop().then(() => {
            console.error(`· daemon stopped after ${handle.scanCount()} scan(s)`);
            resolvePromise();
          });
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
      const recipes = await loadRecipes(recipesDir);
      const map = buildFrontier({
        frontier: dataset.frontier(),
        adjudications: await loadAdjudications(adjudicationsDir),
        recipes,
        collectors: allCollectors,
        datasetVersion: dataset.version(),
        ksiReachedControls: dataset.ksiReachedControls(),
        // ground rule 10's catalog arm: upstream's own recipes, which the
        // frontier cannot report because a control upstream has answered has
        // left it. Passed from here rather than read inside `buildFrontier`
        // so the derivation stays pure and testable without a dataset.
        upstreamRecipesFor: (controlId) => dataset.upstreamRecipesFor(controlId),
      });
      if (values["by-controls"]) {
        // the legacy view, unchanged (ground rule 1: neither view is removed
        // until a reviewed decision does it)
        if (values.json) console.log(JSON.stringify(map, null, 2));
        else console.log(renderFrontier(map, useColor));
      } else {
        // frontier v2 (SPEC §12.5): the KSI register — the owed side (Q1) ×
        // the derived methods (Q2.2) × the projector's method register over
        // the local ledger (Q2.3). The broken-link and --strict gates below
        // run on the SAME control map either way: the register view changes
        // the denominator, never the checks.
        const registerClass = (values.class ?? "b") as OfferingClass;
        if (!OFFERING_CLASSES.includes(registerClass)) usage();
        const catalog = await loadKsiCatalogFromSlices(datasetDir, datasetPin);
        const methods = deriveCatalogMethods(
          recipes,
          allCollectors.map((c) => c.manifest),
        );
        const projector = createProjector({
          recipes,
          methods,
          ksiIds: catalog.ksis.map((k) => k.id),
          methodFloor: catalog.floors[registerClass].minPerKsi,
          historyFloorMonths: catalog.historyFloors[registerClass].months,
          machineWindow: catalog.windows[registerClass],
          nonMachineWindow: catalog.nonMachineWindow,
        });
        const projection = await projector.fold(createLocalLedger(ledgerDir));
        const view = buildKsiRegister({
          catalog,
          offeringClass: registerClass,
          methods,
          methodRegisters: projection.methodRegisters,
          frontier: map,
        });
        view.frontierOverlay = DEFAULT_OVERLAY_PINS["automation-frontier.json"] ?? "";
        if (values.json) console.log(JSON.stringify(view, null, 2));
        else console.log(renderKsiRegister(view, useColor, new Date()));
      }
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

    case "gaps": {
      // The gap register as a computation (plan Q3 exit gate): the same
      // joins the frontier makes — owed side × derived methods × the fold
      // over the local ledger × the control frontier — rendered as one row
      // per gap instance, each citing its rule id and the evidence digest
      // where evidence exists. Nothing probed, nothing typed.
      const dataset = await loadLocalDataset(datasetDir, datasetPin);
      const recipes = await loadRecipes(recipesDir);
      const map = buildFrontier({
        frontier: dataset.frontier(),
        adjudications: await loadAdjudications(adjudicationsDir),
        recipes,
        collectors: allCollectors,
        datasetVersion: dataset.version(),
        ksiReachedControls: dataset.ksiReachedControls(),
        upstreamRecipesFor: (controlId) => dataset.upstreamRecipesFor(controlId),
      });
      const registerClass = (values.class ?? "b") as OfferingClass;
      if (!OFFERING_CLASSES.includes(registerClass)) usage();
      const catalog = await loadKsiCatalogFromSlices(datasetDir, datasetPin);
      const methods = deriveCatalogMethods(
        recipes,
        allCollectors.map((c) => c.manifest),
      );
      const projector = createProjector({
        recipes,
        methods,
        ksiIds: catalog.ksis.map((k) => k.id),
        methodFloor: catalog.floors[registerClass].minPerKsi,
        historyFloorMonths: catalog.historyFloors[registerClass].months,
        machineWindow: catalog.windows[registerClass],
        nonMachineWindow: catalog.nonMachineWindow,
      });
      const projection = await projector.fold(createLocalLedger(ledgerDir));
      const view = buildGapRegister({
        catalog,
        offeringClass: registerClass,
        methods,
        methodRegisters: projection.methodRegisters,
        vulnerabilities: projection.vulnerabilities,
        frontier: map,
      });
      if (values.json) console.log(JSON.stringify(view, null, 2));
      else console.log(renderGapRegister(view, useColor));
      if (map.problems.length > 0) {
        console.error(
          `\n${map.problems.length} broken link(s) in the adjudication overlay:\n` +
            map.problems.map((p) => `  - ${p}`).join("\n"),
        );
        process.exit(1);
      }
      return;
    }
    case "exports": {
      // The two FedRAMP schema-target exports (plan Q5.1 — G10, G12): a
      // Certification Package Overview and an Ongoing Certification Report as
      // JSON valid against the PINNED FedRAMP schemas. Generated exactly as
      // OpenVEX is — an export, no new state, regenerated per scan — from the
      // scanned repo's declared `offering` block joined to the fold over the
      // local ledger. Exits 1 on a nonconforming document (FRC-CSO-JSN).
      const offeringRoot = target ?? ".";
      const offering = await loadOffering(offeringRoot);
      if (offering === undefined) {
        console.error(
          `no \`offering\` block in ${join(offeringRoot, "rampscan.config.json")} — an offering nobody declared is a claim never made, and neither FedRAMP document can be generated from an evidence ledger alone (SPEC §12, plan Q5.1). Declare one to generate the Certification Package Overview`,
        );
        process.exit(1);
      }
      const exportClass = (values.class ?? "b") as OfferingClass;
      if (!OFFERING_CLASSES.includes(exportClass)) usage();
      const exportCatalog = await loadKsiCatalogFromSlices(datasetDir, datasetPin);
      const exportRecipes = await loadRecipes(recipesDir);
      const exportProjector = createProjector({
        recipes: exportRecipes,
        methods: deriveCatalogMethods(
          exportRecipes,
          allCollectors.map((c) => c.manifest),
        ),
        ksiIds: exportCatalog.ksis.map((k) => k.id),
        methodFloor: exportCatalog.floors[exportClass].minPerKsi,
        historyFloorMonths: exportCatalog.historyFloors[exportClass].months,
        machineWindow: exportCatalog.windows[exportClass],
        nonMachineWindow: exportCatalog.nonMachineWindow,
      });
      const exportProjection = await exportProjector.fold(createLocalLedger(ledgerDir));
      // one offering per export: when the ledger holds several repos, --repo
      // names the one this document speaks for rather than summing strangers
      const exportRepos = [...new Set(exportProjection.methodRegisters.map((r) => r.repo))].sort();
      if (exportRepos.length > 1 && values.repo === undefined) {
        console.error(
          `the ledger holds ${exportRepos.length} offerings (${exportRepos.join(", ")}) — name the one this document speaks for with --repo. A document summing two offerings would describe neither`,
        );
        process.exit(1);
      }
      const exportRepo = values.repo ?? exportRepos[0];
      const exportResult = await writeFedrampExports({
        schemaRoot: REPO_ROOT,
        exportsDir: join(values.out ?? "./rampscan-out", "exports"),
        offering,
        offeringClass: exportClass,
        ...(exportRepo !== undefined ? { repo: exportRepo } : {}),
        projectedAt: exportProjection.projectedAt,
        datasetVersion: exportProjection.datasetVersion,
        methodRegisters: exportProjection.methodRegisters.filter(
          (r) => exportRepo === undefined || r.repo === exportRepo,
        ),
        vulnerabilities: exportProjection.vulnerabilities.filter(
          (v) => exportRepo === undefined || v.repo === exportRepo,
        ),
        drift: exportProjection.drift.filter(
          (d) => exportRepo === undefined || d.repo === exportRepo,
        ),
      });
      if (values.json) console.log(JSON.stringify(exportResult, null, 2));
      else console.log(renderFedrampExports(exportResult));
      if (!exportResult.conformant) process.exit(1);
      return;
    }
    case "conformance": {
      // The package conformance check (plan Q5.2 — G10, `FRC-CSO-JSN`). Reads
      // documents from disk rather than from a fold, so it answers for a
      // certification package another tool wrote, one edited by hand, or one
      // this appliance generated before the pins moved. Fails closed: a
      // document whose schema cannot be resolved is an exit, not a skip.
      const conformanceTarget = target ?? join(values.out ?? "./rampscan-out", "exports");
      let conformanceResult;
      try {
        conformanceResult = await checkConformance({
          schemaRoot: REPO_ROOT,
          target: conformanceTarget,
          ...(values.schema !== undefined ? { schema: values.schema } : {}),
        });
      } catch (cause) {
        console.error(
          `conformance check refused: ${cause instanceof Error ? cause.message : String(cause)}`,
        );
        process.exit(1);
      }
      if (values.json) console.log(JSON.stringify(conformanceResult, null, 2));
      else console.log(renderConformance(conformanceResult));
      if (!conformanceResult.conformant) process.exit(1);
      return;
    }
    case "owed": {
      // The Q1 exit gate: the owed state for any (KSI, class) pair, every
      // number read from the pinned JSON. Both legs of the dual-source
      // contract (SPEC §12.4) reach this one surface: the ramprules slices by
      // default, the canonical rules JSON under --rules — same catalog value,
      // by test.
      const owedClass = (values.class ?? "b") as OfferingClass;
      if (!OFFERING_CLASSES.includes(owedClass)) usage();
      const catalog = values.rules
        ? await loadKsiCatalogFromRules(values.rules, datasetPin)
        : await loadKsiCatalogFromSlices(datasetDir, datasetPin);
      if (values.json) {
        console.log(
          JSON.stringify(
            target ? { class: owedClass, ksi: catalog.ksis.find((k) => k.id === target) } : catalog,
            null,
            2,
          ),
        );
        if (target && !catalog.ksis.some((k) => k.id === target)) process.exit(1);
        return;
      }
      if (target) {
        const detail = renderOwedKsi(catalog, owedClass, target);
        if (detail === undefined) {
          console.error(
            `no such KSI at this pin: ${target} (${catalog.ksis.length} ids — try \`rampscan owed\`)`,
          );
          process.exit(1);
        }
        console.log(detail);
      } else {
        console.log(renderOwed(catalog, owedClass));
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
