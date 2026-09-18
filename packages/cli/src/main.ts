#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { parseArgs } from "node:util";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { allCollectors, loadToolManifest } from "@rampscan/collectors";
import {
  DEFAULT_DATASET_PIN,
  DEFAULT_OVERLAY_PINS,
  OFFERING_CLASSES,
  loadKsiCatalog,
  loadRuleRegister,
  loadLocalDataset,
  type OfferingClass,
} from "@rampscan/dataset";
import { createLocalLedger } from "@rampscan/ledger";
import { createProjector } from "@rampscan/projector";
import type { CertClass } from "@rampscan/core";
import { Cadence } from "@rampscan/schema";
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
import { buildOngoingCertificationReport, buildPackageOverview } from "./fedramp-exports.js";
import { checkConformance, renderConformance } from "./fedramp-conformance.js";
import { buildRejectionRegister, renderRejectionRegister } from "./submission.js";
import { loadOffering } from "./offering.js";
import { mintComputedArtifact } from "./artifacts.js";
import { scaffoldArtifact } from "./artifacts-scaffold.js";
import {
  buildArtifactsView,
  checkArtifacts,
  renderArtifact,
  renderArtifactCheck,
  renderArtifacts,
} from "./artifacts-view.js";
import { buildKsiRegister, renderKsiRegister } from "./ksi-register.js";
import { startDaemon } from "./daemon.js";
import { computeRepoModel, renderRepoModel, serializeRepoModel } from "./model.js";
import { renderOwed, renderOwedKsi } from "./owed.js";
import { DEFAULT_ALLOWLIST_PATH, loadAwsActionAllowlist } from "./aws-actions.js";
import { DEFAULT_BINDINGS_PATH, loadAwsLiteralBindings } from "./aws-bindings.js";
import { classifyAwsRecipes, loadAwsConfig, renderAwsRecipes, windowEnding } from "./aws-recipes.js";
import { recordRunnerRegistration, runnerRegistry } from "./runner-registry.js";
import { runnerPolicy } from "./runner-policy.js";
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
//   rampscan artifacts       the five owed per KSI (SDR-CSX-KSI): list, show one,
//                            scaffold the two that are yours, generate the three
//                            that are computed, check that what exists is sound
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
      "                    a submission file, an Evidence/ tree with ingest-manifest.json, or a",
      "                    machine-readable assessment package (.yaml; needs --cadence, and",
      "                    --crosswalk when its KSI ids are an earlier catalog's).",
      "                    Requires --repo; validates against the pinned catalog; refuses the",
      "                    whole batch before signing anything. Never executes an AWS call",
      "  board             show the projection: registers, live evidence, graveyard (--json for the fold)",
      "  board --as-of <iso>  the same projection at a past instant, refolded from the ledger",
      "  board --since previous|<iso>  what moved since a prior scan's board (I2d)",
      "  rebuild           rebuild projection stores from the ledger and PROVE projection ≡ ledger",
      "  serve             start PocketBase + the Next.js console (the visual board);",
      "                    --repo <path> names the repository cloud runs are requested for",
      "                    (its rampscan.config.json aws block; default: this checkout)",
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
      "  artifacts [KSI]   the five owed artifacts per KSI (SDR-CSX-KSI, SPEC \u00a713): every cell",
      "                    naming its source and its age, with the empty ones as a work queue.",
      "                    With a KSI, the long view of that one indicator's five slots",
      "  artifacts scaffold <KSI> --artifact 1|3   write the stub for an artifact that is YOURS:",
      "                    what rampscan measured is filled in, the claim is left blank, and the",
      "                    reason-for-absence path is offered beside it. Never drafts (\u00a713.4)",
      "  artifacts generate <KSI>  mint the computed artifacts (2, 4, 5) from the fold and append",
      "                    them signed; prints the reason where there is nothing honest to compute",
      "  artifacts check   is the plane SOUND \u2014 declarations that stopped resolving, bodies",
      "                    past VDR-TFR-NMV, judgments about bytes that were revised. An empty",
      "                    slot is not a finding here: how much is owed is frontier's question",
      "  exports           the two FedRAMP schema-target exports (plan Q5): a Certification",
      "                    Package Overview (FRC-CSO-PKG) and an Ongoing Certification Report",
      "                    (CCM-OCR-AVL) as JSON valid against the PINNED FedRAMP schemas —",
      "                    the scanned repo's declared `offering` block joined to the fold.",
      "                    Lands in <out>/exports/fedramp/. Exits 1 on a nonconforming document",
      "                    (FRC-CSO-JSN); every document carries its own conformance verdict",
      "  conformance [path]  the package conformance check (plan Q5.2 — G10, FRC-CSO-JSN):",
      "                    certification JSON on disk validated against the PINNED FedRAMP",
      "                    schemas — rampscan's own exports or a document another tool wrote.",
      "                    Defaults to <out>/exports/fedramp/; takes a file or a directory. Also",
      "                    checks each document's own conformance stamp AGAINST a fresh",
      "                    validation, so a file claiming a verdict it no longer earns fails.",
      "                    Exits 1 on any violation, disagreement, or unresolvable schema",
      "                    — never a skip",
      "  submission [path]   the rejection register (P2, community #167): one section per",
      "                    reason FedRAMP published for rejecting a 20x submission, each",
      "                    carrying the reason's own words and the rules that bind it — the",
      "                    per-class rule denominator nobody publishes (129 MUST/SHOULD at",
      "                    class b), the KSIs with no method, the schema-bearing rules with",
      "                    no example, and the conformance verdict reprojected. The",
      "                    trust-center gate prints UNMEASURED always: it is FedRAMP's first",
      "                    listed reason and a property of a live URL this appliance does not",
      "                    fetch (#213). Exits 1 only on a rejection the appliance can stand",
      "                    behind — an unaddressed rule is counted and named, never accused,",
      "                    until the declaration surface exists. Accepts --class a|b|c|d",
      "  gaps              the gap register as a computation (plan Q3 exit): every G1–G6, G8,",
      "                    G13 row, each citing its rule id and the evidence digest where",
      "                    evidence exists to cite. Accepts --class a|b|c|d like frontier",
      "  recipes --aws [path]  which pinned AWS recipes a client runner could run (plan T1-5):",
      "                    every command's action against the reviewed allowlist, every example",
      "                    literal against the reviewed binding table, every placeholder against",
      "                    <path>/rampscan.config.json's `aws` block — and every manual recipe with",
      "                    every reason. Computed, never typed. Nothing executes",
      "  runner register|revoke --name <slug> --public-key <pem-file> --host <where> --account <id>",
      "                    --partition aws|aws-us-gov --proposed-by <id> --approved-by <id> --repo <name>",
      "                    the fourth two-key write (plan T3-2): an approver's key turn over a",
      "                    runner's public key. Only a registered key's transcripts are read",
      "  runner list       what stands in the registry: name, keyid, host, expected account",
      "  runner policy [path]  the IAM policy for the runner's role (plan T3-3): the allowlist's actions",
      "                    for exactly the recipes runnable under <path>/rampscan.config.json's aws block,",
      "                    plus the runner's own two calls. Generated, never typed; Resource \"*\"",
      "  owed [ksi-id]     the owed side (SPEC §12): what any (KSI, class) pair owes — statement,",
      "                    method floor, validation window, artifact count — every number read",
      "                    from the pinned JSON. Accepts --class a|b|c|d (reporting is a what-if;",
      "                    the scheduler still refuses d)",
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
      "  --crosswalk <file>  ingest (package): the reviewed KSI crosswalk placing an earlier",
      "                    catalog's ids at this pin (recipes/crosswalks/)",
      "  --cadence <c>     ingest (package): the declared refresh cycle — a package carries none",
      "  --strict          frontier: exit 1 on a pipeline-unreviewed control, not only a broken link",
      "  --class <b|c>     target cert class → MVX window (b=7d, c=3d; default: b).",
      "                    owed, frontier, gaps and exports: also accept a and d — reporting",
      "                    is a what-if",
      "                    against that class's floors (SPEC §12.3/§12.5); the scheduler still",
      "                    refuses d",
      "  --rules <file>    path to fedramp-consolidated-rules.json (Path B of the dual-source",
      "                    contract). Loaded beside the ramprules slices and cross-checked",
      "                    against them at every command; defaults to the vendored copy",
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
      crosswalk: { type: "string" },
      cadence: { type: "string" },
      strict: { type: "boolean" },
      "by-controls": { type: "boolean" },
      aws: { type: "boolean" },
      name: { type: "string" },
      "public-key": { type: "string" },
      host: { type: "string" },
      account: { type: "string" },
      partition: { type: "string" },
      "proposed-by": { type: "string" },
      "approved-by": { type: "string" },
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
      artifact: { type: "string" },
      path: { type: "string" },
      "no-color": { type: "boolean" },
    },
  });

  const [command, target] = positionals;
  const ledgerDir = values.ledger ?? "./rampscan-ledger";
  const keysDir = values.keys ?? "./rampscan-keys";
  const datasetDir = values.dataset ?? join(REPO_ROOT, "docs/context/ramprules/derived");
  // Both legs of the dual-source contract are vendored at the same pin, and
  // R0.2 loads BOTH by default (SPEC §13.7): class applicability is an owed
  // fact only the canonical rules JSON states, and the slices alone would
  // divide every class-b meter by 46 where the rules oblige 41. `--rules`
  // now points the canonical leg somewhere else rather than switching paths.
  const rulesFile =
    values.rules ?? join(REPO_ROOT, "docs/context/fedramp-rules/fedramp-consolidated-rules.json");
  const datasetPin = values.pin ?? DEFAULT_DATASET_PIN;
  const catalogSources = { derivedDir: datasetDir, rulesFile, pin: datasetPin };
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
    command !== "artifacts" &&
    command !== "exports" &&
    command !== "submission" &&
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
      if (values.cadence !== undefined && !Cadence.options.includes(values.cadence as Cadence)) {
        console.error(`--cadence must be one of ${Cadence.options.join("|")}, not ${values.cadence}`);
        process.exit(2);
      }
      await ingest({
        path: target,
        repo: values.repo,
        datasetDir,
        rulesFile,
        datasetPin,
        ledgerDir,
        keysDir,
        crosswalk: values.crosswalk,
        cadence: values.cadence as Cadence | undefined,
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
      const rebuildCatalog = await loadKsiCatalog(catalogSources);
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
        const catalog = await loadKsiCatalog(catalogSources);
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

    case "artifacts": {
      // `rampscan artifacts` (plan R1.5, SPEC §13) — the artifact plane's
      // surface. The list is a work queue with a command attached: every empty
      // cell says whose move is next, and for artifacts 1 and 3 the honest
      // answer is always "yours", because §13.4 forbids this appliance from
      // drafting them however easy that would be to ship.
      const artifactsClass = (values.class ?? "b") as OfferingClass;
      if (!OFFERING_CLASSES.includes(artifactsClass)) usage();
      const catalog = await loadKsiCatalog(catalogSources);
      const recipes = await loadRecipes(recipesDir);
      const methods = deriveCatalogMethods(
        recipes,
        allCollectors.map((c) => c.manifest),
      );
      const projector = createProjector({
        recipes,
        methods,
        ksiIds: catalog.ksis.map((k) => k.id),
        methodFloor: catalog.floors[artifactsClass].minPerKsi,
        historyFloorMonths: catalog.historyFloors[artifactsClass].months,
        machineWindow: catalog.windows[artifactsClass],
        nonMachineWindow: catalog.nonMachineWindow,
      });
      const projection = await projector.fold(createLocalLedger(ledgerDir));
      // one offering per document (§12.11): with several repos in a ledger the
      // caller names which, rather than the view picking one and not saying
      const repos = [...new Set(projection.methodRegisters.map((r) => r.repo))].sort();
      if (values.repo === undefined && repos.length > 1) {
        console.error(
          `this ledger holds ${repos.length} repos — name one with --repo:\n` +
            repos.map((r) => `  ${r}`).join("\n"),
        );
        process.exit(1);
      }
      const artifactsRepo = values.repo ?? repos[0] ?? null;
      const subcommand = positionals[1];

      if (subcommand === "scaffold") {
        const ksiId = positionals[2];
        const slot = Number(values.artifact ?? "1");
        if (ksiId === undefined || (slot !== 1 && slot !== 3)) {
          console.error(
            "usage: rampscan artifacts scaffold <KSI> --artifact 1|3\n" +
              "  Only 1 and 3 are scaffolded: they are the provider's own claims (SPEC §13.4).\n" +
              "  2, 4 and 5 are computed — `rampscan artifacts generate <KSI>`.",
          );
          process.exit(1);
        }
        const register = projection.methodRegisters.find(
          (r) => r.ksi === ksiId && (artifactsRepo === null || r.repo === artifactsRepo),
        );
        const result = await scaffoldArtifact({
          catalog,
          ksiId,
          artifact: slot,
          // the repository the stub is written into — the working directory,
          // because a scaffold belongs beside the code it describes and this
          // command is run from the repo like every other authoring step
          root: process.cwd(),
          ...(register !== undefined ? { register } : {}),
          ...(values.path !== undefined ? { path: values.path } : {}),
        });
        console.log(
          [
            `wrote ${result.path}`,
            "",
            "  What rampscan measured is filled in. The claim is not: artifacts 1 and 3 are",
            "  yours, and this tool does not draft them (SPEC §13.4). The reason-for-absence",
            "  path is offered beside it and satisfies the rule just as well.",
            "",
            "  Then declare it, so the scan signs it and the clock starts:",
            "",
            ...JSON.stringify({ artifacts: [result.declaration] }, null, 2)
              .split("\n")
              .map((l) => `    ${l}`),
            "",
          ].join("\n"),
        );
        break;
      }

      if (subcommand === "generate") {
        const ksiId = positionals[2];
        if (ksiId === undefined) {
          console.error("usage: rampscan artifacts generate <KSI> [--artifact 2|4|5]");
          process.exit(1);
        }
        if (artifactsRepo === null) {
          console.error("this ledger holds no repo to generate against — run a scan first");
          process.exit(1);
        }
        const slots =
          values.artifact === undefined
            ? ([2, 4, 5] as const)
            : ([Number(values.artifact)] as ReadonlyArray<number>);
        for (const slot of slots) {
          if (slot !== 2 && slot !== 4 && slot !== 5) {
            console.error(
              `artifact ${slot} is not computed: 1 and 3 are the provider's own claims ` +
                `(SPEC §13.4) — rampscan artifacts scaffold ${ksiId} --artifact ${slot}`,
            );
            process.exit(1);
          }
          const minted = await mintComputedArtifact({
            repo: artifactsRepo,
            ksiId,
            artifact: slot,
            projection,
            offeringClass: artifactsClass,
            datasetDir,
            datasetPin,
            ledgerDir,
            keysDir,
          });
          console.log(
            minted.minted
              ? `  ${ksiId} #${slot} — minted ${minted.bodyDigest.slice(0, 12)}… → ${minted.digest.slice(0, 12)}…`
              : `  ${ksiId} #${slot} — not minted: ${minted.reason}`,
          );
        }
        break;
      }

      const view = buildArtifactsView({
        catalog,
        offeringClass: artifactsClass,
        repo: artifactsRepo,
        methodRegisters: projection.methodRegisters,
      });

      if (subcommand === "check") {
        const problems = checkArtifacts(view);
        if (values.json) console.log(JSON.stringify({ view, problems }, null, 2));
        else console.log(renderArtifactCheck(view, problems));
        if (problems.length > 0) process.exit(1);
        break;
      }

      // `artifacts show <KSI>` and the bare `artifacts <KSI>` are the same
      // view: the verb reads better in prose and in a scaffold's own pointer,
      // and typing the id alone is what an operator does at a prompt
      const showing = subcommand === "show" ? positionals[2] : subcommand;
      if (subcommand === "show" && showing === undefined) {
        console.error("usage: rampscan artifacts show <KSI>");
        process.exit(1);
      }
      if (showing !== undefined) {
        const row = view.rows.find((r) => r.ksi === showing);
        if (row === undefined) {
          console.error(`unknown KSI ${showing} — not in the pinned catalog at ${catalog.datasetVersion}`);
          process.exit(1);
        }
        if (values.json) console.log(JSON.stringify(row, null, 2));
        else console.log(renderArtifact(view, row, new Date()));
        break;
      }

      if (values.json) console.log(JSON.stringify(view, null, 2));
      else console.log(renderArtifacts(view, new Date()));
      break;
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
      const catalog = await loadKsiCatalog(catalogSources);
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
      const exportCatalog = await loadKsiCatalog(catalogSources);
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
        // The schema-gated family gets its own directory (R0.3, SPEC §13.8):
        // `scan` writes openvex.json into <out>/exports/, and a conformance
        // check whose default path met a document no FedRAMP schema gates
        // would exit — correctly and uselessly.
        exportsDir: join(values.out ?? "./rampscan-out", "exports", "fedramp"),
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
      const conformanceTarget =
        target ?? join(values.out ?? "./rampscan-out", "exports", "fedramp");
      let conformanceResult: Awaited<ReturnType<typeof checkConformance>>;
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
    case "submission": {
      // The rejection register (P2-3, docs/RESEARCH-REJECTION-LINTER.md §4):
      // the five reasons FedRAMP published for rejecting a 20x submission
      // (FedRAMP/community#167), plus the KSI half of reason 3.
      //
      // Every arm is OPTIONAL and a missing arm prints as unmeasured rather
      // than clean, because this command answers a question about a package
      // that may not exist yet. What is never optional is the denominator: the
      // rule register loads from the pin, so "129 MUST/SHOULD applicable at
      // class b" is stated even when nothing else can be.
      const submissionClass = (values.class ?? "b") as OfferingClass;
      if (!OFFERING_CLASSES.includes(submissionClass)) usage();
      const ruleRegister = await loadRuleRegister(rulesFile, datasetPin);

      // the KSI half: the same joins `gaps` makes, so reason 3's KSI arm is
      // measured rather than skipped — this is the half rampscan is best at
      const submissionDataset = await loadLocalDataset(datasetDir, datasetPin);
      const submissionRecipes = await loadRecipes(recipesDir);
      const submissionCatalog = await loadKsiCatalog(catalogSources);
      const submissionMethods = deriveCatalogMethods(
        submissionRecipes,
        allCollectors.map((c) => c.manifest),
      );
      const submissionProjection = await createProjector({
        recipes: submissionRecipes,
        methods: submissionMethods,
        ksiIds: submissionCatalog.ksis.map((k) => k.id),
        methodFloor: submissionCatalog.floors[submissionClass].minPerKsi,
        historyFloorMonths: submissionCatalog.historyFloors[submissionClass].months,
        machineWindow: submissionCatalog.windows[submissionClass],
        nonMachineWindow: submissionCatalog.nonMachineWindow,
      }).fold(createLocalLedger(ledgerDir));
      const submissionKsis = buildKsiRegister({
        catalog: submissionCatalog,
        offeringClass: submissionClass,
        methods: submissionMethods,
        methodRegisters: submissionProjection.methodRegisters,
        frontier: buildFrontier({
          frontier: submissionDataset.frontier(),
          adjudications: await loadAdjudications(adjudicationsDir),
          recipes: submissionRecipes,
          collectors: allCollectors,
          datasetVersion: submissionDataset.version(),
          ksiReachedControls: submissionDataset.ksiReachedControls(),
          upstreamRecipesFor: (controlId) => submissionDataset.upstreamRecipesFor(controlId),
        }),
      });

      // the offering declaration, when the target repo carries one. Absent is
      // a legitimate state: reason 5 and the trust-center row then say so.
      const submissionRoot = target ?? process.cwd();
      let submissionOffering: Awaited<ReturnType<typeof loadOffering>> | undefined;
      try {
        submissionOffering = await loadOffering(submissionRoot);
      } catch {
        submissionOffering = undefined;
      }

      // reason 1, 2 and 5, REPROJECTED: the exports' own `problems` channel,
      // read rather than recomputed (§5) — and read HERE rather than only in
      // the unit suite, which is where it was until this commit. The register
      // declared the reprojection and the shipped command handed it nothing to
      // reproject, so three sections quietly carried only what they could
      // compute for themselves and an undeclared next-OCR date reached nobody.
      // Building the two documents is pure and writes nothing; only the
      // problems are taken.
      const submissionRepos = [
        ...new Set(submissionProjection.methodRegisters.map((r) => r.repo)),
      ].sort();
      const submissionRepo =
        values.repo ?? (submissionRepos.length === 1 ? submissionRepos[0] : undefined);
      let submissionProblems: string[] | undefined;
      if (submissionOffering === undefined) {
        // nothing to read: the sections that would have carried these already
        // say an offering was not supplied
      } else if (submissionRepos.length > 1 && submissionRepo === undefined) {
        // Not "pick the first", which is what §12.11's one-offering-per-document
        // rule refuses: `FRC-APP-FCP` freshness over a union of offerings would
        // let a fresh one mask a stale one, which is the optimistic direction.
        console.error(
          `the ledger holds ${submissionRepos.length} offerings (${submissionRepos.join(", ")}) — name the one this register speaks for with --repo to read the exports' problems channel; FRC-APP-FCP freshness over a union of offerings would let a fresh one mask a stale one`,
        );
      } else {
        const submissionExportInput = {
          offering: submissionOffering,
          offeringClass: submissionClass,
          ...(submissionRepo !== undefined ? { repo: submissionRepo } : {}),
          projectedAt: submissionProjection.projectedAt,
          datasetVersion: submissionProjection.datasetVersion,
          methodRegisters: submissionProjection.methodRegisters.filter(
            (r) => submissionRepo === undefined || r.repo === submissionRepo,
          ),
          vulnerabilities: submissionProjection.vulnerabilities.filter(
            (v) => submissionRepo === undefined || v.repo === submissionRepo,
          ),
          drift: submissionProjection.drift.filter(
            (d) => submissionRepo === undefined || d.repo === submissionRepo,
          ),
        };
        submissionProblems = [
          ...buildPackageOverview(submissionExportInput).problems,
          ...(buildOngoingCertificationReport(submissionExportInput).export?.problems ?? []),
        ];
      }

      // reason 4, REPROJECTED: `checkConformance` is the one verdict on schema
      // validity and this register does not re-implement it (§5). A directory
      // that is not there leaves the section unmeasured rather than clean.
      const submissionOut = join(values.out ?? "./rampscan-out", "exports", "fedramp");
      let submissionConformance: Awaited<ReturnType<typeof checkConformance>> | undefined;
      try {
        submissionConformance = await checkConformance({
          schemaRoot: REPO_ROOT,
          target: submissionOut,
        });
      } catch {
        submissionConformance = undefined;
      }

      const submissionView = await buildRejectionRegister({
        register: ruleRegister,
        offeringClass: submissionClass,
        ksis: submissionKsis,
        ...(submissionOffering !== undefined ? { offering: submissionOffering } : {}),
        ...(submissionConformance !== undefined ? { conformance: submissionConformance } : {}),
        ...(submissionProblems !== undefined ? { problems: submissionProblems } : {}),
        outDir: submissionOut,
      });
      if (values.json) console.log(JSON.stringify(submissionView, null, 2));
      else console.log(renderRejectionRegister(submissionView, useColor));
      // Only rejections the appliance can stand behind exit 1. An unaddressed
      // rule is not one of them until P2-1 and P2-2 land — see the section's
      // own note, and `submission.test.ts` for why either alternative is worse.
      if (submissionView.rejections > 0) process.exit(1);
      return;
    }
    case "runner": {
      // T3-2: the registry's two verbs and its listing. The console's decide
      // route (T4-2) reaches recordRunnerRegistration the way attestations do
      const verb = target;
      if (verb === "policy") {
        const root = positionals[2] ?? ".";
        const list = await loadAwsActionAllowlist(join(REPO_ROOT, DEFAULT_ALLOWLIST_PATH));
        const dataset = await loadLocalDataset(datasetDir, datasetPin);
        const report = classifyAwsRecipes(
          dataset.recipes(),
          list,
          await loadAwsLiteralBindings(join(REPO_ROOT, DEFAULT_BINDINGS_PATH)),
          await loadAwsConfig(root),
          windowEnding(new Date(), 30),
          datasetPin,
        );
        const { policy, recipes } = runnerPolicy(report, list);
        console.error(
          `rampscan runner policy: ${policy.Statement[1]!.Action.length} read actions for ${recipes.length} runnable recipe(s)` +
            (report.config === undefined ? " (no aws block — placeholders unbound; bind them and the set grows)" : ` under account ${report.config.account_id}`) +
            `, plus ${policy.Statement[0]!.Action.length} of the runner's own`,
        );
        console.log(JSON.stringify(policy, null, 2));
        return;
      }
      if (verb === "list") {
        const registry = await runnerRegistry(createLocalLedger(ledgerDir));
        if (registry.size === 0) console.log("no runner is registered — nothing this appliance would read a transcript from");
        for (const r of registry.values()) {
          console.log(`${r.name}  keyid ${r.keyid.slice(0, 16)}…  on ${r.host}  expected in ${r.account} (${r.partition})  registered ${r.registeredAt} by ${r.approvedBy}`);
        }
        return;
      }
      if (verb !== "register" && verb !== "revoke") usage();
      const need = (k: "name" | "public-key" | "host" | "account" | "partition" | "proposed-by" | "approved-by" | "repo"): string => {
        const v = values[k];
        if (v === undefined || v === "") {
          console.error(`rampscan runner ${verb}: --${k} is required`);
          process.exit(2);
        }
        return v;
      };
      const partition = need("partition");
      if (partition !== "aws" && partition !== "aws-us-gov") usage();
      const { digest, keyid } = await recordRunnerRegistration({
        action: verb === "register" ? "registered" : "revoked",
        runnerName: need("name"),
        publicKeyPem: await readFile(need("public-key"), "utf8"),
        host: need("host"),
        account: need("account"),
        partition,
        repo: need("repo"),
        proposedBy: need("proposed-by"),
        approvedBy: need("approved-by"),
        datasetVersion: datasetPin,
        ledgerDir,
        keysDir,
        log: (line) => console.error(line),
      });
      console.log(`${verb === "register" ? "registered" : "revoked"} ${values.name} (keyid ${keyid.slice(0, 12)}…) — ledger ${digest}`);
      return;
    }
    case "recipes": {
      // T1-5: the classification of the pinned overlay, printed from the
      // function the runner will be handed argv by (ground rule 4). `--aws`
      // is the only mode today; the pipeline recipes have `tools` and `model`.
      if (!values.aws) usage();
      const dataset = await loadLocalDataset(datasetDir, datasetPin);
      const report = classifyAwsRecipes(
        dataset.recipes(),
        await loadAwsActionAllowlist(join(REPO_ROOT, DEFAULT_ALLOWLIST_PATH)),
        await loadAwsLiteralBindings(join(REPO_ROOT, DEFAULT_BINDINGS_PATH)),
        await loadAwsConfig(target ?? "."),
        windowEnding(new Date(), 30),
        datasetPin,
      );
      console.log(values.json ? JSON.stringify(report, null, 2) : renderAwsRecipes(report));
      return;
    }
    case "owed": {
      // The Q1 exit gate: the owed state for any (KSI, class) pair, every
      // number read from the pinned JSON. Both legs of the dual-source
      // contract (SPEC §12.4) reach this one surface and are cross-checked
      // against each other at load (R0.2, §13.7) — a disagreement at the same
      // pin is a broken port and is refused here rather than printed.
      const owedClass = (values.class ?? "b") as OfferingClass;
      if (!OFFERING_CLASSES.includes(owedClass)) usage();
      const catalog = await loadKsiCatalog(catalogSources);
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
        // the repository cloud runs are requested for (T4): --repo names it,
        // the same option ingest uses to say whose register evidence joins
        ...(values.repo !== undefined ? { runsRepoRoot: values.repo } : {}),
        ledgerDir: resolve(ledgerDir),
        keysDir: resolve(keysDir),
        recipesDir: resolve(recipesDir),
        datasetDir: resolve(datasetDir),
        rulesFile: resolve(rulesFile),
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
