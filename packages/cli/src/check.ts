import { execFile } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { promisify } from "node:util";
import { createJournaledRunner } from "@rampscan/collectors";
import { createLocalRepoSource, createLocalRunner, joinRecipeResults } from "@rampscan/core";
import type {
  CertClass,
  Collector,
  RegisterRow,
  RegisterState,
  RunResult,
  Workspace,
} from "@rampscan/core";
import { loadLocalDataset } from "@rampscan/dataset";
import { createLocalLedger } from "@rampscan/ledger";
import { createProjector } from "@rampscan/projector";
import { windowMsFor } from "@rampscan/scheduler";
import type { AssertionResult, Verdict } from "@rampscan/schema";
import { loadRecipes, validateRecipeIds } from "./recipes.js";

const execFileAsync = promisify(execFile);

// `rampscan check <path>` — the L3a dry run: what a scan WOULD conclude over
// the working tree, right now, before anything is committed. It answers the one
// question the rest of this system structurally cannot: "would my change break
// the contract?" — asked by a human before committing, by a git pre-commit
// hook, by a CI pull-request job, or by a coding agent, all through the same
// command.
//
// It is NOT evidence, and that is a property of the input rather than a
// disclaimer bolted onto the output:
//
//   - the walk is over the WORKTREE (index + untracked-not-ignored, minus
//     deleted), so the files it reads include bytes no commit can name, and
//     every bundle in this system anchors to a commit's content hashes;
//   - nothing is signed, nothing is appended, no artifact lands in the scan
//     output dir, and no projection moves. The scratch graph.db goes to a temp
//     dir and is deleted.
//
// So the output type has no `verdict` field anywhere: rows carry `would_be`,
// the envelope carries `dry_run: true` and a sentence naming what it is not.
// A caller cannot accidentally render a dry run as a board state, because the
// two shapes do not share a field name for the answer.
//
// WHICH GATES RUN IS COMPUTED, NOT LISTED (see dryRunnable): every collector
// that spawns no external tool and whose inputs are produced by other such
// collectors. On today's registry that is repo-facts, graph and contract — and
// repo-facts falls out of the rule rather than being invited, which is right:
// unpinning a CI action is exactly the kind of thing a developer wants caught
// before the commit, and repo-facts reads the filesystem already.
//
// The two gates it REFUSES are the interesting half. `sast-reachability` and
// `no-critical-reachable-advisories` are pure joins, so purity alone would let
// them in — but each consumes a producer's artifact (semgrep-results.json,
// osv-results.json) that only a real scan makes, and the only such artifact
// available at dry-run time is from an earlier run over a DIFFERENT tree.
// Joining a fresh graph against a stale finding set answers about neither tree.
// That mixed-tree read is precisely the class of bug the self-scan already
// caught once (H6's false not_affected), so the refusal is stated per gate.

export const DRY_RUN_LABEL = "dry-run — not evidence, nothing signed, nothing appended";

export const DRY_RUN_NOT_EVIDENCE =
  "This is a dry run over your working tree, not evidence. The walk includes files no commit can " +
  "name yet, and every signed claim in this system anchors to a commit's content hashes — so nothing " +
  "here was signed, nothing was appended to the ledger, and no board row moved. Run `rampscan scan` " +
  "after committing to turn any of it into evidence.";

/** a collector that spawns no external tool — `tools: []` or no declaration at all */
function isPure(collector: Collector): boolean {
  return (collector.manifest.tools ?? []).length === 0;
}

export interface RefusedGate {
  collector: string;
  recipes: string[];
  reason: string;
}

/**
 * The dry-run collector set, computed from the manifests: pure, and fed only by
 * artifacts other members produce. `collectors` is taken in execution order
 * (`allCollectors` is dependency-sorted by construction), so one pass suffices
 * — a consumer always follows its producer.
 *
 * Every excluded collector comes back with the reason it was excluded, because
 * a dry run that silently checked three of fifteen recipes would read as a
 * clean bill of health for twelve checks it never made (I15).
 */
export function dryRunnable(collectors: Collector[]): {
  run: Collector[];
  refused: RefusedGate[];
} {
  const run: Collector[] = [];
  const available = new Set<string>();
  const producerOf = new Map<string, string>();
  for (const collector of collectors) {
    for (const out of collector.manifest.outputs ?? []) {
      producerOf.set(out, collector.manifest.name);
    }
  }

  const refused: RefusedGate[] = [];
  for (const collector of collectors) {
    const { name, recipes, tools, inputs } = collector.manifest;
    const row = { collector: name, recipes: [...recipes] };
    if (!isPure(collector)) {
      refused.push({
        ...row,
        reason:
          `spawns ${(tools ?? []).join(", ")} — a dry run runs no external tool, and each of these reads the ` +
          "COMMITTED tree (or the git history), so it could not see an uncommitted change even if it ran",
      });
      continue;
    }
    const missing = (inputs ?? []).filter((input) => !available.has(input));
    if (missing.length > 0) {
      const producers = [...new Set(missing.map((m) => producerOf.get(m) ?? "no registered collector"))];
      refused.push({
        ...row,
        reason:
          `pure, but consumes ${missing.join(", ")} — produced only by ${producers.join(", ")}, which this dry run ` +
          "does not run. The artifact left by an earlier scan is from a DIFFERENT tree, and joining a fresh graph " +
          "against a stale finding set would answer about neither tree",
      });
      continue;
    }
    run.push(collector);
    for (const out of collector.manifest.outputs ?? []) available.add(out);
  }
  return { run, refused };
}

/** how the working tree differs from HEAD — the reader's own answer to "why is this not just a scan?" */
export interface TreeDelta {
  modified: string[];
  untracked: string[];
  deleted: string[];
  /** false when the working tree is clean: a dry run then describes the committed tree after all */
  differsFromHead: boolean;
}

export async function treeDelta(root: string): Promise<TreeDelta> {
  const modified: string[] = [];
  const untracked: string[] = [];
  const deleted: string[] = [];
  try {
    // porcelain v1, NUL-delimited: paths with spaces or quotes stay intact
    const { stdout } = await execFileAsync(
      "git",
      ["status", "--porcelain=v1", "-z", "--untracked-files=all"],
      { cwd: root, maxBuffer: 64 * 1024 * 1024 },
    );
    const records = stdout.split("\0").filter((r) => r !== "");
    for (let i = 0; i < records.length; i += 1) {
      const record = records[i]!;
      const code = record.slice(0, 2);
      const path = record.slice(3);
      if (code === "??") untracked.push(path);
      else if (code.includes("D")) deleted.push(path);
      else {
        modified.push(path);
        // a rename record is followed by its source path in its own field
        if (code.includes("R") || code.includes("C")) i += 1;
      }
    }
  } catch {
    // not a git checkout: the caller already failed to pin a commit, so this
    // never runs in practice — an empty delta is the honest answer, not zero
  }
  return {
    modified: modified.sort(),
    untracked: untracked.sort(),
    deleted: deleted.sort(),
    differsFromHead: modified.length + untracked.length + deleted.length > 0,
  };
}

export interface DryRunRow {
  recipeId: string;
  collector: string;
  /**
   * What a scan over this tree would conclude. Deliberately not named
   * `verdict`: a verdict in this system is a signed fact about a commit, and
   * this is neither.
   */
  wouldBe: Verdict;
  /** why nothing could be observed, when wouldBe is unevidenced — the join's own words */
  reason?: string;
  /**
   * The evaluated assertions, offenders and all. The pointers a reader acts on
   * are `assertions[].offenders` (I2c) — read from the FAILING ASSERTION rather
   * than from the collector's findings, because a finding names its collector
   * and one collector answers several recipes: the contract gate emits both a
   * route-auth and a boundary finding, so grouping findings by collector put
   * the boundary offender on the route-auth row and vice versa. The assertion's
   * offenders are per-recipe by construction, and they are the same pointers
   * the board and the queue render.
   */
  assertions: AssertionResult[];
  /**
   * The board's current state for this (repo, recipe), when a ledger was
   * readable — so the reader can tell "I broke this" from "this was already
   * broken". `absent` means no row: the recipe has no cell for this repo yet.
   *
   * The comparison is stated, never computed into a single "regression" flag:
   * the board state is a fold of signed evidence about a COMMIT, and this row
   * is a dry run over a worktree, so the two are different kinds of statement
   * and the reader is entitled to see both rather than their difference.
   */
  boardState?: RegisterState | "absent";
}

export interface DryRunOutcome {
  /** structural, not prose: the field exists so no caller can render this as a scan result */
  dryRun: true;
  notEvidence: string;
  repo: string;
  /** the commit the worktree sits on top of — what a real scan would have anchored to */
  headCommit: string;
  tree: TreeDelta;
  gatesRun: string[];
  gatesRefused: RefusedGate[];
  rows: DryRunRow[];
  summary: { evidenced: number; violated: number; unevidenced: number };
  /** true when at least one row would be violated — what a hook or CI job exits on */
  wouldViolate: boolean;
  datasetVersion: string;
}

export interface CheckOptions {
  /** the checkout whose WORKING TREE is dry-run */
  path: string;
  datasetDir: string;
  datasetPin: string;
  recipesDir: string;
  /** the full registry; the dry-run subset is computed from it */
  collectors: Collector[];
  /**
   * Read-only, for the board comparison. Omit and rows carry no `boardState` —
   * the dry run still answers, it just cannot say whether the state moved.
   */
  ledgerDir?: string;
  certClass?: CertClass;
  now?: Date;
  log?: (line: string) => void;
}

/**
 * The dry run. Reuses the REAL runner and the REAL join (`joinRecipeResults`),
 * so a dry run and a scan cannot disagree about a recipe for any reason except
 * the tree they read — which is the only difference worth having.
 */
export async function check(options: CheckOptions): Promise<DryRunOutcome> {
  const log = options.log ?? (() => {});
  const now = options.now ?? new Date();

  const pinned = await createLocalRepoSource().fetch({ repo: resolve(options.path) });
  // the same root, read as the WORKTREE — the one substantive difference from
  // scan(), and the reason this output can never be signed
  const workspace: Workspace = { ...pinned, tree: "worktree" };
  log(`worktree ${workspace.root} on top of ${workspace.commit.slice(0, 12)}`);

  const dataset = await loadLocalDataset(options.datasetDir, options.datasetPin);
  const recipes = await loadRecipes(options.recipesDir);
  const problems = validateRecipeIds(recipes, dataset);
  if (problems.length > 0) {
    throw new Error(
      `recipe validation against dataset ${dataset.version()} failed:\n  ${problems.join("\n  ")}`,
    );
  }

  const { run: gates, refused } = dryRunnable(options.collectors);
  log(`dry-run gates: ${gates.map((c) => c.manifest.name).join(", ")} (${refused.length} refused)`);

  // the scratch dir is the whole write surface of this command, and it is
  // deleted before returning: no artifact of a dry run outlives it
  const scratch = await mkdtemp(join(tmpdir(), "rampscan-check-"));
  const runs = new Map<string, RunResult>();
  try {
    const inputs = new Map<string, string>();
    const runner = createJournaledRunner(
      createLocalRunner({ collectors: gates, artifactDir: scratch, inputs, runId: "dry-run" }),
      { safeRoots: [scratch] },
    );
    for (const collector of gates) {
      const name = collector.manifest.name;
      try {
        const result = await runner.run(collector.manifest, workspace);
        runs.set(name, result);
        log(
          result.skipped
            ? `gate ${name} skipped: ${result.skipped.reason}`
            : `gate ${name} done (${result.findings.length} finding(s))`,
        );
      } catch (error) {
        // a crashed gate is visible, exactly as in scan() — and a contract that
        // fails to parse arrives here, which is the one case a developer most
        // needs the dry run to shout about
        const reason = `gate crashed: ${error instanceof Error ? error.message : String(error)}`;
        runs.set(name, {
          findings: [],
          artifacts: [],
          observations: {},
          anchors: {},
          toolVersion: "error",
          exitCode: -1,
          skipped: { reason },
        });
        log(`gate ${name} CRASHED — recorded as skipped: ${reason}`);
      }
    }
  } finally {
    await rm(scratch, { recursive: true, force: true });
  }

  // the same join a scan runs, over the same recipe catalog
  const joined = joinRecipeResults({
    recipes,
    runs,
    workspace,
    datasetVersion: dataset.version(),
    runId: "dry-run",
    now,
  });

  // the board, read-only, for the "did I break it" half
  let board: Map<string, RegisterRow> | undefined;
  if (options.ledgerDir !== undefined) {
    try {
      const projector = createProjector({
        recipes,
        windowMs: windowMsFor(options.certClass ?? "b"),
      });
      const projection = await projector.fold(createLocalLedger(options.ledgerDir));
      board = new Map(
        projection.registers
          .filter((r) => r.repo === workspace.repo)
          .map((r) => [r.recipeId, r]),
      );
    } catch {
      // no ledger yet (a first-ever run, a fresh clone): the dry run still
      // answers, and the rows simply carry no board state to compare against
      log("no readable ledger — rows will carry no board comparison");
    }
  }

  const gateNames = new Set(gates.map((c) => c.manifest.name));

  const rows: DryRunRow[] = [];
  for (const result of joined) {
    // a recipe no dry-run gate answers is not this command's business: it is
    // reported once, as a refused gate, rather than fifteen times as an empty
    // row that looks like a finding of absence
    if (!gateNames.has(result.collector)) continue;
    const row: DryRunRow = {
      recipeId: result.recipe_id,
      collector: result.collector,
      wouldBe: result.verdict,
      assertions: result.assertions,
    };
    if (result.reason !== undefined) row.reason = result.reason;
    if (board !== undefined) row.boardState = board.get(result.recipe_id)?.state ?? "absent";
    rows.push(row);
  }

  const count = (verdict: Verdict) => rows.filter((r) => r.wouldBe === verdict).length;
  return {
    dryRun: true,
    notEvidence: DRY_RUN_NOT_EVIDENCE,
    repo: workspace.repo,
    headCommit: workspace.commit,
    tree: await treeDelta(workspace.root),
    gatesRun: [...gateNames],
    gatesRefused: refused,
    rows,
    summary: {
      evidenced: count("evidenced"),
      violated: count("violated"),
      unevidenced: count("unevidenced"),
    },
    wouldViolate: rows.some((r) => r.wouldBe === "violated"),
    datasetVersion: dataset.version(),
  };
}

export function renderCheck(outcome: DryRunOutcome, useColor: boolean): string {
  const paint = (code: string, s: string) => (useColor ? `[${code}m${s}[0m` : s);
  const green = (s: string) => paint("32", s);
  const red = (s: string) => paint("31", s);
  const yellow = (s: string) => paint("33", s);
  const dim = (s: string) => paint("2", s);
  const bold = (s: string) => paint("1", s);

  const lines: string[] = [
    bold(`DRY RUN — ${outcome.repo}`),
    dim(`worktree on top of ${outcome.headCommit.slice(0, 12)} · dataset ${outcome.datasetVersion}`),
    "",
    dim(DRY_RUN_LABEL),
    "",
  ];

  const { tree } = outcome;
  if (tree.differsFromHead) {
    const parts = [
      tree.modified.length > 0 ? `${tree.modified.length} modified` : undefined,
      tree.untracked.length > 0 ? `${tree.untracked.length} untracked` : undefined,
      tree.deleted.length > 0 ? `${tree.deleted.length} deleted` : undefined,
    ].filter((p): p is string => p !== undefined);
    lines.push(`WORKING TREE (${parts.join(", ")})`);
    for (const path of [...tree.modified, ...tree.untracked].slice(0, 12)) {
      lines.push(`  ${dim(tree.untracked.includes(path) ? "new" : "mod")} ${path}`);
    }
    for (const path of tree.deleted.slice(0, 12)) lines.push(`  ${dim("del")} ${path}`);
    const shown = Math.min(tree.modified.length + tree.untracked.length, 12) +
      Math.min(tree.deleted.length, 12);
    const total = tree.modified.length + tree.untracked.length + tree.deleted.length;
    if (total > shown) lines.push(dim(`  … and ${total - shown} more`));
  } else {
    lines.push(
      "WORKING TREE",
      dim("  clean — this dry run describes the committed tree, so a scan would reach the same rows"),
    );
  }
  lines.push("");

  const colorFor: Record<Verdict, (s: string) => string> = {
    evidenced: green,
    violated: red,
    unevidenced: yellow,
  };
  const label: Record<Verdict, string> = {
    evidenced: "WOULD PASS",
    violated: "WOULD VIOLATE",
    unevidenced: "NOTHING OBSERVED",
  };
  for (const verdict of ["violated", "evidenced", "unevidenced"] as Verdict[]) {
    const rows = outcome.rows.filter((r) => r.wouldBe === verdict);
    if (rows.length === 0) continue;
    lines.push(`${colorFor[verdict](label[verdict])} (${rows.length})`);
    for (const row of rows) {
      const moved =
        row.boardState === undefined
          ? ""
          : row.boardState === "absent"
            ? dim("  (no row on the board yet)")
            : row.boardState === verdict
              ? dim(`  (board: ${row.boardState} — unchanged)`)
              : `  ${yellow(`(board: ${row.boardState} → would be ${verdict})`)}`;
      lines.push(`  ${row.recipeId.padEnd(36)}${moved}`);
      if (row.reason !== undefined) lines.push(dim(`      ${row.reason}`));
      for (const assertion of row.assertions.filter((a) => !a.passed)) {
        lines.push(`      ${red("assert")} ${assertion.description}`);
        // the offenders of THIS assertion — per-recipe by construction, so a
        // gate answering two recipes cannot put one row's offender on the other
        for (const offender of (assertion.offenders ?? []).slice(0, 5)) {
          const where = [offender.file, offender.line].filter((x) => x !== undefined).join(":");
          const what = offender.call_path ?? offender.check;
          lines.push(
            `      ${red("↳")} ${where || "(no file)"}${what !== undefined ? ` — ${what}` : ""}`,
          );
        }
        const total = assertion.offender_count ?? (assertion.offenders ?? []).length;
        const shown = Math.min((assertion.offenders ?? []).length, 5);
        // The true total, always stated when the list is short of it (I2c) —
        // and the two ways it can be short are DIFFERENT facts: a bounded list
        // has more rows behind it, while an empty list means the failing rows
        // carry nothing to point at (I2c drops an empty pointer rather than
        // recording `{}`, so `{codeowners_present: false}` has no file). Saying
        // "and 1 more" over an empty list would promise a pointer that is not
        // being withheld — it does not exist.
        if (shown > 0 && total > shown) {
          lines.push(dim(`      … and ${total - shown} more failing row(s)`));
        } else if (shown === 0 && total > 0) {
          lines.push(
            dim(`      ${total} failing row(s), none carrying a file or check to point at`),
          );
        }
      }
    }
    lines.push("");
  }

  if (outcome.gatesRefused.length > 0) {
    lines.push(`NOT DRY-RUN (${outcome.gatesRefused.length} collector(s))`);
    for (const gate of outcome.gatesRefused) {
      lines.push(`  ${gate.collector.padEnd(20)} ${dim(gate.reason)}`);
      if (gate.recipes.length > 0) {
        lines.push(dim(`      unanswered here: ${gate.recipes.join(", ")} — run \`rampscan scan\` for these`));
      }
    }
    lines.push("");
  }

  lines.push(dim(DRY_RUN_NOT_EVIDENCE));
  return lines.join("\n");
}
