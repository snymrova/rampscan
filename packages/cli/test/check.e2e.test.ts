import { execFileSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import { allCollectors } from "@rampscan/collectors";
import { DEFAULT_DATASET_PIN } from "@rampscan/dataset";
import { createLocalLedger } from "@rampscan/ledger";
import { createProjector } from "@rampscan/projector";
import type { PipelineRecipe } from "@rampscan/schema";
import {
  DRY_RUN_NOT_EVIDENCE,
  check,
  dryRunnable,
  loadRecipes,
  renderCheck,
  scan,
  treeDelta,
} from "../src/index.js";
import type { DryRunOutcome, DryRunRow } from "../src/index.js";
import { movementOf, renderCheckComment } from "../src/check-comment.js";

// The L3a exit test over a REAL scanned world: an app that declares its own
// architecture contract, scanned for real (signed evidence, a real board), then
// dry-run over a working tree that is edited underneath it.
//
// Four properties carry this phase, and each is a way the dry run could be
// quietly wrong rather than loudly broken:
//
//   1. IT READS THE WORKING TREE, AND A SCAN CANNOT. The load-bearing pair: an
//      UNTRACKED file that breaks the declared boundary is an offender in the
//      dry run and is absent from the committed walk the same repo's evidence
//      rests on. If that pair ever agrees, this command has no reason to exist.
//   2. IT IS NOT EVIDENCE, STRUCTURALLY. No field named `verdict` anywhere in
//      the output, `dryRun: true` in the envelope, and the ledger byte-identical
//      across a full dry run — a caller cannot render this as a board state and
//      the command cannot leave a trace if it tried.
//   3. THE GATE SET IS COMPUTED, AND ITS REFUSALS ARE STATED. Every collector in
//      the registry is either dry-run or refused BY NAME with a reason; the two
//      pure-but-fed gates are refused for the mixed-tree reason rather than
//      quietly included.
//   4. OFFENDERS BELONG TO THEIR OWN ROW. The contract gate answers two recipes,
//      so a pointer read off the collector's findings lands on the wrong row —
//      the first version of this code did exactly that, and this test is what
//      pins the fix (the offenders come off the failing ASSERTION).

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "../../..");
const recipesDir = join(repoRoot, "recipes/commit");
const datasetDir = join(repoRoot, "docs/context/ramprules/derived");

const gitEnv = {
  ...process.env,
  GIT_AUTHOR_NAME: "l3a-test",
  GIT_AUTHOR_EMAIL: "l3a@rampscan.invalid",
  GIT_COMMITTER_NAME: "l3a-test",
  GIT_COMMITTER_EMAIL: "l3a@rampscan.invalid",
};

function git(cwd: string, ...args: string[]): string {
  return execFileSync("git", args, { cwd, env: gitEnv, encoding: "utf8" }).trim();
}

const CONTRACT =
  JSON.stringify(
    {
      contract: {
        rules: [
          {
            kind: "boundary",
            id: "billing-isolated",
            module: "src/billing",
            allowedImporters: ["src/server.js"],
            description: "billing is reached only through the server layer",
          },
          {
            kind: "route-auth",
            id: "all-routes-authed",
            routes: "/*",
            description: "every route this service registers requires an authenticated caller",
          },
        ],
      },
    },
    null,
    2,
  ) + "\n";

/** the committed offender: render reaches straight into the guarded module */
const RENDER_BREACHING =
  'const { invoice } = require("./billing");\nfunction render(x) { return JSON.stringify(invoice(x)); }\nmodule.exports = { render };\n';
/** the same file with the boundary respected — no import of the guarded module */
const RENDER_CLEAN =
  "function render(x) { return JSON.stringify({ shown: x }); }\nmodule.exports = { render };\n";

/**
 * The fixture app, written into `root` with `render.js` supplied by the caller
 * — breaching or clean. Extracted so the baseline suite below builds the SAME
 * app the rest of this file scans: a second hand-written copy would drift, and
 * a baseline test that drifts from its subject proves nothing about it.
 */
async function writeApp(root: string, render: string): Promise<void> {
  await mkdir(join(root, "src"), { recursive: true });
  await writeFile(
    join(root, "package.json"),
    JSON.stringify({ name: "l3a-app", version: "1.0.0", main: "src/index.js" }, null, 2),
  );
  await writeFile(
    join(root, "src", "billing.js"),
    "function invoice(x) { return { total: 0, x }; }\nmodule.exports = { invoice };\n",
  );
  await writeFile(
    join(root, "src", "index.js"),
    'const { render } = require("./render");\nfunction handle(i) { return render(i); }\nmodule.exports = { handle };\n',
  );
  await writeFile(join(root, "src", "render.js"), render);
  await writeFile(
    join(root, "src", "auth.js"),
    "function requireAuth(req, res, next) { return next(); }\nmodule.exports = { requireAuth };\n",
  );
  await writeFile(
    join(root, "src", "server.js"),
    [
      'const express = require("express");',
      'const { requireAuth } = require("./auth");',
      'const { invoice } = require("./billing");',
      "const app = express();",
      'app.get("/health", (req, res) => res.send("ok"));',
      'app.get("/invoice", requireAuth, (req, res) => res.send(invoice(req.query)));',
      "module.exports = { app };",
    ].join("\n") + "\n",
  );
  await writeFile(join(root, "rampscan.config.json"), CONTRACT);
}

let base: string;
let appRoot: string;
let ledgerDir: string;
let outDir: string;
let recipes: PipelineRecipe[];
const BOUNDARY = "arch-boundaries-hold";
const ROUTE_AUTH = "arch-route-auth-declared";

function row(outcome: DryRunOutcome, recipeId: string): DryRunRow {
  const found = outcome.rows.find((r) => r.recipeId === recipeId);
  if (!found) throw new Error(`no dry-run row for ${recipeId}`);
  return found;
}

/** every offender pointer of a row's failing assertions, flattened */
function offenders(outcome: DryRunOutcome, recipeId: string): string {
  return JSON.stringify(
    row(outcome, recipeId)
      .assertions.filter((a) => !a.passed)
      .flatMap((a) => a.offenders ?? []),
  );
}

/** the dry run under test; `noLedger` drops the board comparison entirely */
async function dry(opts: { noLedger?: boolean } = {}): Promise<DryRunOutcome> {
  return check({
    path: appRoot,
    datasetDir,
    datasetPin: DEFAULT_DATASET_PIN,
    recipesDir,
    collectors: allCollectors,
    ...(opts.noLedger === true ? {} : { ledgerDir }),
    now: new Date("2026-08-16T10:00:00Z"),
  });
}

/** run `body` with a file replaced, then put the original bytes back */
async function withFile(rel: string, contents: string, body: () => Promise<void>): Promise<void> {
  return withFileIn(appRoot, rel, contents, body);
}

async function withFileIn(
  root: string,
  rel: string,
  contents: string,
  body: () => Promise<void>,
): Promise<void> {
  const path = join(root, rel);
  const original = await readFile(path, "utf8").catch(() => undefined);
  await writeFile(path, contents);
  try {
    await body();
  } finally {
    if (original === undefined) await rm(path, { force: true });
    else await writeFile(path, original);
  }
}

beforeAll(async () => {
  base = await mkdtemp(join(tmpdir(), "rampscan-l3a-"));
  appRoot = join(base, "app");
  ledgerDir = join(base, "ledger");
  outDir = join(base, "out");
  await writeApp(appRoot, RENDER_BREACHING);

  git(appRoot, "init", "-q", "-b", "main");
  git(appRoot, "add", "-A");
  git(appRoot, "commit", "-qm", "app with a declared contract");

  // a REAL scan, so the board the dry run compares against is signed evidence
  // about a commit rather than a fixture literal
  await scan({
    path: appRoot,
    outDir,
    datasetDir,
    datasetPin: DEFAULT_DATASET_PIN,
    recipesDir,
    collectors: allCollectors,
    ledgerDir,
    keysDir: join(base, "keys"),
    trigger: "test",
    now: new Date("2026-08-16T09:00:00Z"),
  });
  recipes = await loadRecipes(recipesDir);
}, 300_000);

describe("the dry-run gate set is computed from the manifests, and every refusal is stated", () => {
  it("runs exactly the pure collectors whose inputs other pure collectors produce", () => {
    const { run } = dryRunnable(allCollectors);
    // `documents` joined the set on its first day and by the same rule the
    // other three are in it: it spawns nothing and consumes no artifact, so
    // the working tree is all it needs. That makes a declared document deleted
    // in an uncommitted change a row `rampscan check` fails on before the
    // commit exists, which is the property this list is for.
    expect(run.map((c) => c.manifest.name)).toEqual([
      "repo-facts",
      "documents",
      "graph",
      "contract",
    ]);
  });

  it("accounts for every collector in the registry — nothing is silently dropped", () => {
    const { run, refused } = dryRunnable(allCollectors);
    const named = [...run.map((c) => c.manifest.name), ...refused.map((r) => r.collector)].sort();
    expect(named).toEqual(allCollectors.map((c) => c.manifest.name).sort());
  });

  it("refuses a tool-spawning collector by naming the tool, not by omitting the row", () => {
    const { refused } = dryRunnable(allCollectors);
    const semgrep = refused.find((r) => r.collector === "semgrep");
    expect(semgrep?.reason).toContain("spawns semgrep");
    expect(semgrep?.reason).toContain("COMMITTED tree");
  });

  it("refuses the two PURE gates for the mixed-tree reason, naming the artifact and its producer", () => {
    const { refused } = dryRunnable(allCollectors);
    const sast = refused.find((r) => r.collector === "sast-reachability");
    expect(sast?.reason).toContain("pure, but consumes semgrep-results.json");
    expect(sast?.reason).toContain("semgrep");
    expect(sast?.reason).toContain("DIFFERENT tree");
    expect(sast?.recipes).toEqual(["no-reachable-dangerous-code"]);

    const advisories = refused.find((r) => r.collector === "reachability");
    expect(advisories?.reason).toContain("osv-results.json");
    expect(advisories?.reason).toContain("osv-scanner");
  });

  it("names the recipes each refusal leaves unanswered, so the gap is countable", () => {
    const { refused } = dryRunnable(allCollectors);
    const unanswered = refused.flatMap((r) => r.recipes);
    expect(unanswered).toContain("no-secrets-in-history");
    expect(unanswered).toContain("iac-baseline-clean");
    expect(unanswered).toContain("container-base-image-patched");
    // and none of them is a recipe a dry-run gate answers
    const { run } = dryRunnable(allCollectors);
    const answered = new Set(run.flatMap((c) => c.manifest.recipes));
    expect(unanswered.filter((r) => answered.has(r))).toEqual([]);
  });
});

describe("a dry run over a real repo answers the contract and says what it is not", () => {
  it("labels itself a dry run in the envelope and in prose", async () => {
    const outcome = await dry();
    expect(outcome.dryRun).toBe(true);
    expect(outcome.notEvidence).toBe(DRY_RUN_NOT_EVIDENCE);
    expect(outcome.notEvidence).toContain("not evidence");
    expect(outcome.headCommit).toBe(git(appRoot, "rev-parse", "HEAD"));
  });

  it("has NO field named `verdict` anywhere — a dry run cannot be rendered as a scan result", async () => {
    const outcome = await dry();
    const keys = new Set<string>();
    const walk = (value: unknown): void => {
      if (Array.isArray(value)) value.forEach(walk);
      else if (value !== null && typeof value === "object") {
        for (const [key, child] of Object.entries(value)) {
          keys.add(key);
          walk(child);
        }
      }
    };
    walk(JSON.parse(JSON.stringify(outcome)));
    expect(keys.has("verdict")).toBe(false);
    expect(keys.has("wouldBe")).toBe(true);
  });

  it("finds the committed boundary breach and the unauthenticated route", async () => {
    const outcome = await dry();
    expect(row(outcome, BOUNDARY).wouldBe).toBe("violated");
    expect(row(outcome, ROUTE_AUTH).wouldBe).toBe("violated");
    expect(outcome.wouldViolate).toBe(true);
    expect(offenders(outcome, BOUNDARY)).toContain("src/render.js");
  });

  it("keeps each row's offenders on its OWN row — the contract gate answers two recipes", async () => {
    const outcome = await dry();
    // the boundary row points at the importer and never at the route rule
    expect(offenders(outcome, BOUNDARY)).toContain("src/billing.js");
    expect(offenders(outcome, BOUNDARY)).not.toContain("all-routes-authed");
    // and the route row points at the route rule and never at the guarded module
    expect(offenders(outcome, ROUTE_AUTH)).toContain("all-routes-authed");
    expect(offenders(outcome, ROUTE_AUTH)).not.toContain("src/billing.js");
  });

  it("reports only the recipes its own gates answer — the rest are refused gates, not empty rows", async () => {
    const outcome = await dry();
    const answered = new Set(dryRunnable(allCollectors).run.flatMap((c) => c.manifest.recipes));
    for (const r of outcome.rows) expect(answered.has(r.recipeId)).toBe(true);
    expect(outcome.rows.some((r) => r.recipeId === "no-reachable-dangerous-code")).toBe(false);
  });

  it("states the board's own answer beside each row, and omits it when no ledger was given", async () => {
    const withBoard = await dry();
    // the real scan recorded these rows, so the board has an answer to compare
    expect(row(withBoard, BOUNDARY).boardState).toBe("violated");

    const withoutBoard = await dry({ noLedger: true });
    expect(row(withoutBoard, BOUNDARY).boardState).toBeUndefined();
    expect(row(withoutBoard, BOUNDARY).wouldBe).toBe("violated");
  });

  it("renders the not-evidence sentence and the refusals in the text reading", async () => {
    const text = renderCheck(await dry(), false);
    expect(text).toContain("DRY RUN");
    expect(text).toContain(DRY_RUN_NOT_EVIDENCE);
    expect(text).toContain("NOT DRY-RUN");
    expect(text).toContain("sast-reachability");
    expect(text).not.toMatch(/\bVIOLATED\b(?! \()/); // the board's word is not this command's word
  });
});

describe("the working tree is what it reads — and a scan cannot see it", () => {
  it("says the tree is clean when it is, and names the dry run's own scope honestly", async () => {
    const delta = await treeDelta(appRoot);
    expect(delta.differsFromHead).toBe(false);
    expect(renderCheck(await dry(), false)).toContain("clean");
  });

  it("catches a boundary breach in an UNTRACKED file that the committed walk cannot see", async () => {
    await withFile(
      "src/reports.js",
      'const { invoice } = require("./billing");\nmodule.exports = { report: (x) => invoice(x) };\n',
      async () => {
        const delta = await treeDelta(appRoot);
        expect(delta.untracked).toContain("src/reports.js");
        expect(delta.differsFromHead).toBe(true);

        const outcome = await dry();
        expect(offenders(outcome, BOUNDARY)).toContain("src/reports.js");

        // The load-bearing pair, asserted against GIT'S OWN answer rather than
        // ours: the committed tree every signed claim rests on does not contain
        // this file at all, which is exactly why the dry run's verdict may
        // never be signed — and the board, folded from that evidence, has never
        // heard of it either.
        expect(git(appRoot, "ls-tree", "-r", "--name-only", "HEAD")).not.toContain(
          "src/reports.js",
        );
        const projection = await createProjector({ recipes }).fold(createLocalLedger(ledgerDir));
        expect(JSON.stringify(projection)).not.toContain("src/reports.js");
      },
    );
  });

  it("catches a breach added to a tracked file that is not committed yet", async () => {
    await withFile(
      "src/auth.js",
      'const { invoice } = require("./billing");\nfunction requireAuth(req, res, next) { return next(invoice); }\nmodule.exports = { requireAuth };\n',
      async () => {
        expect((await treeDelta(appRoot)).modified).toContain("src/auth.js");
        expect(offenders(await dry(), BOUNDARY)).toContain("src/auth.js");
      },
    );
  });

  it("flips the row to would-pass when the worktree FIXES the breach, while the board stays violated", async () => {
    await withFile("src/render.js", RENDER_CLEAN, async () => {
      const outcome = await dry();
      expect(row(outcome, BOUNDARY).wouldBe).toBe("evidenced");
      // the fix is real, and it is not evidence: the signed board is unmoved
      expect(row(outcome, BOUNDARY).boardState).toBe("violated");

      const projection = await createProjector({ recipes }).fold(createLocalLedger(ledgerDir));
      const boardRow = projection.registers.find((r) => r.recipeId === BOUNDARY);
      expect(boardRow?.state).toBe("violated");
    });
  });

  it("drops a file deleted from disk, so the dry run describes the tree as it now is", async () => {
    const path = join(appRoot, "src", "render.js");
    const original = await readFile(path, "utf8");
    await rm(path);
    try {
      const delta = await treeDelta(appRoot);
      expect(delta.deleted).toContain("src/render.js");
      // the deleted importer is STILL IN THE INDEX — a worktree walk that
      // trusted the index alone would keep reporting an offender the developer
      // has already removed, which is what the on-disk existence filter is for
      expect(git(appRoot, "ls-files")).toContain("src/render.js");
      expect(offenders(await dry(), BOUNDARY)).not.toContain("src/render.js");
    } finally {
      await writeFile(path, original);
    }
  });
});

describe("a dry run writes nothing", () => {
  it("leaves the ledger byte-identical and creates no output directory", async () => {
    const indexPath = join(ledgerDir, "index.jsonl");
    const before = await readFile(indexPath);
    const scratchOut = join(base, "should-not-exist");

    await withFile(
      "src/reports.js",
      'const { invoice } = require("./billing");\nmodule.exports = { report: (x) => invoice(x) };\n',
      async () => {
        const outcome = await dry();
        expect(outcome.wouldViolate).toBe(true);
      },
    );

    expect(await readFile(indexPath)).toEqual(before);
    await expect(stat(scratchOut)).rejects.toThrow();
    // and the board it read is unchanged, because reading is all it did
    const projection = await createProjector({ recipes }).fold(createLocalLedger(ledgerDir));
    expect(projection.registers.find((r) => r.recipeId === BOUNDARY)?.state).toBe("violated");
  });

  it("removes its scratch graph — no dry-run artifact outlives the command", async () => {
    const scratchDirs = async () =>
      (await readdir(tmpdir())).filter((n) => n.startsWith("rampscan-check-")).length;
    const before = await scratchDirs();

    const outcome = await dry();
    expect(outcome.gatesRun).toContain("contract");
    // the graph this dry run walked was real; the file it lived in is gone
    expect(await scratchDirs()).toBe(before);
    // and no artifact is offered to the caller, because there is nothing to
    // hand anyone: the scratch path never appears in the output either
    expect(Object.keys(outcome)).not.toContain("artifacts");
    expect(JSON.stringify(outcome)).not.toContain("rampscan-check-");
  });
});

describe("the pull-request comment (N2a), over the same real world", () => {
  // The exit test's clauses, against signed evidence and a real worktree
  // rather than a fixture literal. One clause is deliberately NOT here: the
  // `evidenced → violated` movement. Every row this fixture's scan reached is
  // violated on its board — the scan and the dry run read the same tree — so
  // producing an evidenced row would take a second full scan of a repaired
  // tree, two more minutes of suite for a sentence that check-comment.test.ts
  // already pins exactly. The movement vocabulary is unit-tested; what is
  // tested HERE is what only a real world can show: that the offenders, the
  // streak and the authored sentence all arrive on the right row.

  it("says the breaches are inherited, not caused, and names the streak's commit", async () => {
    const body = renderCheckComment(await dry());
    expect(body).toBeDefined();
    expect(body).toContain("Inherited, not introduced here");
    expect(body).toContain("This pull request did not cause it");
    // every row this fixture reaches is already violated on its board, so the
    // headline must not read as an accusation against the tree in front of it
    expect(body).toContain("None of these is introduced by this tree");
    const head = git(appRoot, "rev-parse", "HEAD");
    expect(body).toContain(`violated since \`${head.slice(0, 12)}\``);
  });

  it("quotes the recipe's own fix sentence, read from the catalog and not paraphrased", async () => {
    const body = renderCheckComment(await dry());
    const recipe = recipes.find((r) => r.id === BOUNDARY);
    expect(recipe?.plain?.fix).toBeDefined();
    expect(body).toContain(recipe!.plain!.fix);
    expect(body).toContain(recipe!.plain!.violation);
  });

  it("points at the offending file and the import chain that reaches it", async () => {
    const body = renderCheckComment(await dry());
    // the committed breach: render.js reaches into billing, and the pointer
    // carries the chain rather than the file alone
    expect(body).toMatch(/src\/render\.js/);
    // `call_path` is the chain, not the file: the reader is told which edge
    // reaches the boundary, which is the difference between a pointer and a shrug
    expect(body).toContain("src/render.js » src/billing.js");
  });

  it("carries an UNTRACKED breach into the comment — the thing a scan cannot see", async () => {
    await withFile("src/sneaky.js", 'const { invoice } = require("./billing");\nmodule.exports = { invoice };\n', async () => {
      const body = renderCheckComment(await dry());
      expect(body).toContain("src/sneaky.js");
    });
  });

  it("drops a row the worktree fixes, while the board still holds it violated", async () => {
    await withFile("src/render.js", RENDER_CLEAN, async () => {
      const outcome = await dry();
      expect(row(outcome, BOUNDARY).wouldBe).toBe("evidenced");
      expect(row(outcome, BOUNDARY).boardState).toBe("violated");
      const body = renderCheckComment(outcome);
      // the board's violation is real and stays on the board; this comment is
      // about the tree in front of the reader, and the tree fixed it
      expect(body).not.toContain(`#### \`${BOUNDARY}\``);
    });
  });

  it("renders no comment at all when nothing in the tree would be violated", () => {
    // the whole-comment case, over a hand-shaped outcome: this fixture always
    // has something violated (it has no CODEOWNERS and no lockfile), so the
    // empty world is constructed rather than scanned
    const clean: DryRunOutcome = {
      dryRun: true,
      notEvidence: DRY_RUN_NOT_EVIDENCE,
      repo: "l3a-app",
      headCommit: "0".repeat(40),
      tree: { modified: [], untracked: [], deleted: [], differsFromHead: false },
      gatesRun: ["repo-facts", "graph", "contract"],
      gatesRefused: [],
      rows: [],
      summary: { evidenced: 3, violated: 0, unevidenced: 0 },
      wouldViolate: false,
      datasetVersion: DEFAULT_DATASET_PIN,
    };
    expect(renderCheckComment(clean)).toBeUndefined();
  });

  it("leaves the ledger byte-identical across a comment render", async () => {
    const before = await readFile(join(ledgerDir, "index.jsonl"), "utf8");
    const body = renderCheckComment(await dry());
    expect(body).toBeDefined();
    const after = await readFile(join(ledgerDir, "index.jsonl"), "utf8");
    expect(after).toBe(before);
  });
});

// #19 — the baseline a CI job can actually obtain.
//
// The gate shipped failing only on what a tree MADE WORSE, which is the right
// question, and then had nothing to ask it against: `rampscan-ledger/` is
// gitignored, so a pull-request job reads no board, every violation classifies
// as `no-baseline`, and `would-introduce` is false on every run that has ever
// executed. PR #18 breached a declared boundary in public and the job went
// green.
//
// So this suite runs under the CI condition rather than the fixture's: NO
// LEDGER ANYWHERE. The baseline is a second dry run over the base ref's tree —
// same command, same catalog, two trees — and the only thing that can tell an
// introduced breach from an inherited one.
describe("check --baseline-ref: the gate's missing half", () => {
  let repo: string;

  beforeAll(async () => {
    repo = join(await mkdtemp(join(tmpdir(), "rampscan-gate-")), "app");
    await writeApp(repo, RENDER_CLEAN);
    git(repo, "init", "-q", "-b", "main");
    git(repo, "add", "-A");
    git(repo, "commit", "-qm", "an app that respects the boundary it declares");
  });

  /** the dry run as CI runs it: a base ref, and deliberately no ledger */
  async function against(ref: string): Promise<DryRunOutcome> {
    return check({
      path: repo,
      datasetDir,
      datasetPin: DEFAULT_DATASET_PIN,
      recipesDir,
      collectors: allCollectors,
      baselineRef: ref,
      now: new Date("2026-08-20T10:00:00Z"),
    });
  }

  it("calls a breach this tree adds INTRODUCED, with no ledger in reach", async () => {
    await withFileIn(repo, "src/render.js", RENDER_BREACHING, async () => {
      const outcome = await against("main");
      const boundary = row(outcome, BOUNDARY);

      // the CI condition, asserted rather than assumed: no board, at all
      expect(boundary.boardState).toBeUndefined();
      expect(outcome.wouldViolate).toBe(true);
      expect(boundary.wouldBe).toBe("violated");
      // and the base tree answers where the board could not
      expect(boundary.baselineWouldBe).toBe("evidenced");
      expect(movementOf(boundary)).toEqual({
        kind: "changed",
        source: "base-tree",
        change: "newly-violated",
        from: "evidenced",
      });
      expect(outcome.baseline?.ref).toBe("main");
      expect(outcome.baseline?.commit).toBe(git(repo, "rev-parse", "main"));

      // the number the gate reads, and the whole point: it is not zero
      const body = renderCheckComment(outcome);
      expect(body).toContain("introduced=1");
      expect(body).toContain("src/render.js");
    });
  });

  it("leaves the baseline worktree behind on neither success nor failure", async () => {
    // a dry run that litters `.git/worktrees` would break the next run of the
    // same command, and the cleanup is in a `finally` precisely so a throwing
    // inner run cannot skip it. One line = the main worktree and nothing else;
    // matching on the temp prefix would match this fixture's own directory.
    expect(git(repo, "worktree", "list").split("\n")).toHaveLength(1);
  });

  it("refuses to go quiet when the baseline ref will not resolve", async () => {
    // The defect this whole suite exists for was a baseline that vanished
    // without saying so. A shallow clone is the realistic way to lose one, and
    // degrading to "nothing was introduced" would restore the bug exactly.
    await expect(against("no-such-ref")).rejects.toThrow(/could not check out the baseline ref/);
  });

  it("calls a breach the base tree already carries INHERITED, not caused", async () => {
    // both trees breach now: the pull request found it rather than wrote it
    await writeFile(join(repo, "src", "render.js"), RENDER_BREACHING);
    git(repo, "add", "-A");
    git(repo, "commit", "-qm", "the breach, committed");

    const outcome = await against("HEAD");
    const boundary = row(outcome, BOUNDARY);
    expect(boundary.wouldBe).toBe("violated");
    expect(boundary.baselineWouldBe).toBe("violated");
    expect(movementOf(boundary)).toEqual({ kind: "inherited", source: "base-tree" });

    const body = renderCheckComment(outcome);
    expect(body).toContain("introduced=0");
    expect(body).toContain("Inherited, not introduced here.");
    // the board's streak sentence belongs to the board and there is no board
    expect(body).not.toContain("The board already holds");
  });
});
