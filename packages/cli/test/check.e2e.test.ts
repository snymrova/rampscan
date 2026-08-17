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
  const path = join(appRoot, rel);
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
  await mkdir(join(appRoot, "src"), { recursive: true });

  await writeFile(
    join(appRoot, "package.json"),
    JSON.stringify({ name: "l3a-app", version: "1.0.0", main: "src/index.js" }, null, 2),
  );
  await writeFile(
    join(appRoot, "src", "billing.js"),
    "function invoice(x) { return { total: 0, x }; }\nmodule.exports = { invoice };\n",
  );
  await writeFile(
    join(appRoot, "src", "index.js"),
    'const { render } = require("./render");\nfunction handle(i) { return render(i); }\nmodule.exports = { handle };\n',
  );
  await writeFile(join(appRoot, "src", "render.js"), RENDER_BREACHING);
  await writeFile(
    join(appRoot, "src", "auth.js"),
    "function requireAuth(req, res, next) { return next(); }\nmodule.exports = { requireAuth };\n",
  );
  await writeFile(
    join(appRoot, "src", "server.js"),
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
  await writeFile(join(appRoot, "rampscan.config.json"), CONTRACT);

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
    expect(run.map((c) => c.manifest.name)).toEqual(["repo-facts", "graph", "contract"]);
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
