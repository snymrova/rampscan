import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import { contract, graphCollector, loadToolManifest } from "@rampscan/collectors";
import { DEFAULT_DATASET_PIN, loadLocalDataset } from "@rampscan/dataset";
import type { DatasetClient } from "@rampscan/dataset";
import { createLocalLedger } from "@rampscan/ledger";
import { createProjector } from "@rampscan/projector";
import { isScanRun } from "@rampscan/schema";
import type { PipelineRecipe } from "@rampscan/schema";
import type { Projection } from "@rampscan/core";
import {
  REPO_MODEL_ARTIFACT,
  buildRepoModel,
  buildToolMap,
  computeRepoModel,
  loadRecipes,
  renderRepoModel,
  scan,
  serializeRepoModel,
} from "../src/index.js";
import type { ContractRuleNode, GraphNode, RecipeNode, RepoModel, ToolMap } from "../src/index.js";

// The L2 exit test over a REAL scanned world (the L1 fixture's shape: an app
// that declares its own architecture contract, checked by the real graph and
// contract collectors — both pure, so every line here is shipping code).
//
// Four properties carry this phase, and each is a way the artifact could be
// quietly wrong rather than loudly broken:
//
//   1. THE ARTIFACT IS ATTESTED. The bytes on disk hash to the digest the run
//      record's subject names. An artifact nobody signed is a file.
//   2. THE MODEL IS A LEDGER DERIVATIVE, NOT A REPO READ. Editing
//      rampscan.config.json after the scan must not move the contract the
//      model states, because the model states the contract the EVIDENCE was
//      checked against. This is the test that would fail if someone
//      "simplified" the basis read into a config read.
//   3. IT CARRIES NO CLOCK. The same ledger yields the same bytes, so
//      `rampscan model --json` reproduces the artifact a scan attested.
//   4. NO LINK DANGLES. Every link's endpoints are nodes, and a link that
//      could not be drawn is a STATED problem rather than a silent absence.

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "../../..");
const recipesDir = join(repoRoot, "recipes/commit");
const datasetDir = join(repoRoot, "docs/context/ramprules/derived");

const gitEnv = {
  ...process.env,
  GIT_AUTHOR_NAME: "l2-test",
  GIT_AUTHOR_EMAIL: "l2@rampscan.invalid",
  GIT_COMMITTER_NAME: "l2-test",
  GIT_COMMITTER_EMAIL: "l2@rampscan.invalid",
};

function git(cwd: string, ...args: string[]): string {
  return execFileSync("git", args, { cwd, env: gitEnv, encoding: "utf8" }).trim();
}

function contractJson(description: string): string {
  return (
    JSON.stringify(
      {
        contract: {
          rules: [
            {
              kind: "boundary",
              id: "billing-isolated",
              module: "src/billing",
              allowedImporters: ["src/server.js"],
              description,
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
    ) + "\n"
  );
}

/** the description the SCAN saw; the test later rewrites the file to something else */
const SIGNED_DESCRIPTION = "billing is reached only through the server layer";

let base: string;
let appRoot: string;
let ledgerDir: string;
let outDir: string;
let recipes: PipelineRecipe[];
let dataset: DatasetClient;
let toolMap: ToolMap;
let projection: Projection;
let model: RepoModel;
let attestedDigest: string;
let modelPath: string;

async function build(over: { recipes?: PipelineRecipe[]; toolMap?: ToolMap } = {}): Promise<RepoModel> {
  return buildRepoModel({
    entries: await createLocalLedger(ledgerDir).list(),
    recipes: over.recipes ?? recipes,
    dataset,
    toolMap: over.toolMap ?? toolMap,
  });
}

beforeAll(async () => {
  base = await mkdtemp(join(tmpdir(), "rampscan-l2-"));
  appRoot = join(base, "app");
  ledgerDir = join(base, "ledger");
  outDir = join(base, "out");
  await mkdir(join(appRoot, "src"), { recursive: true });

  await writeFile(
    join(appRoot, "package.json"),
    JSON.stringify({ name: "l2-app", version: "1.0.0", main: "src/index.js" }, null, 2),
  );
  await writeFile(
    join(appRoot, "src", "billing.js"),
    "function invoice(x) { return { total: 0, x }; }\nmodule.exports = { invoice };\n",
  );
  await writeFile(
    join(appRoot, "src", "index.js"),
    'const { render } = require("./render");\nfunction handle(i) { return render(i); }\nmodule.exports = { handle };\n',
  );
  // the offender: render reaches straight into the guarded module
  await writeFile(
    join(appRoot, "src", "render.js"),
    'const { invoice } = require("./billing");\nfunction render(x) { return JSON.stringify(invoice(x)); }\nmodule.exports = { render };\n',
  );
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
  await writeFile(join(appRoot, "rampscan.config.json"), contractJson(SIGNED_DESCRIPTION));

  git(appRoot, "init", "-q", "-b", "main");
  git(appRoot, "add", "-A");
  git(appRoot, "commit", "-qm", "app with a declared contract");

  const outcome = await scan({
    path: appRoot,
    outDir,
    datasetDir,
    datasetPin: DEFAULT_DATASET_PIN,
    recipesDir,
    // a deliberately SMALL registry: this world really does have two
    // collectors, so the recipes whose collectors are absent are honestly
    // unlinkable — the case property 4 below is asserted on
    collectors: [graphCollector, contract],
    ledgerDir,
    keysDir: join(base, "keys"),
    trigger: "test",
    now: new Date("2026-08-15T10:00:00Z"),
  });
  modelPath = outcome.model!.path;
  attestedDigest = outcome.model!.sha256;

  recipes = await loadRecipes(recipesDir);
  dataset = await loadLocalDataset(datasetDir, DEFAULT_DATASET_PIN);
  toolMap = buildToolMap({
    recipes,
    collectors: [graphCollector, contract],
    toolManifest: await loadToolManifest(),
  });
  projection = await createProjector({ recipes }).fold(createLocalLedger(ledgerDir));
  model = await build();
}, 180_000);

describe("L2 — the repo model is an attested derivation of the ledger", () => {
  it("the scan wrote it and the run record attests those exact bytes", async () => {
    const bytes = await readFile(modelPath);
    expect(createHash("sha256").update(bytes).digest("hex")).toBe(attestedDigest);

    const runs = (await createLocalLedger(ledgerDir).list()).filter((e) => isScanRun(e.bundle));
    expect(runs).toHaveLength(1);
    const subject = runs[0]!.bundle.subject.find((s) => s.name === REPO_MODEL_ARTIFACT);
    expect(subject, "the run record names repo-model.json as a subject").toBeDefined();
    expect(subject!.digest["sha256"]).toBe(attestedDigest);
  });

  it("rebuilding it from the same ledger reproduces the artifact byte-for-byte", async () => {
    const rebuilt = serializeRepoModel(
      await computeRepoModel({ ledgerDir, recipesDir, dataset, toolMap }),
    );
    expect(rebuilt).toBe(await readFile(modelPath, "utf8"));
  });

  it("it is deterministic: two builds over one ledger are identical bytes", async () => {
    expect(serializeRepoModel(await build())).toBe(serializeRepoModel(await build()));
  });

  it("it carries no clock — no instant appears anywhere in the artifact", () => {
    // the property that makes the byte-identity above hold forever, guarded
    // against a future `generated_at` being added without noticing
    expect(serializeRepoModel(model)).not.toMatch(/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/);
  });
});

describe("L2 — completeness: nothing on the board is missing from the model", () => {
  it("every live register row appears as a state link carrying the same state", () => {
    const states = model.links.filter((l) => l.kind === "state");
    expect(states).toHaveLength(projection.registers.length);
    for (const row of projection.registers) {
      const link = states.find(
        (l) => l.from === `repo:${row.repo}` && l.to === `recipe:${row.recipeId}`,
      );
      expect(link, `no state link for ${row.repo} × ${row.recipeId}`).toBeDefined();
      expect(link!.kind === "state" && link!.state).toBe(row.state);
      if (row.bundleDigest !== undefined) {
        expect(link!.kind === "state" && link!.bundleDigest).toBe(row.bundleDigest);
      }
    }
    // and the world really was scanned — a vacuous pass over zero rows would
    // satisfy every line above
    expect(states.filter((l) => l.kind === "state" && l.state === "violated").length).toBeGreaterThan(0);
  });

  it("every rule the contract gate signed appears as a node, both kinds", () => {
    const rules = model.nodes.filter((n): n is ContractRuleNode => n.kind === "contract-rule");
    expect(rules.map((r) => r.ruleId).sort()).toEqual(["all-routes-authed", "billing-isolated"]);
    expect(rules.map((r) => r.ruleKind).sort()).toEqual(["boundary", "route-auth"]);
    // each rule is linked to the repo that declared it and to the recipe whose
    // gate evaluated it — the two halves of "who said this, and who checked it"
    for (const rule of rules) {
      expect(model.links).toContainEqual({
        kind: "declares",
        from: `repo:${appRoot}`,
        to: rule.id,
      });
      const checked = model.links.filter((l) => l.kind === "checked-by" && l.from === rule.id);
      expect(checked).toHaveLength(1);
    }
    expect(
      model.links.find((l) => l.kind === "checked-by" && l.from.endsWith(":billing-isolated"))?.to,
    ).toBe("recipe:arch-boundaries-hold");
  });

  it("the graph the gates walked is summarized, and says which claim it came from", () => {
    const graph = model.nodes.find((n): n is GraphNode => n.kind === "graph")!;
    expect(graph.repo).toBe(appRoot);
    expect(graph.nodeCount).toBeGreaterThan(0);
    expect(graph.edgeCount).toBeGreaterThan(0);
    expect(graph.entrypoints).toContain("src/index.js");
    expect(graph.entrypointSource).toBe("package.json");
    expect(["arch-boundaries-hold", "arch-route-auth-declared"]).toContain(graph.from.recipeId);
    expect(model.links).toContainEqual({
      kind: "walked",
      from: `repo:${appRoot}`,
      to: graph.id,
    });
  });

  it("a recipe that left the catalog keeps its node, its state, and its honesty", async () => {
    const reduced = recipes.filter((r) => r.id !== "arch-boundaries-hold");
    const shrunk = await build({ recipes: reduced });
    const node = shrunk.nodes.find(
      (n): n is RecipeNode => n.kind === "recipe" && n.recipeId === "arch-boundaries-hold",
    )!;
    expect(node.inCatalog).toBe(false);
    // the catalog-only fields are ABSENT, never guessed from the live bundle
    expect(node.cadence).toBeUndefined();
    expect(node.automatable).toBeUndefined();
    // and the cell it still holds evidence for is still on the board
    expect(
      shrunk.links.some((l) => l.kind === "state" && l.to === "recipe:arch-boundaries-hold"),
    ).toBe(true);
    // the in-catalog case, for contrast
    const inCatalog = model.nodes.find(
      (n): n is RecipeNode => n.kind === "recipe" && n.recipeId === "arch-boundaries-hold",
    )!;
    expect(inCatalog.inCatalog).toBe(true);
    expect(inCatalog.cadence).toBeDefined();
  });
});

describe("L2 — the model states the ledger, not the working tree", () => {
  it("editing the contract file after the scan does not move the model's rule text", async () => {
    await writeFile(join(appRoot, "rampscan.config.json"), contractJson("a different sentence"));
    const after = await build();
    const rule = after.nodes.find(
      (n): n is ContractRuleNode => n.kind === "contract-rule" && n.ruleId === "billing-isolated",
    )!;
    expect(rule.declaration).toContain(SIGNED_DESCRIPTION);
    expect(rule.declaration).not.toContain("a different sentence");
    // restore, so nothing after this test reads a rewritten world
    await writeFile(join(appRoot, "rampscan.config.json"), contractJson(SIGNED_DESCRIPTION));
  });

  it("the rule text is the canonical declaration the basis signed, byte-for-byte", async () => {
    const entries = await createLocalLedger(ledgerDir).list();
    const signed = entries
      .flatMap((e) =>
        "predicate" in e.bundle && "basis" in e.bundle.predicate
          ? ((e.bundle.predicate as { basis?: { contract_rules?: string[] } }).basis
              ?.contract_rules ?? [])
          : [],
      )
      .sort();
    const declared = model.nodes
      .filter((n): n is ContractRuleNode => n.kind === "contract-rule")
      .map((n) => n.declaration)
      .sort();
    expect(declared).toEqual([...new Set(signed)].sort());
  });
});

describe("L2 — no link dangles, and what could not be drawn is stated", () => {
  it("every link's endpoints are nodes of this model", () => {
    const ids = new Set(model.nodes.map((n) => n.id));
    for (const link of model.links) {
      expect(ids.has(link.from), `${link.kind} from ${link.from}`).toBe(true);
      expect(ids.has(link.to), `${link.kind} to ${link.to}`).toBe(true);
    }
    // the invariant is also self-reported, so a future break says so out loud
    expect(model.problems.filter((p) => p.startsWith("internal:"))).toEqual([]);
  });

  it("a recipe whose collector is not registered gets a problem instead of a broken link", () => {
    // this world registered two collectors, so the other recipes' collectors
    // genuinely are not here — the honest reading, said rather than dropped
    const unlinked = recipes.filter(
      (r) => !["graph", "contract"].includes(r.collection.collector),
    );
    expect(unlinked.length).toBeGreaterThan(0);
    for (const recipe of unlinked) {
      expect(model.problems.some((p) => p.includes(`recipe "${recipe.id}"`))).toBe(true);
      expect(model.links.some((l) => l.kind === "evidenced-by" && l.from === `recipe:${recipe.id}`)).toBe(
        false,
      );
    }
    // and the two that ARE registered are linked
    expect(model.links).toContainEqual({
      kind: "evidenced-by",
      from: "recipe:arch-boundaries-hold",
      to: "collector:contract",
    });
  });

  it("the whole registry links cleanly — the problems above are this world's, not the model's", async () => {
    const { allCollectors } = await import("@rampscan/collectors");
    const full = await build({
      toolMap: buildToolMap({
        recipes,
        collectors: allCollectors,
        toolManifest: await loadToolManifest(),
      }),
    });
    expect(full.problems).toEqual([]);
    expect(full.nodes.filter((n) => n.kind === "collector").length).toBe(allCollectors.length);
    // the transitive provenance J5 established: a pure gate still reaches its
    // tool through the artifact it eats
    expect(full.links).toContainEqual({
      kind: "consumes",
      from: "collector:contract",
      to: "collector:graph",
      artifact: "graph.db",
    });
  });
});

describe("L2 — the text reading", () => {
  it("names the repo, its cells, its contract and its graph, and states nothing it does not list", () => {
    const text = renderRepoModel(model, false);
    expect(text).toContain(appRoot);
    expect(text).toContain("billing-isolated (boundary)");
    expect(text).toContain("name-inferred");
    expect(text).toContain(`NODES (${model.nodes.length})`);
    expect(text).toContain(`LINKS (${model.links.length})`);
    expect(text).toContain(`PROBLEMS (${model.problems.length})`);
  });
});
