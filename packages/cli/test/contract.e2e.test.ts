import { execFileSync } from "node:child_process";
import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import { contract, graphCollector } from "@rampscan/collectors";
import { DEFAULT_DATASET_PIN } from "@rampscan/dataset";
import { createLocalLedger } from "@rampscan/ledger";
import { createProjector } from "@rampscan/projector";
import { windowMsFor } from "@rampscan/scheduler";
import { isEvidenceBundle } from "@rampscan/schema";
import type { EvidenceBundle } from "@rampscan/schema";
import type { Projection } from "@rampscan/core";
import { loadRecipes, scan, verify } from "../src/index.js";

// The L1 exit test over a REAL scanned world: an app that declares its own
// architecture contract, checked by the real contract gate against the real
// graph and signed into a real ledger. No external tool is involved — `graph`
// and `contract` are both pure — so every line here is shipping code.
//
// What this file exists to prove, and what a gate unit test cannot: the claim
// an auditor reads is TRUE OF THE SIGNED STATEMENT. In particular the L0
// identity decision, driven for real rather than asserted over synthetic
// bundles — widening an allow-list must kill the evidence that said the old,
// narrower rule held, because that evidence is now a claim about a contract
// that no longer exists.

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "../../..");

const gitEnv = {
  ...process.env,
  GIT_AUTHOR_NAME: "l1-test",
  GIT_AUTHOR_EMAIL: "l1@rampscan.invalid",
  GIT_COMMITTER_NAME: "l1-test",
  GIT_COMMITTER_EMAIL: "l1@rampscan.invalid",
};

function git(cwd: string, ...args: string[]): string {
  return execFileSync("git", args, { cwd, env: gitEnv, encoding: "utf8" }).trim();
}

const BOUNDARY = "arch-boundaries-hold";
const ROUTES = "arch-route-auth-declared";

/** the contract the app declares about itself; `allowedImporters` is what the second scan widens */
function contractJson(allowedImporters: string[]): string {
  return (
    JSON.stringify(
      {
        contract: {
          rules: [
            {
              kind: "boundary",
              id: "billing-isolated",
              module: "src/billing",
              allowedImporters,
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
    ) + "\n"
  );
}

let appRoot: string;
let ledgerDir: string;
let keysDir: string;
let base: string;
let boundaryBundle: EvidenceBundle;
let boundaryDigest: string;
let routeBundle: EvidenceBundle;
let projection: Projection;

async function runScan(now: Date): Promise<void> {
  await scan({
    path: appRoot,
    outDir: join(base, "out"),
    datasetDir: join(repoRoot, "docs/context/ramprules/derived"),
    datasetPin: DEFAULT_DATASET_PIN,
    recipesDir: join(repoRoot, "recipes/pipeline"),
    collectors: [graphCollector, contract],
    ledgerDir,
    keysDir,
    trigger: "test",
    now,
  });
}

async function fold(): Promise<Projection> {
  return createProjector({
    recipes: await loadRecipes(join(repoRoot, "recipes/pipeline")),
    windowMs: windowMsFor("b"),
    now: () => new Date("2026-08-15T12:00:00Z"),
  }).fold(createLocalLedger(ledgerDir));
}

beforeAll(async () => {
  base = await mkdtemp(join(tmpdir(), "rampscan-l1-"));
  appRoot = join(base, "app");
  ledgerDir = join(base, "ledger");
  keysDir = join(base, "keys");
  await mkdir(join(appRoot, "src"), { recursive: true });

  await writeFile(
    join(appRoot, "package.json"),
    JSON.stringify({ name: "l1-app", version: "1.0.0", main: "src/index.js" }, null, 2),
  );
  // the guarded module, and the two importers: one allowed, one not
  await writeFile(
    join(appRoot, "src", "billing.js"),
    "function invoice(x) { return { total: 0, x }; }\nmodule.exports = { invoice };\n",
  );
  await writeFile(
    join(appRoot, "src", "index.js"),
    'const { render } = require("./render");\nfunction handle(i) { return render(i); }\nmodule.exports = { handle };\n',
  );
  // the OFFENDER: render reaches straight into billing
  await writeFile(
    join(appRoot, "src", "render.js"),
    'const { invoice } = require("./billing");\nfunction render(x) { return JSON.stringify(invoice(x)); }\nmodule.exports = { render };\n',
  );
  await writeFile(
    join(appRoot, "src", "auth.js"),
    "function requireAuth(req, res, next) { return next(); }\nmodule.exports = { requireAuth };\n",
  );
  // the ALLOWED importer, plus the route surface: one authed, one not
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
  await writeFile(join(appRoot, "rampscan.config.json"), contractJson(["src/server.js"]));

  git(appRoot, "init", "-q", "-b", "main");
  git(appRoot, "add", "-A");
  git(appRoot, "commit", "-qm", "app with a declared contract");

  await runScan(new Date("2026-08-15T10:00:00Z"));

  const entries = await createLocalLedger(ledgerDir).list();
  const boundary = entries.find(
    (e) => isEvidenceBundle(e.bundle) && e.bundle.predicate.recipe_id === BOUNDARY,
  )!;
  boundaryBundle = boundary.bundle as EvidenceBundle;
  boundaryDigest = boundary.digest;
  routeBundle = entries.find(
    (e) => isEvidenceBundle(e.bundle) && e.bundle.predicate.recipe_id === ROUTES,
  )!.bundle as EvidenceBundle;
  projection = await fold();
}, 180_000);

describe("L1 — a declared architecture contract becomes signed evidence", () => {
  it("the breach is a signed violation naming the rule the repo wrote about itself", () => {
    expect(boundaryBundle.predicate.verdict).toBe("violated");
    expect(boundaryBundle.predicate.collector).toBe("contract");
    const failing = boundaryBundle.predicate.assertions.find((a) => !a.passed)!;
    expect(failing.detail).toContain("src/render.js");
    // the offending import IS the artifact: file, and the edge as the path
    expect(failing.offenders?.[0]?.file).toBe("src/render.js");
    expect(failing.offenders?.[0]?.call_path).toBe("src/render.js » src/billing.js");
    expect(failing.offenders?.[0]?.call_path_resolutions).toEqual(["exact"]);
  });

  it("the allowed importer is not an offender — the allow-list is honored, not ignored", () => {
    const failing = boundaryBundle.predicate.assertions.find((a) => !a.passed)!;
    expect(failing.offender_count).toBe(1);
    expect(failing.detail ?? "").not.toContain('"file":"src/server.js"');
  });

  it("the unauthenticated route breaks the declared route rule, and the authed one does not", () => {
    expect(routeBundle.predicate.verdict).toBe("violated");
    const failing = routeBundle.predicate.assertions.find((a) => !a.passed)!;
    expect(failing.detail).toContain("/health");
    expect(failing.detail ?? "").not.toContain("/invoice");
  });

  it("both claims carry the rules they were checked against, and the direction of their walk", () => {
    const boundaryBasis = boundaryBundle.predicate.basis!;
    const routeBasis = routeBundle.predicate.basis!;
    expect(boundaryBasis.approximation).toBe("over");
    expect(routeBasis.approximation).toBe("under");
    // signed with the claim, and per kind — the L0 identity decision, visible
    // in the statement an auditor downloads
    expect(boundaryBasis.contract_rules).toHaveLength(1);
    expect(boundaryBasis.contract_rules![0]).toContain("billing-isolated");
    expect(routeBasis.contract_rules![0]).toContain("all-routes-authed");
    // and the graph the walk ran over is counted, like every graph-gated claim
    expect(boundaryBasis.graph!.node_count).toBeGreaterThan(0);
  });

  it("the contract file is an anchor: the evidence is about a commit AND a declaration", () => {
    const anchors = boundaryBundle.predicate.anchor_paths.map((a) => a.path);
    expect(anchors).toContain("rampscan.config.json");
    expect(anchors).toContain("src/render.js");
  });

  it("it verifies offline like any other statement — nothing about this tier is special", async () => {
    const report = await verify({ digest: boundaryDigest, ledgerDir, keysDir });
    expect(report.ok).toBe(true);
    expect(report.lines.join("\n")).toContain("signature ok");
    expect(report.lines.join("\n")).toContain("payload  ok");
  });

  it("the rows fold onto the board like any recipe, with their collector and prose", () => {
    const row = projection.registers.find((r) => r.recipeId === BOUNDARY)!;
    expect(row.state).toBe("violated");
    // J3's hop and K1's prose ride the same catalog join — no new plumbing
    expect(row.collector).toBe("contract");
    expect(row.plain?.checks).toContain("module boundaries the repository declares");
    expect(row.plain?.fix).toContain("rampscan.config.json");
    expect(row.runId).toBeTruthy();
    expect(row.pointers?.[0]?.call_path).toBe("src/render.js » src/billing.js");
    // and the crosswalk join: the CM-family controls L0 picked
    expect(row.controlIds).toEqual(["cm-2", "cm-6"]);
  });
});

describe("L1 — editing the contract kills the claim that the old contract held", () => {
  it("widening the allow-list re-keys the boundary evidence and supersedes the old bundle", async () => {
    // the same code, the same "who imports what" — but a DIFFERENT rule. The
    // old bundle said "no importer outside [src/server.js]"; leaving it live
    // would leave that sentence standing over a contract nobody declared any
    // more. This is the case the L0 keying decision exists for.
    await writeFile(
      join(appRoot, "rampscan.config.json"),
      contractJson(["src/server.js", "src/render.js"]),
    );
    git(appRoot, "add", "-A");
    git(appRoot, "commit", "-qm", "widen the billing allow-list");

    await runScan(new Date("2026-08-15T11:00:00Z"));
    const after = await fold();

    const live = after.registers.find((r) => r.recipeId === BOUNDARY)!;
    // the widened contract is now satisfied — the offender became an allowed importer
    expect(live.state).toBe("evidenced");
    expect(live.bundleDigest).not.toBe(boundaryDigest);

    // the old bundle is DEAD, and the record says which way it died
    const old = after.rows.find((r) => r.bundleDigest === boundaryDigest)!;
    expect(old.status.state).toBe("dead");
    expect(["superseded", "anchor-drift"]).toContain(
      (old.status as { cause: string }).cause,
    );

    // the new claim states the new rules — not the old ones
    const entries = await createLocalLedger(ledgerDir).list({ recipeId: BOUNDARY });
    const fresh = entries.find((e) => e.digest === live.bundleDigest)!.bundle as EvidenceBundle;
    expect(fresh.predicate.basis!.contract_rules![0]).toContain("src/render.js");
    expect(fresh.predicate.verdict).toBe("evidenced");
  }, 180_000);

  it("the route claim, whose rule did not change, is untouched by the boundary edit", async () => {
    // per-kind keying earning its keep: one recipe's contract moved, the other
    // recipe's did not, and a shared blob would have re-keyed both
    const after = await fold();
    const routeRow = after.registers.find((r) => r.recipeId === ROUTES)!;
    const entries = await createLocalLedger(ledgerDir).list({ recipeId: ROUTES });
    const liveRoute = entries.find((e) => e.digest === routeRow.bundleDigest)!.bundle as EvidenceBundle;
    expect(liveRoute.predicate.basis!.contract_rules).toEqual(
      routeBundle.predicate.basis!.contract_rules,
    );
  });
});
