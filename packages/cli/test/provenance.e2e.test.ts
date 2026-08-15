import { execFileSync } from "node:child_process";
import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import { graphCollector, sastGate } from "@rampscan/collectors";
import type { Collector } from "@rampscan/core";
import { DEFAULT_DATASET_PIN } from "@rampscan/dataset";
import { createLocalLedger } from "@rampscan/ledger";
import { isEvidenceBundle, isScanRun } from "@rampscan/schema";
import type { EvidenceBundle, ScanRun } from "@rampscan/schema";
import { scan, verify } from "../src/index.js";

// The J5 / I3f exit test over a REAL scanned world: a two-file app with an
// eval reachable from its entry point, gated by the real `sast-reachability`
// collector against the real graph, signed into a real ledger.
//
// No external tool is needed for any of it. `graph` is pure, and semgrep's
// side is a stand-in producer that writes the same artifact the real semgrep
// writes — so the collector under test, the graph walk, the basis, the
// per-hop marks and the run record's `consumes` are all the shipping code.
//
// What this file is for: the claims the console renders must be TRUE OF THE
// SIGNED STATEMENT, not merely renderable. A page can show an entry-point set
// that no bundle contains; that would pass a UI test and fail an auditor.

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "../../..");

const gitEnv = {
  ...process.env,
  GIT_AUTHOR_NAME: "j5-test",
  GIT_AUTHOR_EMAIL: "j5@rampscan.invalid",
  GIT_COMMITTER_NAME: "j5-test",
  GIT_COMMITTER_EMAIL: "j5@rampscan.invalid",
};

/** stands in for semgrep: writes the artifact the real one writes, spawns nothing */
const fakeSemgrep: Collector = {
  manifest: {
    name: "semgrep",
    toolVersion: "1.173.0",
    recipes: [],
    outputs: ["semgrep-results.json"],
    tools: [],
  },
  async collect(ctx) {
    const path = join(ctx.artifactDir, "semgrep-results.json");
    await writeFile(
      path,
      JSON.stringify({
        tool: "semgrep",
        version: "1.173.0",
        rules: "0".repeat(64),
        error_count: 0,
        results: [
          {
            check_id: "dangerous-eval",
            path: "src/render.js",
            start_line: 3,
            end_line: 3,
            severity: "ERROR",
            message: "eval() executes dynamically constructed code",
          },
          {
            check_id: "dangerous-eval",
            path: "src/orphan.js",
            start_line: 2,
            end_line: 2,
            severity: "ERROR",
            message: "eval() executes dynamically constructed code",
          },
        ],
      }) + "\n",
    );
    return {
      findings: [],
      artifacts: [{ name: "semgrep-results.json", path }],
      observations: {},
      toolVersion: "1.173.0",
      exitCode: 0,
    };
  },
};

let appRoot: string;
let ledgerDir: string;
let keysDir: string;
let sastBundle: EvidenceBundle;
let sastDigest: string;
let routeBundle: EvidenceBundle;
let runRecord: ScanRun;

function git(cwd: string, ...args: string[]): string {
  return execFileSync("git", args, { cwd, env: gitEnv, encoding: "utf8" }).trim();
}

beforeAll(async () => {
  const base = await mkdtemp(join(tmpdir(), "rampscan-j5-"));
  appRoot = join(base, "app");
  ledgerDir = join(base, "ledger");
  keysDir = join(base, "keys");
  await mkdir(join(appRoot, "src"), { recursive: true });
  await writeFile(
    join(appRoot, "package.json"),
    JSON.stringify({ name: "j5-app", version: "1.0.0", main: "src/index.js" }, null, 2),
  );
  // index → render (reachable eval); orphan is imported by nothing
  await writeFile(
    join(appRoot, "src", "index.js"),
    'const { render } = require("./render");\nfunction handle(input) { return render(input); }\nmodule.exports = { handle };\n',
  );
  await writeFile(
    join(appRoot, "src", "render.js"),
    'function render(t) {\n  // eslint-disable-next-line\n  return eval(t);\n}\nmodule.exports = { render };\n',
  );
  await writeFile(
    join(appRoot, "src", "orphan.js"),
    'function dead(t) {\n  return eval(t);\n}\nmodule.exports = { dead };\n',
  );
  // a route surface, so the SAME scan also produces the claim whose walk errs
  // the other way — "this route reaches auth" is positive and must rest on a
  // real chain
  await writeFile(
    join(appRoot, "src", "server.js"),
    [
      'const express = require("express");',
      'const { requireAuth } = require("./auth");',
      "const app = express();",
      'app.get("/health", (req, res) => res.send("ok"));',
      'app.get("/secret", requireAuth, (req, res) => res.send("shh"));',
      "module.exports = { app };",
    ].join("\n") + "\n",
  );
  await writeFile(
    join(appRoot, "src", "auth.js"),
    "function requireAuth(req, res, next) { return next(); }\nmodule.exports = { requireAuth };\n",
  );
  git(appRoot, "init", "-q", "-b", "main");
  git(appRoot, "add", "-A");
  git(appRoot, "commit", "-qm", "app");

  await scan({
    path: appRoot,
    outDir: join(base, "out"),
    datasetDir: join(repoRoot, "docs/context/ramprules/derived"),
    datasetPin: DEFAULT_DATASET_PIN,
    recipesDir: join(repoRoot, "recipes/pipeline"),
    collectors: [graphCollector, fakeSemgrep, sastGate],
    ledgerDir,
    keysDir,
    trigger: "test",
    now: new Date("2026-08-15T10:00:00Z"),
  });

  const entries = await createLocalLedger(ledgerDir).list();
  const sast = entries.find(
    (e) => isEvidenceBundle(e.bundle) && e.bundle.predicate.recipe_id === "no-reachable-dangerous-code",
  )!;
  sastBundle = sast.bundle as EvidenceBundle;
  sastDigest = sast.digest;
  routeBundle = entries.find(
    (e) => isEvidenceBundle(e.bundle) && e.bundle.predicate.recipe_id === "route-auth-coverage",
  )!.bundle as EvidenceBundle;
  runRecord = entries.find((e) => isScanRun(e.bundle))!.bundle as ScanRun;
}, 180_000);

describe("J5 — the chain rests on signed data, not on today's catalog", () => {
  it("the bundle names the collector that produced it", () => {
    expect(sastBundle.predicate.collector).toBe("sast-reachability");
  });

  it("the run record says what that collector ate, so the chain can reach the tool behind it", () => {
    const row = runRecord.predicate.collectors.find((c) => c.collector === "sast-reachability")!;
    // the gate spawns nothing: without `consumes` the chain would say "no
    // external tool" over a verdict semgrep's output produced
    expect(row.tools).toEqual([]);
    expect(row.consumes).toEqual(["semgrep-results.json", "graph.db"]);
    const producer = runRecord.predicate.collectors.find((c) =>
      c.artifacts.some((a) => a.name === "semgrep-results.json"),
    )!;
    expect(producer.collector).toBe("semgrep");
  });

  it("the whole thing still verifies offline", async () => {
    const report = await verify({ digest: sastDigest, ledgerDir, keysDir });
    expect(report.ok).toBe(true);
  });
});

describe("I3f — the not-affected claim shows its work", () => {
  it("the verdict rests on a basis the statement itself carries", () => {
    const basis = sastBundle.predicate.basis!;
    expect(basis).toBeDefined();
    expect(basis.approximation).toBe("over");
    // the entry-point set, and where it came from — the two facts a reader
    // needs to disagree with a not-affected claim
    expect(basis.entrypoints).toEqual(["src/index.js"]);
    expect(basis.entrypoint_source).toBe("package.json");
    expect(basis.degraded).toBeUndefined();
  });

  it("states the direction of the error out loud — unknowns count against us", () => {
    const statement = sastBundle.predicate.basis!.statement;
    expect(statement).toContain("OVER-approximate");
    expect(statement.toLowerCase()).toContain("unknowns count against us");
  });

  it("names the graph it walked, including how many edges were only name-inferred", () => {
    const graph = sastBundle.predicate.basis!.graph!;
    expect(graph.commit).toHaveLength(40);
    expect(graph.node_count).toBeGreaterThan(0);
    expect(graph.inferred_edge_count).toBeLessThanOrEqual(graph.edge_count);
  });

  it("the reachable hit is violated with a per-hop marked call path", () => {
    const assertion = sastBundle.predicate.assertions[0]!;
    expect(assertion.passed).toBe(false);
    const offender = assertion.offenders!.find((o) => o.file === "src/render.js")!;
    expect(offender.call_path).toBe("src/index.js » src/render.js");
    // one mark per hop, and the marks describe THIS path
    expect(offender.call_path_resolutions).toEqual(["exact"]);
    expect(offender.call_path_resolutions).toHaveLength(
      offender.call_path!.split(" » ").length - 1,
    );
  });

  it("the unreachable hit is waived, and the waiver is exactly what the basis grounds", () => {
    // src/orphan.js has the same ERROR-severity eval and is imported by
    // nothing — it is not_affected, which is the claim the entry-point set
    // above is the entire justification for
    const assertion = sastBundle.predicate.assertions[0]!;
    const offenders = assertion.offenders!.map((o) => o.file);
    expect(offenders).toContain("src/render.js");
    expect(offenders).not.toContain("src/orphan.js");
    expect(assertion.offender_count).toBe(1);
  });

  it("the route-auth claim carries the OTHER approximation direction", () => {
    // a positive claim ("this route reaches auth") may only rest on a real
    // call chain, so its walk errs the opposite way from the gates' — and the
    // basis says which, rather than leaving both walks to read alike
    const basis = routeBundle.predicate.basis!;
    expect(basis.approximation).toBe("under");
    expect(basis.statement).toContain("UNCOVERED");
    // both claims came out of one graph, and both name it
    expect(basis.graph!.commit).toBe(sastBundle.predicate.basis!.graph!.commit);
    expect(basis.route_roots).toBe(2);
  });
});

describe("I3f — a walk with no root proves nothing, and says so", () => {
  it("an app whose entry points cannot be detected records a degraded basis", async () => {
    const base = await mkdtemp(join(tmpdir(), "rampscan-j5-noentry-"));
    const root = join(base, "app");
    await mkdir(join(root, "lib"), { recursive: true });
    // no package.json main/bin/exports and no conventional filename: nothing
    // to root the walk at
    await writeFile(join(root, "package.json"), JSON.stringify({ name: "no-entry" }, null, 2));
    await writeFile(join(root, "lib", "thing.js"), "function f(t) { return eval(t); }\nmodule.exports = { f };\n");
    git(root, "init", "-q", "-b", "main");
    git(root, "add", "-A");
    git(root, "commit", "-qm", "app");

    const semgrepForThing: Collector = {
      ...fakeSemgrep,
      async collect(ctx) {
        const path = join(ctx.artifactDir, "semgrep-results.json");
        await writeFile(
          path,
          JSON.stringify({
            tool: "semgrep",
            version: "1.173.0",
            rules: "0".repeat(64),
            error_count: 0,
            results: [
              {
                check_id: "dangerous-eval",
                path: "lib/thing.js",
                start_line: 1,
                end_line: 1,
                severity: "ERROR",
                message: "eval()",
              },
            ],
          }) + "\n",
        );
        return {
          findings: [],
          artifacts: [{ name: "semgrep-results.json", path }],
          observations: {},
          toolVersion: "1.173.0",
          exitCode: 0,
        };
      },
    };

    const ledger2 = join(base, "ledger");
    await scan({
      path: root,
      outDir: join(base, "out"),
      datasetDir: join(repoRoot, "docs/context/ramprules/derived"),
      datasetPin: DEFAULT_DATASET_PIN,
      recipesDir: join(repoRoot, "recipes/pipeline"),
      collectors: [graphCollector, semgrepForThing, sastGate],
      ledgerDir: ledger2,
      keysDir,
      trigger: "test",
      now: new Date("2026-08-15T10:00:00Z"),
    });

    const entries = await createLocalLedger(ledger2).list();
    const bundle = entries.find(
      (e) => isEvidenceBundle(e.bundle) && e.bundle.predicate.recipe_id === "no-reachable-dangerous-code",
    )!.bundle as EvidenceBundle;
    const basis = bundle.predicate.basis!;
    expect(basis.entrypoints).toEqual([]);
    expect(basis.degraded).toContain("no entry points detected");
    // and the hit COUNTS: a walk with no root waives nothing
    expect(bundle.predicate.verdict).toBe("violated");
  }, 180_000);
});
