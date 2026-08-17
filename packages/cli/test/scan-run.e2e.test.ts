import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, mkdir, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import { exec, repoFacts, resolveTool } from "@rampscan/collectors";
import type { Collector, Projection } from "@rampscan/core";
import { DEFAULT_DATASET_PIN } from "@rampscan/dataset";
import { createLocalLedger } from "@rampscan/ledger";
import { statementFromEnvelope } from "@rampscan/signer";
import { canonicalJson, isScanRun } from "@rampscan/schema";
import type { ScanRun } from "@rampscan/schema";
import { rebuild, scan, verify } from "../src/index.js";
import type { ScanOutcome } from "../src/index.js";

// The Phase J1 exit test, verbatim: a fixture scan appends exactly ONE
// scan-run statement; it verifies offline like any bundle; every dispatched
// collector appears with a version, a runtime, a duration, an exit code and
// its artifact digests; a collector whose tool is hidden from PATH with
// Docker disabled records `runtime: absent` plus the skip reason; `rebuild`
// reproduces `scan_runs` byte-for-byte; and a secret planted in a tool's argv
// never appears in the signed payload.
//
// repo-facts only for the real work — no external tools, CI-safe — plus two
// purpose-built collectors that exercise the absent-tool and planted-secret
// clauses without needing anything installed.

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "../../..");
const PLANTED_SECRET = "ghp_PlantedIntoScanArgv0123456789";

const gitEnv = {
  ...process.env,
  GIT_AUTHOR_NAME: "j1-test",
  GIT_AUTHOR_EMAIL: "j1@rampscan.invalid",
  GIT_COMMITTER_NAME: "j1-test",
  GIT_COMMITTER_EMAIL: "j1@rampscan.invalid",
};

/** a collector whose tool resolves to nothing: no binary, no Docker */
const toollessCollector: Collector = {
  manifest: { name: "toolless", toolVersion: "resolved-at-run", recipes: [], outputs: [] },
  async collect() {
    const tool = await resolveTool(
      "definitely-not-a-real-tool",
      { args: ["--version"], parse: (s) => s },
      { binaryVersion: null, docker: false, manifest: {} },
    );
    return {
      findings: [],
      artifacts: [],
      observations: {},
      toolVersion: "absent",
      exitCode: -1,
      ...(tool ? {} : { skipped: { reason: "definitely-not-a-real-tool did not resolve" } }),
    };
  },
};

/** a collector that spawns a process with a secret sitting in its argv */
const leakyCollector: Collector = {
  manifest: { name: "leaky", toolVersion: "1.0.0", recipes: [], outputs: ["leaky.json"] },
  async collect(ctx) {
    // `--` so node hands the rest to the script instead of parsing it
    const run = await exec(process.execPath, ["-e", "0", "--", "--token", PLANTED_SECRET]);
    const path = join(ctx.artifactDir, "leaky.json");
    await writeFile(path, JSON.stringify({ ok: true }) + "\n");
    return {
      findings: [],
      artifacts: [{ name: "leaky.json", path }],
      observations: {},
      toolVersion: "1.0.0",
      exitCode: run.exitCode,
    };
  },
};

let appRoot: string;
let ledgerDir: string;
let keysDir: string;
let outDir: string;
let cacheDir: string;
let outcome: ScanOutcome;
let runRecord: ScanRun;
let runDigest: string;

function git(cwd: string, ...args: string[]): string {
  return execFileSync("git", args, { cwd, env: gitEnv, encoding: "utf8" }).trim();
}

function runScan(overrides: Partial<Parameters<typeof scan>[0]> = {}) {
  return scan({
    path: appRoot,
    outDir,
    datasetDir: join(repoRoot, "docs/context/ramprules/derived"),
    datasetPin: DEFAULT_DATASET_PIN,
    recipesDir: join(repoRoot, "recipes/commit"),
    collectors: [repoFacts, toollessCollector, leakyCollector],
    ledgerDir,
    keysDir,
    now: new Date("2026-08-15T10:00:00Z"),
    ...overrides,
  });
}

beforeAll(async () => {
  const base = await mkdtemp(join(tmpdir(), "rampscan-j1-"));
  appRoot = join(base, "app");
  ledgerDir = join(base, "ledger");
  keysDir = join(base, "keys");
  outDir = join(base, "out");
  cacheDir = join(base, "cache");
  await mkdir(join(appRoot, ".github", "workflows"), { recursive: true });
  await writeFile(
    join(appRoot, "package.json"),
    JSON.stringify({ name: "j1-app", version: "1.0.0" }, null, 2),
  );
  await writeFile(
    join(appRoot, "package-lock.json"),
    JSON.stringify({ name: "j1-app", version: "1.0.0", lockfileVersion: 3, packages: {} }, null, 2),
  );
  await writeFile(
    join(appRoot, ".github", "workflows", "ci.yml"),
    ["on: push", "jobs:", "  test:", "    runs-on: ubuntu-latest", "    steps:", "      - run: npm test"].join("\n") + "\n",
  );
  git(appRoot, "init", "-q", "-b", "main");
  git(appRoot, "add", "-A");
  git(appRoot, "commit", "-qm", "app");

  outcome = await runScan({ trigger: "test" });

  const entries = await createLocalLedger(ledgerDir).list();
  const runs = entries.filter((e) => isScanRun(e.bundle));
  expect(runs).toHaveLength(1);
  runDigest = runs[0]!.digest;
  runRecord = runs[0]!.bundle as ScanRun;
}, 120_000);

describe("J1 — the run record is appended, signed, and verifiable", () => {
  it("appends exactly one scan-run per scan and reports its digest", () => {
    expect(outcome.run).toBeDefined();
    expect(outcome.run!.digest).toBe(runDigest);
    expect(outcome.run!.collectors).toBe(3);
    expect(outcome.run!.skipped).toBe(1);
  });

  it("verifies offline exactly like an evidence bundle", async () => {
    const report = await verify({ digest: runDigest, ledgerDir, keysDir });
    expect(report.ok).toBe(true);
    expect(report.lines.join("\n")).toContain("scan-run");
    expect(report.lines.join("\n")).toContain("signature ok");
    expect(report.lines.join("\n")).toContain("payload  ok");
  });

  it("carries the run's own clock — the same instant its bundles do", async () => {
    const entries = await createLocalLedger(ledgerDir).list();
    const bundleTimes = new Set(
      entries.filter((e) => !isScanRun(e.bundle)).map((e) => e.bundle.predicate.timestamp),
    );
    expect(bundleTimes.has(runRecord.predicate.timestamp)).toBe(true);
    expect(runRecord.predicate.trigger).toBe("test");
  });

  it("attests to scan-result.json by digest, so a run with no artifacts still has a subject", async () => {
    const subject = runRecord.subject.find((s) => s.name === "scan-result.json");
    expect(subject).toBeDefined();
    const onDisk = createHash("sha256")
      .update(await readFile(join(outDir, "scan-result.json")))
      .digest("hex");
    expect(subject!.digest["sha256"]).toBe(onDisk);
  });
});

describe("J1 — every collector that was dispatched is in the record", () => {
  it("names all three, whether they ran or not", () => {
    expect(runRecord.predicate.collectors.map((c) => c.collector)).toEqual([
      "repo-facts",
      "toolless",
      "leaky",
    ]);
  });

  it("records version, duration, exit code and artifact digests for a collector that ran", async () => {
    const leaky = runRecord.predicate.collectors.find((c) => c.collector === "leaky")!;
    expect(leaky.tool_version).toBe("1.0.0");
    expect(leaky.exit_code).toBe(0);
    expect(leaky.duration_ms).toBeGreaterThanOrEqual(0);
    expect(leaky.skip_reason).toBeUndefined();
    expect(leaky.invocations.length).toBeGreaterThan(0);

    // the digest in the record is the digest of the bytes on disk — not a
    // name, not a path, the content
    const artifact = leaky.artifacts.find((a) => a.name === "leaky.json")!;
    const onDisk = createHash("sha256")
      .update(await readFile(join(outDir, "artifacts", "leaky", "leaky.json")))
      .digest("hex");
    expect(artifact.sha256).toBe(onDisk);
    expect(artifact.bytes).toBeGreaterThan(0);
  });

  it("records `absent` plus the named reason when a tool does not resolve", () => {
    const toolless = runRecord.predicate.collectors.find((c) => c.collector === "toolless")!;
    expect(toolless.skip_reason).toContain("did not resolve");
    expect(toolless.tools).toHaveLength(1);
    const runtime = toolless.tools[0]!.runtime;
    expect(runtime.kind).toBe("absent");
    // the operator-facing half: WHY nothing resolved, not just that nothing did
    expect(runtime.kind === "absent" && runtime.reason).toMatch(/not on PATH/);
    expect(toolless.tools[0]!.version).toBeUndefined();
  });

  it("states no cache when none was configured, rather than guessing a state", () => {
    for (const collector of runRecord.predicate.collectors) {
      expect(collector.cache.state).toBe("none");
      expect(collector.cache.key).toBeUndefined();
    }
  });

  it("quotes no verdict, no register state, and no coverage number", () => {
    const text = canonicalJson(runRecord);
    for (const forbidden of ["evidenced", "violated", "unevidenced", "notApplicable"]) {
      expect(text).not.toContain(`"${forbidden}"`);
    }
  });
});

describe("J1 — the redaction holds in the signed payload", () => {
  it("never lets a planted argv secret into the permanent record", async () => {
    // three places it could have leaked: the statement, the canonical bytes
    // the digest addresses, and the base64 payload the signature covers
    expect(canonicalJson(runRecord)).not.toContain(PLANTED_SECRET);

    const entry = await createLocalLedger(ledgerDir).get(runDigest);
    expect(JSON.stringify(statementFromEnvelope(entry!.envelope!))).not.toContain(PLANTED_SECRET);
    expect(Buffer.from(entry!.envelope!.payload, "base64").toString("utf8")).not.toContain(
      PLANTED_SECRET,
    );

    // and the placeholder is there instead — the record says an argument was
    // present and how big it was, it just does not say what it held
    const leaky = runRecord.predicate.collectors.find((c) => c.collector === "leaky")!;
    expect(leaky.invocations.flatMap((i) => i.argv)).toContain(
      `<redacted:${PLANTED_SECRET.length} bytes>`,
    );
    expect(leaky.invocations.flatMap((i) => i.argv)).toContain("--token");
  });
});

describe("J1 — the projection folds it and rebuild proves it", () => {
  let projection: Projection;

  beforeAll(async () => {
    const report = await rebuild({
      ledgerDir,
      recipesDir: join(repoRoot, "recipes/commit"),
      dbPath: join(await mkdtemp(join(tmpdir(), "rampscan-j1-db-")), "projection.db"),
    });
    expect(report.ok).toBe(true); // sqlite reads back byte-identical to the fold
    projection = report.projection;
  }, 60_000);

  it("projects the run, structurally, straight off the signed predicate", () => {
    expect(projection.scanRuns).toHaveLength(1);
    const row = projection.scanRuns[0]!;
    expect(row.digest).toBe(runDigest);
    expect(row.runId).toBe(runRecord.predicate.run_id);
    expect(row.trigger).toBe("test");
    expect(canonicalJson(row.collectors)).toBe(canonicalJson(runRecord.predicate.collectors));
  });

  it("lets no run record touch a register cell", () => {
    // the fold derives repos from evidence and scoping alone: a scan run
    // names a repo too, and if it could introduce cells the board would be
    // partly a function of the run log
    for (const row of projection.registers) {
      expect(row.repo).toBe(runRecord.predicate.repo);
    }
    expect(projection.rows.every((r) => r.recipeId.length > 0)).toBe(true);
    // and nothing in the coverage chain points at the run record's digest
    expect(projection.rows.some((r) => r.bundleDigest === runDigest)).toBe(false);
    expect(projection.registers.some((r) => r.bundleDigest === runDigest)).toBe(false);
  });
});

describe("J1 — the cache states are recorded, not inferred", () => {
  it("records miss then hit across two cached scans, and replays the cached telemetry", async () => {
    const first = await runScan({
      cache: { dir: cacheDir, mode: "incremental" },
      now: new Date("2026-08-15T11:00:00Z"),
      trigger: "daemon-incremental",
    });
    const second = await runScan({
      cache: { dir: cacheDir, mode: "incremental" },
      now: new Date("2026-08-15T12:00:00Z"),
      trigger: "daemon-incremental",
    });

    const entries = await createLocalLedger(ledgerDir).list();
    const byDigest = new Map(entries.map((e) => [e.digest, e.bundle]));
    const firstRun = byDigest.get(first.run!.digest) as ScanRun;
    const secondRun = byDigest.get(second.run!.digest) as ScanRun;

    const facts = (r: ScanRun) => r.predicate.collectors.find((c) => c.collector === "repo-facts")!;
    expect(facts(firstRun).cache.state).toBe("miss");
    expect(facts(secondRun).cache.state).toBe("hit");
    // the key and the DECLARED scope terms ride along; the resolved file list
    // (a thousand blob hashes) deliberately does not
    expect(facts(secondRun).cache.key).toBe(facts(firstRun).cache.key);
    expect(facts(secondRun).cache.scope).toContain("package.json");

    // a collector with no cacheScope is never cached, and says so by name
    expect(
      firstRun.predicate.collectors.find((c) => c.collector === "leaky")!.cache.state,
    ).toBe("uncachable");

    // three scans, three run records — always-append, never deduplicated:
    // two identical-looking scans an hour apart are two facts, not one
    expect(entries.filter((e) => isScanRun(e.bundle))).toHaveLength(3);
  }, 120_000);
});
