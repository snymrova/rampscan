import { execFileSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { beforeEach, describe, expect, it } from "vitest";
import { createCachingRunner, createLocalRunner, globToRegExp } from "../src/index.js";
import type { CacheOutcome, Collector, Workspace } from "../src/index.js";

// The scan cache (G2): dirty-set by content hash, read from the committed
// tree. A changed scoped file changes the key; an unrelated change does not;
// a changed tool version always does; skipped runs are never cached.

const gitEnv = {
  ...process.env,
  GIT_AUTHOR_NAME: "m5-test",
  GIT_AUTHOR_EMAIL: "m5@rampscan.invalid",
  GIT_COMMITTER_NAME: "m5-test",
  GIT_COMMITTER_EMAIL: "m5@rampscan.invalid",
};

function git(cwd: string, ...args: string[]): string {
  return execFileSync("git", args, { cwd, env: gitEnv, encoding: "utf8" }).trim();
}

async function makeRepo(): Promise<Workspace> {
  const root = await mkdtemp(join(tmpdir(), "rampscan-cache-repo-"));
  await writeFile(join(root, "package.json"), '{"name":"x"}\n');
  await mkdir(join(root, "src"), { recursive: true });
  await writeFile(join(root, "src/app.ts"), "export const a = 1;\n");
  await writeFile(join(root, "README.md"), "hello\n");
  git(root, "init", "-q");
  git(root, "add", "-A");
  git(root, "commit", "-qm", "initial");
  return { root, repo: root, commit: git(root, "rev-parse", "HEAD") };
}

interface TestHarness {
  workspace: Workspace;
  cacheDir: string;
  artifactDir: string;
  inputs: Map<string, string>;
  runs: number;
  outcomes: CacheOutcome[];
  run(mode?: "incremental" | "full", toolVersion?: string): Promise<Awaited<ReturnType<ReturnType<typeof createLocalRunner>["run"]>>>;
}

async function makeHarness(cacheScope: string[]): Promise<TestHarness> {
  const workspace = await makeRepo();
  const cacheDir = await mkdtemp(join(tmpdir(), "rampscan-cache-"));

  const h: TestHarness = {
    workspace,
    cacheDir,
    artifactDir: "",
    inputs: new Map(),
    runs: 0,
    outcomes: [],
    async run(mode = "incremental", toolVersion = "1.0.0") {
      // each scan gets a fresh artifact dir and inputs map, like a real run
      h.artifactDir = await mkdtemp(join(tmpdir(), "rampscan-cache-art-"));
      h.inputs = new Map();
      const collector: Collector = {
        manifest: { name: "probe", toolVersion, recipes: ["r1"], cacheScope },
        collect: async (ctx) => {
          h.runs += 1;
          const p = join(ctx.artifactDir, "probe.json");
          await writeFile(p, JSON.stringify({ run: h.runs }));
          return {
            findings: [],
            artifacts: [{ name: "probe.json", path: p }],
            observations: { r1: [{ run: h.runs }] },
            toolVersion,
            exitCode: 0,
          };
        },
      };
      const inner = createLocalRunner({
        collectors: [collector],
        artifactDir: h.artifactDir,
        inputs: h.inputs,
        runId: `t-${h.runs}`,
      });
      const runner = createCachingRunner(inner, {
        dir: cacheDir,
        mode,
        artifactDir: h.artifactDir,
        inputs: h.inputs,
        onOutcome: (_c, outcome) => h.outcomes.push(outcome),
      });
      return runner.run(collector.manifest, workspace);
    },
  };
  return h;
}

describe("globToRegExp", () => {
  it("`*` and `?` stay inside a path segment; `**` crosses", () => {
    expect(globToRegExp("*.ts").test("a.ts")).toBe(true);
    expect(globToRegExp("*.ts").test("src/a.ts")).toBe(false);
    expect(globToRegExp("**/*.ts").test("src/deep/a.ts")).toBe(true);
    expect(globToRegExp("**/*.ts").test("a.ts")).toBe(true); // `**/` matches zero dirs
    expect(globToRegExp("src/?.ts").test("src/a.ts")).toBe(true);
    expect(globToRegExp("src/?.ts").test("src/ab.ts")).toBe(false);
    expect(globToRegExp(".github/workflows/*.yml").test(".github/workflows/ci.yml")).toBe(true);
  });
});

describe("createCachingRunner", () => {
  let h: TestHarness;
  beforeEach(async () => {
    h = await makeHarness(["package.json", "src/**/*.ts"]);
  });

  it("miss then hit: the second run reuses the result and restores artifacts", async () => {
    const first = await h.run();
    const second = await h.run();
    expect(h.runs).toBe(1); // the collector ran once
    expect(h.outcomes).toEqual(["miss", "hit"]);
    expect(second.observations).toEqual(first.observations);
    // the artifact was restored into the NEW artifact dir and registered as an input
    const restored = h.inputs.get("probe.json");
    expect(restored).toBe(join(h.artifactDir, "probe", "probe.json"));
    expect(JSON.parse(await readFile(restored!, "utf8"))).toEqual({ run: 1 });
  });

  it("a committed change to a scoped file is a dirty set of one → miss", async () => {
    await h.run();
    await writeFile(join(h.workspace.root, "src/app.ts"), "export const a = 2;\n");
    git(h.workspace.root, "add", "-A");
    git(h.workspace.root, "commit", "-qm", "touch scoped");
    await h.run();
    expect(h.runs).toBe(2);
    expect(h.outcomes).toEqual(["miss", "miss"]);
  });

  it("a committed change OUTSIDE the scope leaves the key clean → hit", async () => {
    await h.run();
    await writeFile(join(h.workspace.root, "README.md"), "changed\n");
    git(h.workspace.root, "add", "-A");
    git(h.workspace.root, "commit", "-qm", "touch unscoped");
    await h.run();
    expect(h.runs).toBe(1);
    expect(h.outcomes).toEqual(["miss", "hit"]);
  });

  it("a tool version change re-keys everything (ground rule 5)", async () => {
    await h.run("incremental", "1.0.0");
    await h.run("incremental", "2.0.0");
    expect(h.runs).toBe(2);
    expect(h.outcomes).toEqual(["miss", "miss"]);
  });

  it("full mode bypasses reads but refreshes the entry", async () => {
    await h.run(); // miss → entry written
    await h.run("full"); // bypass → runs again, rewrites entry
    expect(h.runs).toBe(2);
    await h.run(); // the refreshed entry serves the hit
    expect(h.runs).toBe(2);
    expect(h.outcomes).toEqual(["miss", "bypass", "hit"]);
  });

  it("@commit keys on the commit: an unrelated commit still re-runs", async () => {
    const hc = await makeHarness(["@commit"]);
    await hc.run();
    await writeFile(join(hc.workspace.root, "README.md"), "moved\n");
    git(hc.workspace.root, "add", "-A");
    git(hc.workspace.root, "commit", "-qm", "any commit");
    hc.workspace.commit = git(hc.workspace.root, "rev-parse", "HEAD");
    await hc.run();
    expect(hc.runs).toBe(2);
  });

  it("no cacheScope → uncachable, always runs", async () => {
    const hn = await makeHarness([]);
    await hn.run();
    await hn.run();
    expect(hn.runs).toBe(2);
    expect(hn.outcomes).toEqual(["uncachable", "uncachable"]);
  });

  it("a skipped run is never cached — skip reasons are environmental", async () => {
    const workspace = await makeRepo();
    const cacheDir = await mkdtemp(join(tmpdir(), "rampscan-cache-"));
    let runs = 0;
    const skipper: Collector = {
      manifest: { name: "skipper", toolVersion: "1", recipes: [], cacheScope: ["package.json"] },
      collect: async () => {
        runs += 1;
        return {
          findings: [],
          artifacts: [],
          observations: {},
          toolVersion: "1",
          exitCode: 0,
          skipped: { reason: "tool missing" },
        };
      },
    };
    const artifactDir = await mkdtemp(join(tmpdir(), "rampscan-cache-art-"));
    const inputs = new Map<string, string>();
    const runner = createCachingRunner(
      createLocalRunner({ collectors: [skipper], artifactDir, inputs, runId: "t" }),
      { dir: cacheDir, mode: "incremental", artifactDir, inputs },
    );
    await runner.run(skipper.manifest, workspace);
    await runner.run(skipper.manifest, workspace);
    expect(runs).toBe(2); // no entry was ever written
  });
});
