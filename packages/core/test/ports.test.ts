import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  createLocalRepoSource,
  createLocalRunner,
  createLocalScheduler,
} from "../src/index.js";
import type { Collector } from "../src/index.js";

// Runner and RepoSource are real as of M1; ledger/signer/projector are real
// as of M2 and live in their own packages. The still-stubbed Scheduler must
// keep failing loudly rather than silently succeeding — a stub that returns
// fake data is worse than none.

describe("still-stubbed local adapters", () => {
  it("the scheduler rejects with its landing milestone", async () => {
    await expect(
      createLocalScheduler().ensureCadence("b", { repo: "x" }),
    ).rejects.toThrow(/M5/);
  });
});

describe("local RepoSource (M1)", () => {
  it("pins a workspace to the checkout's HEAD commit", async () => {
    // this repo is itself a git checkout — the cheapest honest fixture
    const ws = await createLocalRepoSource().fetch({ repo: join(import.meta.dirname, "../../..") });
    expect(ws.commit).toMatch(/^[0-9a-f]{40}$/);
  });

  it("refuses a path without git history — commit anchoring is not optional", async () => {
    const dir = await mkdtemp(join(tmpdir(), "rampscan-nogit-"));
    await expect(createLocalRepoSource().fetch({ repo: dir })).rejects.toThrow(/git/);
  });
});

describe("local Runner (M1)", () => {
  const workspace = { root: "/tmp", repo: "x", commit: "0".repeat(40) };

  it("rejects a manifest with no registered collector", async () => {
    const runner = createLocalRunner({
      collectors: [],
      artifactDir: tmpdir(),
      runId: "test",
    });
    await expect(
      runner.run({ name: "ghost", toolVersion: "0", recipes: [] }, workspace),
    ).rejects.toThrow(/no collector registered/);
  });

  it("hashes artifacts, relativizes paths, and exposes them to later collectors", async () => {
    const artifactDir = await mkdtemp(join(tmpdir(), "rampscan-artifacts-"));
    const producer: Collector = {
      manifest: { name: "producer", toolVersion: "1", recipes: ["r1"] },
      collect: async (ctx) => {
        const p = join(ctx.artifactDir, "out.json");
        await writeFile(p, '{"hello":true}');
        return {
          findings: [],
          artifacts: [{ name: "out.json", path: p }],
          observations: { r1: [{ ok: true }] },
          toolVersion: "1",
          exitCode: 0,
        };
      },
    };
    const inputs = new Map<string, string>();
    const runner = createLocalRunner({ collectors: [producer], artifactDir, runId: "t", inputs });
    const result = await runner.run(producer.manifest, workspace);
    expect(result.artifacts).toHaveLength(1);
    expect(result.artifacts[0]!.path).toBe(join("producer", "out.json"));
    expect(result.artifacts[0]!.sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(inputs.get("out.json")).toBe(join(artifactDir, "producer", "out.json"));
  });

  it("is the Zod boundary: malformed findings from a collector fail loudly", async () => {
    const artifactDir = await mkdtemp(join(tmpdir(), "rampscan-artifacts-"));
    const liar: Collector = {
      manifest: { name: "liar", toolVersion: "1", recipes: [] },
      collect: async () => ({
        findings: [{ not: "a finding" } as never],
        artifacts: [],
        observations: {},
        toolVersion: "1",
        exitCode: 0,
      }),
    };
    const runner = createLocalRunner({ collectors: [liar], artifactDir, runId: "t" });
    await expect(runner.run(liar.manifest, workspace)).rejects.toThrow();
  });
});
