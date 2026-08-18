import { describe, expect, it } from "vitest";
import type { Collector, Runner, Workspace } from "@rampscan/core";
import {
  CONTAINER_MOUNT_ROOT,
  createJournaledRunner,
  isSafeArgvToken,
  redactArgv,
  resolveBinaryPath,
  withJournal,
} from "../src/journal.js";
import { exec } from "../src/support.js";
import { resolveTool } from "../src/tools.js";

// The exec journal (plan J1). Two things are pinned here: the ALLOWLIST that
// decides what argv survives into a permanent signed statement, and the fact
// that a collector cannot opt out of being recorded.

const ROOTS = ["/work/repo", "/work/out", CONTAINER_MOUNT_ROOT];

describe("argv redaction — allowlist", () => {
  it("keeps the shapes collectors actually pass", () => {
    const safe = [
      "--version",
      "-o",
      "--format=json",
      "scan",
      "cyclonedx-json",
      "anchore/syft:v1.18.1",
      "dir:/work/repo",
      "./**/node_modules/**",
      "/work/repo/src/index.js",
      // a real path under a root the run owns keeps its capitals
      "/work/repo/SRC/Index.JS",
      // a docker bind mount: host path, container path, mode
      `/work/out:${CONTAINER_MOUNT_ROOT}/m0:ro`,
      "",
    ];
    expect(redactArgv(safe, ROOTS)).toEqual(safe);
  });

  it("redacts credential shapes, whatever they are called", () => {
    const planted = [
      "ghp_S3cretTokenValue123456",
      "AKIAIOSFODNN7EXAMPLE",
      "sk-proj-" + "a".repeat(40),
      "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln",
      "x".repeat(41),
      // underscore is allowed only inside path-shaped tokens, so a bare
      // `service_account_key`-shaped value never reaches the vocabulary rule
      "sk_live_" + "abcdefghijklmnop",
      // slash-bearing, lowercase — but one segment is far too long to be a
      // path segment, which is what separates a directory from a blob
      `a/${"b".repeat(65)}`,
    ];
    for (const token of planted) {
      expect(isSafeArgvToken(token, ROOTS), token).toBe(false);
    }
    for (const rendered of redactArgv(planted, ROOTS)) {
      expect(rendered).toMatch(/^<redacted:\d+ bytes>$/);
    }
  });

  it("keeps the flag and hides only the value on --flag=<secret>", () => {
    expect(redactArgv(["--token=ghp_S3cretTokenValue123456"], ROOTS)).toEqual([
      "--token=<redacted:26 bytes>",
    ]);
  });

  it("reads an env pair by name, and still judges the value on its own merits", () => {
    // uppercase is expected on the LEFT of an `=` and nowhere else, so a
    // docker `-e HOME=/tmp` stays legible while a token never does
    expect(redactArgv(["HOME=/tmp", "GITHUB_TOKEN=ghp_S3cretTokenValue123456"], ["/tmp"])).toEqual([
      "HOME=/tmp",
      "GITHUB_TOKEN=<redacted:26 bytes>",
    ]);
  });

  it("redacts a value that follows a flag, and says how big it was", () => {
    const secret = "ghp_PlantedIntoArgv0123456789";
    const out = redactArgv(["--auth", secret, "--verbose"], ROOTS);
    expect(out).toEqual(["--auth", `<redacted:${secret.length} bytes>`, "--verbose"]);
    expect(out.join(" ")).not.toContain(secret);
  });

  it("refuses a path that is NOT under a root this run owns", () => {
    // absolute, but somewhere else entirely: it could be anything, so the
    // allowlist declines rather than guessing it is harmless
    expect(isSafeArgvToken("/etc/Secrets/Prod.key", ROOTS)).toBe(false);
  });
});

describe("the journal records what a collector spawns", () => {
  it("captures invocations and resolutions without the collector cooperating", async () => {
    const { value, journal } = await withJournal([], async () => {
      // a tool that cannot resolve: no binary, no Docker
      const absent = await resolveTool(
        "definitely-not-a-real-tool",
        { args: ["--version"], parse: (s) => s },
        { binaryVersion: null, docker: false, manifest: {} },
      );
      // `--` so node hands the rest to the script rather than parsing it
      const run = await exec(process.execPath, [
        "-e",
        "0",
        "--",
        "--planted",
        "ghp_S3cretArgvValue12345",
      ]);
      return { absent, exitCode: run.exitCode };
    });

    expect(value.absent).toBeUndefined();
    expect(value.exitCode).toBe(0);

    // the resolution was recorded, absent and all, with the reason stated
    expect(journal.tools).toHaveLength(1);
    expect(journal.tools[0]!.tool).toBe("definitely-not-a-real-tool");
    expect(journal.tools[0]!.runtime.kind).toBe("absent");
    expect(journal.tools[0]!.runtime).toHaveProperty("reason");

    // the spawn was recorded, and the planted secret did not survive into it
    const spawn = journal.invocations.find((i) => i.argv.includes("--planted"));
    expect(spawn).toBeDefined();
    expect(spawn!.exit_code).toBe(0);
    expect(JSON.stringify(journal.invocations)).not.toContain("ghp_S3cretArgvValue12345");
  });

  it("records nothing when no journal is open — doctor and unit tests stay quiet", async () => {
    const { journal } = await withJournal([], async () => {});
    expect(journal.invocations).toEqual([]);
    // spawned OUTSIDE any journal: nowhere to land, and no crash for trying
    await expect(exec(process.execPath, ["-e", "0"])).resolves.toMatchObject({ exitCode: 0 });
  });

  it("attaches telemetry at the runner boundary, per collector", async () => {
    const workspace: Workspace = { root: process.cwd(), repo: "r", commit: "c" };
    const collector: Collector = {
      manifest: { name: "spawner", toolVersion: "1", recipes: [], outputs: [] },
      async collect() {
        await exec(process.execPath, ["-e", "0"]);
        return { findings: [], artifacts: [], observations: {}, toolVersion: "1", exitCode: 0 };
      },
    };
    const inner: Runner = {
      async run(_manifest, ws) {
        const out = await collector.collect({
          workspace: ws,
          artifactDir: "/tmp",
          inputs: new Map(),
          runId: "r",
        });
        return { ...out, artifacts: [], anchors: {} };
      },
    };
    const result = await createJournaledRunner(inner, { safeRoots: [] }).run(
      collector.manifest,
      workspace,
    );
    expect(result.telemetry).toBeDefined();
    expect(result.telemetry!.invocations).toHaveLength(1);
    expect(result.telemetry!.durationMs).toBeGreaterThanOrEqual(0);
  });
});

describe("binary path resolution", () => {
  it("finds a binary that is on PATH", () => {
    // node is what is running this test, so it is on PATH by construction
    expect(resolveBinaryPath("node")).toBeTypeOf("string");
  });

  it("returns undefined rather than guessing when nothing is there", () => {
    expect(resolveBinaryPath("definitely-not-a-real-tool")).toBeUndefined();
  });
});
