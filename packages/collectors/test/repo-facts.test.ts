import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import type { CollectOutput } from "@rampscan/core";
import { repoFacts } from "../src/index.js";

// repo-facts against the planted-fault fixture: the faults are deliberate,
// so the expected observations are known in advance.

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "../../..");
const fixtureRoot = join(repoRoot, "fixtures/vulnerable-app");

let out: CollectOutput;

// the fixture itself is built once for the whole run by vitest's globalSetup

beforeAll(async () => {
  out = await repoFacts.collect({
    workspace: { root: fixtureRoot, repo: "fixtures/vulnerable-app", commit: "0".repeat(40) },
    artifactDir: await mkdtemp(join(tmpdir(), "rampscan-repofacts-")),
    inputs: new Map(),
    runId: "test-run",
  });
}, 30_000);

describe("repo-facts on the fixture", () => {
  it("sees the lockfile and calls the deps pinned", () => {
    expect(out.observations["lockfile-pinned-deps"]).toEqual([
      { manifest: "package.json", lockfile: "package-lock.json", lockfile_present: true },
    ]);
  });

  it("catches both unpinned CI actions (tag refs, not SHAs)", () => {
    const rows = out.observations["ci-actions-pinned"]!;
    expect(rows).toHaveLength(2);
    expect(rows.every((r) => r["pinned_to_sha"] === false)).toBe(true);
  });

  it("sees CI but no provenance step", () => {
    expect(out.observations["ci-provenance-present"]).toEqual([
      { workflow_count: 1, provenance_step_count: 0 },
    ]);
  });

  it("finds no recognized test step (a bare `node -e` is not a test suite)", () => {
    expect(out.observations["tests-in-ci"]).toEqual([
      { workflow_count: 1, test_step_count: 0 },
    ]);
  });

  it("reports the Dockerfile running as root (no USER directive)", () => {
    const rows = out.observations["container-runs-nonroot"]!;
    expect(rows[0]).toMatchObject({ final_user: "root", nonroot: false });
  });

  it("emits findings for the planted faults with resolvable IDs", () => {
    const summaries = out.findings.map((f) => f.summary);
    expect(summaries.some((s) => s.includes("actions/checkout@v4"))).toBe(true);
    expect(summaries.some((s) => s.includes("provenance"))).toBe(true);
    for (const f of out.findings) {
      expect(f.ksi_ids.length).toBeGreaterThan(0);
      expect(f.control_ids.length).toBeGreaterThan(0);
    }
  });

  it("anchors observations to the files they are about", () => {
    const anchors = out.anchors!["lockfile-pinned-deps"]!;
    expect(anchors.map((a) => a.path).sort()).toEqual(["package-lock.json", "package.json"]);
    for (const a of anchors) expect(a.contentHash).toMatch(/^[0-9a-f]{64}$/);
  });
});
