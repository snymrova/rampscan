import { describe, expect, it } from "vitest";
import type {
  MethodCell,
  MethodRegisterRow,
  RegisterRow,
  ScanRunRow,
} from "@rampscan/core";
import type { CollectorRun } from "@rampscan/schema";
import { generateArtifact4 } from "../src/artifact-generators.js";
import type { ArtifactGenerationInput } from "../src/artifact-generators.js";

// R1.2 — computed artifact 4, from the exec journal:
//
//   "Verification that the automation in place is accurate and sufficient to
//    demonstrate appropriate measures for the Key Security Indicator, or that
//    automation is not necessary for each measure."
//
// The first half is a question about EXECUTION and `ScanRun` has been
// recording the answer since J1. The second half is the provider's claim about
// their own risk, and the tests below hold the generator to never making it.

const REPO = "fixtures/vulnerable-app";
const KSI = "KSI-SCR-MIT";
const T1 = "2026-09-10T00:00:00.000Z";

function method(overrides: Partial<MethodCell> = {}): MethodCell {
  return {
    methodId: "pipeline:pinned-actions@repo",
    source: "pipeline",
    automated: true,
    clock: "machine",
    standing: "full",
    recipeId: "pinned-actions",
    collector: "repo-facts",
    state: "evidenced",
    bundleDigest: "b".repeat(64),
    freshAsOf: T1,
    window: { num: 7, unit: "days" },
    freshMet: true,
    ...overrides,
  };
}

function collectorRun(overrides: Partial<CollectorRun> = {}): CollectorRun {
  return {
    collector: "repo-facts",
    tool_version: "0.1.0",
    duration_ms: 120,
    exit_code: 0,
    findings: 5,
    tools: [],
    invocations: [],
    artifacts: [],
    cache: { state: "miss" },
    ...overrides,
  };
}

function input(overrides: {
  methods?: MethodCell[];
  collectors?: CollectorRun[];
  registers?: RegisterRow[];
  runs?: ScanRunRow[];
}): ArtifactGenerationInput {
  const methods = overrides.methods ?? [method()];
  const row: MethodRegisterRow = {
    repo: REPO,
    ksi: KSI,
    methods,
    automatedMethods: methods.filter((m) => m.automated).length,
    methodFloor: 1,
    floorMet: true,
    staleMethods: 0,
    historyFloorMonths: null,
    historyMet: null,
    artifacts: [],
    artifactsPresent: 0,
    pointInTimeMethods: 0,
  };
  const registers = overrides.registers ?? [
    {
      repo: REPO,
      recipeId: "pinned-actions",
      ksiIds: [KSI],
      controlIds: ["si-7.1"],
      state: "evidenced",
      runId: "run-1",
    },
  ];
  const runs = overrides.runs ?? [
    {
      digest: "a".repeat(64),
      runId: "run-1",
      repo: REPO,
      commit: "c".repeat(40),
      trigger: "manual",
      startedAt: T1,
      timestamp: T1,
      durationMs: 900,
      datasetVersion: "2026.07.14.01",
      collectors: overrides.collectors ?? [collectorRun()],
    },
  ];
  return { repo: REPO, ksiId: KSI, row, registers, scanRuns: runs, datasetVersion: "2026.07.14.01" };
}

function bodyOf(result: ReturnType<typeof generateArtifact4>): string {
  expect(result.generated, "generated" in result && !result.generated ? result.reason : "").toBe(
    true,
  );
  return (result as { body: string }).body;
}

describe("generateArtifact4 (R1.2)", () => {
  it("is deterministic — the same fold renders the same bytes", () => {
    const one = generateArtifact4(input({}));
    const two = generateArtifact4(input({}));
    expect(bodyOf(one)).toBe(bodyOf(two));
  });

  it("names the tool, its version, how it resolved, and the run record behind it", () => {
    const body = bodyOf(
      generateArtifact4(
        input({
          methods: [method({ collector: "semgrep", methodId: "pipeline:sast@tree" })],
          collectors: [
            collectorRun({
              collector: "semgrep",
              tool_version: "0.4.0",
              tools: [
                {
                  tool: "semgrep",
                  version: "1.90.0",
                  runtime: {
                    kind: "docker",
                    image: "ghcr.io/semgrep/semgrep:1.90.0",
                    digest: "sha256:" + "d".repeat(64),
                  },
                },
              ],
              invocations: [
                { command: "docker", argv: ["run", "--rm"], duration_ms: 800, exit_code: 0 },
              ],
            }),
          ],
        }),
      ),
    );
    expect(body).toContain("semgrep 1.90.0");
    expect(body).toContain("ghcr.io/semgrep/semgrep:1.90.0 @ sha256:");
    expect(body).toContain("1 invocation(s), exit 0");
    expect(body).toContain("run run-1");
    expect(body).toContain("aaaaaaaaaaaa…"); // the run record, quoted for verification
  });

  it("says so when a pure collector spawned nothing — that is automation too", () => {
    const body = bodyOf(generateArtifact4(input({})));
    expect(body).toContain("no external tool — rampscan reads the repository itself");
    expect(body).toContain("spawned nothing");
  });

  it("REFUSES where there is no automation, and does not argue none was needed (§13.4)", () => {
    const result = generateArtifact4(
      input({ methods: [method({ automated: false, source: "attestation" })] }),
    );
    expect(result.generated).toBe(false);
    const reason = (result as { reason: string }).reason;
    expect(reason).toContain("no automated measure");
    expect(reason).toContain("rampscan does not write it");
  });

  it("refuses when no signed execution record stands behind the automation", () => {
    const result = generateArtifact4(input({ runs: [] }));
    expect(result.generated).toBe(false);
    expect((result as { reason: string }).reason).toContain("no signed execution record");
  });

  it("states a collector that did not run, in the run record's own words", () => {
    const body = bodyOf(
      generateArtifact4(
        input({ collectors: [collectorRun({ skip_reason: "syft is not installed" })] }),
      ),
    );
    expect(body).toContain("the collector did not run: syft is not installed");
  });

  it("states a tool that did not resolve — nothing it would have measured was measured", () => {
    const body = bodyOf(
      generateArtifact4(
        input({
          collectors: [
            collectorRun({
              tools: [
                { tool: "grype", runtime: { kind: "absent", reason: "not on PATH" } },
              ],
            }),
          ],
        }),
      ),
    );
    expect(body).toContain("a tool did not resolve");
    expect(body).toContain("grype — not on PATH");
  });

  it("states an image whose tag never resolved to a digest — a pin that is not content", () => {
    const body = bodyOf(
      generateArtifact4(
        input({
          collectors: [
            collectorRun({
              tools: [
                {
                  tool: "syft",
                  version: "1.0.0",
                  runtime: {
                    kind: "docker",
                    image: "anchore/syft:v1.0.0",
                    digest: null,
                    digest_reason: "docker daemon unavailable",
                  },
                },
              ],
            }),
          ],
        }),
      ),
    );
    expect(body).toContain("the version pin is a tag rather than content");
    expect(body).toContain("docker daemon unavailable");
  });

  it("states a cache hit — nothing was spawned on the run this cites", () => {
    const body = bodyOf(
      generateArtifact4(
        input({ collectors: [collectorRun({ cache: { state: "hit", key: "k" } })] }),
      ),
    );
    expect(body).toContain("served from cache");
    expect(body).toContain("the invocations above are those of the earlier run");
  });

  it("states a non-zero tool exit — a tool that exited badly may have measured less", () => {
    const body = bodyOf(
      generateArtifact4(
        input({
          collectors: [
            collectorRun({
              invocations: [
                { command: "syft", argv: ["scan"], duration_ms: 10, exit_code: 2 },
              ],
            }),
          ],
        }),
      ),
    );
    expect(body).toContain("non-zero tool exit");
  });

  it("counts call-path hops the graph matched by NAME rather than resolved (I3f)", () => {
    const body = bodyOf(
      generateArtifact4(
        input({
          registers: [
            {
              repo: REPO,
              recipeId: "pinned-actions",
              ksiIds: [KSI],
              controlIds: ["si-7.1"],
              state: "violated",
              runId: "run-1",
              pointers: [
                {
                  call_path: "handler » parse » sink",
                  call_path_resolutions: ["exact", "inferred"],
                },
              ],
            },
          ],
        }),
      ),
    );
    expect(body).toContain("1 hop(s) across 1 call path(s) were matched by NAME");
    expect(body).toContain("not that this call chain does");
  });

  it("counts the measures that are not automated without claiming they need not be", () => {
    const body = bodyOf(
      generateArtifact4(
        input({
          methods: [
            method(),
            {
              // a non-pipeline method: no recipe, no collector, nothing spawned
              methodId: "attestation:incident-review#KSI-SCR-MIT",
              source: "attestation",
              automated: false,
              clock: "non-machine",
              standing: "narrative",
              state: "evidenced",
              window: { num: 3, unit: "months" },
              freshMet: true,
            },
          ],
        }),
      ),
    );
    expect(body).toContain("1 of 2 measure(s) for this indicator are automated");
    expect(body).toContain("does not claim");
    expect(body).toContain("rampscan does not write it");
  });

  it("says plainly when nothing limits the automation, rather than leaving the section empty", () => {
    const body = bodyOf(generateArtifact4(input({})));
    expect(body).toContain("ran, resolved its tools, and exited cleanly");
  });

  it("pins what it was computed from: the run, the commit, the dataset, the versions", () => {
    const result = generateArtifact4(
      input({
        collectors: [
          collectorRun({
            tools: [
              { tool: "semgrep", version: "1.90.0", runtime: { kind: "binary", path: "/usr/bin/semgrep" } },
            ],
          }),
        ],
      }),
    );
    const generator = (result as { generator: { pins: Record<string, string>; tool_versions: Record<string, string>; journal_digest?: string } }).generator;
    expect(generator.pins).toEqual({
      dataset: "2026.07.14.01",
      run: "run-1",
      commit: "c".repeat(40),
    });
    expect(generator.tool_versions).toEqual({ "repo-facts": "0.1.0", semgrep: "1.90.0" });
    expect(generator.journal_digest).toBe("a".repeat(64));
  });

  it("cites the run behind the LIVE evidence, not merely the newest run on the repo", () => {
    const newer: ScanRunRow = {
      digest: "f".repeat(64),
      runId: "run-2",
      repo: REPO,
      commit: "e".repeat(40),
      trigger: "manual",
      startedAt: "2026-09-12T00:00:00.000Z",
      timestamp: "2026-09-12T00:00:00.000Z",
      durationMs: 100,
      // a later run that did not touch this collector at all
      collectors: [collectorRun({ collector: "gitleaks" })],
      datasetVersion: "2026.07.14.01",
    };
    const older: ScanRunRow = {
      digest: "a".repeat(64),
      runId: "run-1",
      repo: REPO,
      commit: "c".repeat(40),
      trigger: "manual",
      startedAt: T1,
      timestamp: T1,
      durationMs: 900,
      collectors: [collectorRun()],
      datasetVersion: "2026.07.14.01",
    };
    const body = bodyOf(generateArtifact4(input({ runs: [newer, older] })));
    expect(body).toContain("run run-1");
    expect(body).not.toContain("run run-2");
  });
});
