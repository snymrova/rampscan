import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";

// The provenance chain and the gate basis (plan J5 + I3f), pinned in the
// export-csv / runs-view / mvx-twin posture: this test loads the CONSOLE's own
// copy by path, because the console is not a workspace package and a static
// import would emit compiled duplicates into console/web/lib (the I3e lesson).
//
// The property that matters here is that GAPS ARE STATED. A chain that
// silently omits the hop it cannot draw reads exactly like a chain with
// nothing missing, and the missing hops are what an auditor came for: the run
// this projection no longer holds, the collector the run never dispatched, the
// bundle minted before its producer was signed into the predicate.

interface ChainHop {
  kind: string;
  label: string;
  detail?: string;
  href?: string;
  missing?: string;
  digest?: string;
}

interface ProvenanceModule {
  provenanceChain(input: Record<string, unknown>): ChainHop[];
  toolsBehind(
    run: unknown,
    collector: string,
  ): Array<{ tool: string; version?: string; runtime: string; through?: string; artifact?: string }>;
  collectorRunOf(run: unknown, collector: string): unknown;
  missingRunReason(runId: string, runCount: number): string;
  callPathHops(
    path: string,
    resolutions?: string[],
  ): Array<{ node: string; resolution?: string }>;
  entrypointSourceNote(source: string): string;
  basisStrength(basis: unknown): "weak" | "stated";
  producedByRun(bundles: unknown[]): Map<string, Array<{ recipeId: string; digest: string }>>;
  toolHealth(runs: unknown[]): Array<{
    tool: string;
    latest: { runtime: string; version?: string; at: string; runId: string };
    changedAt?: { from: string; since: string; sinceRunId: string };
    askedBy: string[];
    absentRuns: number;
  }>;
}

const consoleLib = join(
  dirname(fileURLToPath(import.meta.url)),
  "../../../console/web/lib/provenance.ts",
);

let M: ProvenanceModule;

beforeAll(async () => {
  M = (await import(consoleLib)) as ProvenanceModule;
});

/** the fixture's real shape: semgrep produces, the gate consumes and spawns nothing */
function gateRun(overrides: Record<string, unknown> = {}) {
  return {
    id: "r1",
    digest: "d".repeat(64),
    run_id: "run-1",
    repo: "acme/app",
    commit_sha: "c".repeat(40),
    trigger_kind: "manual",
    started_at: "2026-08-15T10:00:00.000Z",
    run_timestamp: "2026-08-15T10:05:00.000Z",
    duration_ms: 300_000,
    dataset_version: "v1",
    collectors: [
      {
        collector: "semgrep",
        tool_version: "1.173.0",
        duration_ms: 20_000,
        exit_code: 0,
        findings: 2,
        tools: [
          {
            tool: "semgrep",
            version: "1.173.0",
            runtime: { kind: "docker", image: "semgrep/semgrep:1.173.0", digest: null },
          },
        ],
        invocations: [],
        artifacts: [{ name: "semgrep-results.json", sha256: "a".repeat(64) }],
        cache: { state: "miss" },
      },
      {
        collector: "graph",
        tool_version: "0.2.0",
        duration_ms: 900,
        exit_code: 0,
        findings: 1,
        tools: [],
        invocations: [],
        artifacts: [{ name: "graph.db", sha256: "b".repeat(64) }],
        cache: { state: "miss" },
      },
      {
        collector: "sast-reachability",
        tool_version: "0.1.0+graph0.2.0",
        duration_ms: 120,
        exit_code: 0,
        findings: 1,
        tools: [],
        invocations: [],
        artifacts: [],
        consumes: ["semgrep-results.json", "graph.db"],
        cache: { state: "miss" },
      },
    ],
    ...overrides,
  };
}

function chainInput(overrides: Record<string, unknown> = {}) {
  return {
    recipeId: "no-reachable-dangerous-code",
    collector: "sast-reachability",
    runId: "run-1",
    repo: "acme/app",
    digest: "e".repeat(64),
    controlIds: ["sa-11", "si-10"],
    subjects: [{ name: "src/render.js", sha256: "f".repeat(64), isAnchor: true }],
    run: gateRun(),
    runsLoaded: true,
    runCount: 3,
    ...overrides,
  };
}

describe("toolsBehind: a gate that spawns nothing still names the tool its verdict rests on", () => {
  it("reaches semgrep through the artifact the gate consumed", () => {
    const tools = M.toolsBehind(gateRun(), "sast-reachability");
    expect(tools).toHaveLength(1);
    expect(tools[0]!.tool).toBe("semgrep");
    expect(tools[0]!.through).toBe("semgrep");
    expect(tools[0]!.artifact).toBe("semgrep-results.json");
    expect(tools[0]!.runtime).toContain("semgrep/semgrep:1.173.0");
  });

  it("a producer that spawned nothing contributes nothing rather than an empty tool", () => {
    // graph.db is consumed too, and `graph` is pure — it must not appear as a
    // nameless tool just because the gate ate its output
    const tools = M.toolsBehind(gateRun(), "sast-reachability");
    expect(tools.map((t) => t.tool)).toEqual(["semgrep"]);
  });

  it("walks two levels: syft reached through osv-scanner's sbom", () => {
    const run = gateRun({
      collectors: [
        {
          collector: "syft",
          tool_version: "1.51.0",
          duration_ms: 1,
          exit_code: 0,
          findings: 0,
          tools: [{ tool: "syft", version: "1.51.0", runtime: { kind: "binary", path: "/b/syft" } }],
          invocations: [],
          artifacts: [{ name: "sbom.cdx.json", sha256: "1".repeat(64) }],
          cache: { state: "miss" },
        },
        {
          collector: "osv-scanner",
          tool_version: "2.5.0",
          duration_ms: 1,
          exit_code: 0,
          findings: 0,
          tools: [
            { tool: "osv-scanner", version: "2.5.0", runtime: { kind: "binary", path: "/b/osv" } },
          ],
          invocations: [],
          artifacts: [{ name: "osv-results.json", sha256: "2".repeat(64) }],
          consumes: ["sbom.cdx.json"],
          cache: { state: "miss" },
        },
        {
          collector: "reachability",
          tool_version: "0.1.0",
          duration_ms: 1,
          exit_code: 0,
          findings: 0,
          tools: [],
          invocations: [],
          artifacts: [],
          consumes: ["osv-results.json"],
          cache: { state: "miss" },
        },
      ],
    });
    const tools = M.toolsBehind(run, "reachability");
    expect(tools.map((t) => t.tool).sort()).toEqual(["osv-scanner", "syft"]);
    // each tool is attributed to the collector that RAN it and the artifact
    // that carried its answer forward — that is the collector whose row on
    // /runs holds the invocation, which is where the hop's link must land
    const syft = tools.find((t) => t.tool === "syft")!;
    expect(syft.through).toBe("syft");
    expect(syft.artifact).toBe("sbom.cdx.json");
    expect(tools.find((t) => t.tool === "osv-scanner")!.through).toBe("osv-scanner");
  });

  it("a consumption cycle terminates instead of hanging", () => {
    const run = gateRun({
      collectors: [
        {
          collector: "a",
          tool_version: "1",
          duration_ms: 1,
          exit_code: 0,
          findings: 0,
          tools: [],
          invocations: [],
          artifacts: [{ name: "x", sha256: "1".repeat(64) }],
          consumes: ["y"],
          cache: { state: "none" },
        },
        {
          collector: "b",
          tool_version: "1",
          duration_ms: 1,
          exit_code: 0,
          findings: 0,
          tools: [{ tool: "t", version: "1", runtime: { kind: "binary" } }],
          invocations: [],
          artifacts: [{ name: "y", sha256: "2".repeat(64) }],
          consumes: ["x"],
          cache: { state: "none" },
        },
      ],
    });
    expect(M.toolsBehind(run, "a").map((t) => t.tool)).toEqual(["t"]);
  });
});

describe("provenanceChain: five hops, and every gap named in the hop's own place", () => {
  it("draws the full chain for a gate-produced bundle", () => {
    const hops = M.provenanceChain(chainInput());
    expect(hops.map((h) => h.kind)).toEqual([
      "recipe",
      "collector",
      "tool",
      "artifact",
      "bundle",
    ]);
    expect(hops[1]!.label).toBe("sast-reachability");
    expect(hops[1]!.href).toBe("/runs?scan=run-1&collector=sast-reachability");
    expect(hops[2]!.label).toBe("semgrep@1.173.0");
    // the tool hop points at the collector that RAN it, not at the gate
    expect(hops[2]!.href).toBe("/runs?scan=run-1&collector=semgrep");
    expect(hops[4]!.digest).toBe("e".repeat(64));
    expect(hops.some((h) => h.missing !== undefined)).toBe(false);
  });

  it("a bundle minted before J5 says the collector is not recorded, and refuses to guess", () => {
    const hops = M.provenanceChain(chainInput({ collector: "" }));
    const collector = hops.find((h) => h.kind === "collector")!;
    expect(collector.missing).toContain("not");
    expect(collector.href).toBeUndefined();
    // the chain keeps its shape: a gap is drawn as a gap, never as a shorter chain
    expect(hops.map((h) => h.kind)).toEqual(["recipe", "collector", "tool", "artifact", "bundle"]);
  });

  it("names WHICH absence applies when the run record is not held", () => {
    const capped = M.provenanceChain(chainInput({ run: null, runCount: 200 }));
    expect(capped.find((h) => h.kind === "tool")!.missing).toContain("older than the newest 200");

    const none = M.provenanceChain(chainInput({ run: null, runCount: 0 }));
    const reason = none.find((h) => h.kind === "tool")!.missing!;
    expect(reason).toContain("never written down");
    expect(reason).not.toContain("older than");
  });

  it("a collector the run never dispatched is a different fact from one that skipped", () => {
    const hops = M.provenanceChain(chainInput({ collector: "grype" }));
    expect(hops.find((h) => h.kind === "tool")!.missing).toContain("not in that run's collector set");
  });

  it("a pure collector that consumed nothing says so without claiming a missing binary", () => {
    const run = gateRun();
    const hops = M.provenanceChain(chainInput({ collector: "graph", run }));
    const tool = hops.find((h) => h.kind === "tool")!;
    expect(tool.label).toBe("no external tool");
    expect(tool.missing).toBeUndefined();
    expect(tool.detail).toContain("not a missing binary");
  });

  it("an anchor-only bundle states that it attests no artifact rather than showing an empty hop", () => {
    const hops = M.provenanceChain(chainInput());
    const artifact = hops.find((h) => h.kind === "artifact")!;
    expect(artifact.label).toBe("none attested");
    expect(artifact.detail).toContain("anchor file");
  });

  it("attested artifacts ride the chain by digest", () => {
    const hops = M.provenanceChain(
      chainInput({
        subjects: [
          { name: "openvex.json", sha256: "9".repeat(64), isAnchor: false },
          { name: "package.json", sha256: "8".repeat(64), isAnchor: true },
        ],
      }),
    );
    const artifacts = hops.filter((h) => h.kind === "artifact");
    expect(artifacts).toHaveLength(1);
    expect(artifacts[0]!.label).toBe("openvex.json");
    expect(artifacts[0]!.digest).toBe("9".repeat(64));
  });

  it("says it is still reading rather than reporting an absence it has not established", () => {
    const hops = M.provenanceChain(chainInput({ run: null, runsLoaded: false }));
    const tool = hops.find((h) => h.kind === "tool")!;
    expect(tool.missing).toBeUndefined();
  });
});

describe("callPathHops: every edge marked, or none of them", () => {
  it("marks each hop with the edge that arrives at it", () => {
    const hops = M.callPathHops("a » b » c", ["exact", "inferred"]);
    expect(hops).toEqual([
      { node: "a" },
      { node: "b", resolution: "exact" },
      { node: "c", resolution: "inferred" },
    ]);
  });

  it("refuses marks that do not describe this path", () => {
    // a short array would otherwise shift every mark onto the wrong edge, and
    // a wrong mark on a call path is worse than no mark
    const hops = M.callPathHops("a » b » c", ["inferred"]);
    expect(hops.slice(1).every((h) => h.resolution === "unmarked")).toBe(true);
  });

  it("pre-I3f pointers render unmarked rather than assumed exact", () => {
    const hops = M.callPathHops("a » b");
    expect(hops[1]!.resolution).toBe("unmarked");
  });

  it("a single-node path has no edges to mark", () => {
    expect(M.callPathHops("a", [])).toEqual([{ node: "a" }]);
  });
});

describe("the basis reads as ground, not decoration", () => {
  it("names each entry-point source in terms of what the reader can do about it", () => {
    expect(M.entrypointSourceNote("config")).toContain("rampscan.config.json");
    expect(M.entrypointSourceNote("package.json")).toContain("inferred");
    expect(M.entrypointSourceNote("fallback")).toContain("weakest");
    expect(M.entrypointSourceNote("none")).toContain("NOT DETECTED");
    expect(M.entrypointSourceNote("unavailable")).toContain("no graph");
    // an unknown source renders literally rather than being mapped to a lie
    expect(M.entrypointSourceNote("something-new")).toBe("something-new");
  });

  it("calls the ground weak whenever the walk could have missed a root", () => {
    const strong = {
      approximation: "over",
      statement: "s",
      entrypoints: ["src/index.js"],
      entrypoint_source: "package.json",
    };
    expect(M.basisStrength(strong)).toBe("stated");
    expect(M.basisStrength({ ...strong, entrypoint_source: "fallback" })).toBe("weak");
    expect(M.basisStrength({ ...strong, entrypoints: [] })).toBe("weak");
    expect(M.basisStrength({ ...strong, degraded: "no graph" })).toBe("weak");
    // a declared entry point that resolved to nothing silently shrank the walk
    expect(M.basisStrength({ ...strong, entrypoints_unresolved: ["./missing.js"] })).toBe("weak");
  });
});

describe("producedByRun: the chain walked backwards, without importing a verdict", () => {
  const bundle = (digest: string, predicate: Record<string, unknown>) => ({
    digest,
    statement: {
      predicateType: "https://rampscan.dev/evidence/v1",
      predicate: {
        run_id: "run-1",
        collector: "repo-facts",
        recipe_id: "tests-in-ci",
        verdict: "violated",
        ...predicate,
      },
    },
  });

  it("keys by run and collector, sorted by recipe", () => {
    const map = M.producedByRun([
      bundle("1".repeat(64), { recipe_id: "tests-in-ci" }),
      bundle("2".repeat(64), { recipe_id: "codeowners-defined" }),
      bundle("3".repeat(64), { recipe_id: "no-secrets-in-history", collector: "gitleaks" }),
      bundle("4".repeat(64), { recipe_id: "tests-in-ci", run_id: "run-0" }),
    ]);
    expect(map.get("run-1\nrepo-facts")!.map((r) => r.recipeId)).toEqual([
      "codeowners-defined",
      "tests-in-ci",
    ]);
    // a different collector and a different run are different keys — a run
    // row must never show evidence another run produced
    expect(map.get("run-1\ngitleaks")!.map((r) => r.digest)).toEqual(["3".repeat(64)]);
    expect(map.get("run-0\nrepo-facts")!).toHaveLength(1);
  });

  it("ignores run records and scoping events — they produce no evidence", () => {
    const map = M.producedByRun([
      { digest: "3".repeat(64), statement: { predicateType: "https://rampscan.dev/scan-run/v1", predicate: { run_id: "run-1", collector: "repo-facts" } } },
      { digest: "4".repeat(64), statement: { predicateType: "https://rampscan.dev/scoping/v1", predicate: { run_id: "run-1", collector: "repo-facts" } } },
    ]);
    expect(map.size).toBe(0);
  });

  it("drops a pre-J5 bundle rather than attaching it to a guessed collector", () => {
    const map = M.producedByRun([
      { digest: "5".repeat(64), statement: { predicateType: "https://rampscan.dev/evidence/v1", predicate: { run_id: "run-1", recipe_id: "tests-in-ci" } } },
    ]);
    expect(map.size).toBe(0);
  });
});

describe("toolHealth: when did this tool stop resolving the way it used to", () => {
  const run = (
    id: string,
    at: string,
    tool: { runtime: Record<string, unknown>; version?: string },
    collector = "sbom",
  ) => ({
    id,
    digest: "d".repeat(64),
    run_id: id,
    repo: "acme/app",
    commit_sha: "c".repeat(40),
    trigger_kind: "manual",
    started_at: at,
    run_timestamp: at,
    duration_ms: 1,
    dataset_version: "v1",
    collectors: [
      {
        collector,
        tool_version: "x",
        duration_ms: 1,
        exit_code: 0,
        findings: 0,
        tools: [{ tool: "syft", ...tool }],
        invocations: [],
        artifacts: [],
        cache: { state: "none" },
      },
    ],
  });

  it("reports the newest resolution and dates the change at the oldest run that already showed it", () => {
    const runs = [
      run("r1", "2026-08-01T00:00:00.000Z", { runtime: { kind: "docker", image: "anchore/syft:v1.51.0", digest: null } }),
      run("r2", "2026-08-02T00:00:00.000Z", { runtime: { kind: "binary", path: "/usr/bin/syft" } }),
      run("r3", "2026-08-03T00:00:00.000Z", { runtime: { kind: "binary", path: "/usr/bin/syft" } }),
    ];
    const [h] = M.toolHealth(runs);
    expect(h!.latest.runtime).toBe("binary /usr/bin/syft");
    expect(h!.changedAt!.from).toBe("docker anchore/syft:v1.51.0");
    // r2 is the oldest run that already showed the binary — not r3 (which
    // would claim the change happened later than the record supports) and not
    // r1 (which still showed the old answer)
    expect(h!.changedAt!.sinceRunId).toBe("r2");
  });

  it("reports no change when every run resolved the same way", () => {
    const runs = [
      run("r1", "2026-08-01T00:00:00.000Z", { runtime: { kind: "binary", path: "/usr/bin/syft" } }),
      run("r2", "2026-08-02T00:00:00.000Z", { runtime: { kind: "binary", path: "/usr/bin/syft" } }),
    ];
    expect(M.toolHealth(runs)[0]!.changedAt).toBeUndefined();
  });

  it("counts the runs where the tool resolved to nothing at all", () => {
    const runs = [
      run("r1", "2026-08-01T00:00:00.000Z", { runtime: { kind: "absent", reason: "not on PATH" } }),
      run("r2", "2026-08-02T00:00:00.000Z", { runtime: { kind: "absent", reason: "not on PATH" } }),
    ];
    const [h] = M.toolHealth(runs);
    expect(h!.absentRuns).toBe(2);
    expect(h!.latest.runtime).toBe("absent");
  });

  it("lists every collector that asked for the tool in the newest run", () => {
    const r = run("r1", "2026-08-01T00:00:00.000Z", { runtime: { kind: "binary" } });
    r.collectors.push({ ...r.collectors[0]!, collector: "vuln" });
    expect(M.toolHealth([r])[0]!.askedBy).toEqual(["sbom", "vuln"]);
  });
});
