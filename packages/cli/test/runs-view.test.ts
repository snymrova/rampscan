import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";

// The run view's derivations (plan J2), pinned in the export-csv / mvx-twin /
// action-queue posture: this test loads the CONSOLE's copy by path (a
// workspace import would break `tsc --build`, and the console is not a
// workspace package).
//
// The property that matters most here is arithmetic, not formatting: the
// timeline row's summary must be reproducible by a reader who recounts the
// expanded collector table, so the three buckets have to PARTITION the
// dispatched set. Overlapping buckets — counting a cache hit as "ran" — would
// break that recount quietly, which is the one failure mode a page about
// honesty cannot have.

interface RunCounts {
  dispatched: number;
  ran: number;
  cacheHit: number;
  skipped: number;
}

interface RunsModule {
  runCounts(collectors: unknown[]): RunCounts;
  runtimeKind(c: unknown): string;
  toolLabel(t: unknown): string;
  imageDigestNote(t: unknown): string | null;
  argvLine(inv: { command: string; argv: string[] }): string;
  redactionCount(c: unknown): number;
  formatRunDuration(ms: number): string;
  sortRuns(runs: unknown[]): Array<{ run_id: string }>;
  sortCollectors(collectors: unknown[]): Array<{ collector: string }>;
  runHop(row: {
    repo: string;
    state: string;
    collector: string;
    run_id: string;
  }): { href: string; label: string; title: string } | null;
}

const consoleLib = join(dirname(fileURLToPath(import.meta.url)), "../../../console/web/lib/runs.ts");

let M: RunsModule;

beforeAll(async () => {
  M = (await import(consoleLib)) as RunsModule;
});

function collector(overrides: Record<string, unknown> = {}) {
  return {
    collector: "sbom",
    tool_version: "syft 1.51.0",
    duration_ms: 4200,
    exit_code: 0,
    findings: 12,
    tools: [{ tool: "syft", version: "1.51.0", runtime: { kind: "binary", path: "/usr/bin/syft" } }],
    invocations: [
      { command: "syft", argv: ["scan", "dir:/w", "-o", "json"], duration_ms: 4100, exit_code: 0 },
    ],
    artifacts: [{ name: "sbom.json", sha256: "a".repeat(64), bytes: 900 }],
    cache: { state: "miss", key: "k", scope: ["@tree"] },
    ...overrides,
  };
}

describe("runCounts: the timeline row's summary is a recount of the expanded table", () => {
  it("ran + cache-hit + skipped is exactly the number dispatched", () => {
    const collectors = [
      collector({ collector: "sbom" }),
      collector({ collector: "vuln", cache: { state: "hit", key: "k" } }),
      collector({ collector: "secrets", skip_reason: "gitleaks did not resolve" }),
      collector({ collector: "graph", tools: [], cache: { state: "none" } }),
    ];
    const counts = M.runCounts(collectors);
    expect(counts).toEqual({ dispatched: 4, ran: 2, cacheHit: 1, skipped: 1 });
    expect(counts.ran + counts.cacheHit + counts.skipped).toBe(counts.dispatched);
  });

  it("a cache hit is not counted as having run — nothing was spawned", () => {
    expect(M.runCounts([collector({ cache: { state: "hit" } })])).toEqual({
      dispatched: 1,
      ran: 0,
      cacheHit: 1,
      skipped: 0,
    });
  });

  it("a skipped collector whose cache says hit still counts once, as skipped", () => {
    const counts = M.runCounts([
      collector({ skip_reason: "no docker, no binary", cache: { state: "hit" } }),
    ]);
    expect(counts).toEqual({ dispatched: 1, ran: 0, cacheHit: 0, skipped: 1 });
  });

  it("an empty run counts to zero rather than throwing", () => {
    expect(M.runCounts([])).toEqual({ dispatched: 0, ran: 0, cacheHit: 0, skipped: 0 });
  });
});

describe("runtimeKind: one pill per collector, skip loudest", () => {
  it("a skip outranks everything else about the collector", () => {
    expect(
      M.runtimeKind(
        collector({
          skip_reason: "grype did not resolve",
          cache: { state: "hit" },
          tools: [{ tool: "grype", runtime: { kind: "docker", image: "grype:1", digest: null } }],
        }),
      ),
    ).toBe("skipped");
  });

  it("a cache hit outranks how the tools resolved — nothing ran this time", () => {
    expect(M.runtimeKind(collector({ cache: { state: "hit" } }))).toBe("cache-hit");
  });

  it("docker beats binary when a collector used both", () => {
    expect(
      M.runtimeKind(
        collector({
          tools: [
            { tool: "git", runtime: { kind: "binary", path: "/usr/bin/git" } },
            { tool: "semgrep", runtime: { kind: "docker", image: "semgrep:1", digest: "sha256:x" } },
          ],
        }),
      ),
    ).toBe("docker");
  });

  it("a collector that asked for no tool is `pure`, never `absent`", () => {
    expect(M.runtimeKind(collector({ tools: [] }))).toBe("pure");
  });

  it("tools that all failed to resolve read `absent`", () => {
    expect(
      M.runtimeKind(
        collector({ tools: [{ tool: "grype", runtime: { kind: "absent", reason: "not on PATH" } }] }),
      ),
    ).toBe("absent");
  });
});

describe("labels quote the record and never invent one", () => {
  it("a docker tool names its pinned image", () => {
    expect(
      M.toolLabel({ tool: "semgrep", version: "1.173.0", runtime: { kind: "docker", image: "semgrep/semgrep:1.173.0", digest: "sha256:abc" } }),
    ).toBe("semgrep@1.173.0 · semgrep/semgrep:1.173.0");
  });

  it("an absent tool states the reason instead of a path", () => {
    expect(M.toolLabel({ tool: "grype", runtime: { kind: "absent", reason: "no binary, no docker" } })).toBe(
      "grype · absent — no binary, no docker",
    );
  });

  it("an unresolved image digest says so — a tag is never quoted as a digest", () => {
    expect(
      M.imageDigestNote({
        tool: "grype",
        runtime: { kind: "docker", image: "grype:0.117.0", digest: null, digest_reason: "docker not reachable" },
      }),
    ).toBe("digest unresolved — docker not reachable");
    expect(
      M.imageDigestNote({ tool: "grype", runtime: { kind: "docker", image: "grype:0.117.0", digest: "sha256:beef" } }),
    ).toBe("sha256:beef");
    expect(M.imageDigestNote({ tool: "git", runtime: { kind: "binary" } })).toBeNull();
  });

  it("argv renders as the line a reader would type", () => {
    expect(M.argvLine({ command: "syft", argv: ["scan", "dir:/w", "-o", "json"] })).toBe(
      "syft scan dir:/w -o json",
    );
  });

  it("redactions are counted, not hidden — the allowlist is visible", () => {
    expect(
      M.redactionCount(
        collector({
          invocations: [
            { command: "tool", argv: ["--token", "<redacted:24 bytes>"], duration_ms: 1, exit_code: 0 },
            { command: "tool", argv: ["--flag=<redacted:8 bytes>"], duration_ms: 1, exit_code: 0 },
            { command: "tool", argv: ["--safe"], duration_ms: 1, exit_code: 0 },
          ],
        }),
      ),
    ).toBe(2);
  });
});

describe("formatRunDuration", () => {
  it("scales from milliseconds to minutes", () => {
    expect(M.formatRunDuration(420)).toBe("420 ms");
    expect(M.formatRunDuration(4200)).toBe("4.2s");
    expect(M.formatRunDuration(331_000)).toBe("5m 31s");
  });

  it("refuses to render a number it was not given", () => {
    expect(M.formatRunDuration(Number.NaN)).toBe("—");
  });
});

describe("ordering", () => {
  it("runs read newest first, with a total order across equal clocks", () => {
    const runs = [
      { run_id: "b", run_timestamp: "2026-08-15T09:00:00.000Z" },
      { run_id: "c", run_timestamp: "2026-08-15T10:00:00.000Z" },
      { run_id: "a", run_timestamp: "2026-08-15T09:00:00.000Z" },
    ];
    expect(M.sortRuns(runs).map((r) => r.run_id)).toEqual(["c", "b", "a"]);
  });

  it("skipped collectors sort to the top — a skip buried at row 9 is the bug", () => {
    const collectors = [
      collector({ collector: "sbom" }),
      collector({ collector: "vuln", skip_reason: "grype did not resolve" }),
      collector({ collector: "api-spec" }),
    ];
    expect(M.sortCollectors(collectors).map((c) => c.collector)).toEqual([
      "vuln",
      "api-spec",
      "sbom",
    ]);
  });
});

// J3: the board hop's href, resolved from what the register row already
// carries after the fold's catalog join. The board fetches no run data to
// build this — if it did, the board would become partly a function of the run
// log, which is the one thing the fold's standing rule forbids.
describe("runHop: the board's link to the machinery (J3)", () => {
  function row(overrides: Record<string, unknown> = {}) {
    return {
      repo: "fixtures/app",
      state: "evidenced",
      collector: "sbom",
      run_id: "run-2026-08-15T10:00:00.000Z",
      ...overrides,
    } as { repo: string; state: string; collector: string; run_id: string };
  }

  it("an evidenced row points at THE run that produced it, at its collector", () => {
    const hop = M.runHop(row())!;
    expect(hop.href).toBe("/runs?scan=run-2026-08-15T10%3A00%3A00.000Z&collector=sbom");
    expect(hop.label).toBe("how was this produced?");
  });

  it("a violated row hops the same way — a verdict is still a produced answer", () => {
    expect(M.runHop(row({ state: "violated" }))!.href).toContain("scan=run-");
  });

  it("an unevidenced row names no scan — no run produced it — and asks the repo instead", () => {
    const hop = M.runHop(row({ state: "unevidenced", run_id: "" }))!;
    expect(hop.href).toBe("/runs?repo=fixtures%2Fapp&collector=sbom");
    expect(hop.href).not.toContain("scan=");
    // the question the row actually raises, not the one an evidenced row does
    expect(hop.label).toBe("why is this empty?");
    expect(hop.title).toContain("no run produced this cell");
  });

  it("a scoped-out row gets NO hop — its provenance is the scoping event, not a run", () => {
    expect(M.runHop(row({ state: "notApplicable", run_id: "" }))).toBeNull();
    // and not even when a stale run id is somehow present
    expect(M.runHop(row({ state: "notApplicable" }))).toBeNull();
  });

  it("a row with neither a run nor a collector gets no hop rather than a guessed one", () => {
    expect(M.runHop(row({ state: "unevidenced", run_id: "", collector: "" }))).toBeNull();
  });

  it("a recipe that left the catalog still hops to its run, just without a collector", () => {
    const hop = M.runHop(row({ collector: "" }))!;
    expect(hop.href).toBe("/runs?scan=run-2026-08-15T10%3A00%3A00.000Z");
    expect(hop.href).not.toContain("collector=");
  });

  it("repo and run id are URL-encoded — a slash in a repo name is not a path segment", () => {
    const hop = M.runHop(row({ state: "unevidenced", run_id: "", repo: "acme/web app" }))!;
    expect(hop.href).toBe("/runs?repo=acme%2Fweb+app&collector=sbom");
    expect(hop.href.split("?")[1]!.split("&")[0]).toBe("repo=acme%2Fweb+app");
  });
});
