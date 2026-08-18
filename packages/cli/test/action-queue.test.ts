import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import { absentReason } from "@rampscan/collectors";

// I2a — the action queue derivation, tested through the console's own copy
// (console/web/lib/queue.ts, loaded by path like the mvx twin test: it lives
// in the Next.js TS project, so a workspace import would break `tsc --build`).
// Two honesty pins ride here:
//   1. classifySkip is tested against the REAL reason producers — the
//      collectors' absentReason() wording and the join's `collector "x"
//      skipped: …` wrapping — so a reworded reason breaks this test instead
//      of silently falling off the queue.
//   2. the ranking of record: divergence > expiring > new violation >
//      actionable unevidenced, and honest skips never queued.

interface QueueModule {
  classifySkip(reason: string): {
    actionable: boolean;
    category: "tool-missing" | "collector-failed" | "honest-skip";
    hint?: string;
  };
  deriveActionQueue(input: {
    registers: unknown[];
    drift: unknown[];
    events: unknown[];
    certClass: "b" | "c";
    now?: number;
    /** run records (K1) — the skip-reason tier's source when no daemon has run */
    runs?: unknown[];
  }): Array<{
    kind: string;
    rank: number;
    repo: string;
    recipeIds: string[];
    at: string;
    title: string;
    detail: string;
    action: string;
    /** the recipe's authored "fixing it" sentence (K1) */
    plain?: string;
    bundleDigest?: string;
  }>;
}

const queuePath = join(
  dirname(fileURLToPath(import.meta.url)),
  "../../../console/web/lib/queue.ts",
);

let queue: QueueModule;
beforeAll(async () => {
  queue = (await import(queuePath)) as QueueModule;
});

const NOW = Date.parse("2026-08-14T12:00:00.000Z");
const DAY = 24 * 60 * 60 * 1000;
const WINDOW = 7 * DAY; // class b

const iso = (msAgo: number) => new Date(NOW - msAgo).toISOString();

function register(overrides: Record<string, unknown>): Record<string, unknown> {
  return {
    id: "r",
    repo: "/repo",
    recipe_id: "some-recipe",
    ksi_ids: [],
    control_ids: [],
    state: "evidenced",
    cadence: "",
    bundle_digest: "",
    fresh_as_of: "",
    commit_sha: "",
    scoping: null,
    ...overrides,
  };
}

function driftEvent(overrides: Record<string, unknown>): Record<string, unknown> {
  return {
    id: "d",
    at: iso(DAY),
    repo: "/repo",
    recipe_id: "some-recipe",
    kind: "born",
    cause: "",
    killing_commit: "",
    from_verdict: "",
    to_verdict: "",
    bundle_digest: "sha256:drift",
    ...overrides,
  };
}

function daemonEvent(overrides: Record<string, unknown>): Record<string, unknown> {
  return { id: "e", at: iso(DAY), kind: "scan-recorded", repo: "/repo", payload: {}, ...overrides };
}

describe("classifySkip, pinned to the real reason producers", () => {
  it("the collectors' absentReason wording (wrapped by the join) is tool-missing, with the doctor hint", () => {
    const wrapped = `collector "checkov" skipped: ${absentReason("checkov")}`;
    const result = queue.classifySkip(wrapped);
    expect(result.actionable).toBe(true);
    expect(result.category).toBe("tool-missing");
    expect(result.hint).toContain("pnpm run doctor");
  });

  it("the collectors' crash wording is collector-failed", () => {
    const wrapped = 'collector "spectral" skipped: spectral failed (exit 2, via docker): boom';
    const result = queue.classifySkip(wrapped);
    expect(result.actionable).toBe(true);
    expect(result.category).toBe("collector-failed");
  });

  it("honest skips and unregistered collectors are not actionable", () => {
    for (const reason of [
      'collector "checkov" skipped: no IaC in the committed tree (Dockerfile, GitHub workflow, Terraform) — nothing config-shaped to scan',
      'collector "spectral" skipped: no OpenAPI/Swagger documents in the committed tree — nothing API-shaped to lint',
      'collector "graph" is not registered in this run',
    ]) {
      expect(queue.classifySkip(reason).actionable, reason).toBe(false);
    }
  });
});

describe("deriveActionQueue: the ranked list of record", () => {
  const registers = [
    // fresh evidence — queued nowhere
    register({ id: "r1", recipe_id: "fresh-recipe", fresh_as_of: iso(1 * DAY), bundle_digest: "sha256:fresh" }),
    // past 0.75 of the window — expiring tier
    register({ id: "r2", recipe_id: "expiring-recipe", fresh_as_of: iso(6 * DAY), bundle_digest: "sha256:exp" }),
    // past the whole window — expired, most urgent inside the tier
    register({ id: "r3", recipe_id: "expired-recipe", fresh_as_of: iso(8 * DAY), bundle_digest: "sha256:dead" }),
    // live violations, fresh — violation tier
    register({ id: "r4", recipe_id: "flipped-recipe", state: "violated", fresh_as_of: iso(2 * 60 * 60 * 1000), bundle_digest: "sha256:vio1", commit_sha: "cafebabe1234deadbeef" }),
    register({ id: "r5", recipe_id: "born-bad-recipe", state: "violated", fresh_as_of: iso(3 * 60 * 60 * 1000), bundle_digest: "sha256:vio2", commit_sha: "0123456789abcdef0123" }),
    // unevidenced: one fixable, one honest
    register({ id: "r6", recipe_id: "iac-baseline-clean", state: "unevidenced" }),
    register({ id: "r7", recipe_id: "api-spec-lint-clean", state: "unevidenced" }),
  ];

  const drift = [
    driftEvent({ id: "d1", recipe_id: "flipped-recipe", at: iso(5 * DAY), kind: "born", to_verdict: "evidenced" }),
    driftEvent({ id: "d2", recipe_id: "flipped-recipe", at: iso(2 * 60 * 60 * 1000), kind: "verdict-flipped", from_verdict: "evidenced", to_verdict: "violated", killing_commit: "cafebabe1234deadbeef" }),
    driftEvent({ id: "d3", recipe_id: "born-bad-recipe", at: iso(3 * 60 * 60 * 1000), kind: "born", to_verdict: "violated" }),
    // a violation that has since been fixed — its row is evidenced now, never queued
    driftEvent({ id: "d4", recipe_id: "fresh-recipe", at: iso(4 * DAY), kind: "verdict-flipped", from_verdict: "evidenced", to_verdict: "violated" }),
  ];

  const events = [
    daemonEvent({
      id: "e1",
      at: iso(60 * 60 * 1000),
      kind: "divergence",
      payload: {
        comparison: { divergences: [{ recipeId: "lockfile-pinned-deps", field: "verdict" }] },
        reportPath: "/out/divergence-report.json",
      },
    }),
    daemonEvent({
      id: "e2",
      at: iso(30 * 60 * 1000),
      kind: "scan-recorded",
      payload: {
        unevidenced: [
          { recipeId: "iac-baseline-clean", collector: "checkov", reason: `collector "checkov" skipped: ${absentReason("checkov")}` },
          { recipeId: "api-spec-lint-clean", collector: "spectral", reason: 'collector "spectral" skipped: no OpenAPI/Swagger documents in the committed tree — nothing API-shaped to lint' },
        ],
      },
    }),
  ];

  const derive = () =>
    queue.deriveActionQueue({ registers, drift, events, certClass: "b", now: NOW });

  it("orders the tiers: divergence > expiring > new violation > actionable unevidenced", () => {
    const kinds = derive().map((i) => i.kind);
    expect(kinds).toEqual([
      "divergence",
      "expiring", // expired-recipe (least remaining) first
      "expiring",
      "new-violation",
      "new-violation",
      "actionable-unevidenced",
    ]);
    expect(derive().map((i) => i.rank)).toEqual([0, 1, 1, 2, 2, 3]);
  });

  it("divergence carries the diverging recipes and points at the report", () => {
    const item = derive()[0]!;
    expect(item.recipeIds).toEqual(["lockfile-pinned-deps"]);
    expect(item.action).toContain("/out/divergence-report.json");
  });

  it("a later cache-verified clears the divergence — the latest verification outcome stands", () => {
    const cleared = queue.deriveActionQueue({
      registers,
      drift,
      events: [...events, daemonEvent({ id: "e3", at: iso(10 * 60 * 1000), kind: "cache-verified" })],
      certClass: "b",
      now: NOW,
    });
    expect(cleared.some((i) => i.kind === "divergence")).toBe(false);
  });

  it("the expiring tier sorts most-urgent first and stamps when the band was entered", () => {
    const [expired, expiring] = derive().filter((i) => i.kind === "expiring");
    expect(expired!.recipeIds).toEqual(["expired-recipe"]);
    expect(expired!.title).toContain("expired");
    expect(expiring!.recipeIds).toEqual(["expiring-recipe"]);
    expect(expiring!.title).toContain("expires in");
    // at = fresh_as_of + 0.75 × window
    expect(expiring!.at).toBe(new Date(NOW - 6 * DAY + 0.75 * WINDOW).toISOString());
    expect(expiring!.bundleDigest).toBe("sha256:exp");
  });

  it("violations ride with the drift event that made them: newest movement first, flip and commit named", () => {
    const violations = derive().filter((i) => i.kind === "new-violation");
    expect(violations.map((i) => i.recipeIds[0])).toEqual(["flipped-recipe", "born-bad-recipe"]);
    expect(violations[0]!.title).toContain("was evidenced");
    expect(violations[0]!.detail).toContain("cafebabe1234");
    expect(violations[0]!.bundleDigest).toBe("sha256:vio1");
    expect(violations[1]!.title).toContain("since first evidence");
  });

  it("a violation whose register row carries fix pointers (I2c) leads with them and the introducing commit", () => {
    const items = queue.deriveActionQueue({
      registers: [
        register({
          recipe_id: "pointed-recipe",
          state: "violated",
          fresh_as_of: iso(60 * 60 * 1000),
          bundle_digest: "sha256:ptr",
          commit_sha: "feedface0000feedface",
          pointers: [
            { file: "src/exec.ts", line: 42, check: "detect-child-process" },
            { file: "src/other.ts", line: 7 },
          ],
          introduced_at: iso(3 * DAY),
          introducing_commit: "beefbeef1111beefbeef",
        }),
      ],
      drift: [],
      events: [],
      certClass: "b",
      now: NOW,
    });
    const item = items.find((i) => i.kind === "new-violation")!;
    expect(item.detail).toBe(
      "detect-child-process — src/exec.ts:42 (+1 more) — first seen at commit beefbeef1111",
    );
  });

  it("fixable skips are queued with the doctor hint; honest skips never are", () => {
    const actionable = derive().filter((i) => i.kind === "actionable-unevidenced");
    expect(actionable).toHaveLength(1);
    expect(actionable[0]!.recipeIds).toEqual(["iac-baseline-clean"]);
    expect(actionable[0]!.title).toContain('"checkov"');
    expect(actionable[0]!.action).toContain("pnpm run doctor");
    // the honest spectral skip stays on the board, not the queue
    expect(derive().some((i) => i.recipeIds.includes("api-spec-lint-clean"))).toBe(false);
  });

  it("a fixed violation (row evidenced again) and fresh evidence are queued nowhere", () => {
    expect(derive().some((i) => i.recipeIds.includes("fresh-recipe"))).toBe(false);
  });

  it("with no daemon events, the projection-only tiers still work", () => {
    const items = queue.deriveActionQueue({ registers, drift, events: [], certClass: "b", now: NOW });
    expect(items.map((i) => i.kind)).toEqual([
      "expiring",
      "expiring",
      "new-violation",
      "new-violation",
    ]);
  });
});

// K1 — the skip-reason tier used to be reachable only through the daemon's
// `scan-recorded` events. An operator who runs `rampscan scan` by hand got an
// empty action queue while their toolchain was broken, and the page told them
// so in the subtitle, which is not the same as telling them what was wrong.
// Every scan has signed a run record since J1 and that record carries the same
// reason, so the tier now falls back to it — through the SAME hand the board's
// guided empty states use, because two surfaces disagreeing about whether a
// collector failure is worth doing something about would be worse than either
// of them being silent.
describe("actionable-unevidenced from the run record, with no daemon anywhere (K1)", () => {
  const registers = [
    register({
      id: "u1",
      recipe_id: "iac-baseline-clean",
      state: "unevidenced",
      collector: "checkov",
      plain: { checks: "c", violation: "v", fix: "the authored fix sentence" },
    }),
    register({
      id: "u2",
      recipe_id: "api-spec-lint-clean",
      state: "unevidenced",
      collector: "spectral",
      plain: null,
    }),
  ];

  function collectorRow(overrides: Record<string, unknown>): Record<string, unknown> {
    return {
      collector: "checkov",
      tool_version: "",
      duration_ms: 10,
      exit_code: 0,
      findings: 0,
      tools: [],
      invocations: [],
      artifacts: [],
      cache: { state: "miss" },
      ...overrides,
    };
  }

  const runRecord = {
    id: "run1",
    digest: "a".repeat(64),
    run_id: "run-2026-08-14T11:30:00.000Z",
    repo: "/repo",
    commit_sha: "b".repeat(40),
    trigger_kind: "manual",
    started_at: iso(31 * 60 * 1000),
    run_timestamp: iso(30 * 60 * 1000),
    duration_ms: 60_000,
    dataset_version: "2026.07.14.01",
    collectors: [
      collectorRow({ collector: "checkov", skip_reason: absentReason("checkov") }),
      collectorRow({
        collector: "spectral",
        skip_reason:
          "no OpenAPI/Swagger documents in the committed tree — nothing API-shaped to lint",
      }),
    ],
  };

  const derive = (extra: Record<string, unknown> = {}) =>
    queue.deriveActionQueue({
      registers,
      drift: [],
      events: [],
      runs: [runRecord],
      certClass: "b",
      now: NOW,
      ...extra,
    });

  it("the missing tool reaches the queue with no daemon event in sight", () => {
    const items = derive();
    expect(items).toHaveLength(1);
    expect(items[0]!.kind).toBe("actionable-unevidenced");
    expect(items[0]!.recipeIds).toEqual(["iac-baseline-clean"]);
    expect(items[0]!.detail).toContain(absentReason("checkov"));
    expect(items[0]!.action).toContain("pnpm run doctor");
    // stamped with the run's own clock — the queue says when, and the only
    // honest instant available is the scan's
    expect(items[0]!.at).toBe(runRecord.run_timestamp);
  });

  it("an honest skip is still not a task, whichever source states it", () => {
    expect(derive().some((i) => i.recipeIds.includes("api-spec-lint-clean"))).toBe(false);
  });

  it("the recipe's authored fix sentence rides the item, and its absence is not faked", () => {
    expect(derive()[0]!.plain).toBe("the authored fix sentence");
    const noProse = queue.deriveActionQueue({
      registers: [register({ id: "u3", recipe_id: "iac-baseline-clean", state: "unevidenced", collector: "checkov", plain: null })],
      drift: [],
      events: [],
      runs: [runRecord],
      certClass: "b",
      now: NOW,
    });
    expect(noProse[0]!.plain).toBeUndefined();
  });

  it("the daemon event wins where both exist — the fallback only fills silence", () => {
    const withEvent = derive({
      events: [
        daemonEvent({
          id: "e9",
          at: iso(5 * 60 * 1000),
          kind: "scan-recorded",
          payload: {
            unevidenced: [
              {
                recipeId: "iac-baseline-clean",
                collector: "checkov",
                reason: `collector "checkov" skipped: ${absentReason("checkov")}`,
              },
            ],
          },
        }),
      ],
    });
    const actionable = withEvent.filter((i) => i.kind === "actionable-unevidenced");
    // one item, not two — the same cell explained twice is a queue that
    // double-counts the same piece of work
    expect(actionable).toHaveLength(1);
    expect(actionable[0]!.at).toBe(iso(5 * 60 * 1000));
    expect(actionable[0]!.title).toContain("has no tool to run");
  });

  it("a collector the run never dispatched is queued as its own fact", () => {
    const items = queue.deriveActionQueue({
      registers: [register({ id: "u4", recipe_id: "no-secrets-in-history", state: "unevidenced", collector: "gitleaks" })],
      drift: [],
      events: [],
      runs: [runRecord],
      certClass: "b",
      now: NOW,
    });
    expect(items).toHaveLength(1);
    expect(items[0]!.title).toContain("never dispatched");
    expect(items[0]!.detail).toContain("never dispatched");
  });

  it("passing no run records at all leaves the queue exactly as it was", () => {
    expect(
      queue.deriveActionQueue({ registers, drift: [], events: [], certClass: "b", now: NOW }),
    ).toEqual([]);
  });

  it("conditions with no instant stay off the queue and are left to the board", () => {
    // "no scan of this repo has ever been recorded" and "the catalog lost this
    // recipe" are conditions, not events: there is no honest time to stamp a
    // queue row with, so they are explained on the board's empty row instead
    // of arriving here dated with something invented.
    const noRunForRepo = queue.deriveActionQueue({
      registers,
      drift: [],
      events: [],
      runs: [{ ...runRecord, repo: "/somewhere-else" }],
      certClass: "b",
      now: NOW,
    });
    expect(noRunForRepo).toEqual([]);
    const lostRecipe = queue.deriveActionQueue({
      registers: [register({ id: "u5", recipe_id: "gone-from-catalog", state: "unevidenced", collector: "" })],
      drift: [],
      events: [],
      runs: [runRecord],
      certClass: "b",
      now: NOW,
    });
    expect(lostRecipe).toEqual([]);
  });
});
