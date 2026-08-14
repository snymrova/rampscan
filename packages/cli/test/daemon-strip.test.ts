import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";

// I2b — the daemon status strip derivation, tested through the console's own
// copy (console/web/lib/status.ts, loaded by path like the queue and mvx twin
// tests: it lives in the Next.js TS project, so a workspace import would
// break `tsc --build`). The pins of record:
//   1. liveness is computed from the heartbeat the daemon itself declared
//      (its `at` + its `checkIntervalMs`) — stale after STALE_AFTER_INTERVALS
//      missed intervals, and a heartbeat that omits its interval fails toward
//      STALE, never toward reassurance;
//   2. no heartbeat row at all is "no-daemon", said instead of guessed;
//   3. the standing-divergence reading is the queue's own (shared function),
//      so the strip and the queue can never disagree about the report.

interface StatusModule {
  STALE_AFTER_INTERVALS: number;
  standingDivergences(events: unknown[]): Array<{ repo: string; at: string }>;
  deriveDaemonStrip(input: { status: unknown[]; events: unknown[]; now?: number }): Array<{
    repo: string;
    liveness: "alive" | "stale" | "no-daemon";
    heartbeatAgeMs?: number;
    checkIntervalMs?: number;
    lastScan?: { at: string; commit: string; mode: string };
    next?: { scanDue: boolean; reason?: string; nextScanDueAt?: string };
    divergence?: { at: string; reportPath?: string };
  }>;
  describeNext(
    next: { scanDue: boolean; reason?: string; nextScanDueAt?: string } | undefined,
    now?: number,
  ): string;
}

const statusPath = join(
  dirname(fileURLToPath(import.meta.url)),
  "../../../console/web/lib/status.ts",
);

let mod: StatusModule;
beforeAll(async () => {
  mod = (await import(statusPath)) as StatusModule;
});

const NOW = Date.parse("2026-08-14T12:00:00.000Z");
const MIN = 60_000;
const INTERVAL = 5 * MIN;

const iso = (msAgo: number) => new Date(NOW - msAgo).toISOString();

function heartbeat(msAgo: number, extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: "s1",
    at: iso(msAgo),
    kind: "tick",
    repo: "/repo",
    payload: { checkIntervalMs: INTERVAL, rows: 12, scanDue: false, ...extra },
  };
}

function event(overrides: Record<string, unknown>): Record<string, unknown> {
  return { id: "e", at: iso(60 * MIN), kind: "scan-recorded", repo: "/repo", payload: {}, ...overrides };
}

describe("deriveDaemonStrip: liveness from the daemon's own declared interval", () => {
  it("a heartbeat inside STALE_AFTER_INTERVALS × checkInterval is alive", () => {
    expect(mod.STALE_AFTER_INTERVALS).toBe(2); // the threshold of record
    const [row] = mod.deriveDaemonStrip({
      status: [heartbeat(INTERVAL * 1.5)],
      events: [],
      now: NOW,
    });
    expect(row!.liveness).toBe("alive");
    expect(row!.heartbeatAgeMs).toBe(INTERVAL * 1.5);
    expect(row!.checkIntervalMs).toBe(INTERVAL);
  });

  it("past the missed-tick threshold the daemon is STALE — said loudly, not absorbed", () => {
    const [row] = mod.deriveDaemonStrip({
      status: [heartbeat(INTERVAL * 2.1)],
      events: [],
      now: NOW,
    });
    expect(row!.liveness).toBe("stale");
  });

  it("a heartbeat that omits its check interval cannot prove liveness — it fails toward stale", () => {
    const [row] = mod.deriveDaemonStrip({
      status: [heartbeat(MIN, { checkIntervalMs: undefined })],
      events: [],
      now: NOW,
    });
    expect(row!.liveness).toBe("stale");
  });

  it("events without any heartbeat are 'no-daemon' — absence is said, never guessed over", () => {
    const [row] = mod.deriveDaemonStrip({
      status: [],
      events: [
        event({ payload: { commit: "cafebabe1234deadbeef", mode: "incremental" } }),
      ],
      now: NOW,
    });
    expect(row!.liveness).toBe("no-daemon");
    expect(row!.heartbeatAgeMs).toBeUndefined();
    expect(row!.lastScan).toMatchObject({ commit: "cafebabe1234deadbeef", mode: "incremental" });
  });

  it("no telemetry at all derives an empty strip", () => {
    expect(mod.deriveDaemonStrip({ status: [], events: [], now: NOW })).toEqual([]);
  });
});

describe("deriveDaemonStrip: last scan, cadence outlook, standing divergence", () => {
  const events = [
    event({ id: "e1", at: iso(3 * 60 * MIN), payload: { commit: "older000", mode: "full" } }),
    event({ id: "e2", at: iso(30 * MIN), payload: { commit: "cafebabe1234deadbeef", mode: "incremental" } }),
    event({
      id: "e3",
      at: iso(2 * 60 * MIN),
      kind: "divergence",
      payload: { reportPath: "/out/divergence-report.json" },
    }),
  ];

  it("the newest scan-recorded wins, and the heartbeat's outlook rides through verbatim", () => {
    const [row] = mod.deriveDaemonStrip({
      status: [heartbeat(MIN, { nextScanDueAt: iso(-2 * 60 * MIN) })],
      events,
      now: NOW,
    });
    expect(row!.lastScan).toMatchObject({ commit: "cafebabe1234deadbeef", mode: "incremental" });
    expect(row!.next).toEqual({ scanDue: false, nextScanDueAt: iso(-2 * 60 * MIN) });
  });

  it("a divergence with no later cache-verified is standing; a later one clears it — the queue's own reading", () => {
    const [row] = mod.deriveDaemonStrip({ status: [heartbeat(MIN)], events, now: NOW });
    expect(row!.divergence).toEqual({
      at: iso(2 * 60 * MIN),
      reportPath: "/out/divergence-report.json",
    });

    const cleared = mod.deriveDaemonStrip({
      status: [heartbeat(MIN)],
      events: [...events, event({ id: "e4", at: iso(10 * MIN), kind: "cache-verified" })],
      now: NOW,
    });
    expect(cleared[0]!.divergence).toBeUndefined();
    expect(mod.standingDivergences(events)).toHaveLength(1);
  });
});

describe("describeNext: the outlook in one phrase", () => {
  it("due now names the reason; a future due time counts down; a past one says overdue", () => {
    expect(mod.describeNext({ scanDue: true, reason: "head-moved" }, NOW)).toBe(
      "scan due now (head-moved)",
    );
    expect(mod.describeNext({ scanDue: false, nextScanDueAt: iso(-90 * MIN) }, NOW)).toBe(
      "next cadence scan in 1h 30m",
    );
    expect(
      mod.describeNext({ scanDue: false, nextScanDueAt: iso(45 * MIN) }, NOW),
    ).toContain("overdue by 45m");
    expect(mod.describeNext({ scanDue: false }, NOW)).toContain("HEAD move");
  });
});
