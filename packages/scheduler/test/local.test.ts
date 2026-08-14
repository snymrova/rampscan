import { describe, expect, it } from "vitest";
import { createLocalScheduler } from "../src/index.js";
import type { LiveEvidence, SchedulerEvent } from "../src/index.js";

// The Scheduler local adapter under a fake clock: warnings fire once per
// bundle digest and land before the scan decision; scans run on the cadence
// math; a failing scan is an event, not a crash.

const T0 = Date.parse("2026-08-13T00:00:00.000Z");
const WINDOW = 1000;

interface Harness {
  events: SchedulerEvent[];
  scans: Array<{ reason: string }>;
  setRows(rows: LiveEvidence[]): void;
  setNow(t: number): void;
  setHead(commit: string | undefined): void;
  setLastCommit(commit: string | undefined): void;
  failScans(fail: boolean): void;
  scheduler: ReturnType<typeof createLocalScheduler>;
}

function harness(): Harness {
  let rows: LiveEvidence[] = [];
  let now = T0;
  let head: string | undefined;
  let lastCommit: string | undefined;
  let failing = false;
  const events: SchedulerEvent[] = [];
  const scans: Array<{ reason: string }> = [];

  const scheduler = createLocalScheduler({
    assess: async () => {
      const assessment: { rows: LiveEvidence[]; lastCommit?: string } = { rows };
      if (lastCommit !== undefined) assessment.lastCommit = lastCommit;
      return assessment;
    },
    scan: async (_target, reason) => {
      if (failing) throw new Error("collector exploded");
      scans.push({ reason });
    },
    head: async () => head,
    checkIntervalMs: 60_000_000, // the loop timer never fires in tests — tick() drives
    windowMs: { b: WINDOW },
    onEvent: (e) => events.push(e),
    clock: () => now,
  });

  return {
    events,
    scans,
    scheduler,
    setRows: (r) => (rows = r),
    setNow: (t) => (now = t),
    setHead: (c) => (head = c),
    setLastCommit: (c) => (lastCommit = c),
    failScans: (f) => (failing = f),
  };
}

function row(recipeId: string, freshAt: number, digest = `d-${recipeId}-${freshAt}`): LiveEvidence {
  return { recipeId, bundleDigest: digest, freshAsOf: new Date(freshAt).toISOString() };
}

describe("createLocalScheduler", () => {
  it("ensureCadence runs an immediate assessment: no evidence → scan now", async () => {
    const h = harness();
    await h.scheduler.ensureCadence("b", { repo: "/repo" });
    h.scheduler.stop();
    expect(h.scans).toEqual([{ reason: "no-evidence" }]);
    expect(h.events.some((e) => e.kind === "registered")).toBe(true);
  });

  it("fresh evidence → a tick does nothing", async () => {
    const h = harness();
    h.setRows([row("a", T0 - 100)]);
    await h.scheduler.ensureCadence("b", { repo: "/repo" });
    h.scheduler.stop();
    expect(h.scans).toHaveLength(0);
  });

  it("past the scan-at fraction → scan due (cadence)", async () => {
    const h = harness();
    h.setRows([row("a", T0 - 600)]);
    await h.scheduler.ensureCadence("b", { repo: "/repo" });
    h.scheduler.stop();
    expect(h.scans).toEqual([{ reason: "cadence" }]);
  });

  it("a moved HEAD → scan due even with fresh evidence", async () => {
    const h = harness();
    h.setRows([row("a", T0 - 100)]);
    h.setLastCommit("aaa");
    h.setHead("bbb");
    await h.scheduler.ensureCadence("b", { repo: "/repo" });
    h.scheduler.stop();
    expect(h.scans).toEqual([{ reason: "head-moved" }]);
  });

  it("warns once per bundle digest, before the scan — and an expired bundle warns louder", async () => {
    const h = harness();
    h.setRows([row("aging", T0 - 800, "digest-aging"), row("gone", T0 - 1200, "digest-gone")]);
    await h.scheduler.ensureCadence("b", { repo: "/repo" });

    const kinds = h.events.map((e) => e.kind);
    const firstWarn = kinds.findIndex((k) => k === "warn-expiring" || k === "warn-expired");
    const firstScan = kinds.indexOf("scan-started");
    expect(firstWarn).toBeGreaterThanOrEqual(0);
    expect(firstWarn).toBeLessThan(firstScan); // warnings land first

    expect(h.events.filter((e) => e.kind === "warn-expiring")).toHaveLength(1);
    expect(h.events.filter((e) => e.kind === "warn-expired")).toHaveLength(1);

    // second tick with the same rows: the warnings do NOT repeat
    await h.scheduler.tick();
    h.scheduler.stop();
    expect(h.events.filter((e) => e.kind === "warn-expiring")).toHaveLength(1);
    expect(h.events.filter((e) => e.kind === "warn-expired")).toHaveLength(1);
  });

  it("a refreshed bundle (new digest) earns a fresh warning slot", async () => {
    const h = harness();
    h.setRows([row("a", T0 - 800, "digest-1")]);
    await h.scheduler.ensureCadence("b", { repo: "/repo" });
    h.setRows([row("a", T0 - 800, "digest-2")]); // re-signed: same age, new digest
    await h.scheduler.tick();
    h.scheduler.stop();
    expect(h.events.filter((e) => e.kind === "warn-expiring")).toHaveLength(2);
  });

  it("a failing scan emits scan-failed and the loop survives", async () => {
    const h = harness();
    h.failScans(true);
    await h.scheduler.ensureCadence("b", { repo: "/repo" });
    expect(h.events.some((e) => e.kind === "scan-failed")).toBe(true);
    h.failScans(false);
    await h.scheduler.tick();
    h.scheduler.stop();
    expect(h.scans).toHaveLength(1); // the retry on the next tick succeeded
  });

  it("every assessment emits one tick heartbeat — including quiet ones (I2b: a silent daemon is indistinguishable from a dead one)", async () => {
    const h = harness();
    h.setRows([row("a", T0 - 100)]); // fresh — nothing due
    await h.scheduler.ensureCadence("b", { repo: "/repo" });
    await h.scheduler.tick();
    h.scheduler.stop();
    expect(h.scans).toHaveLength(0); // both ticks were quiet
    const ticks = h.events.filter((e) => e.kind === "tick");
    expect(ticks).toHaveLength(2);
    expect(ticks[0]).toMatchObject({
      repo: "/repo",
      cls: "b",
      windowMs: WINDOW,
      checkIntervalMs: 60_000_000,
      rows: 1,
      scanDue: false,
    });
  });

  it("the tick carries the cadence outlook: next scan due when the oldest bundle crosses the scan-at fraction", async () => {
    const h = harness();
    h.setRows([row("young", T0 - 100), row("old", T0 - 300)]);
    await h.scheduler.ensureCadence("b", { repo: "/repo" });
    h.scheduler.stop();
    const tick = h.events.find((e) => e.kind === "tick");
    expect(tick).toBeDefined();
    if (tick?.kind !== "tick") throw new Error("unreachable");
    // the OLDEST bundle (T0-300) + 0.5 × window drives the next due time
    expect(tick.nextScanDueAt).toBe(new Date(T0 - 300 + WINDOW * 0.5).toISOString());
    expect(tick.oldestFractionUsed).toBeCloseTo(300 / WINDOW);
  });

  it("a due tick says so: scanDue + reason ride the heartbeat; no evidence means no next-due time", async () => {
    const h = harness();
    await h.scheduler.ensureCadence("b", { repo: "/repo" }); // no evidence → scan now
    h.scheduler.stop();
    const tick = h.events.find((e) => e.kind === "tick");
    if (tick?.kind !== "tick") throw new Error("no tick emitted");
    expect(tick.scanDue).toBe(true);
    expect(tick.reason).toBe("no-evidence");
    expect(tick.nextScanDueAt).toBeUndefined();
  });

  it("the heartbeat lands before the scan decision — like the warnings, it must be on the record even if the scan hangs", async () => {
    const h = harness();
    h.setRows([row("a", T0 - 600)]); // cadence due
    await h.scheduler.ensureCadence("b", { repo: "/repo" });
    h.scheduler.stop();
    const kinds = h.events.map((e) => e.kind);
    expect(kinds.indexOf("tick")).toBeLessThan(kinds.indexOf("scan-started"));
  });

  it("stop() halts the loop; registrations remain listed", async () => {
    const h = harness();
    h.setRows([row("a", T0 - 100)]);
    await h.scheduler.ensureCadence("b", { repo: "/repo" });
    h.scheduler.stop();
    expect(h.scheduler.targets()).toEqual([{ cls: "b", target: { repo: "/repo" } }]);
  });
});
