import { readFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { DEFAULT_SCAN_AT_FRACTION, assessCadence, windowMsFor } from "@rampscan/scheduler";

// N1-4 (docs/PLAN-REACH.md): `rampscan daemon` is the appliance form of the
// scheduled self-scan, and the two must agree about WHEN a scan is owed. The
// daemon's clock is `assessCadence` over the live evidence; the workflow's is
// a cron. This test holds the cron to the daemon's arithmetic: by the time
// the weekly run fires, the daemon would already have requested the same
// scan — and never the reverse, a cron slower than the window it serves.

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const DAY = 86_400_000;

/** the workflow's schedule, read from the file rather than restated */
async function scanCron(): Promise<string> {
  const yml = await readFile(join(REPO_ROOT, ".github/workflows/scan.yml"), "utf8");
  const m = /^\s*-\s*cron:\s*"([^"]+)"/m.exec(yml);
  if (m === null) throw new Error("scan.yml carries no cron schedule");
  return m[1]!;
}

/** the longest gap a five-field cron can leave between firings, in days, for the shapes this file admits */
function maxGapDays(cron: string): number {
  const [, , dom, , dow] = cron.split(/\s+/);
  if (dom === "*" && dow === "*") return 1;
  if (dom === "*" && /^\d$/.test(dow!)) return 7;
  throw new Error(`cron "${cron}" is neither daily nor weekly — teach this test its gap before using it`);
}

describe("the daemon and the scheduled self-scan keep one clock (N1-4)", () => {
  it("the workflow is weekly, which is the class-b MVX window — never slower than what it serves", async () => {
    const gap = maxGapDays(await scanCron());
    expect(gap * DAY).toBeLessThanOrEqual(windowMsFor("b"));
  });

  it("by the time the weekly run fires, the daemon's tick would have requested the same scan", async () => {
    const gap = maxGapDays(await scanCron());
    const lastRun = "2026-09-14T06:00:00.000Z";
    const rows = [{ recipeId: "r", bundleDigest: "d", freshAsOf: lastRun }];
    // the daemon re-scans once the oldest live bundle has used half its window
    const dueAt = Date.parse(lastRun) + windowMsFor("b") * DEFAULT_SCAN_AT_FRACTION;
    const nextRun = Date.parse(lastRun) + gap * DAY;
    expect(nextRun).toBeGreaterThanOrEqual(dueAt);
    const atNextRun = assessCadence(rows, { windowMs: windowMsFor("b"), now: nextRun });
    expect(atNextRun.scanDue).toBe(true);
    expect(atNextRun.reason).toBe("cadence");
    // and the day after a run, neither clock wants one
    const dayAfter = assessCadence(rows, { windowMs: windowMsFor("b"), now: Date.parse(lastRun) + DAY });
    expect(dayAfter.scanDue).toBe(false);
  });
});
