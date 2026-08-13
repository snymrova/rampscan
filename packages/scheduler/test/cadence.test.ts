import { describe, expect, it } from "vitest";
import { assessCadence, clockState, windowMsFor } from "../src/index.js";
import type { LiveEvidence } from "../src/index.js";

// The cadence math, pure and clock-injected. Thresholds under test are the
// product's: scan at 0.5 of the MVX window, warn at 0.75 (the console's
// "expiring"), expired past 1.0.

const WINDOW = 1000; // ms — tiny window, fake clock
const T0 = Date.parse("2026-08-13T00:00:00.000Z");

function row(recipeId: string, ageMs: number): LiveEvidence {
  return {
    recipeId,
    bundleDigest: `digest-${recipeId}`,
    freshAsOf: new Date(T0 - ageMs).toISOString(),
  };
}

describe("clockState", () => {
  it("matches the console's thresholds: fresh < 0.75 ≤ expiring < 1.0 ≤ expired", () => {
    expect(clockState(row("r", 500).freshAsOf, WINDOW, T0).status).toBe("fresh");
    expect(clockState(row("r", 750).freshAsOf, WINDOW, T0).status).toBe("expiring");
    expect(clockState(row("r", 999).freshAsOf, WINDOW, T0).status).toBe("expiring");
    expect(clockState(row("r", 1000).freshAsOf, WINDOW, T0).status).toBe("expired");
  });

  it("reports remaining time, negative once expired", () => {
    expect(clockState(row("r", 400).freshAsOf, WINDOW, T0).remainingMs).toBe(600);
    expect(clockState(row("r", 1200).freshAsOf, WINDOW, T0).remainingMs).toBe(-200);
  });
});

describe("assessCadence", () => {
  it("no evidence at all → scan due immediately", () => {
    const a = assessCadence([], { windowMs: WINDOW, now: T0 });
    expect(a.scanDue).toBe(true);
    expect(a.reason).toBe("no-evidence");
  });

  it("fresh evidence → nothing due, nothing warned", () => {
    const a = assessCadence([row("a", 100), row("b", 200)], { windowMs: WINDOW, now: T0 });
    expect(a.scanDue).toBe(false);
    expect(a.expiring).toHaveLength(0);
    expect(a.expired).toHaveLength(0);
  });

  it("the OLDEST bundle drives the scan decision: one bundle past 0.5 → due", () => {
    const a = assessCadence([row("young", 100), row("old", 600)], { windowMs: WINDOW, now: T0 });
    expect(a.scanDue).toBe(true);
    expect(a.reason).toBe("cadence");
    expect(a.oldest?.recipeId).toBe("old");
  });

  it("a moved HEAD forces a scan even when everything is fresh", () => {
    const a = assessCadence([row("a", 100)], { windowMs: WINDOW, now: T0, headMoved: true });
    expect(a.scanDue).toBe(true);
    expect(a.reason).toBe("head-moved");
  });

  it("warns at 0.75 — before the window closes, never after", () => {
    const a = assessCadence([row("aging", 800), row("gone", 1100), row("ok", 100)], {
      windowMs: WINDOW,
      now: T0,
    });
    expect(a.expiring.map((r) => r.recipeId)).toEqual(["aging"]);
    expect(a.expired.map((r) => r.recipeId)).toEqual(["gone"]);
  });

  it("scan-at fraction is configurable", () => {
    const a = assessCadence([row("a", 300)], {
      windowMs: WINDOW,
      scanAtFraction: 0.25,
      now: T0,
    });
    expect(a.scanDue).toBe(true);
  });

  it("real windows: class b is 7 days, class c is 3", () => {
    expect(windowMsFor("b")).toBe(7 * 24 * 3600 * 1000);
    expect(windowMsFor("c")).toBe(3 * 24 * 3600 * 1000);
  });
});
