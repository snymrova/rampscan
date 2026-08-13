import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import type { CertClass } from "@rampscan/core";
import { MVX_WINDOW_DAYS, clockState, windowMsFor } from "../src/index.js";

// I1c — the mvx twin test, closing the drift gap found 2026-08-14: the
// console ships its own copy of the MVX math (console/web/lib/mvx.ts) because
// it rides in a client bundle, and src/mvx.ts claims "the thresholds agree by
// test". This is that test: it imports BOTH copies and asserts the windows
// and the status boundaries (fresh < 0.75 ≤ expiring < 1.0 ≤ expired) agree.
// The console module belongs to another TS project (Next.js, bundler
// resolution), so it is loaded by path at runtime — vitest transforms it —
// rather than through a workspace import that would break `tsc --build`.

interface ConsoleMvx {
  MVX_WINDOW_DAYS: Record<CertClass, number>;
  clockState(
    freshAsOf: string,
    certClass: CertClass,
    now?: number,
  ): { windowMs: number; status: "fresh" | "expiring" | "expired"; remainingMs: number };
}

const consoleMvxPath = join(
  dirname(fileURLToPath(import.meta.url)),
  "../../../console/web/lib/mvx.ts",
);

let consoleMvx: ConsoleMvx;
beforeAll(async () => {
  consoleMvx = (await import(consoleMvxPath)) as ConsoleMvx;
});

const NOW = Date.parse("2026-08-14T00:00:00.000Z");
const CLASSES: CertClass[] = ["b", "c"];

function agedBy(fraction: number, windowMs: number): string {
  return new Date(NOW - fraction * windowMs).toISOString();
}

describe("mvx twins: scheduler and console compute the same clock", () => {
  it("the windows agree: b=7d, c=3d in both copies", () => {
    expect(consoleMvx.MVX_WINDOW_DAYS).toEqual(MVX_WINDOW_DAYS);
    for (const cls of CLASSES) {
      expect(consoleMvx.clockState(agedBy(0, windowMsFor(cls)), cls, NOW).windowMs).toBe(
        windowMsFor(cls),
      );
    }
  });

  it("the thresholds agree: fresh < 0.75 ≤ expiring < 1.0 ≤ expired", () => {
    // boundary fractions on either side of each threshold
    const probes: Array<[number, "fresh" | "expiring" | "expired"]> = [
      [0, "fresh"],
      [0.5, "fresh"],
      [0.7499, "fresh"],
      [0.75, "expiring"],
      [0.9999, "expiring"],
      [1.0, "expired"],
      [1.5, "expired"],
    ];
    for (const cls of CLASSES) {
      const windowMs = windowMsFor(cls);
      for (const [fraction, expected] of probes) {
        const freshAsOf = agedBy(fraction, windowMs);
        const server = clockState(freshAsOf, windowMs, NOW).status;
        const client = consoleMvx.clockState(freshAsOf, cls, NOW).status;
        expect(server, `class ${cls} at ${fraction} of the window`).toBe(expected);
        expect(client, `console: class ${cls} at ${fraction} of the window`).toBe(expected);
      }
    }
  });

  it("remaining time agrees to the millisecond", () => {
    for (const cls of CLASSES) {
      const windowMs = windowMsFor(cls);
      for (const fraction of [0.25, 0.8, 1.2]) {
        const freshAsOf = agedBy(fraction, windowMs);
        expect(consoleMvx.clockState(freshAsOf, cls, NOW).remainingMs).toBe(
          clockState(freshAsOf, windowMs, NOW).remainingMs,
        );
      }
    }
  });
});
