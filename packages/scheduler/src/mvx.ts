import type { CertClass } from "@rampscan/core";

// The MVX re-verification clock (FedRAMP 20x): evidence must be re-verified
// inside the class window — 7 days at class b, 3 at class c. This is the
// server-side twin of console/web/lib/mvx.ts (the console keeps its own copy
// because it ships in a client bundle); the thresholds agree by test —
// test/mvx-twin.test.ts imports both copies and fails if they drift.

export const MVX_WINDOW_DAYS: Record<CertClass, number> = { b: 7, c: 3 };

export const DAY_MS = 24 * 60 * 60 * 1000;

export function windowMsFor(cls: CertClass): number {
  return MVX_WINDOW_DAYS[cls] * DAY_MS;
}

export interface ClockState {
  ageMs: number;
  windowMs: number;
  remainingMs: number; // negative → expired
  fractionUsed: number; // 0..∞ (>1 → expired)
  status: "fresh" | "expiring" | "expired";
}

/** matches the console's clock view: "expiring" from 0.75 of the window */
export const EXPIRING_FRACTION = 0.75;

export function clockState(
  freshAsOf: string,
  windowMs: number,
  now: number,
  expiringFraction = EXPIRING_FRACTION,
): ClockState {
  const ageMs = Math.max(0, now - Date.parse(freshAsOf));
  const remainingMs = windowMs - ageMs;
  const fractionUsed = ageMs / windowMs;
  return {
    ageMs,
    windowMs,
    remainingMs,
    fractionUsed,
    status: remainingMs <= 0 ? "expired" : fractionUsed >= expiringFraction ? "expiring" : "fresh",
  };
}

export function formatDuration(ms: number): string {
  const abs = Math.abs(ms);
  const days = Math.floor(abs / DAY_MS);
  const hours = Math.floor((abs % DAY_MS) / 3_600_000);
  const minutes = Math.floor((abs % 3_600_000) / 60_000);
  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${minutes}m`;
  return `${minutes}m`;
}
