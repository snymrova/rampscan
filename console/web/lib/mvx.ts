// The MVX re-verification clock (FedRAMP 20x): evidence must be re-verified
// inside the class window — 7 days at class b, 3 at class c. The clock view
// exists because the regulation demands the loop; these helpers keep the math
// in one place, computed from bundle timestamps, never typed. This is the
// client-bundle twin of packages/scheduler/src/mvx.ts — the scheduler's
// test/mvx-twin.test.ts imports both copies and fails if the thresholds drift.

export const MVX_WINDOW_DAYS: Record<"b" | "c", number> = { b: 7, c: 3 };

/** the fraction of the window where "fresh" becomes "expiring" — the twin test pins it */
export const EXPIRING_AT_FRACTION = 0.75;

const DAY_MS = 24 * 60 * 60 * 1000;

export interface ClockState {
  ageMs: number;
  windowMs: number;
  remainingMs: number; // negative → expired
  fractionUsed: number; // 0..∞ (>1 → expired)
  status: "fresh" | "expiring" | "expired";
}

export function clockState(freshAsOf: string, certClass: "b" | "c", now = Date.now()): ClockState {
  const windowMs = MVX_WINDOW_DAYS[certClass] * DAY_MS;
  const ageMs = Math.max(0, now - Date.parse(freshAsOf));
  const remainingMs = windowMs - ageMs;
  const fractionUsed = ageMs / windowMs;
  return {
    ageMs,
    windowMs,
    remainingMs,
    fractionUsed,
    status: remainingMs <= 0 ? "expired" : fractionUsed >= EXPIRING_AT_FRACTION ? "expiring" : "fresh",
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

export function formatAge(iso: string, now = Date.now()): string {
  return formatDuration(now - Date.parse(iso));
}
