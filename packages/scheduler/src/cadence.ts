import { EXPIRING_FRACTION, clockState } from "./mvx.js";
import type { ClockState } from "./mvx.js";

// The cadence decision, pure (plan G1): given the live evidence for a target
// and the class window, decide whether a re-scan is due and which bundles
// deserve a nearing-expiry warning. The daemon's tick calls this; tests call
// it with a fake clock. Warnings are computed from the CURRENT state before
// any scan runs, so a daemon that slept through most of a window still warns
// before (or with) the refresh — never after the window closed silently.

export interface LiveEvidence {
  recipeId: string;
  bundleDigest: string;
  freshAsOf: string; // ISO 8601 — the bundle timestamp
}

export type ScanReason = "no-evidence" | "cadence" | "head-moved";

export interface AssessedEvidence extends LiveEvidence {
  clock: ClockState;
}

export interface CadenceAssessment {
  scanDue: boolean;
  reason?: ScanReason;
  /** fractionUsed ≥ warnAtFraction but not yet expired */
  expiring: AssessedEvidence[];
  /** the window closed without re-verification */
  expired: AssessedEvidence[];
  /** the bundle whose clock has run the furthest */
  oldest?: AssessedEvidence;
}

export interface CadenceOptions {
  windowMs: number;
  /** re-scan once the oldest live bundle has used this fraction of its window */
  scanAtFraction?: number; // default 0.5
  /** warn once a bundle has used this fraction of its window */
  warnAtFraction?: number; // default 0.75 — the console's "expiring"
  /** the target repo's HEAD moved since the last recorded scan */
  headMoved?: boolean;
  now: number;
}

export const DEFAULT_SCAN_AT_FRACTION = 0.5;

export function assessCadence(rows: LiveEvidence[], options: CadenceOptions): CadenceAssessment {
  const scanAt = options.scanAtFraction ?? DEFAULT_SCAN_AT_FRACTION;
  const warnAt = options.warnAtFraction ?? EXPIRING_FRACTION;

  const assessed: AssessedEvidence[] = rows.map((row) => ({
    ...row,
    clock: clockState(row.freshAsOf, options.windowMs, options.now, warnAt),
  }));
  assessed.sort((a, b) => b.clock.fractionUsed - a.clock.fractionUsed);

  const expired = assessed.filter((r) => r.clock.status === "expired");
  const expiring = assessed.filter((r) => r.clock.status === "expiring");
  const oldest = assessed[0];

  const result: CadenceAssessment = { scanDue: false, expiring, expired };
  if (oldest) result.oldest = oldest;

  if (rows.length === 0) {
    result.scanDue = true;
    result.reason = "no-evidence";
  } else if (options.headMoved) {
    result.scanDue = true;
    result.reason = "head-moved";
  } else if (oldest && oldest.clock.fractionUsed >= scanAt) {
    result.scanDue = true;
    result.reason = "cadence";
  }
  return result;
}
