import { formatDuration } from "./mvx";
import type { DaemonEventRecord, DaemonStatusRecord } from "./types";

// The daemon status strip derivation (plan I2b): "is the machine that keeps
// this board honest actually running?" — answered from the daemon's own
// telemetry, computed at render time, never stored. An operator who cannot
// see the daemon died owns a silently rotting board, so absence of signal is
// itself the loudest signal here: no heartbeat row → "no daemon", a heartbeat
// past the check interval → "stale", and only a recent heartbeat earns
// "alive". The strip points at the board and the queue; it moves nothing.

/**
 * Stale once this many check intervals pass without a heartbeat — one fully
 * missed tick. The interval itself rides in the heartbeat payload (the
 * scheduler stamps it), so the threshold is computed from what the daemon
 * declared, never typed to match it.
 */
export const STALE_AFTER_INTERVALS = 2;

export type DaemonLiveness = "alive" | "stale" | "no-daemon";

/** the tick heartbeat's payload, as the scheduler emits it (local.ts "tick") */
interface TickPayload {
  cls?: "b" | "c";
  windowMs?: number;
  checkIntervalMs?: number;
  rows?: number;
  scanDue?: boolean;
  reason?: string;
  nextScanDueAt?: string;
}

interface ScanRecordedPayload {
  commit?: string;
  mode?: string;
}

interface DivergencePayload {
  reportPath?: string;
}

export interface DaemonStripRow {
  repo: string;
  liveness: DaemonLiveness;
  /** ms since the last heartbeat — absent when no heartbeat exists */
  heartbeatAgeMs?: number;
  /** the check interval the daemon declared in its heartbeat */
  checkIntervalMs?: number;
  /** the newest scan-recorded event for this repo */
  lastScan?: { at: string; commit: string; mode: string };
  /** the cadence outlook as of the last heartbeat's assessment */
  next?: { scanDue: boolean; reason?: string; nextScanDueAt?: string };
  /** a divergence with no later cache-verified — the report is standing */
  divergence?: { at: string; reportPath?: string };
}

/**
 * The most recent full-scan verification outcome per repo, kept only when it
 * is a divergence: a later cache-verified means the cache agrees again. The
 * action queue's tier 0 and the strip's report flag share this one reading.
 */
export function standingDivergences(events: DaemonEventRecord[]): DaemonEventRecord[] {
  const sorted = [...events].sort(
    (a, b) => a.at.localeCompare(b.at) || a.id.localeCompare(b.id),
  );
  const verifications = new Map<string, DaemonEventRecord>();
  for (const event of sorted) {
    if (event.kind === "divergence" || event.kind === "cache-verified") {
      verifications.set(event.repo, event);
    }
  }
  return [...verifications.values()]
    .filter((event) => event.kind === "divergence")
    .sort((a, b) => b.at.localeCompare(a.at));
}

export interface StripInput {
  status: DaemonStatusRecord[];
  events: DaemonEventRecord[];
  now?: number;
}

export function deriveDaemonStrip(input: StripInput): DaemonStripRow[] {
  const now = input.now ?? Date.now();
  const sortedEvents = [...input.events].sort(
    (a, b) => a.at.localeCompare(b.at) || a.id.localeCompare(b.id),
  );

  const heartbeats = new Map<string, DaemonStatusRecord>();
  for (const row of [...input.status].sort((a, b) => a.at.localeCompare(b.at))) {
    heartbeats.set(row.repo, row);
  }
  const lastScans = new Map<string, DaemonEventRecord>();
  for (const event of sortedEvents) {
    if (event.kind === "scan-recorded") lastScans.set(event.repo, event);
  }
  const divergences = new Map(standingDivergences(input.events).map((e) => [e.repo, e]));

  const repos = [...new Set([...heartbeats.keys(), ...lastScans.keys()])].sort();

  return repos.map((repo) => {
    const strip: DaemonStripRow = { repo, liveness: "no-daemon" };

    const heartbeat = heartbeats.get(repo);
    if (heartbeat) {
      const payload = heartbeat.payload as TickPayload;
      const ageMs = Math.max(0, now - Date.parse(heartbeat.at));
      strip.heartbeatAgeMs = ageMs;
      // a heartbeat without its declared interval cannot prove liveness —
      // failing toward "stale" is the safe direction (loud, not reassuring)
      const intervalMs =
        typeof payload.checkIntervalMs === "number" && payload.checkIntervalMs > 0
          ? payload.checkIntervalMs
          : 0;
      if (intervalMs > 0) strip.checkIntervalMs = intervalMs;
      strip.liveness = ageMs <= intervalMs * STALE_AFTER_INTERVALS ? "alive" : "stale";
      const next: DaemonStripRow["next"] = { scanDue: payload.scanDue === true };
      if (typeof payload.reason === "string") next.reason = payload.reason;
      if (typeof payload.nextScanDueAt === "string") next.nextScanDueAt = payload.nextScanDueAt;
      strip.next = next;
    }

    const scan = lastScans.get(repo);
    if (scan) {
      const payload = scan.payload as ScanRecordedPayload;
      strip.lastScan = {
        at: scan.at,
        commit: typeof payload.commit === "string" ? payload.commit : "",
        mode: typeof payload.mode === "string" ? payload.mode : "",
      };
    }

    const divergence = divergences.get(repo);
    if (divergence) {
      const payload = divergence.payload as DivergencePayload;
      const standing: DaemonStripRow["divergence"] = { at: divergence.at };
      if (typeof payload.reportPath === "string") standing.reportPath = payload.reportPath;
      strip.divergence = standing;
    }

    return strip;
  });
}

/** the strip's one-line phrasing of the cadence outlook, as of the last heartbeat */
export function describeNext(next: DaemonStripRow["next"], now = Date.now()): string {
  if (!next) return "";
  if (next.scanDue) return `scan due now${next.reason ? ` (${next.reason})` : ""}`;
  if (next.nextScanDueAt) {
    const inMs = Date.parse(next.nextScanDueAt) - now;
    return inMs > 0
      ? `next cadence scan in ${formatDuration(inMs)}`
      : `cadence scan overdue by ${formatDuration(inMs)}`;
  }
  return "next scan on evidence or a HEAD move";
}
