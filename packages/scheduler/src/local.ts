import type { CertClass, ScanTarget, Scheduler } from "@rampscan/core";
import { assessCadence } from "./cadence.js";
import type { LiveEvidence, ScanReason } from "./cadence.js";
import { formatDuration, windowMsFor } from "./mvx.js";

// The Scheduler local adapter (plan G1) — the sixth and last port to grow a
// real local implementation. Later: EventBridge. Deviation from the plan's
// "node-cron": a plain setTimeout tick chain, dependency-free, same house
// style as DSSE-without-cosign — cron expressions add nothing when the
// schedule is "check every N minutes, act on the clock math"; node-cron
// slots in behind the same port if a cron surface is ever wanted.
//
// ensureCadence(cls, target) registers the target and guarantees the loop
// runs: each tick folds the current evidence state (via the injected assess),
// emits nearing-expiry warnings BEFORE the scan decision, then re-scans when
// the cadence math says so. Warnings are once-per-bundle-digest: a refresh
// mints a new digest and thereby a new warning slot.

export interface SchedulerAssessment {
  rows: LiveEvidence[];
  /** the commit the newest live evidence was scanned at, when known */
  lastCommit?: string;
}

export type SchedulerEvent =
  | { kind: "registered"; repo: string; cls: CertClass; windowMs: number }
  | {
      kind: "warn-expiring" | "warn-expired";
      repo: string;
      recipeId: string;
      bundleDigest: string;
      freshAsOf: string;
      remainingMs: number;
    }
  | { kind: "scan-started"; repo: string; reason: ScanReason }
  | { kind: "scan-completed"; repo: string; reason: ScanReason }
  | { kind: "scan-failed"; repo: string; reason: ScanReason; error: string }
  | { kind: "tick-failed"; repo: string; error: string };

export interface LocalSchedulerOptions {
  /** current live evidence for the target — the daemon folds the projection here */
  assess(target: ScanTarget): Promise<SchedulerAssessment>;
  /** run one scan; the scheduler's clock decides when, the daemon decides how */
  scan(target: ScanTarget, reason: ScanReason): Promise<void>;
  /** current HEAD of the target; when it differs from lastCommit a scan is due */
  head?(target: ScanTarget): Promise<string | undefined>;
  /** how often the loop re-checks the clock (default 5 minutes) */
  checkIntervalMs?: number;
  /** MVX window override per class — tests only; defaults to b=7d, c=3d */
  windowMs?: Partial<Record<CertClass, number>>;
  scanAtFraction?: number;
  warnAtFraction?: number;
  onEvent?(event: SchedulerEvent): void;
  /** injectable clock for tests */
  clock?: () => number;
}

export interface LocalScheduler extends Scheduler {
  /** one assessment cycle across all registered targets — the loop calls this */
  tick(): Promise<void>;
  stop(): void;
  targets(): Array<{ cls: CertClass; target: ScanTarget }>;
}

const DEFAULT_CHECK_INTERVAL_MS = 5 * 60 * 1000;

export function createLocalScheduler(options: LocalSchedulerOptions): LocalScheduler {
  const emit = options.onEvent ?? (() => {});
  const clock = options.clock ?? Date.now;
  const checkIntervalMs = options.checkIntervalMs ?? DEFAULT_CHECK_INTERVAL_MS;

  interface Registration {
    cls: CertClass;
    target: ScanTarget;
    windowMs: number;
  }
  const registrations = new Map<string, Registration>();
  const warned = new Set<string>(); // `${digest}:${expiring|expired}` — once each
  let timer: NodeJS.Timeout | undefined;
  let stopped = false;
  let ticking = false;

  function keyOf(cls: CertClass, target: ScanTarget): string {
    return `${cls}:${target.repo}:${target.ref ?? "HEAD"}`;
  }

  async function tickOne(reg: Registration): Promise<void> {
    const now = clock();
    const { rows, lastCommit } = await options.assess(reg.target);

    let headMoved = false;
    if (options.head && lastCommit !== undefined) {
      const head = await options.head(reg.target);
      headMoved = head !== undefined && head !== lastCommit;
    }

    const cadenceOpts: Parameters<typeof assessCadence>[1] = {
      windowMs: reg.windowMs,
      headMoved,
      now,
    };
    if (options.scanAtFraction !== undefined) cadenceOpts.scanAtFraction = options.scanAtFraction;
    if (options.warnAtFraction !== undefined) cadenceOpts.warnAtFraction = options.warnAtFraction;
    const assessment = assessCadence(rows, cadenceOpts);

    // warnings first — they must land even if the scan below fails or hangs
    for (const row of [...assessment.expired, ...assessment.expiring]) {
      const kind = row.clock.status === "expired" ? "warn-expired" : "warn-expiring";
      const onceKey = `${row.bundleDigest}:${kind}`;
      if (warned.has(onceKey)) continue;
      warned.add(onceKey);
      emit({
        kind,
        repo: reg.target.repo,
        recipeId: row.recipeId,
        bundleDigest: row.bundleDigest,
        freshAsOf: row.freshAsOf,
        remainingMs: row.clock.remainingMs,
      });
    }

    if (!assessment.scanDue || assessment.reason === undefined) return;
    const reason = assessment.reason;
    emit({ kind: "scan-started", repo: reg.target.repo, reason });
    try {
      await options.scan(reg.target, reason);
      emit({ kind: "scan-completed", repo: reg.target.repo, reason });
    } catch (error) {
      emit({
        kind: "scan-failed",
        repo: reg.target.repo,
        reason,
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }

  async function tick(): Promise<void> {
    if (ticking) return;
    ticking = true;
    try {
      for (const reg of registrations.values()) {
        try {
          await tickOne(reg);
        } catch (error) {
          emit({
            kind: "tick-failed",
            repo: reg.target.repo,
            error: error instanceof Error ? error.message : String(error),
          });
        }
      }
    } finally {
      ticking = false;
    }
  }

  function armTimer(): void {
    if (stopped || timer !== undefined) return;
    timer = setTimeout(() => {
      timer = undefined;
      void tick().finally(armTimer);
    }, checkIntervalMs);
  }

  return {
    async ensureCadence(cls, target): Promise<void> {
      const key = keyOf(cls, target);
      if (!registrations.has(key)) {
        const windowMs = options.windowMs?.[cls] ?? windowMsFor(cls);
        registrations.set(key, { cls, target, windowMs });
        emit({ kind: "registered", repo: target.repo, cls, windowMs });
      }
      await tick(); // an immediate assessment — cadence guarantees start now
      armTimer();
    },
    tick,
    stop(): void {
      stopped = true;
      if (timer !== undefined) clearTimeout(timer);
      timer = undefined;
    },
    targets(): Array<{ cls: CertClass; target: ScanTarget }> {
      return [...registrations.values()].map(({ cls, target }) => ({ cls, target }));
    },
  };
}

export function describeEvent(event: SchedulerEvent): string {
  switch (event.kind) {
    case "registered":
      return `watching ${event.repo} (class window ${formatDuration(event.windowMs)})`;
    case "warn-expiring":
      return `NEARING EXPIRY ${event.recipeId} — ${formatDuration(event.remainingMs)} left in the window (evidence ${event.bundleDigest.slice(0, 12)})`;
    case "warn-expired":
      return `EXPIRED ${event.recipeId} — window closed ${formatDuration(event.remainingMs)} ago (evidence ${event.bundleDigest.slice(0, 12)})`;
    case "scan-started":
      return `scan due (${event.reason}) — scanning ${event.repo}`;
    case "scan-completed":
      return `scan completed (${event.reason})`;
    case "scan-failed":
      return `scan FAILED (${event.reason}): ${event.error}`;
    case "tick-failed":
      return `tick FAILED for ${event.repo}: ${event.error}`;
  }
}
