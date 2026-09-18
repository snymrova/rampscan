import type { LedgerEntry } from "@rampscan/core";
import { foldEntries, type FoldOptions } from "@rampscan/projector";
import { isEvidenceBundle } from "@rampscan/schema";
import { ksiStatus, type KsiStatus } from "./sdr-build.js";

// Historical metrics for the Security Decision Record (R3, docs/PLAN-HISTORY.md).
//
// SDR-CSX-KMT wants, per KSI, a summary of each metric over the past 30 days
// and up to the past year, and at class c every day's data. No rule defines a
// metric (FedRAMP/schemas#10, question 3). FRC-CSX-MOT names one, "status from
// persistent validation", so a KSI's metric for a day is its computed status
// plus the counts it was computed from (H1). Those counts are the D6 basis the
// SDR already publishes, so the history uses the same rule as the current row.
//
// REFOLDED, NEVER ACCUMULATED (H2). Day D's metric is `ksiStatus` over the
// projection folded as of D's last millisecond, which is what `sdr --as-of`
// at that instant would have said. Nothing here is stored between runs, so the
// same ledger at the same instant always yields the same bytes.
//
// ABSENT IS NOT ZERO (H3). Days before the offering's first scan have no
// status, and are counted as absent. A day after it with no new scan is
// covered: the fold still knows the status, which may be evidence going stale,
// and that is a real status.

const DAY_MS = 86_400_000;

/** a KSI's metric on one day: its D6 status and the counts behind it */
export interface KsiDayMetric {
  status: KsiStatus;
  methodsInScope: number;
  methodsPassing: number;
  violatedMethods: number;
  staleMethods: number;
  automatedWithEvidence: number;
  artifactsPresent: number;
}

export const METRIC_COUNTS = [
  "methodsInScope",
  "methodsPassing",
  "violatedMethods",
  "staleMethods",
  "automatedWithEvidence",
  "artifactsPresent",
] as const satisfies readonly (keyof KsiDayMetric)[];
export type MetricCount = (typeof METRIC_COUNTS)[number];

/** one KSI's summary over one window (H7) */
export interface KsiMetricSummary {
  /** first and last UTC day of the window, inclusive */
  from: string;
  to: string;
  daysInWindow: number;
  daysCovered: number;
  /** days before the ledger's first scan of the offering — no status, never a zero */
  daysAbsent: number;
  /** days per status value, over covered days only */
  statusDays: Record<KsiStatus, number>;
  /** the status on the first and last covered day; absent when no day is covered */
  firstStatus?: KsiStatus;
  lastStatus?: KsiStatus;
  /** each count's minimum, maximum and value on the last covered day */
  counts?: Record<MetricCount, { min: number; max: number; last: number }>;
}

export interface MetricsInput {
  /** every ledger entry; the day folds filter by instant themselves */
  entries: readonly LedgerEntry[];
  /** the fold options the record's own projection used, without `asOf` */
  fold: Omit<FoldOptions, "asOf">;
  /** the offering the record speaks for */
  repo: string;
  /** the catalog's indicators, in the rules' order */
  ksiIds: readonly string[];
  /** the record's fold instant; only UTC days that ended at or before it are in the series */
  asOf: string;
  /** how many days back the series reaches; at least 365 */
  reachDays?: number;
}

export interface KsiDaySeries {
  /** the UTC days of the series, oldest first, covered or not */
  days: string[];
  /** the first day with a status, or undefined when the ledger never scanned the offering in reach */
  coveredFrom?: string;
  /** KSI id → metric per covered day, aligned to `days` (undefined = absent) */
  byKsi: Map<string, (KsiDayMetric | undefined)[]>;
}

function utcDay(ms: number): string {
  return new Date(ms).toISOString().slice(0, 10);
}

/** the last millisecond of a UTC day */
export function dayEnd(day: string): string {
  return new Date(Date.parse(`${day}T00:00:00.000Z`) + DAY_MS - 1).toISOString();
}

/**
 * The last `count` completed UTC days before `asOf`, oldest first. A day is
 * complete when its last millisecond is at or before the instant.
 */
export function completedDays(asOf: string, count: number): string[] {
  const t = Date.parse(asOf);
  const lastStart = Math.floor((t + 1) / DAY_MS) * DAY_MS - DAY_MS;
  const days: string[] = [];
  for (let i = count - 1; i >= 0; i--) days.push(utcDay(lastStart - i * DAY_MS));
  return days;
}

/** the UTC day of the offering's first evidence statement, if any */
export function firstScanDay(entries: readonly LedgerEntry[], repo: string): string | undefined {
  let first: string | undefined;
  for (const e of entries) {
    if (!isEvidenceBundle(e.bundle) || e.bundle.predicate.repo !== repo) continue;
    const t = e.bundle.predicate.timestamp;
    if (first === undefined || t < first) first = t;
  }
  return first?.slice(0, 10);
}

/** H2: one fold per covered day, each at that day's last millisecond */
export function daySeries(input: MetricsInput): KsiDaySeries {
  const days = completedDays(input.asOf, Math.max(365, input.reachDays ?? 365));
  const firstDay = firstScanDay(input.entries, input.repo);
  const byKsi = new Map<string, (KsiDayMetric | undefined)[]>(
    input.ksiIds.map((id) => [id, new Array<KsiDayMetric | undefined>(days.length).fill(undefined)]),
  );
  const entries = [...input.entries];
  let coveredFrom: string | undefined;
  days.forEach((day, i) => {
    if (firstDay === undefined || day < firstDay) return;
    coveredFrom ??= day;
    const end = dayEnd(day);
    const projection = foldEntries(entries, end, { ...input.fold, asOf: end });
    const rows = new Map(
      projection.methodRegisters.filter((r) => r.repo === input.repo).map((r) => [r.ksi, r]),
    );
    for (const ksi of input.ksiIds) {
      const { status, basis } = ksiStatus(rows.get(ksi));
      byKsi.get(ksi)![i] = {
        status,
        methodsInScope: basis.methodsInScope,
        methodsPassing: basis.methodsPassing,
        violatedMethods: basis.violatedMethods,
        staleMethods: basis.staleMethods,
        automatedWithEvidence: basis.automatedWithEvidence,
        artifactsPresent: basis.artifactsPresent,
      };
    }
  });
  const series: KsiDaySeries = { days, byKsi };
  if (coveredFrom !== undefined) series.coveredFrom = coveredFrom;
  return series;
}

/** H7: summarize the last `window` days of one KSI's series */
export function summarize(
  days: readonly string[],
  metrics: readonly (KsiDayMetric | undefined)[],
  window: number,
): KsiMetricSummary {
  const from = Math.max(0, days.length - window);
  const inWindow = metrics.slice(from);
  const covered = inWindow.filter((m): m is KsiDayMetric => m !== undefined);
  const summary: KsiMetricSummary = {
    from: days[from]!,
    to: days[days.length - 1]!,
    daysInWindow: inWindow.length,
    daysCovered: covered.length,
    daysAbsent: inWindow.length - covered.length,
    statusDays: { Implemented: 0, "Partially Implemented": 0, "Not Implemented": 0 },
  };
  for (const m of covered) summary.statusDays[m.status]++;
  if (covered.length > 0) {
    const last = covered[covered.length - 1]!;
    summary.firstStatus = covered[0]!.status;
    summary.lastStatus = last.status;
    const counts = {} as Record<MetricCount, { min: number; max: number; last: number }>;
    for (const k of METRIC_COUNTS) {
      const values = covered.map((m) => m[k]);
      counts[k] = { min: Math.min(...values), max: Math.max(...values), last: last[k] };
    }
    summary.counts = counts;
  }
  return summary;
}

export interface KsiMetrics {
  past30Days: KsiMetricSummary;
  pastYear: KsiMetricSummary;
}

/** R3.1: the 30-day and one-year summaries per KSI */
export function metricSummaries(series: KsiDaySeries): Record<string, KsiMetrics> {
  const out: Record<string, KsiMetrics> = {};
  for (const [ksi, metrics] of series.byKsi) {
    out[ksi] = {
      past30Days: summarize(series.days, metrics, 30),
      pastYear: summarize(series.days, metrics, 365),
    };
  }
  return out;
}
