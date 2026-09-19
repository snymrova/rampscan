import type { LedgerEntry } from "@rampscan/core";
import { foldEntries, monthsBefore, type FoldOptions } from "@rampscan/projector";
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

// ---------------------------------------------------------------------------
// R3.2 — the daily data (class c and d) and FRC-CSX-MOT's reach-back
// ---------------------------------------------------------------------------

/** one run of consecutive covered days whose metrics are identical (H5) */
export interface KsiMetricRun extends KsiDayMetric {
  from: string;
  to: string;
  days: number;
}

/** SDR-CSX-KMT wants every day's data at class c; class d must supersede c, so it gets it too */
export function dailyOwed(offeringClass: string): boolean {
  return offeringClass === "c" || offeringClass === "d";
}

/**
 * How many days the series reaches back (H4): a year, or FRC-CSX-MOT's
 * history floor where that is longer (18 months at class d). The floor is
 * counted back from the last completed day with the fold's own month
 * arithmetic, so the series and the history meter agree on where it opens.
 */
export function reachDays(asOf: string, historyFloorMonths: number | null): number {
  const days = completedDays(asOf, 1);
  if (historyFloorMonths === null) return 365;
  const last = Date.parse(`${days[0]!}T00:00:00.000Z`);
  const opens = Date.parse(monthsBefore(dayEnd(days[0]!), historyFloorMonths).slice(0, 10));
  return Math.max(365, Math.round((last - opens) / DAY_MS) + 1);
}

function sameMetric(a: KsiDayMetric, b: KsiDayMetric): boolean {
  return a.status === b.status && METRIC_COUNTS.every((k) => a[k] === b[k]);
}

/**
 * H5: the daily data, losslessly, as runs. An absent day ends a run and
 * starts none, so a gap in coverage stays visible as a gap between runs.
 */
export function dailyRuns(
  days: readonly string[],
  metrics: readonly (KsiDayMetric | undefined)[],
): KsiMetricRun[] {
  const runs: KsiMetricRun[] = [];
  let open: KsiMetricRun | undefined;
  metrics.forEach((m, i) => {
    if (m === undefined) {
      open = undefined;
      return;
    }
    if (open !== undefined && sameMetric(open, m)) {
      open.to = days[i]!;
      open.days++;
      return;
    }
    open = { from: days[i]!, to: days[i]!, days: 1, ...m };
    runs.push(open);
  });
  return runs;
}

/** the inverse of `dailyRuns`: one entry per covered day, oldest first */
export function expandRuns(runs: readonly KsiMetricRun[]): { day: string; metric: KsiDayMetric }[] {
  const out: { day: string; metric: KsiDayMetric }[] = [];
  for (const { from, to: _to, days, ...metric } of runs) {
    const start = Date.parse(`${from}T00:00:00.000Z`);
    for (let i = 0; i < days; i++) out.push({ day: utcDay(start + i * DAY_MS), metric });
  }
  return out;
}

// ---------------------------------------------------------------------------
// R3.3 — the block the record carries under x-rampscan.metrics (H6)
// ---------------------------------------------------------------------------

export interface KsiMetricsCarried extends KsiMetrics {
  /** every covered day in reach, as runs; present at class c and d only */
  daily?: KsiMetricRun[];
}

export interface SdrMetrics {
  basis: string;
  divergence: string;
  dayBoundary: string;
  /** the first and last day the series reaches, covered or not */
  from: string;
  to: string;
  reachDays: number;
  /** the first day with a status; absent when the ledger never scanned the offering in reach */
  coveredFrom?: string;
  dailyIncluded: boolean;
  ksis: Record<string, KsiMetricsCarried>;
}

export const METRICS_BASIS =
  "No FedRAMP rule defines a metric (FedRAMP/schemas#10, question 3). FRC-CSX-MOT names one, status from persistent validation, so a KSI's metric for a day is the ksiImplementationStatus rampscan would have computed at that day's end, plus the counts it was computed from (the statusBasis fields of the same names). Each day is refolded from the ledger, never accumulated, so the same ledger at the same instant yields the same bytes. A day before the offering's first scan is absent: it is counted in daysAbsent and given no status, never a zero.";

export const METRICS_DIVERGENCE =
  "SDR-CSX-KMT asks for these in the Security Decision Record, and the pinned schema has no field for them (FedRAMP/schemas#10). They are carried here, outside the schema, until FedRAMP names a place.";

/** the block, from a series, at a class (H4–H6) */
export function metricsBlock(series: KsiDaySeries, offeringClass: string): SdrMetrics {
  const daily = dailyOwed(offeringClass);
  const summaries = metricSummaries(series);
  const ksis: Record<string, KsiMetricsCarried> = {};
  for (const [ksi, metrics] of series.byKsi) {
    ksis[ksi] = {
      ...summaries[ksi]!,
      ...(daily ? { daily: dailyRuns(series.days, metrics) } : {}),
    };
  }
  const block: SdrMetrics = {
    basis: METRICS_BASIS,
    divergence: METRICS_DIVERGENCE,
    dayBoundary: "UTC days; a day's metric is folded at its last millisecond, and only days that ended at or before the record's instant are included",
    from: series.days[0]!,
    to: series.days[series.days.length - 1]!,
    reachDays: series.days.length,
    dailyIncluded: daily,
    ksis,
  };
  if (series.coveredFrom !== undefined) block.coveredFrom = series.coveredFrom;
  return block;
}
