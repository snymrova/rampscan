import { EXPIRING_AT_FRACTION, clockState, formatDuration } from "./mvx";
import type { DaemonEventRecord, DriftRecord, RegisterRecord } from "./types";

// The action queue (plan I2a): "what do I act on today", as one ranked list.
// A pure derivation over the projection collections and the daemon's event
// stream — computed at render time (the expiring tier moves with the clock,
// so a stored queue would rot between projections), and it can only ever
// POINT AT register rows, never mute, hide, or reorder their verdicts.
//
// Ranking, by decision of record:
//   0  cache divergence      the evidence pipeline itself is suspect
//   1  expiring evidence     the clock outran the cadence — freshness at risk
//   2  new violation         a real repo fact needs fixing
//   3  actionable unevidenced a collector skipped for a FIXABLE reason
//
// Honest skips ("no IaC in the committed tree") are not actionable and stay
// off the queue — the board's unevidenced register still shows them.

export type QueueKind = "divergence" | "expiring" | "new-violation" | "actionable-unevidenced";

export interface QueueItem {
  kind: QueueKind;
  /** the tier — 0 outranks 3; items arrive sorted (tier, then tier order) */
  rank: 0 | 1 | 2 | 3;
  repo: string;
  recipeIds: string[];
  /** when this became actionable (ISO 8601) — event time, band entry, drift time */
  at: string;
  title: string;
  detail: string;
  /** the concrete next move — a command, a doctor hint, a report path */
  action: string;
  bundleDigest?: string;
}

export interface SkipClassification {
  actionable: boolean;
  category: "tool-missing" | "collector-failed" | "honest-skip";
  hint?: string;
}

/**
 * Classify a collector skip reason. The wording is pinned by test against the
 * real producers (`absentReason` in collectors, the `failed (exit …)` shape),
 * so a reworded reason breaks the test instead of silently falling off the
 * queue. Anything unrecognized counts as an honest skip — the queue never
 * invents work.
 */
export function classifySkip(reason: string): SkipClassification {
  if (/is not installed/.test(reason)) {
    return {
      actionable: true,
      category: "tool-missing",
      hint: "install the tool or Docker — `pnpm doctor` lists what's missing and how to get it",
    };
  }
  if (/failed \(exit /.test(reason)) {
    return {
      actionable: true,
      category: "collector-failed",
      hint: "the collector crashed instead of observing — read the reason, fix the cause, re-scan",
    };
  }
  return { actionable: false, category: "honest-skip" };
}

interface DivergencePayload {
  comparison?: { divergences?: Array<{ recipeId: string; field: string }> };
  reportPath?: string;
}

interface ScanRecordedPayload {
  unevidenced?: Array<{ recipeId: string; collector: string; reason: string }>;
}

export interface QueueInput {
  registers: RegisterRecord[];
  drift: DriftRecord[];
  events: DaemonEventRecord[];
  certClass: "b" | "c";
  now?: number;
}

export function deriveActionQueue(input: QueueInput): QueueItem[] {
  const now = input.now ?? Date.now();
  const eventsByTime = [...input.events].sort(
    (a, b) => a.at.localeCompare(b.at) || a.id.localeCompare(b.id),
  );
  const items: QueueItem[] = [];

  // tier 0 — divergence: the most recent full-scan verification outcome per
  // repo stands. A later cache-verified means the cache agrees again; until
  // then the divergence is live and outranks everything.
  const verifications = new Map<string, DaemonEventRecord>();
  for (const event of eventsByTime) {
    if (event.kind === "divergence" || event.kind === "cache-verified") {
      verifications.set(event.repo, event);
    }
  }
  const standing = [...verifications.values()]
    .filter((event) => event.kind === "divergence")
    .sort((a, b) => b.at.localeCompare(a.at));
  for (const event of standing) {
    const payload = event.payload as DivergencePayload;
    const divergences = payload.comparison?.divergences ?? [];
    items.push({
      kind: "divergence",
      rank: 0,
      repo: event.repo,
      recipeIds: [...new Set(divergences.map((d) => d.recipeId))].sort(),
      at: event.at,
      title: "cache divergence — the full scan disagrees with the incremental result",
      detail: divergences.map((d) => `${d.recipeId} (${d.field})`).join(", "),
      action:
        `the full result is the record; inspect ${payload.reportPath ?? "divergence-report.json"} — ` +
        "a poisoned cache entry, an advisory published since the cached run, or tool drift",
    });
  }

  // tier 1 — expiring before the next cadence refresh: the daemon refreshes
  // at 0.5 of the window, so any live evidence past the 0.75 band means the
  // cadence already missed it. Most urgent (least remaining) first.
  const expiring = input.registers
    .filter((row) => (row.state === "evidenced" || row.state === "violated") && row.fresh_as_of)
    .map((row) => ({ row, clock: clockState(row.fresh_as_of, input.certClass, now) }))
    .filter(({ clock }) => clock.status !== "fresh")
    .sort((a, b) => a.clock.remainingMs - b.clock.remainingMs);
  for (const { row, clock } of expiring) {
    const item: QueueItem = {
      kind: "expiring",
      rank: 1,
      repo: row.repo,
      recipeIds: [row.recipe_id],
      at: new Date(
        Date.parse(row.fresh_as_of) + clock.windowMs * EXPIRING_AT_FRACTION,
      ).toISOString(),
      title:
        clock.status === "expired"
          ? `evidence expired ${formatDuration(clock.remainingMs)} ago`
          : `evidence expires in ${formatDuration(clock.remainingMs)}`,
      detail:
        `last verified ${formatDuration(clock.ageMs)} ago — ` +
        "the cadence should have refreshed it at half the window",
      action: `check the daemon is running, or refresh now: pnpm rampscan scan ${row.repo}`,
    };
    if (row.bundle_digest) item.bundleDigest = row.bundle_digest;
    items.push(item);
  }

  // tier 2 — new violations: every currently-violated register row, stamped
  // with the drift event that made it violated (born or verdict-flipped).
  // Newest movement first — "new" is an ordering, not a filter: a violation
  // needs action until it is fixed.
  const violatingDrift = new Map<string, DriftRecord>();
  const sortedDrift = [...input.drift].sort(
    (a, b) => a.at.localeCompare(b.at) || a.bundle_digest.localeCompare(b.bundle_digest),
  );
  for (const event of sortedDrift) {
    if (
      (event.kind === "born" || event.kind === "verdict-flipped") &&
      event.to_verdict === "violated"
    ) {
      violatingDrift.set(`${event.repo} ${event.recipe_id}`, event);
    }
  }
  const violations = input.registers
    .filter((row) => row.state === "violated")
    .map((row) => ({ row, event: violatingDrift.get(`${row.repo} ${row.recipe_id}`) }))
    .sort(
      (a, b) =>
        (b.event?.at ?? b.row.fresh_as_of).localeCompare(a.event?.at ?? a.row.fresh_as_of) ||
        a.row.recipe_id.localeCompare(b.row.recipe_id),
    );
  for (const { row, event } of violations) {
    const item: QueueItem = {
      kind: "new-violation",
      rank: 2,
      repo: row.repo,
      recipeIds: [row.recipe_id],
      at: event?.at ?? row.fresh_as_of,
      title:
        event?.kind === "verdict-flipped"
          ? `flipped to violated (was ${event.from_verdict})`
          : "violated since first evidence",
      detail: event?.killing_commit
        ? `at commit ${event.killing_commit.slice(0, 12)}`
        : `at commit ${row.commit_sha.slice(0, 12)}`,
      action: "open the evidence — the assertions and artifacts name exactly what failed",
    };
    if (row.bundle_digest) item.bundleDigest = row.bundle_digest;
    items.push(item);
  }

  // tier 3 — actionable unevidenced: the register says unevidenced, and the
  // latest scan's event carries the honest reason. Only FIXABLE reasons make
  // the queue; honest skips stay on the board's unevidenced register.
  const latestScan = new Map<string, DaemonEventRecord>();
  for (const event of eventsByTime) {
    if (event.kind === "scan-recorded") latestScan.set(event.repo, event);
  }
  const unevidencedRows = input.registers
    .filter((row) => row.state === "unevidenced")
    .sort((a, b) => a.recipe_id.localeCompare(b.recipe_id) || a.repo.localeCompare(b.repo));
  for (const row of unevidencedRows) {
    const scanEvent = latestScan.get(row.repo);
    const reasons = (scanEvent?.payload as ScanRecordedPayload | undefined)?.unevidenced;
    const reasonRow = reasons?.find((u) => u.recipeId === row.recipe_id);
    if (!scanEvent || !reasonRow) continue;
    const classified = classifySkip(reasonRow.reason);
    if (!classified.actionable) continue;
    items.push({
      kind: "actionable-unevidenced",
      rank: 3,
      repo: row.repo,
      recipeIds: [row.recipe_id],
      at: scanEvent.at,
      title:
        classified.category === "tool-missing"
          ? `collector "${reasonRow.collector}" has no tool to run`
          : `collector "${reasonRow.collector}" failed`,
      detail: reasonRow.reason,
      action: classified.hint ?? "",
    });
  }

  return items;
}
