import { classifySkip, explainUnevidenced, newestRunOf } from "./emptystate";
import { EXPIRING_AT_FRACTION, clockState, formatDuration } from "./mvx";
import { pointerSummary } from "./pointers";
import { standingDivergences } from "./status";
import type { DaemonEventRecord, DriftRecord, RegisterRecord, ScanRunRecord } from "./types";

// classifySkip moved to ./emptystate in K1 — the board's guided empty states
// and this queue must classify a skip reason the same way or the two surfaces
// would disagree about whether the same collector failure is worth doing
// something about. Re-exported here because it is part of this module's
// contract (and its twin test's).
export { classifySkip } from "./emptystate";
export type { SkipClassification } from "./emptystate";

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
  /**
   * The recipe's authored "what fixing it looks like" sentence (K1), when the
   * catalog carries one. It sits BESIDE `action` rather than replacing it:
   * `action` is what to do about this item now, `plain` is what fixing this
   * kind of finding means at all, and a queue that showed only the second
   * would be a glossary.
   */
  plain?: string;
  bundleDigest?: string;
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
  /**
   * Run records (K1). The skip-reason tier used to be reachable only through
   * the daemon's `scan-recorded` events, so an operator who runs `rampscan
   * scan` by hand — no daemon anywhere — got an empty queue while their
   * toolchain was broken. Every scan has signed a run record since J1, and
   * that record carries the same reason, so the tier now falls back to it.
   * Optional: a caller that passes none behaves exactly as before.
   */
  runs?: ScanRunRecord[];
}

export function deriveActionQueue(input: QueueInput): QueueItem[] {
  const now = input.now ?? Date.now();
  const eventsByTime = [...input.events].sort(
    (a, b) => a.at.localeCompare(b.at) || a.id.localeCompare(b.id),
  );
  const items: QueueItem[] = [];

  // tier 0 — divergence: the most recent full-scan verification outcome per
  // repo stands. A later cache-verified means the cache agrees again; until
  // then the divergence is live and outranks everything. The reading is
  // shared with the status strip (status.ts) so the two can never disagree.
  for (const event of standingDivergences(input.events)) {
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
    // the fix pointer (I2c) rides the register row, lifted from the evidence
    // at fold time — pre-I2c evidence carries none and the detail falls back
    // to the commit alone, honestly unadorned
    const pointer = pointerSummary(row.pointers ?? []);
    const introducedAt = row.introducing_commit || null;
    const commitNote = introducedAt
      ? `first seen at commit ${introducedAt.slice(0, 12)}`
      : event?.killing_commit
        ? `at commit ${event.killing_commit.slice(0, 12)}`
        : `at commit ${row.commit_sha.slice(0, 12)}`;
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
      detail: pointer !== "" ? `${pointer} — ${commitNote}` : commitNote,
      action: "open the evidence — the assertions and artifacts name exactly what failed",
    };
    if (row.bundle_digest) item.bundleDigest = row.bundle_digest;
    // what fixing this KIND of finding looks like, authored in the catalog
    // (K1) — the row above already says which one and where
    if (row.plain) item.plain = row.plain.fix;
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
  const runs = input.runs ?? [];
  for (const row of unevidencedRows) {
    const scanEvent = latestScan.get(row.repo);
    const reasons = (scanEvent?.payload as ScanRecordedPayload | undefined)?.unevidenced;
    const reasonRow = reasons?.find((u) => u.recipeId === row.recipe_id);
    if (scanEvent && reasonRow) {
      const classified = classifySkip(reasonRow.reason);
      if (!classified.actionable) continue;
      const item: QueueItem = {
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
      };
      if (row.plain) item.plain = row.plain.fix;
      items.push(item);
      continue;
    }
    // no daemon event for this cell — read the run record instead (K1). The
    // daemon event wins where both exist so a queue that has always been
    // driven by the daemon does not change shape underneath its operator; the
    // fallback only ever fills silence.
    if (runs.length === 0) continue;
    const why = explainUnevidenced({
      row,
      run: newestRunOf(runs, row.repo),
      runsLoaded: true,
      runCount: runs.length,
    });
    // an honest skip is not a task, exactly as with the daemon path: the
    // board's unevidenced register still shows it, and the queue stays a list
    // of things a person can actually do
    if (!why || !why.actionable) continue;
    // Every queue row states WHEN it became actionable, and the only honest
    // instant available here is the run's own clock. "No scan of this repo has
    // ever been recorded" and "the catalog lost this recipe" have no instant
    // at all — they are conditions, not events — so they stay off the queue
    // and are explained on the board's empty row instead, where nothing has to
    // pretend to have happened at a time.
    const runAt = runs.find((r) => r.run_id === why.runId)?.run_timestamp;
    if (runAt === undefined) continue;
    const item: QueueItem = {
      kind: "actionable-unevidenced",
      rank: 3,
      repo: row.repo,
      recipeIds: [row.recipe_id],
      at: runAt,
      title:
        why.source === "skip-reason"
          ? `collector "${why.collector}" could not run`
          : `collector "${why.collector}" was never dispatched`,
      detail: why.reason,
      action: why.action,
    };
    if (row.plain) item.plain = row.plain.fix;
    items.push(item);
  }

  return items;
}
