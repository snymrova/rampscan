"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import { RequireAuth } from "../../components/guard";
import { useCollection } from "../../lib/pb";
import { MVX_WINDOW_DAYS, clockState, formatDuration } from "../../lib/mvx";
import type { GapRecord, MetaRecord, RegisterRecord } from "../../lib/types";

// The clock view (SPEC §8.2): every live bundle's age against the class's
// MVX window (b=7d, c=3d), expiring-soon first. This is the screen that
// exists because the regulation demands the loop — stale is visually loud.
//
// Below it, the cadence-gap timeline (plan I3d over I1d): every interval
// where a cell's evidence sat past the window UNREFRESHED, read straight
// from the projected `gaps` collection — bundle chains × the MVX window,
// never a wall clock. The auditor's question it answers: "did evidence
// lapse during the assessment period, and for how long?"

export default function ClockPage() {
  return (
    <RequireAuth>
      <Clock />
    </RequireAuth>
  );
}

function Clock() {
  const { records } = useCollection<RegisterRecord>("registers");
  const gaps = useCollection<GapRecord>("gaps", { sort: "repo,recipe_id,gap_start" });
  const meta = useCollection<MetaRecord>("meta");
  const [now, setNow] = useState(() => Date.now());

  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 30_000);
    return () => clearInterval(timer);
  }, []);

  const certClass = meta.records[0]?.settings?.certClass ?? "b";
  const live = records
    .filter((r) => (r.state === "evidenced" || r.state === "violated") && r.fresh_as_of)
    .map((r) => ({ row: r, clock: clockState(r.fresh_as_of, certClass, now) }))
    .sort((a, b) => a.clock.remainingMs - b.clock.remainingMs);
  const expired = live.filter((e) => e.clock.status === "expired").length;
  const expiring = live.filter((e) => e.clock.status === "expiring").length;

  return (
    <>
      <h1>Clock</h1>
      <p className="subtitle">
        class {certClass} → {MVX_WINDOW_DAYS[certClass]}-day MVX window · {live.length} live
        bundle(s)
        {expired > 0 && <> · <span style={{ color: "var(--violated)" }}>{expired} EXPIRED</span></>}
        {expiring > 0 && <> · <span style={{ color: "var(--unevidenced)" }}>{expiring} expiring</span></>}
      </p>

      <div className="panel">
        <table className="reg">
          <thead>
            <tr>
              <th>Remaining</th>
              <th style={{ width: 180 }}>Window</th>
              <th>Recipe</th>
              <th>Repo</th>
              <th>State</th>
              <th>Fresh as of</th>
            </tr>
          </thead>
          <tbody>
            {live.map(({ row, clock }) => (
              <tr key={row.id}>
                <td className={`remaining ${clock.status}`}>
                  {clock.remainingMs <= 0
                    ? `expired ${formatDuration(clock.remainingMs)} ago`
                    : formatDuration(clock.remainingMs)}
                </td>
                <td>
                  <div className={`clockbar clock-${clock.status}`}>
                    <div style={{ width: `${Math.min(100, clock.fractionUsed * 100)}%` }} />
                  </div>
                </td>
                <td className="mono">
                  <Link href={`/evidence/${row.bundle_digest}`}>{row.recipe_id}</Link>
                </td>
                <td className="muted">{row.repo}</td>
                <td>
                  <span className={`pill ${row.state}`}>{row.state}</span>
                </td>
                <td className="muted">{new Date(row.fresh_as_of).toLocaleString()}</td>
              </tr>
            ))}
            {live.length === 0 && (
              <tr>
                <td colSpan={6} className="empty">
                  no live evidence yet — scan something
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      <GapTimeline
        gaps={gaps.records}
        loading={gaps.loading}
        error={gaps.error}
        projectedAt={meta.records[0]?.projected_at}
      />
    </>
  );
}

/**
 * The cadence-gap timeline (I3d over I1d). Every bar segment is one projected
 * CadenceGap — an interval where the cell's evidence sat past 1.0 of the MVX
 * window unrefreshed, computed by the fold from bundle timestamps and its
 * projectedAt, never typed and never from this browser's clock. An ongoing
 * lapse runs to the projection's edge and is said out loud.
 */
function GapTimeline({
  gaps,
  loading,
  error,
  projectedAt,
}: {
  gaps: GapRecord[];
  loading: boolean;
  error: string | null;
  projectedAt: string | undefined;
}) {
  const cells = useMemo(() => {
    const map = new Map<string, GapRecord[]>();
    for (const gap of gaps) {
      const key = `${gap.repo} ${gap.recipe_id}`;
      (map.get(key) ?? map.set(key, []).get(key)!).push(gap);
    }
    return [...map.entries()].sort(([a], [b]) => a.localeCompare(b));
  }, [gaps]);

  // one shared time domain so the tracks line up: first window close →
  // the projection's edge (projected_at — the fold's clock, not ours)
  const domain = useMemo(() => {
    if (gaps.length === 0) return null;
    const start = Math.min(...gaps.map((g) => Date.parse(g.gap_start)));
    const end = Math.max(
      projectedAt ? Date.parse(projectedAt) : Number.NEGATIVE_INFINITY,
      ...gaps.map((g) => Date.parse(g.gap_end)),
    );
    return { start, span: Math.max(end - start, 1) };
  }, [gaps, projectedAt]);

  const ongoing = gaps.filter((g) => g.ongoing);
  const totalMs = gaps.reduce((sum, g) => sum + g.duration_ms, 0);

  return (
    <>
      <h2 className="section-title">Cadence lapses</h2>
      <p className="subtitle">
        every interval where a cell&rsquo;s evidence sat past its MVX window unrefreshed — derived
        from the bundle chains, so &ldquo;did evidence lapse during the assessment period, and for
        how long?&rdquo; has a computed answer
      </p>
      {error && <p className="error">{error}</p>}
      <div className="panel">
        {gaps.length === 0 ? (
          !loading && (
            <p className="empty">
              no cadence lapse on record — every chain was re-verified inside its window
            </p>
          )
        ) : (
          <>
            <div className="gap-summary">
              <span>
                {gaps.length} lapse{gaps.length === 1 ? "" : "s"} across {cells.length} cell
                {cells.length === 1 ? "" : "s"} · total lapsed {formatDuration(totalMs)}
              </span>
              {ongoing.length > 0 && (
                <span className="gap-ongoing-count">
                  {ongoing.length} ONGOING — evidence is lapsed right now
                </span>
              )}
              {domain && (
                <span className="faint" style={{ marginLeft: "auto" }}>
                  {new Date(domain.start).toLocaleString()} →{" "}
                  {new Date(domain.start + domain.span).toLocaleString()}
                </span>
              )}
            </div>
            <table className="reg">
              <thead>
                <tr>
                  <th>Recipe</th>
                  <th>Repo</th>
                  <th>Lapses</th>
                  <th>Lapsed total</th>
                  <th style={{ width: "38%" }}>Timeline</th>
                </tr>
              </thead>
              <tbody>
                {cells.map(([key, cellGaps]) => {
                  const first = cellGaps[0]!;
                  const cellTotal = cellGaps.reduce((sum, g) => sum + g.duration_ms, 0);
                  const cellOngoing = cellGaps.some((g) => g.ongoing);
                  return (
                    <tr key={key}>
                      <td className="mono">{first.recipe_id}</td>
                      <td className="muted">{first.repo}</td>
                      <td>
                        {cellGaps.length}
                        {cellOngoing && <span className="pill violated" style={{ marginLeft: 8 }}>ongoing</span>}
                      </td>
                      <td className="muted">{formatDuration(cellTotal)}</td>
                      <td>
                        <div className="gaptrack">
                          {domain &&
                            cellGaps.map((gap) => {
                              const left =
                                ((Date.parse(gap.gap_start) - domain.start) / domain.span) * 100;
                              const width =
                                ((Date.parse(gap.gap_end) - Date.parse(gap.gap_start)) /
                                  domain.span) *
                                100;
                              return (
                                <Link
                                  key={gap.id}
                                  href={`/evidence/${gap.bundle_digest}`}
                                  className={`gapseg${gap.ongoing ? " ongoing" : ""}`}
                                  style={{ left: `${left}%`, width: `${Math.max(width, 0.75)}%` }}
                                  title={`${new Date(gap.gap_start).toLocaleString()} → ${
                                    gap.ongoing
                                      ? "ongoing"
                                      : new Date(gap.gap_end).toLocaleString()
                                  } · lapsed ${formatDuration(gap.duration_ms)} — the bundle whose window closed`}
                                />
                              );
                            })}
                        </div>
                        <div className="faint" style={{ fontSize: 12, marginTop: 4 }}>
                          {cellGaps.map((gap, i) => (
                            <span key={gap.id}>
                              {i > 0 && " · "}
                              <Link href={`/evidence/${gap.bundle_digest}`}>
                                {new Date(gap.gap_start).toLocaleDateString()}{" "}
                                {formatDuration(gap.duration_ms)}
                                {gap.ongoing ? " (ongoing)" : ""}
                              </Link>
                            </span>
                          ))}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </>
        )}
      </div>
    </>
  );
}
