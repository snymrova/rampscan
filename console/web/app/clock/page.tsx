"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { RequireAuth } from "../../components/guard";
import { useCollection } from "../../lib/pb";
import { MVX_WINDOW_DAYS, clockState, formatDuration } from "../../lib/mvx";
import type { MetaRecord, RegisterRecord } from "../../lib/types";

// The clock view (SPEC §8.2): every live bundle's age against the class's
// MVX window (b=7d, c=3d), expiring-soon first. This is the screen that
// exists because the regulation demands the loop — stale is visually loud.

export default function ClockPage() {
  return (
    <RequireAuth>
      <Clock />
    </RequireAuth>
  );
}

function Clock() {
  const { records } = useCollection<RegisterRecord>("registers");
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
    </>
  );
}
