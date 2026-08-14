"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { formatAge, formatDuration } from "../lib/mvx";
import { useCollection } from "../lib/pb";
import { deriveDaemonStrip, describeNext } from "../lib/status";
import type { DaemonStripRow } from "../lib/status";
import type { DaemonEventRecord, DaemonStatusRecord } from "../lib/types";

// The daemon status strip (plan I2b), on the board header: last scan, alive
// or stale — said loudly — the next expected cadence action, and whether a
// divergence report is standing. Derived at render time from the daemon's
// own telemetry (the heartbeat snapshot + the event mirror); an operator who
// cannot see the daemon died owns a silently rotting board.

export function DaemonStrip() {
  const status = useCollection<DaemonStatusRecord>("daemon_status");
  const events = useCollection<DaemonEventRecord>("daemon_events");
  const [now, setNow] = useState(() => Date.now());

  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 30_000);
    return () => clearInterval(timer);
  }, []);

  if (status.loading || events.loading) return null;
  const rows = deriveDaemonStrip({ status: status.records, events: events.records, now });

  if (rows.length === 0) {
    return (
      <div className="strip nodaemon">
        <span className="strip-dot" />
        no daemon telemetry — <code>pnpm rampscan daemon &lt;path&gt;</code> keeps this board
        fresh on cadence; without it, evidence only moves when someone scans by hand
      </div>
    );
  }

  return (
    <>
      {rows.map((row) => (
        <StripRow key={row.repo} row={row} now={now} />
      ))}
    </>
  );
}

function StripRow({ row, now }: { row: DaemonStripRow; now: number }) {
  const lastScan = row.lastScan && (
    <span>
      last scan{row.lastScan.mode ? ` (${row.lastScan.mode})` : ""}{" "}
      {row.lastScan.commit && <code>{row.lastScan.commit.slice(0, 12)}</code>}{" "}
      {formatAge(row.lastScan.at, now)} ago
    </span>
  );
  const divergence = row.divergence && (
    <span className="strip-divergence">
      divergence report standing since {formatAge(row.divergence.at, now)} ago —{" "}
      <Link href="/queue">action queue</Link>
    </span>
  );

  if (row.liveness === "stale") {
    return (
      <div className="strip stale">
        <span className="strip-dot" />
        <b>DAEMON STALE</b> — no heartbeat for{" "}
        {row.heartbeatAgeMs !== undefined ? formatDuration(row.heartbeatAgeMs) : "?"}
        {row.checkIntervalMs !== undefined && (
          <> (check interval {formatDuration(row.checkIntervalMs)})</>
        )}
        : this board stops being re-verified while the daemon is down
        <span className="strip-sep">·</span>
        {lastScan ?? <span>no scan on record</span>}
        {divergence && <span className="strip-sep">·</span>}
        {divergence}
        <span className="strip-repo mono faint">{row.repo}</span>
      </div>
    );
  }

  if (row.liveness === "no-daemon") {
    return (
      <div className="strip nodaemon">
        <span className="strip-dot" />
        no daemon heartbeat — evidence moves only when someone scans by hand
        <span className="strip-sep">·</span>
        {lastScan ?? <span>no scan on record</span>}
        {divergence && <span className="strip-sep">·</span>}
        {divergence}
        <span className="strip-repo mono faint">{row.repo}</span>
      </div>
    );
  }

  return (
    <div className={`strip alive${row.divergence ? " diverged" : ""}`}>
      <span className="strip-dot" />
      daemon alive
      {row.heartbeatAgeMs !== undefined && (
        <span className="muted"> · tick {formatDuration(row.heartbeatAgeMs)} ago</span>
      )}
      <span className="strip-sep">·</span>
      {lastScan ?? <span>no scan on record</span>}
      {row.next && (
        <>
          <span className="strip-sep">·</span>
          <span>{describeNext(row.next, now)}</span>
        </>
      )}
      {divergence && <span className="strip-sep">·</span>}
      {divergence}
      <span className="strip-repo mono faint">{row.repo}</span>
    </div>
  );
}
