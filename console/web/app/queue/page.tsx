"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import { RequireAuth } from "../../components/guard";
import { useCollection } from "../../lib/pb";
import { formatAge } from "../../lib/mvx";
import { deriveActionQueue } from "../../lib/queue";
import type { QueueItem, QueueKind } from "../../lib/queue";
import type {
  DaemonEventRecord,
  DriftRecord,
  MetaRecord,
  RegisterRecord,
  ScanRunRecord,
} from "../../lib/types";

// The action queue (plan I2a): "what do I act on today", one ranked list —
// divergence > expiring-before-next-cadence > new violation > actionable
// unevidenced. A pure derivation over the projection and the daemon's event
// stream, recomputed as the clock moves; nothing an operator sees here can
// mute, hide, or reorder a register row's verdict.

const KIND_LABEL: Record<QueueKind, string> = {
  divergence: "divergence",
  expiring: "expiring",
  "new-violation": "violation",
  "actionable-unevidenced": "unevidenced",
};

export default function QueuePage() {
  return (
    <RequireAuth>
      <Queue />
    </RequireAuth>
  );
}

function Queue() {
  const registers = useCollection<RegisterRecord>("registers");
  const drift = useCollection<DriftRecord>("drift");
  const events = useCollection<DaemonEventRecord>("daemon_events");
  // run records (K1): the skip-reason tier used to need a daemon to have run.
  // Every scan signs one of these, so a hand-run scan's broken toolchain now
  // reaches this list too.
  const runs = useCollection<ScanRunRecord>("scan_runs");
  const meta = useCollection<MetaRecord>("meta");
  const [now, setNow] = useState(() => Date.now());

  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 30_000);
    return () => clearInterval(timer);
  }, []);

  const certClass = meta.records[0]?.settings?.certClass ?? "b";
  const items = useMemo(
    () =>
      deriveActionQueue({
        registers: registers.records,
        drift: drift.records,
        events: events.records,
        runs: runs.records,
        certClass,
        now,
      }),
    [registers.records, drift.records, events.records, runs.records, certClass, now],
  );
  const loading = registers.loading || drift.loading || events.loading || runs.loading;
  const count = (kind: QueueKind) => items.filter((i) => i.kind === kind).length;

  return (
    <>
      <h1>Action queue</h1>
      <p className="subtitle">
        ranked: divergence &gt; expiring &gt; new violation &gt; actionable unevidenced ·{" "}
        {count("divergence")} / {count("expiring")} / {count("new-violation")} /{" "}
        {count("actionable-unevidenced")} · computed from the projection and the daemon&apos;s
        event stream — this list points at registers, it never moves them
        {events.records.length === 0 && !events.loading && (
          <>
            {" "}
            · no daemon events yet — divergence needs <code>rampscan daemon</code>
            {runs.records.length > 0
              ? "; skip reasons are read from the run records below"
              : " and skip reasons need a recorded scan run"}
          </>
        )}
      </p>

      {(registers.error ?? drift.error ?? events.error) && (
        <p className="error">{registers.error ?? drift.error ?? events.error}</p>
      )}
      <div className="panel">
        <table className="reg">
          <thead>
            <tr>
              <th>Priority</th>
              <th>What</th>
              <th>Repo</th>
              <th>Since</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {items.map((item, i) => (
              <QueueRow key={`${item.kind} ${item.repo} ${item.recipeIds.join(",")} ${i}`} item={item} now={now} />
            ))}
            {!loading && items.length === 0 && (
              <tr>
                <td colSpan={5} className="empty">
                  nothing to act on — the board is fresh, verified, and quiet
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </>
  );
}

function QueueRow({ item, now }: { item: QueueItem; now: number }) {
  const recipes = item.recipeIds.join(" ");
  return (
    <tr>
      <td>
        <span className={`pill qkind-${item.kind}`}>{KIND_LABEL[item.kind]}</span>
      </td>
      <td>
        <div>{item.title}</div>
        <div className="mono faint">
          {item.bundleDigest ? (
            <Link href={`/evidence/${item.bundleDigest}`}>{recipes}</Link>
          ) : (
            recipes
          )}
        </div>
      </td>
      <td className="muted">{item.repo}</td>
      <td className="muted" title={new Date(item.at).toLocaleString()}>
        {formatAge(item.at, now)} ago
      </td>
      <td>
        {item.detail && <div className="muted" style={{ fontSize: 12.5 }}>{item.detail}</div>}
        <div style={{ fontSize: 12.5 }}>{item.action}</div>
        {/* the recipe's own "what fixing it looks like" (K1) — authored prose
            about the check, kept visually separate from the computed detail
            above it so the two are never read as one voice */}
        {item.plain && (
          <div className="faint" style={{ fontSize: 12.5, marginTop: 4, maxWidth: "68ch" }}>
            {item.plain}
          </div>
        )}
      </td>
    </tr>
  );
}
