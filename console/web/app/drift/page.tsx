"use client";

import Link from "next/link";
import { RequireAuth } from "../../components/guard";
import { useCollection } from "../../lib/pb";
import type { DriftRecord } from "../../lib/types";

// The drift view (SPEC §8.3): what died since the last window and why —
// anchor changed, assertion flipped, scoped away. Movement is the finding.

export default function DriftPage() {
  return (
    <RequireAuth>
      <Drift />
    </RequireAuth>
  );
}

function describe(event: DriftRecord): string {
  switch (event.kind) {
    case "born":
      return `first evidence recorded → ${event.to_verdict}`;
    case "died":
      return event.cause === "anchor-drift"
        ? `anchor content changed — evidence died with its code`
        : `superseded by a re-keyed bundle`;
    case "verdict-flipped":
      return `${event.from_verdict} → ${event.to_verdict} (${event.cause})`;
    case "scoped":
      return "scoped notApplicable by two-key approval";
  }
}

function Drift() {
  const { records, loading } = useCollection<DriftRecord>("drift", { sort: "-at" });

  const byDay = new Map<string, DriftRecord[]>();
  for (const event of records) {
    const day = event.at.slice(0, 10);
    (byDay.get(day) ?? byDay.set(day, []).get(day)!).push(event);
  }

  return (
    <>
      <h1>Drift</h1>
      <p className="subtitle">
        every movement the ledger records: evidence born, dead, flipped, or scoped — with its
        cause. Nothing here is typed; it is all computed from bundle chains.
      </p>

      {[...byDay.entries()].map(([day, events]) => (
        <div key={day}>
          <div className="drift-day">{day}</div>
          <div className="panel">
            {events.map((event) => (
              <div className="drift-event" key={event.id}>
                <span className={`drift-kind ${event.kind}`}>{event.kind.replace("-", " ")}</span>
                <span className="mono">
                  <Link href={`/evidence/${event.bundle_digest}`}>{event.recipe_id}</Link>
                </span>
                <span className="muted">{describe(event)}</span>
                {event.killing_commit && (
                  <span className="faint mono">by {event.killing_commit.slice(0, 12)}</span>
                )}
                <span className="nav-spacer" />
                <span className="faint">{new Date(event.at).toLocaleTimeString()}</span>
              </div>
            ))}
          </div>
        </div>
      ))}
      {!loading && records.length === 0 && <div className="empty panel">no movement yet</div>}
    </>
  );
}
