"use client";

import Link from "next/link";
import { RequireAuth } from "../../components/guard";
import { useCollection } from "../../lib/pb";
import type { DriftRecord, VulnerabilityRecord } from "../../lib/types";

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
  const { records: vulnerabilities } = useCollection<VulnerabilityRecord>("vulnerabilities", {
    sort: "-detected_at",
  });

  const byDay = new Map<string, DriftRecord[]>();
  for (const event of records) {
    const day = event.at.slice(0, 10);
    (byDay.get(day) ?? byDay.set(day, []).get(day)!).push(event);
  }
  const open = vulnerabilities.filter((v) => v.vuln_status === "open");
  const resolved = vulnerabilities.length - open.length;

  return (
    <>
      <h1>Drift</h1>
      <p className="subtitle">
        every movement the ledger records: evidence born, dead, flipped, or scoped — with its
        cause. Nothing here is typed; it is all computed from bundle chains.
      </p>

      {/* the failure→vulnerability feed (Q3.5, G13 — VDR-CSO-FAV): a failed
          validation is a vulnerability with detection-and-response
          obligations, so the open episodes lead the drift page rather than
          hiding among its footnotes */}
      {vulnerabilities.length > 0 && (
        <>
          <div className="drift-day">
            failure → vulnerability (VDR-CSO-FAV): {open.length} open · {resolved} resolved
          </div>
          <div className="panel">
            {open.map((v) => (
              <div className="drift-event" key={v.id}>
                <span className="drift-kind verdict-flipped">open</span>
                <span className="mono">
                  <Link href={`/evidence/${v.bundle_digest}`}>{v.recipe_id}</Link>
                </span>
                <span className="muted">
                  {v.ksi_ids.join(" ")} — detected {new Date(v.detected_at).toLocaleString()}
                </span>
                <span className="faint mono">at {v.commit_sha.slice(0, 12)}</span>
                <span className="nav-spacer" />
              </div>
            ))}
            {open.length === 0 && (
              <div className="drift-event">
                <span className="muted">
                  no open records — every violated episode has a later evidenced bundle
                </span>
              </div>
            )}
          </div>
        </>
      )}

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
