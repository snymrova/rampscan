"use client";

import { EntityLink, RepoName } from "../../components/EntityLink";
import { RequireAuth } from "../../components/guard";
import { useCollection } from "../../lib/pb";
import { useRepoScope } from "../../lib/scope";
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
  const drift = useCollection<DriftRecord>("drift", { sort: "-at" });
  const vulns = useCollection<VulnerabilityRecord>("vulnerabilities", {
    sort: "-detected_at",
  });
  // the console's repo scope (U-R5); a row names its repo only under "all"
  const { repo: scope } = useRepoScope();
  const inScope = (r: { repo: string }) => scope === null || r.repo === scope;
  const records = drift.records.filter(inScope);
  const vulnerabilities = vulns.records.filter(inScope);
  const loading = drift.loading;

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
                <EntityLink kind="check" recipe={v.recipe_id} repo={v.repo} />
                <span className="muted">
                  {v.ksi_ids.map((k) => (
                    <EntityLink key={k} kind="ksi" id={k} repo={v.repo} style={{ marginRight: 6 }} />
                  ))}
                  — detected{" "}
                  <EntityLink kind="evidence" digest={v.bundle_digest} className="quiet">
                    {new Date(v.detected_at).toLocaleString()}
                  </EntityLink>
                </span>
                <span className="faint">
                  at <EntityLink kind="commit" sha={v.commit_sha} />
                </span>
                {scope === null && <RepoName repo={v.repo} className="faint" />}
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
                <EntityLink kind="check" recipe={event.recipe_id} repo={event.repo} />
                <span className="muted">{describe(event)}</span>
                {event.killing_commit && (
                  <span className="faint">
                    by <EntityLink kind="commit" sha={event.killing_commit} />
                  </span>
                )}
                {scope === null && <RepoName repo={event.repo} className="faint" />}
                <span className="nav-spacer" />
                {/* the bundle this movement is about, one level down */}
                <EntityLink kind="evidence" digest={event.bundle_digest} className="quiet faint">
                  {new Date(event.at).toLocaleTimeString()}
                </EntityLink>
              </div>
            ))}
          </div>
        </div>
      ))}
      {!loading && records.length === 0 && <div className="empty panel">no movement yet</div>}
    </>
  );
}
