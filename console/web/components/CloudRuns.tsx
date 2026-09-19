"use client";

import { EntityLink } from "./EntityLink";
import { useEffect, useState } from "react";
import { cloudRunPill, describeCloudRun, sortCloudRuns } from "../lib/cloud-runs";
import type { CloudRunRow } from "../lib/cloud-runs";
import { getPb } from "../lib/pb";

// The Runs page's cloud section (T4-3): every request the appliance signed,
// its latest state folded from the ledger on each read. Polled, because
// these statements are not projected into PocketBase — the ledger is the
// only source, and the fold is cheap.

export function CloudRuns() {
  const [rows, setRows] = useState<CloudRunRow[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    const read = () =>
      fetch("/api/runs", { headers: { Authorization: getPb().authStore.token } })
        .then(async (r) => {
          const body = (await r.json()) as { runs?: CloudRunRow[]; error?: string };
          if (cancelled) return;
          if (!r.ok) setError(body.error ?? `HTTP ${r.status}`);
          else setRows(sortCloudRuns(body.runs ?? []));
        })
        .catch((e: unknown) => !cancelled && setError(String(e)));
    void read();
    const timer = setInterval(read, 5_000);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, []);

  return (
    <section data-testid="cloud-runs">
      <h2>Runner requests</h2>
      <p className="subtitle">
        requests a runner in the client's account was asked to collect — every state from the signed ledger statements, a failed run a row with its class,
        never an absence. The appliance judges the bytes; the runner reports none of the verdicts here.
      </p>
      {error && <p className="error">{error}</p>}
      <div className="panel">
        <table className="reg">
          <thead>
            <tr>
              <th>State</th>
              <th>Recipe</th>
              <th>KSI</th>
              <th>Requested</th>
              <th>What happened</th>
            </tr>
          </thead>
          <tbody>
            {(rows ?? []).map((row) => (
              <tr key={row.nonce} data-testid={`cloud-run-${row.nonce.slice(0, 8)}`} data-state={row.state}>
                <td>
                  <span className={`pill ${cloudRunPill(row.state)}`}>{row.state}</span>
                </td>
                <td className="mono">
                  {/* a cloud recipe has no pipeline cell to open; once accepted,
                      its evidence is the level below */}
                  {row.evidence_digest ? (
                    <EntityLink kind="evidence" digest={row.evidence_digest}>
                      {row.recipe_id}
                    </EntityLink>
                  ) : (
                    <span data-entity="check">{row.recipe_id}</span>
                  )}
                </td>
                <td>
                  <EntityLink kind="ksi" id={row.ksi} />
                </td>
                <td className="muted" title={row.requester}>
                  {new Date(row.issued_at).toLocaleString()}
                </td>
                <td className="muted" style={{ fontSize: 12.5 }}>
                  {row.evidence_digest ? (
                    <EntityLink kind="evidence" digest={row.evidence_digest} className="">
                      {describeCloudRun(row)}
                    </EntityLink>
                  ) : (
                    describeCloudRun(row)
                  )}
                </td>
              </tr>
            ))}
            {rows !== null && rows.length === 0 && (
              <tr>
                <td colSpan={5} className="empty">
                  no cloud run has been requested — a KSI row's "Collect evidence" starts one
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}
