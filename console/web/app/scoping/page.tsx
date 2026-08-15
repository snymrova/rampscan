"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { RequireAuth } from "../../components/guard";
import { csvFilename, downloadText, scopingCsv } from "../../lib/export";
import { getPb, useCollection } from "../../lib/pb";
import type {
  MetaRecord,
  ProposalRecord,
  ScopingRegisterResponse,
  ScopingRegisterRow,
  ScopingSignatureStatus,
} from "../../lib/types";

// The scoping register (plan I3c): every scoping decision — approved AND
// rejected — with its full justification, both identities, timestamp, and a
// signature verification status the server just checked (never quoted).
// Approved rows are read from the LEDGER's signed scoping events; rejected
// and pending rows come from the console's proposals collection, which is the
// only place a rejection exists — a rejected scope-out never touches the
// ledger, and this page says so instead of dressing it up. N/A is where
// auditors sample hardest; the honest record of a rejected scope-out is a
// strength. Nothing on this page is writable.

const DECISIONS = [
  { key: "all", label: "All" },
  { key: "approved", label: "Scoped out" },
  { key: "rejected", label: "Rejected" },
  { key: "pending", label: "Pending" },
] as const;
type DecisionFilter = (typeof DECISIONS)[number]["key"];

// what the server's check concluded, styled by how loudly it should read
const SIGNATURE: Record<ScopingSignatureStatus, { label: string; pill: string }> = {
  verified: { label: "signature verified", pill: "evidenced" },
  failed: { label: "signature FAILED", pill: "violated" },
  unsigned: { label: "appended unsigned", pill: "dead" },
  missing: { label: "no ledger record", pill: "violated" },
};

export default function ScopingPage() {
  return (
    <RequireAuth>
      <Scoping />
    </RequireAuth>
  );
}

function Scoping() {
  const [register, setRegister] = useState<ScopingRegisterResponse | null>(null);
  const [filter, setFilter] = useState<DecisionFilter>("all");
  // change signals only: a new proposal/decision or a re-fold means the
  // register the server would compute has moved — refetch, never patch
  const proposals = useCollection<ProposalRecord>("proposals");
  const meta = useCollection<MetaRecord>("meta");
  const projectedAt = meta.records[0]?.projected_at;

  useEffect(() => {
    let cancelled = false;
    fetch("/api/scoping/register", {
      headers: { Authorization: getPb().authStore.token },
    })
      .then((response) => response.json() as Promise<ScopingRegisterResponse>)
      .then((body) => {
        if (!cancelled) setRegister(body);
      })
      .catch((e: unknown) => {
        if (!cancelled) setRegister({ error: e instanceof Error ? e.message : String(e) });
      });
    return () => {
      cancelled = true;
    };
  }, [proposals.records, projectedAt]);

  const rows = register?.rows ?? [];
  const counts = register?.counts;
  const filtered = filter === "all" ? rows : rows.filter((r) => r.decision === filter);

  return (
    <>
      <h1>Scoping register</h1>
      <p className="subtitle">
        every scoping decision on the record — approved scope-outs are the ledger&apos;s signed
        events, re-verified against the serving key on every load; rejections live only in the
        console&apos;s proposal collection and are listed all the same, because the honest record
        of a declined scope-out is a strength, not an apology
      </p>

      <div className="filters">
        <div className="tabs">
          {DECISIONS.map((d) => (
            <button
              key={d.key}
              className={filter === d.key ? "active" : ""}
              onClick={() => setFilter(d.key)}
            >
              {d.label}
              <span className="count">
                {d.key === "all" ? rows.length : (counts?.[d.key] ?? 0)}
              </span>
            </button>
          ))}
        </div>
        <button
          className="btn"
          title="the decisions on screen, this filter included"
          disabled={filtered.length === 0}
          onClick={() =>
            downloadText(
              csvFilename("scoping", projectedAt ?? ""),
              scopingCsv(filtered, projectedAt ?? ""),
            )
          }
        >
          export CSV
        </button>
      </div>

      {register?.error && <p className="error">{register.error}</p>}
      <div className="panel">
        {filtered.map((row, i) => (
          <DecisionView key={row.digest ?? `${row.decision}-${row.recipeId}-${row.timestamp}-${i}`} row={row} />
        ))}
        {register && !register.error && filtered.length === 0 && (
          <div className="empty">
            {rows.length === 0
              ? "no scoping decisions on the record — every catalog recipe is in scope"
              : "no decisions match this filter"}
          </div>
        )}
        {!register && <div className="empty">loading…</div>}
      </div>
    </>
  );
}

function DecisionView({ row }: { row: ScopingRegisterRow }) {
  const signature = row.signature ? SIGNATURE[row.signature] : undefined;
  return (
    <div style={{ padding: "12px 14px", borderBottom: "1px solid var(--border)" }}>
      <div>
        <span
          className={`pill ${
            row.decision === "approved"
              ? "notApplicable"
              : row.decision === "rejected"
                ? "dead"
                : "unevidenced"
          }`}
        >
          {row.decision === "approved" ? "scoped out" : row.decision}
        </span>{" "}
        <span className="mono">{row.recipeId}</span>{" "}
        <span className="muted">on {row.repo}</span>{" "}
        {signature && <span className={`pill ${signature.pill}`}>{signature.label}</span>}{" "}
        {row.digest && (
          <Link className="mono faint" href={`/evidence/${row.digest}`}>
            {row.digest.slice(0, 16)}…
          </Link>
        )}
      </div>
      <div style={{ margin: "6px 0" }}>“{row.justification}”</div>
      <div className="faint" style={{ fontSize: 12.5 }}>
        proposed by {row.proposedBy}
        {row.decidedBy && (
          <>
            {" "}
            · {row.decision === "rejected" ? "rejected" : "approved"} by {row.decidedBy}
          </>
        )}{" "}
        · {new Date(row.timestamp).toLocaleString()}
      </div>
      {(row.ksiIds.length > 0 || row.controlIds.length > 0) && (
        <div className="faint" style={{ fontSize: 12.5, marginTop: 4 }}>
          {row.decision === "approved"
            ? "removed from scope:"
            : row.decision === "rejected"
              ? "kept in scope:"
              : "would remove from scope:"}{" "}
          {row.ksiIds.map((k) => (
            <Link
              key={k}
              className="mono"
              href={`/controls?reg=ksis&id=${encodeURIComponent(k)}`}
              style={{ marginRight: 8 }}
            >
              {k}
            </Link>
          ))}
          {row.controlIds.map((c) => (
            <Link
              key={c}
              className="mono"
              href={`/controls?reg=controls&id=${encodeURIComponent(c)}`}
              style={{ marginRight: 8 }}
            >
              {c}
            </Link>
          ))}
        </div>
      )}
      {row.problems.map((problem) => (
        <p key={problem} className="error" style={{ margin: "4px 0 0", fontSize: 12.5 }}>
          {problem}
        </p>
      ))}
    </div>
  );
}
