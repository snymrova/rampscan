"use client";

import { useState } from "react";
import { RequireAuth } from "../../components/guard";
import { getPb, useAuth, useCollection } from "../../lib/pb";
import type { ProposalRecord } from "../../lib/types";

// The two-key queue (SPEC §8.4): notApplicable proposals showing the DOMAIN
// OBJECT — recipe, repo, justification — never the tool call. The first key
// is the proposal (any console identity); the second is the approver's, and
// turning it appends a SIGNED SCOPING EVENT to the ledger. The register
// flips only when the projector folds that event — approving here writes the
// record, not the board.

export default function ApprovalsPage() {
  return (
    <RequireAuth>
      <Approvals />
    </RequireAuth>
  );
}

function Approvals() {
  const { user } = useAuth();
  const { records, loading, refetch } = useCollection<ProposalRecord>("proposals", {
    sort: "-created",
  });
  const pending = records.filter((p) => p.status === "pending");
  const decided = records.filter((p) => p.status !== "pending");
  const isApprover = user?.role === "approver";

  return (
    <>
      <h1>Approvals</h1>
      <p className="subtitle">
        {isApprover
          ? "your key is the second one — approving signs a scoping event into the ledger"
          : `signed in as ${user?.role || "viewer"} — only an approver can turn the second key`}
      </p>

      <div className="section-title">Pending ({pending.length})</div>
      <div className="panel">
        {pending.map((proposal) => (
          <ProposalView key={proposal.id} proposal={proposal} canDecide={isApprover} onDecided={refetch} />
        ))}
        {!loading && pending.length === 0 && <div className="empty">no pending proposals</div>}
      </div>

      <div className="section-title">Decided ({decided.length})</div>
      <div className="panel">
        {decided.map((proposal) => (
          <div key={proposal.id} style={{ padding: "10px 14px", borderBottom: "1px solid var(--border)" }}>
            <span className={`pill ${proposal.status === "approved" ? "notApplicable" : "dead"}`}>
              {proposal.status}
            </span>{" "}
            <span className="mono">{proposal.recipe_id}</span>{" "}
            <span className="muted">on {proposal.repo}</span>
            <div className="faint" style={{ fontSize: 12.5, marginTop: 4 }}>
              “{proposal.justification}” — proposed {proposal.proposed_by}
              {proposal.decided_by && <>, decided by {proposal.decided_by}</>}
              {proposal.scoping_digest && (
                <>
                  {" "}· ledger <span className="mono">{proposal.scoping_digest.slice(0, 16)}…</span>
                </>
              )}
            </div>
          </div>
        ))}
        {!loading && decided.length === 0 && <div className="empty">nothing decided yet</div>}
      </div>
    </>
  );
}

function ProposalView({
  proposal,
  canDecide,
  onDecided,
}: {
  proposal: ProposalRecord;
  canDecide: boolean;
  onDecided: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function decide(action: "approve" | "reject") {
    setBusy(true);
    setError(null);
    try {
      const response = await fetch("/api/scoping/decide", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: getPb().authStore.token,
        },
        body: JSON.stringify({ proposalId: proposal.id, action }),
      });
      if (!response.ok) {
        const body = (await response.json().catch(() => ({}))) as { error?: string };
        throw new Error(body.error ?? `HTTP ${response.status}`);
      }
      onDecided();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div style={{ padding: "12px 14px", borderBottom: "1px solid var(--border)" }}>
      <div>
        <span className="mono">{proposal.recipe_id}</span>{" "}
        <span className="muted">not applicable to</span> <span className="mono">{proposal.repo}</span>
      </div>
      <div style={{ margin: "6px 0" }}>“{proposal.justification}”</div>
      <div className="faint" style={{ fontSize: 12.5 }}>
        proposed by {proposal.proposed_by} · {new Date(proposal.created).toLocaleString()}
      </div>
      {canDecide && (
        <div style={{ marginTop: 10, display: "flex", gap: 8 }}>
          <button className="btn primary" disabled={busy} onClick={() => decide("approve")}>
            {busy ? "signing…" : "approve & sign"}
          </button>
          <button className="btn danger" disabled={busy} onClick={() => decide("reject")}>
            reject
          </button>
        </div>
      )}
      {error && <p className="error">{error}</p>}
    </div>
  );
}
