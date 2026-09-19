"use client";

import { useState } from "react";
import { EntityLink, RepoName } from "../../components/EntityLink";
import { RequireAuth } from "../../components/guard";
import { getPb, useAuth, useCollection } from "../../lib/pb";
import type {
  AttestationProposalRecord,
  JudgmentProposalRecord,
  ProposalRecord,
} from "../../lib/types";

// The two-key queue (SPEC §8.4): notApplicable proposals showing the DOMAIN
// OBJECT — recipe, repo, justification — never the tool call. The first key
// is the proposal (any console identity); the second is the approver's, and
// turning it appends a SIGNED SCOPING EVENT to the ledger. The register
// flips only when the projector folds that event — approving here writes the
// record, not the board.
//
// Q3.3 adds the sibling queue: artifact-sufficiency judgments (G5). Same
// two keys, same order — approving appends a signed ArtifactJudgment, and
// the board's checklist moves only when the projector folds it.
//
// Q4.2 adds the third: attestations (SPEC §12.9), the acts-on-people path.
// Approving appends a signed Attestation and the KSI gains a non-machine
// method on VDR-TFR-NMV's 3-month clock — so this queue is also where that
// clock gets re-satisfied, by re-signing the same `statement_id`.

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
  const judgments = useCollection<JudgmentProposalRecord>("judgment_proposals", {
    sort: "-created",
  });
  const attestations = useCollection<AttestationProposalRecord>("attestation_proposals", {
    sort: "-created",
  });
  const pending = records.filter((p) => p.status === "pending");
  const decided = records.filter((p) => p.status !== "pending");
  const pendingJudgments = judgments.records.filter((p) => p.status === "pending");
  const decidedJudgments = judgments.records.filter((p) => p.status !== "pending");
  const pendingAttestations = attestations.records.filter((p) => p.status === "pending");
  const decidedAttestations = attestations.records.filter((p) => p.status !== "pending");
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

      <div className="section-title">Pending artifact judgments ({pendingJudgments.length})</div>
      <div className="panel">
        {pendingJudgments.map((proposal) => (
          <JudgmentProposalView
            key={proposal.id}
            proposal={proposal}
            canDecide={isApprover}
            onDecided={judgments.refetch}
          />
        ))}
        {!judgments.loading && pendingJudgments.length === 0 && (
          <div className="empty">no pending artifact judgments</div>
        )}
      </div>

      <div className="section-title">Pending attestations ({pendingAttestations.length})</div>
      <div className="panel">
        {pendingAttestations.map((proposal) => (
          <AttestationProposalView
            key={proposal.id}
            proposal={proposal}
            canDecide={isApprover}
            onDecided={attestations.refetch}
          />
        ))}
        {!attestations.loading && pendingAttestations.length === 0 && (
          <div className="empty">no pending attestations</div>
        )}
      </div>

      <div className="section-title">
        Decided ({decided.length + decidedJudgments.length + decidedAttestations.length})
      </div>
      <div className="panel">
        {decidedAttestations.map((proposal) => (
          <div key={proposal.id} style={{ padding: "10px 14px", borderBottom: "1px solid var(--border)" }}>
            <span className={`pill ${proposal.status === "approved" ? "notApplicable" : "dead"}`}>
              {proposal.status}
            </span>{" "}
            <EntityLink kind="ksi" id={proposal.ksi_id} repo={proposal.repo} />{" "}
            <span className="muted">
              {proposal.action} by {proposal.attestor_role} on <RepoName repo={proposal.repo} />
            </span>
            <div className="faint" style={{ fontSize: 12.5, marginTop: 4 }}>
              “{proposal.statement}” — proposed {proposal.proposed_by}
              {proposal.decided_by && <>, decided by {proposal.decided_by}</>}
              {proposal.ledger_digest && (
                <>
                  {" "}· ledger <EntityLink kind="evidence" digest={proposal.ledger_digest} />
                </>
              )}
            </div>
          </div>
        ))}
        {decidedJudgments.map((proposal) => (
          <div key={proposal.id} style={{ padding: "10px 14px", borderBottom: "1px solid var(--border)" }}>
            <span className={`pill ${proposal.status === "approved" ? "notApplicable" : "dead"}`}>
              {proposal.status}
            </span>{" "}
            <EntityLink kind="ksi" id={proposal.ksi_id} repo={proposal.repo} />{" "}
            <span className="muted">
              artifact {proposal.artifact} {proposal.action} on <RepoName repo={proposal.repo} />
            </span>
            <div className="faint" style={{ fontSize: 12.5, marginTop: 4 }}>
              “{proposal.justification}” — proposed {proposal.proposed_by}
              {proposal.decided_by && <>, decided by {proposal.decided_by}</>}
              {proposal.ledger_digest && (
                <>
                  {" "}· ledger <EntityLink kind="evidence" digest={proposal.ledger_digest} />
                </>
              )}
            </div>
          </div>
        ))}
        {decided.map((proposal) => (
          <div key={proposal.id} style={{ padding: "10px 14px", borderBottom: "1px solid var(--border)" }}>
            <span className={`pill ${proposal.status === "approved" ? "notApplicable" : "dead"}`}>
              {proposal.status}
            </span>{" "}
            <EntityLink kind="check" recipe={proposal.recipe_id} repo={proposal.repo} />{" "}
            <span className="muted">on <RepoName repo={proposal.repo} /></span>
            <div className="faint" style={{ fontSize: 12.5, marginTop: 4 }}>
              “{proposal.justification}” — proposed {proposal.proposed_by}
              {proposal.decided_by && <>, decided by {proposal.decided_by}</>}
              {proposal.scoping_digest && (
                <>
                  {" "}· ledger <EntityLink kind="evidence" digest={proposal.scoping_digest} />
                </>
              )}
            </div>
          </div>
        ))}
        {!loading &&
          decided.length === 0 &&
          decidedJudgments.length === 0 &&
          decidedAttestations.length === 0 && <div className="empty">nothing decided yet</div>}
      </div>
    </>
  );
}

function AttestationProposalView({
  proposal,
  canDecide,
  onDecided,
}: {
  proposal: AttestationProposalRecord;
  canDecide: boolean;
  onDecided: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function decide(action: "approve" | "reject") {
    setBusy(true);
    setError(null);
    try {
      const response = await fetch("/api/attestations/decide", {
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
        <EntityLink kind="ksi" id={proposal.ksi_id} repo={proposal.repo} />{" "}
        <span className="muted">
          {proposal.action} by {proposal.attestor_role} for
        </span>{" "}
        <RepoName repo={proposal.repo} className="mono" />
      </div>
      <div style={{ margin: "6px 0" }}>“{proposal.statement}”</div>
      <div className="faint" style={{ fontSize: 12.5 }}>
        {/* the mechanism's name, because that is what the method is keyed on —
            re-signing it satisfies the NMV clock instead of minting a method */}
        mechanism <span className="mono">{proposal.statement_id}</span> · proposed by{" "}
        {proposal.proposed_by} · {new Date(proposal.created).toLocaleString()}
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

function JudgmentProposalView({
  proposal,
  canDecide,
  onDecided,
}: {
  proposal: JudgmentProposalRecord;
  canDecide: boolean;
  onDecided: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function decide(action: "approve" | "reject") {
    setBusy(true);
    setError(null);
    try {
      const response = await fetch("/api/judgments/decide", {
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
        <EntityLink kind="ksi" id={proposal.ksi_id} repo={proposal.repo} />{" "}
        <span className="muted">artifact {proposal.artifact} {proposal.action} for</span>{" "}
        <RepoName repo={proposal.repo} className="mono" />
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
        <EntityLink kind="check" recipe={proposal.recipe_id} repo={proposal.repo} />{" "}
        <span className="muted">not applicable to</span> <RepoName repo={proposal.repo} className="mono" />
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
