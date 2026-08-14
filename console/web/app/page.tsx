"use client";

import { useRouter } from "next/navigation";
import { useMemo, useState } from "react";
import { DaemonStrip } from "../components/DaemonStrip";
import { RequireAuth } from "../components/guard";
import { getPb, useAuth, useCollection } from "../lib/pb";
import { describePointer } from "../lib/pointers";
import { controlFamily, ksiTheme } from "../lib/types";
import type { MetaRecord, RegisterRecord, RegisterState } from "../lib/types";
import { formatAge } from "../lib/mvx";

// The coverage board (SPEC §8.1): three registers plus notApplicable —
// evidenced, violated, and unevidenced, the honest default, never hidden.
// Every row is a projection of the ledger; nothing here is writable except
// the proposal drawer, and even that lands in the ledger before the row moves.

const STATES: Array<{ key: RegisterState | "all"; label: string }> = [
  { key: "all", label: "All" },
  { key: "evidenced", label: "Evidenced" },
  { key: "violated", label: "Violated" },
  { key: "unevidenced", label: "Unevidenced" },
  { key: "notApplicable", label: "N/A" },
];

export default function BoardPage() {
  return (
    <RequireAuth>
      <Board />
    </RequireAuth>
  );
}

function Board() {
  const { records, loading, error } = useCollection<RegisterRecord>("registers", {
    sort: "recipe_id",
  });
  const meta = useCollection<MetaRecord>("meta");
  const [state, setState] = useState<RegisterState | "all">("all");
  const [repo, setRepo] = useState("all");
  const [theme, setTheme] = useState("all");
  const [family, setFamily] = useState("all");

  const repos = useMemo(() => [...new Set(records.map((r) => r.repo))].sort(), [records]);
  const themes = useMemo(
    () => [...new Set(records.flatMap((r) => r.ksi_ids.map(ksiTheme)))].sort(),
    [records],
  );
  const families = useMemo(
    () => [...new Set(records.flatMap((r) => r.control_ids.map(controlFamily)))].sort(),
    [records],
  );

  const filtered = records.filter(
    (r) =>
      (state === "all" || r.state === state) &&
      (repo === "all" || r.repo === repo) &&
      (theme === "all" || r.ksi_ids.some((k) => ksiTheme(k) === theme)) &&
      (family === "all" || r.control_ids.some((c) => controlFamily(c) === family)),
  );
  const count = (s: RegisterState) => records.filter((r) => r.state === s).length;
  const metaRow = meta.records[0];

  return (
    <>
      <h1>Coverage board</h1>
      <p className="subtitle">
        {metaRow
          ? `dataset ${metaRow.dataset_version} · projected ${new Date(metaRow.projected_at).toLocaleString()} · class ${metaRow.settings?.certClass ?? "?"}`
          : "waiting for a projection — run a scan, or start `rampscan serve` with a ledger"}
      </p>

      <DaemonStrip />

      <div className="filters">
        <div className="tabs">
          {STATES.map((s) => (
            <button
              key={s.key}
              className={state === s.key ? "active" : ""}
              onClick={() => setState(s.key)}
            >
              {s.label}
              <span className="count">
                {s.key === "all" ? records.length : count(s.key)}
              </span>
            </button>
          ))}
        </div>
        <select value={repo} onChange={(e) => setRepo(e.target.value)}>
          <option value="all">all repos</option>
          {repos.map((r) => (
            <option key={r}>{r}</option>
          ))}
        </select>
        <select value={theme} onChange={(e) => setTheme(e.target.value)}>
          <option value="all">all KSI themes</option>
          {themes.map((t) => (
            <option key={t}>{t}</option>
          ))}
        </select>
        <select value={family} onChange={(e) => setFamily(e.target.value)}>
          <option value="all">all control families</option>
          {families.map((f) => (
            <option key={f}>{f}</option>
          ))}
        </select>
      </div>

      {error && <p className="error">{error}</p>}
      <div className="panel">
        <table className="reg">
          <thead>
            <tr>
              <th>State</th>
              <th>Recipe</th>
              <th>Repo</th>
              <th>KSIs</th>
              <th>Controls</th>
              <th>Fresh</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {filtered.map((row) => (
              <RegisterRowView key={row.id} row={row} />
            ))}
            {!loading && filtered.length === 0 && (
              <tr>
                <td colSpan={7} className="empty">
                  nothing in this register{records.length === 0 ? " — no projection yet" : ""}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </>
  );
}

function RegisterRowView({ row }: { row: RegisterRecord }) {
  const router = useRouter();
  const [proposing, setProposing] = useState(false);
  const open = row.bundle_digest
    ? () => router.push(`/evidence/${row.bundle_digest}`)
    : undefined;

  return (
    <>
      <tr className={open ? "rowlink" : ""} onClick={open}>
        <td>
          <span className={`pill ${row.state}`}>
            {row.state === "notApplicable" ? "n/a" : row.state}
          </span>
        </td>
        <td className="mono">{row.recipe_id}</td>
        <td className="muted">{row.repo}</td>
        <td className="mono faint">{row.ksi_ids.join(" ")}</td>
        <td className="mono faint">{row.control_ids.join(" ")}</td>
        <td className="muted">
          {row.fresh_as_of ? `${formatAge(row.fresh_as_of)} ago` : "—"}
        </td>
        <td onClick={(e) => e.stopPropagation()}>
          {row.state === "unevidenced" && (
            <button className="btn" onClick={() => setProposing((p) => !p)}>
              propose N/A
            </button>
          )}
          {row.state === "notApplicable" && row.scoping && (
            <span className="faint" title={row.scoping.justification}>
              approved by {row.scoping.approvedBy.split(" ")[0]}
            </span>
          )}
        </td>
      </tr>
      {proposing && (
        <tr>
          <td colSpan={7} onClick={(e) => e.stopPropagation()}>
            <ProposeForm row={row} done={() => setProposing(false)} />
          </td>
        </tr>
      )}
      {row.state === "violated" && ((row.pointers?.length ?? 0) > 0 || row.introducing_commit) && (
        // the fix pointers (I2c): where the violation lives + when it arrived,
        // on the row itself — the evidence page has the full offender list
        <tr className={open ? "rowlink" : ""} onClick={open}>
          <td colSpan={7} className="pointer-row" style={{ fontSize: 12.5 }}>
            {(row.pointers ?? []).map((p, i) => (
              <span key={i} className="mono pointer">
                {describePointer(p)}
              </span>
            ))}
            {row.introducing_commit && (
              <span className="faint">
                violating since {formatAge(row.introduced_at)} ago · first seen at commit{" "}
                <span className="mono">{row.introducing_commit.slice(0, 12)}</span>
              </span>
            )}
          </td>
        </tr>
      )}
      {row.state === "notApplicable" && row.scoping && (
        <tr>
          <td colSpan={7} className="faint" style={{ fontSize: 12.5 }}>
            scoped not-applicable · “{row.scoping.justification}” — proposed{" "}
            {row.scoping.proposedBy}, approved {row.scoping.approvedBy} ·{" "}
            <span className="mono">{row.scoping.digest.slice(0, 16)}…</span>
          </td>
        </tr>
      )}
    </>
  );
}

function ProposeForm({ row, done }: { row: RegisterRecord; done: () => void }) {
  const { user } = useAuth();
  const [justification, setJustification] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [sent, setSent] = useState(false);

  async function submit() {
    if (!user) return;
    setBusy(true);
    setError(null);
    try {
      await getPb().collection("proposals").create({
        repo: row.repo,
        recipe_id: row.recipe_id,
        justification: justification.trim(),
        status: "pending",
        proposed_by: `${user.email} (pb:${user.id})`,
      });
      setSent(true);
      setTimeout(done, 1200);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  if (sent) return <p className="muted">proposal filed — an approver’s key turn makes it real (Approvals tab)</p>;
  return (
    <div style={{ padding: "6px 0 10px" }}>
      <p className="muted" style={{ margin: "0 0 8px" }}>
        Propose <code>{row.recipe_id}</code> as not applicable to <code>{row.repo}</code>. The
        justification is what the approver signs.
      </p>
      <textarea
        rows={2}
        placeholder="why this recipe does not apply to this repository…"
        value={justification}
        onChange={(e) => setJustification(e.target.value)}
      />
      <div style={{ marginTop: 8, display: "flex", gap: 8 }}>
        <button
          className="btn primary"
          disabled={busy || justification.trim().length === 0}
          onClick={submit}
        >
          file proposal
        </button>
        <button className="btn" onClick={done}>
          cancel
        </button>
      </div>
      {error && <p className="error">{error}</p>}
    </div>
  );
}
