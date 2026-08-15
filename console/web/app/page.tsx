"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useMemo, useState } from "react";
import { DaemonStrip } from "../components/DaemonStrip";
import { RequireAuth } from "../components/guard";
import { PlainLanguage } from "../components/PlainLanguage";
import { RunHopLink } from "../components/RunHopLink";
import { Term } from "../components/Term";
import { asOfRegisterRecord, toLocalInputValue, useAsOfBoard } from "../lib/asof";
import { explainUnevidenced, newestRunOf } from "../lib/emptystate";
import type { EmptyStateExplanation } from "../lib/emptystate";
import { csvFilename, downloadText, registerCsv } from "../lib/export";
import { getPb, useAuth, useCollection } from "../lib/pb";
import { describePointer } from "../lib/pointers";
import { controlFamily, ksiTheme } from "../lib/types";
import type {
  BoardDiffResponse,
  MetaRecord,
  RegisterChange,
  RegisterChangeKind,
  RegisterRecord,
  RegisterState,
  ScanRunRecord,
} from "../lib/types";
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

// the "since baseline" toggle (I2d): shared phrasing with the diff strip and
// the row badges so the summary and the rows can never disagree. Severity
// order twins packages/projector/src/diff.ts — bad news first.
const KIND_ORDER: RegisterChangeKind[] = [
  "newly-violated",
  "evidence-lapsed",
  "unscoped",
  "removed",
  "appeared",
  "scoped",
  "newly-evidenced",
  "resolved",
];
const KIND_PHRASE: Record<RegisterChangeKind, string> = {
  "newly-violated": "newly violated",
  "evidence-lapsed": "evidence lapsed",
  unscoped: "unscoped",
  removed: "removed",
  appeared: "appeared",
  scoped: "scoped n/a",
  "newly-evidenced": "newly evidenced",
  resolved: "resolved",
};
const KIND_PILL: Record<RegisterChangeKind, RegisterState> = {
  "newly-violated": "violated",
  "evidence-lapsed": "violated",
  unscoped: "unevidenced",
  removed: "unevidenced",
  appeared: "unevidenced",
  scoped: "notApplicable",
  "newly-evidenced": "evidenced",
  resolved: "evidenced",
};

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
  // Run records (K1), read for ONE purpose: to explain why an already-drawn
  // empty row is empty. Nothing here may decide which rows exist or what state
  // one is in — that stays folded from evidence and scoping alone (J1's
  // standing rule), and `explainUnevidenced` is structurally incapable of
  // returning anything but sentences.
  const runs = useCollection<ScanRunRecord>("scan_runs");
  const [state, setState] = useState<RegisterState | "all">("all");
  const [repo, setRepo] = useState("all");
  const [theme, setTheme] = useState("all");
  const [family, setFamily] = useState("all");
  // "since baseline" (I2d): null = off; "previous" or a scan instant = on
  const [since, setSince] = useState<string | null>(null);
  const [changedOnly, setChangedOnly] = useState(false);
  const [diffData, setDiffData] = useState<BoardDiffResponse | null>(null);
  // "as of" (I3d): null = live board; an ISO instant = the board refolded
  // there, server-side, by the same hand `rampscan board --as-of` calls
  const [asOf, setAsOf] = useState<string | null>(null);
  const metaRow = meta.records[0];
  const projectedAt = metaRow?.projected_at;
  const asOfData = useAsOfBoard(asOf, projectedAt);
  const historical = asOf !== null;

  // the diff is computed server-side by the SAME code the CLI runs
  // (computeBoardDiff — two as-of folds of the ledger). Refetched whenever
  // the projection moves, so the badges never describe a stale board.
  useEffect(() => {
    if (!since) {
      setDiffData(null);
      return;
    }
    let cancelled = false;
    setDiffData(null);
    fetch(`/api/board/diff?since=${encodeURIComponent(since)}`, {
      headers: { Authorization: getPb().authStore.token },
    })
      .then((r) => r.json())
      .then((data: BoardDiffResponse) => {
        if (!cancelled) setDiffData(data);
      })
      .catch((e: unknown) => {
        if (!cancelled) setDiffData({ error: e instanceof Error ? e.message : String(e) });
      });
    return () => {
      cancelled = true;
    };
  }, [since, projectedAt]);

  const changeByCell = useMemo(() => {
    const map = new Map<string, RegisterChange>();
    for (const change of diffData?.diff?.changes ?? []) {
      map.set(`${change.repo} ${change.recipeId}`, change);
    }
    return map;
  }, [diffData]);

  // the rendered world: the live projection, or the as-of fold's registers
  // renamed into the live record shape — one row component renders both
  const rows = useMemo(
    () => (historical ? (asOfData?.projection?.registers ?? []).map(asOfRegisterRecord) : records),
    [historical, asOfData, records],
  );

  const repos = useMemo(() => [...new Set(rows.map((r) => r.repo))].sort(), [rows]);
  const themes = useMemo(
    () => [...new Set(rows.flatMap((r) => r.ksi_ids.map(ksiTheme)))].sort(),
    [rows],
  );
  const families = useMemo(
    () => [...new Set(rows.flatMap((r) => r.control_ids.map(controlFamily)))].sort(),
    [rows],
  );

  // Every count above the table counts rows a reader can SEE. The state tabs
  // partition the register, so they count within the OTHER filters rather than
  // over the whole projection: with a single repo on the board that difference
  // never showed, and the moment a second one existed (K1's bare-app) an
  // unscoped "All 30" sat above 15 rows — and the CSV, which has always
  // exported exactly the filtered rows, disagreed with the chip above it.
  const scoped = rows.filter(
    (r) =>
      (repo === "all" || r.repo === repo) &&
      (theme === "all" || r.ksi_ids.some((k) => ksiTheme(k) === theme)) &&
      (family === "all" || r.control_ids.some((c) => controlFamily(c) === family)) &&
      (!since || !changedOnly || changeByCell.has(`${r.repo} ${r.recipe_id}`)),
  );
  const filtered = scoped.filter((r) => state === "all" || r.state === state);
  const count = (s: RegisterState) => scoped.filter((r) => r.state === s).length;

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
                {s.key === "all" ? scoped.length : count(s.key)}
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
        {!historical && (
          <button
            className={`btn${since ? " primary" : ""}`}
            onClick={() => {
              setSince(since ? null : "previous");
              setChangedOnly(false);
            }}
          >
            since baseline
          </button>
        )}
        {since && (diffData?.scans?.length ?? 0) > 1 && (
          <select value={since} onChange={(e) => setSince(e.target.value)}>
            <option value="previous">previous scan</option>
            {diffData!
              .scans!.slice(0, -1)
              .reverse()
              .map((s) => (
                <option key={s} value={s}>
                  scan {new Date(s).toLocaleString()}
                </option>
              ))}
          </select>
        )}
        <button
          className={`btn${historical ? " primary" : ""}`}
          onClick={() => {
            // the two lenses on the past are exclusive: turning the as-of
            // view on parks the since-baseline diff
            setAsOf(historical ? null : new Date().toISOString());
            setSince(null);
            setChangedOnly(false);
          }}
        >
          as of
        </button>
        {historical && (
          <>
            <input
              type="datetime-local"
              value={toLocalInputValue(asOf!)}
              onChange={(e) => {
                if (e.target.value) setAsOf(new Date(e.target.value).toISOString());
              }}
            />
            {(asOfData?.scans?.length ?? 0) > 0 && (
              <select
                value={asOfData!.scans!.includes(asOf!) ? asOf! : ""}
                onChange={(e) => {
                  if (e.target.value) setAsOf(e.target.value);
                }}
              >
                <option value="">jump to a scan…</option>
                {[...asOfData!.scans!].reverse().map((s) => (
                  <option key={s} value={s}>
                    scan {new Date(s).toLocaleString()}
                  </option>
                ))}
              </select>
            )}
          </>
        )}
        <button
          className="btn"
          title="the rows on screen, filters and as-of instant included"
          disabled={filtered.length === 0}
          onClick={() => {
            // the instant these rows were true: the chosen as-of instant in a
            // historical view, the projection's own clock in the live one
            const foldedAt = historical ? asOf! : (metaRow?.projected_at ?? "");
            downloadText(
              csvFilename(historical ? "board-asof" : "board", foldedAt),
              registerCsv(filtered, foldedAt),
            );
          }}
        >
          export CSV
        </button>
      </div>

      {historical && (
        <div className="panel diff-strip asof-strip">
          {!asOfData ? (
            <span className="muted">refolding the ledger as of {new Date(asOf!).toLocaleString()}…</span>
          ) : asOfData.error ? (
            <span className="error">{asOfData.error}</span>
          ) : (
            <>
              <span className="pill asof">as of {new Date(asOf!).toLocaleString()}</span>
              <span className="muted">
                refolded from ledger statements at or before this instant
                {asOfData.asOfIsScan ? " (a scan instant)" : ""} · historical view, read-only
              </span>
              {asOfData.projection && (
                <span className="faint" style={{ marginLeft: "auto" }}>
                  dataset {asOfData.projection.datasetVersion || "—"}
                </span>
              )}
            </>
          )}
        </div>
      )}

      {since && (
        <div className="panel diff-strip">
          {!diffData ? (
            <span className="muted">diffing against the baseline…</span>
          ) : diffData.error ? (
            <span className="error">{diffData.error}</span>
          ) : diffData.reason ? (
            <span className="muted">{diffData.reason}</span>
          ) : (
            <DiffSummary
              data={diffData}
              changedOnly={changedOnly}
              setChangedOnly={setChangedOnly}
            />
          )}
        </div>
      )}

      {error && <p className="error">{error}</p>}
      <div className="panel">
        <table className="reg">
          <thead>
            <tr>
              <th>State</th>
              {/* glossary-on-hover (K1): the column headings are the first
                  jargon a reader meets, and a term with no entry renders as
                  plain text rather than an empty tooltip */}
              <th><Term>recipe</Term></th>
              <th>Repo</th>
              <th><Term name="KSI">KSIs</Term></th>
              <th><Term name="control">Controls</Term></th>
              <th><Term name="MVX window">Fresh</Term></th>
              <th />
            </tr>
          </thead>
          <tbody>
            {filtered.map((row) => (
              <RegisterRowView
                key={row.id}
                row={row}
                change={since ? changeByCell.get(`${row.repo} ${row.recipe_id}`) : undefined}
                historical={historical}
                why={
                  // a historical fold is explained by the run log of TODAY,
                  // which is not the world those rows came from — same reason
                  // the as-of board suppresses the run hop and propose-N/A
                  historical
                    ? null
                    : explainUnevidenced({
                        row,
                        run: newestRunOf(runs.records, row.repo),
                        runsLoaded: !runs.loading,
                        runCount: runs.records.length,
                      })
                }
              />
            ))}
            {!loading && (!historical || asOfData !== null) && filtered.length === 0 && (
              <tr>
                <td colSpan={7} className="empty">
                  {historical
                    ? "nothing in this register as of this instant — no ledger statement at or before it"
                    : `nothing in this register${records.length === 0 ? " — no projection yet" : ""}`}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </>
  );
}

function DiffSummary({
  data,
  changedOnly,
  setChangedOnly,
}: {
  data: BoardDiffResponse;
  changedOnly: boolean;
  setChangedOnly: (v: boolean) => void;
}) {
  const diff = data.diff!;
  const moved = KIND_ORDER.filter((k) => diff.counts[k] > 0);
  const removed = diff.changes.filter((c) => c.kind === "removed");
  const baselineLabel = `${new Date(diff.baseline).toLocaleString()}${
    data.baselineIsScan ? "" : " (as-of instant, not a scan)"
  }`;
  return (
    <>
      <span className="muted">since {baselineLabel} —</span>
      {moved.length === 0 ? (
        <span className="muted">
          no register moved ({diff.unchanged} cell{diff.unchanged === 1 ? "" : "s"} held)
        </span>
      ) : (
        <>
          {moved.map((kind) => (
            <span key={kind} className={`pill ${KIND_PILL[kind]}`}>
              {diff.counts[kind]} {KIND_PHRASE[kind]}
            </span>
          ))}
          <span className="faint">{diff.unchanged} unchanged</span>
          {removed.length > 0 && (
            <span className="faint">
              removed: {removed.map((c) => `${c.recipeId} (${c.repo})`).join(", ")}
            </span>
          )}
          <label className="muted" style={{ marginLeft: "auto", cursor: "pointer" }}>
            <input
              type="checkbox"
              checked={changedOnly}
              onChange={(e) => setChangedOnly(e.target.checked)}
            />{" "}
            changed only
          </label>
        </>
      )}
    </>
  );
}

function RegisterRowView({
  row,
  change,
  historical = false,
  why = null,
}: {
  row: RegisterRecord;
  change?: RegisterChange;
  /** an as-of row (I3d): a historical fold offers no actions to take today */
  historical?: boolean;
  /** why this empty row is empty (K1), or null when it needs no explaining */
  why?: EmptyStateExplanation | null;
}) {
  const router = useRouter();
  const [proposing, setProposing] = useState(false);
  // the plain-language paragraphs (K1) ride every row and stay COLLAPSED: the
  // board is a scanning surface, and prose on fifteen rows at once would make
  // the one row an operator came for harder to find, not easier
  const [explaining, setExplaining] = useState(false);
  const open = row.bundle_digest
    ? () => router.push(`/evidence/${row.bundle_digest}`)
    : undefined;

  return (
    <>
      <tr className={open ? "rowlink" : ""} onClick={open}>
        <td>
          <span className={`pill ${row.state}`}>
            <Term name={row.state}>{row.state === "notApplicable" ? "n/a" : row.state}</Term>
          </span>
          {change && (
            <span
              className={`pill ${KIND_PILL[change.kind]}`}
              style={{ marginLeft: 6 }}
              title={KIND_PHRASE[change.kind]}
            >
              {change.from
                ? `was ${change.from === "notApplicable" ? "n/a" : change.from}`
                : "new row"}
            </span>
          )}
        </td>
        <td className="mono">{row.recipe_id}</td>
        <td className="muted">{row.repo}</td>
        <td className="mono faint">
          {/* recipe → KSI/control hop (I3a): each id opens its register rollup */}
          {row.ksi_ids.map((k) => (
            <Link
              key={k}
              href={`/controls?reg=ksis&id=${encodeURIComponent(k)}`}
              onClick={(e) => e.stopPropagation()}
              style={{ marginRight: 8 }}
            >
              {k}
            </Link>
          ))}
        </td>
        <td className="mono faint">
          {row.control_ids.map((c) => (
            <Link
              key={c}
              href={`/controls?reg=controls&id=${encodeURIComponent(c)}`}
              onClick={(e) => e.stopPropagation()}
              style={{ marginRight: 8 }}
            >
              {c}
            </Link>
          ))}
        </td>
        <td className="muted">
          {row.fresh_as_of ? `${formatAge(row.fresh_as_of)} ago` : "—"}
        </td>
        <td onClick={(e) => e.stopPropagation()}>
          {/* K1: authored operator English about the check, one click away and
              beside the row's other question ("how was this produced?").
              Rendered only where the catalog carries it — a recipe that left
              the catalog gets no button rather than an empty panel. It lives
              in this cell rather than beside the recipe id deliberately: the
              recipe cell is a click target and an accessible name that other
              surfaces match on, and a button inside it would change both. */}
          {row.plain && (
            <button
              className="plainbtn"
              aria-expanded={explaining}
              title="what this check means, in plain English"
              onClick={() => setExplaining((v) => !v)}
            >
              {explaining ? "▾ plain English" : "▸ plain English"}
            </button>
          )}
          {/* the hop to the machinery (J3) — how this row was produced, or,
              for an empty row, which run failed to produce it */}
          <RunHopLink row={row} historical={historical} />
          {row.state === "unevidenced" && !historical && (
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
      {explaining && row.plain && (
        <tr className="plain-row">
          <td colSpan={7} onClick={(e) => e.stopPropagation()}>
            <PlainLanguage plain={row.plain} recipeId={row.recipe_id} />
          </td>
        </tr>
      )}
      {/* the guided empty state (K1 over J1): an unevidenced row says why it is
          empty, in the run record's own words. It explains the row; it never
          changes it — this cell is unevidenced with or without the sentence. */}
      {why && (
        <tr className="why-row">
          <td colSpan={7} onClick={(e) => e.stopPropagation()}>
            <span className="why-reason">{why.reason}</span>{" "}
            {why.action !== "" && <span className="why-action">→ {why.action}</span>}{" "}
            <span className="why-src">
              {why.runId
                ? `read from the run record of ${why.runId}`
                : "read from this projection's run records"}
              {why.actionable ? "" : " · not a task — recorded so the empty row is not a mystery"}
            </span>
          </td>
        </tr>
      )}
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
