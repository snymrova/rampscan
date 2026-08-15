"use client";

import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useMemo, useState } from "react";
import { DownloadButton } from "../../components/DownloadButton";
import { RequireAuth } from "../../components/guard";
import { RunHopLink } from "../../components/RunHopLink";
import {
  asOfRegisterRecord,
  asOfRollupRecord,
  toLocalInputValue,
  useAsOfBoard,
} from "../../lib/asof";
import { csvFilename, downloadText, rollupCsv } from "../../lib/export";
import { useCollection } from "../../lib/pb";
import { formatAge } from "../../lib/mvx";
import type { MetaRecord, RegisterRecord, RegisterState, RollupRecord } from "../../lib/types";

// The control register (plan I3a): the auditor's landing view. Control ID →
// mapped recipes → verdicts → evidence bundles, every hop clickable — and the
// evidence page links back here, so the traversal works in both directions.
// Everything rendered is the projector's rollup (I1a): violated beats
// unevidenced beats evidenced, notApplicable only when every mapped recipe
// is, and the counts are attributable — a recount from the register rows
// always agrees. Nothing on this page is writable.

const STATES: Array<{ key: RegisterState | "all"; label: string }> = [
  { key: "all", label: "All" },
  { key: "evidenced", label: "Evidenced" },
  { key: "violated", label: "Violated" },
  { key: "unevidenced", label: "Unevidenced" },
  { key: "notApplicable", label: "N/A" },
];

type RegKind = "controls" | "ksis";

export default function ControlsPage() {
  return (
    <RequireAuth>
      {/* useSearchParams needs a Suspense boundary for the static prerender */}
      <Suspense fallback={null}>
        <Registers />
      </Suspense>
    </RequireAuth>
  );
}

function Registers() {
  const params = useSearchParams();
  // deep link (the "back" direction of the traversal): /controls?reg=ksis&id=KSI-SCR-MON
  const linkedId = params.get("id");
  const [reg, setReg] = useState<RegKind>(params.get("reg") === "ksis" ? "ksis" : "controls");
  const controls = useCollection<RollupRecord>("controls", { sort: "rollup_id" });
  const ksis = useCollection<RollupRecord>("ksis", { sort: "rollup_id" });
  const registers = useCollection<RegisterRecord>("registers");
  const meta = useCollection<MetaRecord>("meta");
  const [state, setState] = useState<RegisterState | "all">("all");
  const [repo, setRepo] = useState("all");
  // expansion override per row; unset rows fall back to the deep-linked id
  const [expanded, setExpanded] = useState<Map<string, boolean>>(new Map());
  // "as of" (I3d): null = live rollups; an ISO instant = both registers
  // refolded there, server-side, by the same hand the board's selector calls
  const [asOf, setAsOf] = useState<string | null>(null);

  const metaRow = meta.records[0];
  const asOfData = useAsOfBoard(asOf, metaRow?.projected_at);
  const historical = asOf !== null;

  // the rendered world: the live rollup collections, or the as-of fold's
  // rollups renamed into the live record shape — one row component for both
  const controlRows = useMemo(
    () =>
      historical
        ? (asOfData?.projection?.controls ?? []).map(asOfRollupRecord)
        : controls.records,
    [historical, asOfData, controls.records],
  );
  const ksiRows = useMemo(
    () =>
      historical ? (asOfData?.projection?.ksis ?? []).map(asOfRollupRecord) : ksis.records,
    [historical, asOfData, ksis.records],
  );
  const activeRows = reg === "controls" ? controlRows : ksiRows;
  const activeCol = reg === "controls" ? controls : ksis;

  // recipe register rows by (repo, recipe) — the expansion joins through this,
  // so the sub-rows show exactly what the coverage board shows (the as-of
  // board when an instant is selected), never a copy
  const registerByCell = useMemo(() => {
    const map = new Map<string, RegisterRecord>();
    const rows = historical
      ? (asOfData?.projection?.registers ?? []).map(asOfRegisterRecord)
      : registers.records;
    for (const r of rows) map.set(`${r.repo} ${r.recipe_id}`, r);
    return map;
  }, [historical, asOfData, registers.records]);

  const repos = useMemo(() => [...new Set(activeRows.map((r) => r.repo))].sort(), [activeRows]);
  const filtered = activeRows.filter(
    (r) => (state === "all" || r.state === state) && (repo === "all" || r.repo === repo),
  );
  const count = (s: RegisterState) => activeRows.filter((r) => r.state === s).length;

  return (
    <>
      <h1>{reg === "controls" ? "Control register" : "KSI register"}</h1>
      <p className="subtitle">
        {metaRow
          ? `dataset ${metaRow.dataset_version} · projected ${new Date(metaRow.projected_at).toLocaleString()}`
          : "waiting for a projection"}{" "}
        · rolled up from the register rows — violated beats unevidenced beats evidenced, n/a only
        when every mapped recipe is; every count is attributable to the recipes listed under it
      </p>

      <div className="filters">
        <div className="tabs">
          <button className={reg === "controls" ? "active" : ""} onClick={() => setReg("controls")}>
            Controls<span className="count">{controlRows.length}</span>
          </button>
          <button className={reg === "ksis" ? "active" : ""} onClick={() => setReg("ksis")}>
            KSIs<span className="count">{ksiRows.length}</span>
          </button>
        </div>
        <div className="tabs">
          {STATES.map((s) => (
            <button
              key={s.key}
              className={state === s.key ? "active" : ""}
              onClick={() => setState(s.key)}
            >
              {s.label}
              <span className="count">{s.key === "all" ? activeRows.length : count(s.key)}</span>
            </button>
          ))}
        </div>
        {repos.length > 1 && (
          <select value={repo} onChange={(e) => setRepo(e.target.value)}>
            <option value="all">all repos</option>
            {repos.map((r) => (
              <option key={r}>{r}</option>
            ))}
          </select>
        )}
        <button
          className={`btn${historical ? " primary" : ""}`}
          onClick={() => setAsOf(historical ? null : new Date().toISOString())}
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
          title="the rollup rows on screen, filters and as-of instant included"
          disabled={filtered.length === 0}
          onClick={() => {
            const foldedAt = historical ? asOf! : (metaRow?.projected_at ?? "");
            downloadText(
              csvFilename(historical ? `${reg}-asof` : reg, foldedAt),
              rollupCsv(filtered, foldedAt),
            );
          }}
        >
          export CSV
        </button>
      </div>

      {historical && (
        <div className="panel diff-strip asof-strip">
          {!asOfData ? (
            <span className="muted">
              refolding the ledger as of {new Date(asOf!).toLocaleString()}…
            </span>
          ) : asOfData.error ? (
            <span className="error">{asOfData.error}</span>
          ) : (
            <>
              <span className="pill asof">as of {new Date(asOf!).toLocaleString()}</span>
              <span className="muted">
                both registers refolded from ledger statements at or before this instant
                {asOfData.asOfIsScan ? " (a scan instant)" : ""} · historical view, read-only
              </span>
            </>
          )}
        </div>
      )}

      {(activeCol.error ?? registers.error) && (
        <p className="error">{activeCol.error ?? registers.error}</p>
      )}
      <div className="panel">
        <table className="reg">
          <thead>
            <tr>
              <th>State</th>
              <th>{reg === "controls" ? "Control" : "KSI"}</th>
              <th>Repo</th>
              <th>Coverage</th>
              <th>Recipes</th>
              <th>Package</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((row) => {
              const key = `${row.repo} ${row.rollup_id}`;
              return (
                <RollupRowView
                  key={row.id}
                  row={row}
                  linked={row.rollup_id === linkedId}
                  open={expanded.get(key) ?? row.rollup_id === linkedId}
                  toggle={() =>
                    setExpanded((m) => {
                      const next = new Map(m);
                      next.set(key, !(m.get(key) ?? row.rollup_id === linkedId));
                      return next;
                    })
                  }
                  registerByCell={registerByCell}
                  reg={reg}
                  historical={historical}
                />
              );
            })}
            {!activeCol.loading && (!historical || asOfData !== null) && filtered.length === 0 && (
              <tr>
                <td colSpan={6} className="empty">
                  {historical
                    ? "nothing in this register as of this instant — no ledger statement at or before it"
                    : `nothing in this register${activeCol.records.length === 0 ? " — no projection yet" : ""}`}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </>
  );
}

function RollupRowView({
  row,
  linked,
  open,
  toggle,
  registerByCell,
  reg,
  historical,
}: {
  row: RollupRecord;
  linked: boolean;
  open: boolean;
  toggle: () => void;
  registerByCell: Map<string, RegisterRecord>;
  reg: RegKind;
  historical: boolean;
}) {
  const recipeIds = row.recipe_ids ?? [];
  const c = row.counts;
  return (
    <>
      <tr className={`rowlink${linked ? " hl" : ""}`} onClick={toggle}>
        <td>
          <span className={`pill ${row.state}`}>
            {row.state === "notApplicable" ? "n/a" : row.state}
          </span>
        </td>
        <td className="mono">{row.rollup_id}</td>
        <td className="muted">{row.repo}</td>
        <td>
          <span className="muted">
            {c.evidenced} of {c.total} mapped recipe{c.total === 1 ? "" : "s"} evidenced
          </span>{" "}
          {c.violated > 0 && <span className="pill violated">{c.violated} violated</span>}{" "}
          {c.unevidenced > 0 && (
            <span className="pill unevidenced">{c.unevidenced} unevidenced</span>
          )}{" "}
          {c.notApplicable > 0 && (
            <span className="pill notApplicable">{c.notApplicable} n/a</span>
          )}
        </td>
        <td className="muted">
          {recipeIds.length} recipe{recipeIds.length === 1 ? "" : "s"} {open ? "▾" : "▸"}
        </td>
        <td>
          {/* the package is assembled from the LIVE ledger; offering it under a
              historical fold would hand back a package that doesn't match the
              rows on screen — suppressed, and it says why (I3d's precedent) */}
          <DownloadButton
            label="evidence package"
            url={`/api/export/control?reg=${reg}&id=${encodeURIComponent(row.rollup_id)}&repo=${encodeURIComponent(row.repo)}`}
            disabled={historical}
            note="live only"
          />
        </td>
      </tr>
      {open &&
        recipeIds.map((recipeId) => (
          <RecipeSubRow
            key={recipeId}
            recipeId={recipeId}
            register={registerByCell.get(`${row.repo} ${recipeId}`)}
            historical={historical}
          />
        ))}
    </>
  );
}

function RecipeSubRow({
  recipeId,
  register,
  historical,
}: {
  recipeId: string;
  register: RegisterRecord | undefined;
  /** an as-of fold (I3d): /runs reads the live projection, so no hop from history */
  historical: boolean;
}) {
  const router = useRouter();
  const digest = register?.bundle_digest;
  const open = digest ? () => router.push(`/evidence/${digest}`) : undefined;
  return (
    <tr className={open ? "rowlink" : ""} onClick={open} style={{ fontSize: 12.5 }}>
      <td>
        {register ? (
          <span className={`pill ${register.state}`}>
            {register.state === "notApplicable" ? "n/a" : register.state}
          </span>
        ) : (
          // the rollup names a recipe the register projection lacks — say so,
          // never render a guessed state
          <span className="faint">not in register</span>
        )}
      </td>
      <td className="mono" style={{ paddingLeft: 32 }}>
        {recipeId}
      </td>
      <td />
      <td className="muted">
        {register?.fresh_as_of ? `fresh ${formatAge(register.fresh_as_of)} ago` : "—"}
      </td>
      <td className="mono faint">
        {digest ? (
          <Link href={`/evidence/${digest}`} onClick={(e) => e.stopPropagation()}>
            {digest.slice(0, 16)}…
          </Link>
        ) : (
          "no bundle"
        )}
      </td>
      <td onClick={(e) => e.stopPropagation()}>
        {/* the same hop the board carries (J3) — an unevidenced recipe under a
            control is exactly the row whose "why" the auditor asks about */}
        {register && <RunHopLink row={register} historical={historical} />}
      </td>
    </tr>
  );
}
