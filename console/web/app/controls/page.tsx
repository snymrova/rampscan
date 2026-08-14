"use client";

import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useMemo, useState } from "react";
import { RequireAuth } from "../../components/guard";
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

  const active = reg === "controls" ? controls : ksis;
  const metaRow = meta.records[0];

  // recipe register rows by (repo, recipe) — the expansion joins through this,
  // so the sub-rows show exactly what the coverage board shows, never a copy
  const registerByCell = useMemo(() => {
    const map = new Map<string, RegisterRecord>();
    for (const r of registers.records) map.set(`${r.repo} ${r.recipe_id}`, r);
    return map;
  }, [registers.records]);

  const repos = useMemo(
    () => [...new Set(active.records.map((r) => r.repo))].sort(),
    [active.records],
  );
  const filtered = active.records.filter(
    (r) => (state === "all" || r.state === state) && (repo === "all" || r.repo === repo),
  );
  const count = (s: RegisterState) => active.records.filter((r) => r.state === s).length;

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
            Controls<span className="count">{controls.records.length}</span>
          </button>
          <button className={reg === "ksis" ? "active" : ""} onClick={() => setReg("ksis")}>
            KSIs<span className="count">{ksis.records.length}</span>
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
              <span className="count">{s.key === "all" ? active.records.length : count(s.key)}</span>
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
      </div>

      {(active.error ?? registers.error) && (
        <p className="error">{active.error ?? registers.error}</p>
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
                />
              );
            })}
            {!active.loading && filtered.length === 0 && (
              <tr>
                <td colSpan={5} className="empty">
                  nothing in this register{active.records.length === 0 ? " — no projection yet" : ""}
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
}: {
  row: RollupRecord;
  linked: boolean;
  open: boolean;
  toggle: () => void;
  registerByCell: Map<string, RegisterRecord>;
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
      </tr>
      {open &&
        recipeIds.map((recipeId) => (
          <RecipeSubRow
            key={recipeId}
            recipeId={recipeId}
            register={registerByCell.get(`${row.repo} ${recipeId}`)}
          />
        ))}
    </>
  );
}

function RecipeSubRow({
  recipeId,
  register,
}: {
  recipeId: string;
  register: RegisterRecord | undefined;
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
    </tr>
  );
}
