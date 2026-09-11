"use client";

import Link from "next/link";
import { useMemo, useState } from "react";
import { DaemonStrip } from "../components/DaemonStrip";
import { RequireAuth } from "../components/guard";
import { Term } from "../components/Term";
import { formatAge } from "../lib/mvx";
import { useCollection } from "../lib/pb";
import type {
  KsiCatalogRecord,
  MetaRecord,
  MethodCellRecord,
  MethodRegisterRecord,
} from "../lib/types";

// The KSI board (SPEC §12.1, Q2.5) — the board after the pivot: one row per
// KSI, 46 always (invariant 4′: a KSI with zero methods is a G1 row, never
// an absent row). Rows come from the projector's method_registers; the
// crosswalk drawer comes from the owed-side ksi_catalog mirror; and every
// method expands to the assessor-interrogation view — state, standing,
// declared scope, and the hop to its signed evidence — because that
// expansion is exactly what FRR-PVA-AA-06 tells an assessor to pull on.
//
// Cover ≠ automate is structural here (plan ground rule 2): the summary
// counts floor-met and no-method side by side, and a row is never green
// because it is empty. The recipe-keyed register lives on at /recipes.

export default function KsiBoardPage() {
  return (
    <RequireAuth>
      <KsiBoard />
    </RequireAuth>
  );
}

/** the row's worst gap, colored with the register's existing pill palette */
function gapPill(gap: MethodRegisterRecord["gap"]): { cls: string; label: string } | null {
  if (gap === "G1") return { cls: "unevidenced", label: "G1 coverage" };
  if (gap === "G2") return { cls: "violated", label: "G2 methods" };
  if (gap === "G4") return { cls: "violated", label: "G4 history" };
  return null;
}

function KsiBoard() {
  const catalog = useCollection<KsiCatalogRecord>("ksi_catalog", { sort: "ksi" });
  const registers = useCollection<MethodRegisterRecord>("method_registers", { sort: "ksi" });
  const meta = useCollection<MetaRecord>("meta");
  const metaRow = meta.records[0];

  const repos = useMemo(
    () => [...new Set(registers.records.map((r) => r.repo))].sort(),
    [registers.records],
  );
  const [repoChoice, setRepoChoice] = useState<string | null>(null);
  const repo = repoChoice ?? repos[0] ?? null;
  const [themeFilter, setThemeFilter] = useState("all");

  const byKsi = useMemo(
    () => new Map(registers.records.filter((r) => r.repo === repo).map((r) => [r.ksi, r])),
    [registers.records, repo],
  );

  const themes = useMemo(
    () => [...new Set(catalog.records.map((k) => k.theme_key))].sort(),
    [catalog.records],
  );

  // one row per owed KSI, from the catalog mirror — the board never shrinks
  // to what the ledger happens to hold
  const rows = catalog.records.filter(
    (k) => themeFilter === "all" || k.theme_key === themeFilter,
  );

  const all = catalog.records.map((k) => byKsi.get(k.ksi));
  const summary = {
    total: catalog.records.length,
    floorMet: all.filter((r) => r?.floor_met === true).length,
    automated: all.filter((r) => (r?.automated_methods ?? 0) > 0).length,
    noMethod: all.filter((r) => (r?.methods?.length ?? 0) === 0).length,
  };

  return (
    <>
      <h1>KSI board</h1>
      <p className="subtitle">
        {metaRow
          ? `dataset ${metaRow.dataset_version} · projected ${new Date(metaRow.projected_at).toLocaleString()} · class ${metaRow.settings?.certClass ?? "?"}`
          : "waiting for a projection — run a scan, or start `rampscan serve` with a ledger"}
      </p>

      <DaemonStrip />

      <div className="filters">
        {catalog.records.length > 0 && (
          <>
            {/* the headline and the covering sentence in the same breath —
                cover ≠ automate, stated structurally (ground rule 2) */}
            <span className="pill evidenced">floor met on {summary.floorMet} of {summary.total}</span>
            <span className="pill">≥1 automated method on {summary.automated}</span>
            <span className="pill unevidenced">no method on {summary.noMethod}</span>
            <span className="muted">
              covering all {summary.total} — a row with nothing to say is still a row
            </span>
          </>
        )}
        <span style={{ marginLeft: "auto" }} />
        <select
          value={themeFilter}
          onChange={(e) => setThemeFilter(e.target.value)}
        >
          <option value="all">all KSI themes</option>
          {themes.map((t) => (
            <option key={t}>{t}</option>
          ))}
        </select>
        {repos.length > 1 && (
          <select value={repo ?? ""} onChange={(e) => setRepoChoice(e.target.value)}>
            {repos.map((r) => (
              <option key={r}>{r}</option>
            ))}
          </select>
        )}
      </div>

      {(catalog.error ?? registers.error) && (
        <p className="error">{catalog.error ?? registers.error}</p>
      )}
      <div className="panel">
        <table className="reg">
          <thead>
            <tr>
              <th><Term name="KSI">KSI</Term></th>
              <th>Indicator</th>
              <th>Methods</th>
              <th><Term name="MVX window">Freshest</Term></th>
              <th>Artifacts</th>
              <th>Worst gap</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((k) => (
              <KsiRowView key={k.ksi} entry={k} register={byKsi.get(k.ksi)} />
            ))}
            {!catalog.loading && rows.length === 0 && (
              <tr>
                <td colSpan={6} className="empty">
                  no KSI catalog mirrored — start `rampscan serve`, which writes it from the
                  pinned dataset
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </>
  );
}

function KsiRowView({
  entry,
  register,
}: {
  entry: KsiCatalogRecord;
  register: MethodRegisterRecord | undefined;
}) {
  // the interrogation view is the DEFAULT detail view: one click on the row
  const [open, setOpen] = useState(false);
  const methods = register?.methods ?? [];
  const floor = register?.method_floor ?? null;
  const automated = register?.automated_methods ?? 0;
  const gap = gapPill(register?.gap ?? (methods.length === 0 ? "G1" : ""));

  return (
    <>
      <tr className="rowlink" onClick={() => setOpen((v) => !v)} aria-expanded={open}>
        <td className="mono">{entry.ksi}</td>
        <td className="muted">{entry.name}</td>
        <td>
          <span className={`pill ${register?.floor_met === true ? "evidenced" : "unevidenced"}`}>
            {automated}/{floor ?? "—"}
            {register?.floor_met === true ? " ok" : ""}
          </span>
        </td>
        <td className="muted">
          {register?.fresh_as_of ? `${formatAge(register.fresh_as_of)} ago` : "—"}
        </td>
        {/* –/5 until Q3 models them: unmeasured, never a fake 0 (§12.5 rule 3) */}
        <td className="muted" title="the five KSI default artifacts — modeled in Q3">
          –/5
        </td>
        <td>
          {gap ? (
            <span className={`pill ${gap.cls}`}>{gap.label}</span>
          ) : (
            <span className="faint">—</span>
          )}
        </td>
      </tr>
      {open && (
        <tr className="plain-row">
          <td colSpan={6}>
            {entry.statement !== null ? (
              <p className="muted" style={{ margin: "6px 0" }}>
                {entry.statement}
              </p>
            ) : (
              <p className="faint" style={{ margin: "6px 0" }}>
                statement varies by certification class at this pin — see the rules JSON
              </p>
            )}

            {methods.length === 0 ? (
              <p className="muted">
                no validation method derives to this KSI — nothing in the pipeline catalog
                claims it. This row is the gap (G1), not an absence of a row.
              </p>
            ) : (
              <table className="reg" style={{ margin: "4px 0 8px" }}>
                <thead>
                  <tr>
                    <th>State</th>
                    <th>Method</th>
                    <th>Source</th>
                    <th>Standing</th>
                    <th>Scope</th>
                    <th>Fresh</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {methods.map((m) => (
                    <MethodRowView key={m.methodId} method={m} />
                  ))}
                </tbody>
              </table>
            )}

            {/* the history meter (Q3.1, FRC-CSX-MOT): counted from the
                ledger's chains, dead bundles included — a young ledger
                states a young number, never a claim it cannot back */}
            {register && register.history_floor_months !== null && (
              <p className="muted" style={{ margin: "4px 0" }}>
                persistent-validation history:{" "}
                {register.history_since
                  ? `since ${new Date(register.history_since).toLocaleDateString()}`
                  : "none in the ledger"}{" "}
                — floor ≥{register.history_floor_months}mo (FRC-CSX-MOT)
                {register.history_met === true ? " · met" : " · not yet met"}
              </p>
            )}

            {/* the crosswalk drawer: controls demoted to annotation — the
                dataset already carries them per KSI, and the register never
                joins through them (SPEC §12.2) */}
            <p className="faint" style={{ margin: "4px 0" }}>
              <Term name="control">controls crosswalk</Term>:{" "}
              {entry.controls.map((c) => (
                <Link
                  key={c}
                  href={`/controls?reg=controls&id=${encodeURIComponent(c)}`}
                  className="mono"
                  style={{ marginRight: 8 }}
                  onClick={(e) => e.stopPropagation()}
                >
                  {c}
                </Link>
              ))}
            </p>
          </td>
        </tr>
      )}
    </>
  );
}

/** one method, interrogable: what walked, what it claims, where the signature is */
function MethodRowView({ method }: { method: MethodCellRecord }) {
  return (
    <tr>
      <td>
        <span className={`pill ${method.state}`}>
          {method.state === "notApplicable" ? "n/a" : method.state}
        </span>
      </td>
      <td className="mono">{method.methodId}</td>
      <td className="muted">
        {method.source}
        {method.automated ? "" : " · not automated"}
        {method.collector ? ` · ${method.collector}` : ""}
      </td>
      <td className="muted">{method.standing}</td>
      <td className="faint">
        {method.scope
          ? `${method.scope.population} · history ${method.scope.history ? "yes" : "no"} · gitignored ${method.scope.gitignored}`
          : "—"}
      </td>
      <td className="muted">{method.freshAsOf ? `${formatAge(method.freshAsOf)} ago` : "—"}</td>
      <td>
        {method.bundleDigest ? (
          <Link href={`/evidence/${method.bundleDigest}`} className="mono">
            evidence → {method.bundleDigest.slice(0, 12)}…
          </Link>
        ) : (
          <span className="faint">no live evidence</span>
        )}
      </td>
    </tr>
  );
}
