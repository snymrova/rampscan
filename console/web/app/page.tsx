"use client";

import { useRouter, useSearchParams } from "next/navigation";
import { useEffect, useMemo, useRef, useState } from "react";
import { DaemonStrip } from "../components/DaemonStrip";
import { CollectEvidence } from "../components/CollectEvidence";
import { EntityLink, RepoName } from "../components/EntityLink";
import { PostureBlock } from "../components/PostureBlock";
import { RequireAuth } from "../components/guard";
import { Term } from "../components/Term";
import { themeHref } from "../lib/links";
import { formatAge } from "../lib/mvx";
import { getPb, useAuth, useCollection } from "../lib/pb";
import { foldPosture } from "../lib/posture";
import { useRepoScope } from "../lib/scope";
import type {
  ArtifactCellRecord,
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
  if (gap === "G3") return { cls: "violated", label: "G3 freshness" };
  if (gap === "G4") return { cls: "violated", label: "G4 history" };
  if (gap === "G5") return { cls: "violated", label: "G5 artifact" };
  if (gap === "G6") return { cls: "violated", label: "G6 evidence" };
  return null;
}

function KsiBoard() {
  const catalog = useCollection<KsiCatalogRecord>("ksi_catalog", { sort: "ksi" });
  const registers = useCollection<MethodRegisterRecord>("method_registers", { sort: "ksi" });
  const meta = useCollection<MetaRecord>("meta");
  const metaRow = meta.records[0];

  // the board reads ONE repo: the console's scope (U-R5), or under "all
  // repos" the newest-scanned one, said out loud below
  const scope = useRepoScope();
  const repo = scope.repo ?? scope.fallback;
  // ?ksi= opens and scrolls to one row (U0) — until U1 gives a KSI its own page
  const params = useSearchParams();
  const linkedKsi = params.get("ksi");
  // ?theme= is L1: one stratum of the posture block, opened as the register
  const router = useRouter();
  const themeFilter = params.get("theme") ?? "all";
  const setThemeFilter = (t: string) => router.push(scope.scoped(t === "all" ? "/" : themeHref(t)));

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

  // The meters count the indicators THIS class obliges (R0.2, §13.7). An
  // optional row keeps its place on the board — the board has 46 rows at
  // every class — and stays out of every numerator and denominator, so a
  // provider who evidences one anyway is never shown 42 of 41.
  const certClass = metaRow?.settings?.certClass;
  const isOptional = (k: KsiCatalogRecord) =>
    certClass !== undefined && (k.optional_at ?? []).includes(certClass);
  const optional = catalog.records.filter(isOptional);
  const obliged = catalog.records.filter((k) => !isOptional(k));
  const all = obliged.map((k) => byKsi.get(k.ksi));
  const posture = foldPosture(catalog.records, byKsi, isOptional);
  const summary = {
    total: obliged.length,
    floorMet: all.filter((r) => r?.floor_met === true).length,
    automated: all.filter((r) => (r?.automated_methods ?? 0) > 0).length,
    noMethod: all.filter((r) => (r?.methods?.length ?? 0) === 0).length,
    optional: optional.map((k) => k.ksi),
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

      {catalog.records.length > 0 && (
        <PostureBlock
          posture={posture}
          repo={repo}
          certClass={certClass === "c" ? "c" : "b"}
          focusTheme={themeFilter === "all" ? null : themeFilter}
        />
      )}

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
            {summary.optional.length > 0 && (
              <span className="muted">
                {summary.optional.length} optional at class {certClass}, outside every meter —{" "}
                {summary.optional.map((k, i) => (
                  <span key={k}>
                    {i > 0 && ", "}
                    <EntityLink kind="ksi" id={k} className="" />
                  </span>
                ))}
              </span>
            )}
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
      </div>
      {scope.repo === null && repo && (
        <p className="muted" style={{ margin: "0 0 12px" }}>
          The board reads one repository at a time; under all repos it shows the newest scanned,{" "}
          <RepoName repo={repo} />.
        </p>
      )}

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
              <KsiRowView
                key={k.ksi}
                entry={k}
                register={byKsi.get(k.ksi)}
                optional={isOptional(k)}
                linked={linkedKsi === k.ksi}
              />
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
  optional,
  linked = false,
}: {
  entry: KsiCatalogRecord;
  register: MethodRegisterRecord | undefined;
  /** this class does not oblige the indicator (R0.2, §13.7) — shown, not hidden */
  optional?: boolean;
  /** the row a `?ksi=` link named: arrives open and in view */
  linked?: boolean;
}) {
  // the interrogation view is the DEFAULT detail view: one click on the row
  const [open, setOpen] = useState(linked);
  const rowRef = useRef<HTMLTableRowElement>(null);
  useEffect(() => {
    if (!linked) return;
    setOpen(true);
    rowRef.current?.scrollIntoView({ block: "start" });
  }, [linked]);
  const methods = register?.methods ?? [];
  const floor = register?.method_floor ?? null;
  const automated = register?.automated_methods ?? 0;
  const gap = gapPill(register?.gap ?? (methods.length === 0 ? "G1" : ""));

  return (
    <>
      <tr
        ref={rowRef}
        id={entry.ksi}
        className={`rowlink ${linked ? "linked" : ""}`}
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
      >
        {/* the row IS this KSI: its id names it, the row's click opens it */}
        <td className="mono" data-entity="ksi">
          {entry.ksi}
        </td>
        <td className="muted">
          {entry.name}
          {optional === true && <span className="muted"> · optional at this class</span>}
        </td>
        <td>
          <span className={`pill ${register?.floor_met === true ? "evidenced" : "unevidenced"}`}>
            {automated}/{floor ?? "—"}
            {register?.floor_met === true ? " ok" : ""}
          </span>
        </td>
        <td className="muted">
          {register?.fresh_as_of ? `${formatAge(register.fresh_as_of)} ago` : "—"}
        </td>
        {/* the five owed artifacts (Q3.3): the fold's count when a scan is
            recorded; "–/5" only when there is no ledger row to measure
            against — unmeasured, never a fake 0 (§12.5 rule 3) */}
        <td title="the five KSI default artifacts (SDR-CSX-KSI) — a cell counts when a signed body fills it; 2 and 5 are computed, 1, 3 and 4 are two-key judged">
          {register ? (
            <span className={`pill ${register.artifacts_present === 5 ? "evidenced" : "unevidenced"}`}>
              {register.artifacts_present}/5
            </span>
          ) : (
            <span className="faint">–/5</span>
          )}
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
                    <MethodRowView key={m.methodId} method={m} repo={register?.repo ?? ""} />
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
                {register.history_met === true
                  ? " · met"
                  : register.history_lapse_at
                    ? ` · status lapsed ${new Date(register.history_lapse_at).toLocaleDateString()}`
                    : register.history_met === null
                      ? " · persistence not judged (no owed window)"
                      : " · not yet met"}
              </p>
            )}

            {/* collect evidence (T4-1): the pinned AWS recipes for this KSI a
                client-deployed runner could run; the click mints a signed
                request, and the appliance judges what comes back */}
            <CollectEvidence ksi={entry.ksi} />

            {/* the artifact checklist (Q3.3, G5): five rows always, quoting
                the pinned rules' own texts. Computed rows name the fact they
                rest on; judged rows show the signed two-key judgment or the
                honest absence — and a propose form, because the judgment
                queue starts here, never a checkbox */}
            {register && (register.artifacts?.length ?? 0) > 0 && (
              <ArtifactChecklist register={register} texts={entry.artifacts ?? []} />
            )}

            {/* the crosswalk drawer: controls demoted to annotation — the
                dataset already carries them per KSI, and the register never
                joins through them (SPEC §12.2) */}
            <p className="faint" style={{ margin: "4px 0" }}>
              <Term name="control">controls crosswalk</Term>:{" "}
              {entry.controls.map((c) => (
                <EntityLink key={c} kind="control" id={c} repo={register?.repo} style={{ marginRight: 8 }} />
              ))}
            </p>
          </td>
        </tr>
      )}
    </>
  );
}

/**
 * The five owed artifacts for one (repo, KSI) — default_artifacts.KSI in the
 * rules' own order. Since R1.1 a cell is present when a signed BODY fills it:
 * the row names where those bytes came from, when their three-month clock
 * started, and what a judgment has said about them. An empty computed cell
 * says whether the fold could generate it, which is a work queue rather than
 * a scold. The judgment form stays exactly as it was — this view reads the
 * plane and never writes it (R1.6: if this grows an artifact editor, the plan
 * has failed).
 */
function ArtifactChecklist({
  register,
  texts,
}: {
  register: MethodRegisterRecord;
  texts: string[];
}) {
  return (
    <div style={{ margin: "8px 0" }}>
      <div className="section-title" style={{ margin: "0 0 4px" }}>
        owed artifacts: {register.artifacts_present}/5 (default_artifacts.KSI)
      </div>
      <table className="reg" style={{ margin: "4px 0 8px" }}>
        <tbody>
          {register.artifacts.map((cell) => (
            <ArtifactRowView
              key={cell.artifact}
              cell={cell}
              text={texts[cell.artifact - 1] ?? ""}
              repo={register.repo}
              ksi={register.ksi}
            />
          ))}
        </tbody>
      </table>
    </div>
  );
}

function ArtifactRowView({
  cell,
  text,
  repo,
  ksi,
}: {
  cell: ArtifactCellRecord;
  text: string;
  repo: string;
  ksi: string;
}) {
  const [proposing, setProposing] = useState(false);
  const derivable =
    cell.artifact === 5
      ? "no body yet — derivable from the methods' own live evidence"
      : "no body yet — derivable from the scheduler's cadence record";
  const origin = cell.body
    ? `${cell.body.source} · ${cell.body.bodyBytes} bytes · clock from ${cell.body.validFrom.slice(0, 10)}` +
      (cell.body.freshMet === false ? " (past VDR-TFR-NMV)" : "") +
      (cell.body.anchor ? ` · ${cell.body.anchor.path}` : "") +
      (cell.body.reviewed ? " · reviewed" : " · no review on record")
    : cell.absent
      ? `the body that stood here is gone — ${cell.absent.reason} (${cell.absent.path}, seen ${cell.absent.at.slice(0, 10)})`
      : cell.basis === "computed"
        ? cell.derivable
          ? derivable
          : "no body, and nothing to generate one from"
        : "no body recorded";
  const verdict = cell.judgment
    ? `judged ${cell.judgment.action} — proposed ${cell.judgment.proposedBy}, approved ${cell.judgment.approvedBy}` +
      (cell.judgment.appliesToLiveBody ? "" : " (about bytes that have since been revised)")
    : cell.basis === "judged"
      ? "no judgment recorded"
      : "computed — no signature may override it";
  const basis = `${origin} · ${verdict}`;
  return (
    <>
      <tr>
        <td style={{ whiteSpace: "nowrap" }}>
          <span className={`pill ${cell.present ? "evidenced" : "unevidenced"}`}>
            {cell.artifact} · {cell.present ? "present" : "absent"}
          </span>
        </td>
        <td className="muted" style={{ fontSize: 12.5 }}>
          {text}
          <div className="faint" style={{ marginTop: 2 }}>
            {basis}
            {cell.body && (
              <>
                {" "}·{" "}
                {/* the artifact's own read-only page (R1.6) — NOT /evidence,
                    which reads the projection's bundles collection and holds no
                    artifact statement */}
                <EntityLink kind="artifact" digest={cell.body.digest}>
                  {cell.body.bodyDigest.slice(0, 12)}…
                </EntityLink>
              </>
            )}
            {cell.judgment && (
              <>
                {" "}·{" "}
                <EntityLink kind="evidence" digest={cell.judgment.digest} />
              </>
            )}
            {/* R1.1: a judgment names the bytes it approved (§13.6), so there
                is nothing to propose until a body fills the slot */}
            {cell.basis === "judged" && cell.body && (
              <>
                {" "}·{" "}
                <button
                  type="button"
                  className="btn"
                  style={{ fontSize: 11.5, padding: "0 6px" }}
                  onClick={(e) => {
                    e.stopPropagation();
                    setProposing((v) => !v);
                  }}
                >
                  {proposing ? "cancel" : "propose judgment"}
                </button>
              </>
            )}
          </div>
        </td>
      </tr>
      {proposing && (
        <tr>
          {/* the click stops the row's toggle; a key press never reached the row, so there is nothing to stop */}
          <td colSpan={2} onClick={(e) => e.stopPropagation()} onKeyDown={(e) => e.stopPropagation()}>
            <ProposeJudgmentForm
              repo={repo}
              ksi={ksi}
              artifact={cell.artifact}
              done={() => setProposing(false)}
            />
          </td>
        </tr>
      )}
    </>
  );
}

function ProposeJudgmentForm({
  repo,
  ksi,
  artifact,
  done,
}: {
  repo: string;
  ksi: string;
  artifact: number;
  done: () => void;
}) {
  const { user } = useAuth();
  const [justification, setJustification] = useState("");
  const [action, setAction] = useState<"sufficient" | "insufficient">("sufficient");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [sent, setSent] = useState(false);

  async function submit() {
    if (!user) return;
    setBusy(true);
    setError(null);
    try {
      await getPb().collection("judgment_proposals").create({
        repo,
        ksi_id: ksi,
        artifact,
        action,
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

  if (sent) {
    return (
      <p className="muted">proposal filed — an approver’s key turn makes it real (Approvals tab)</p>
    );
  }
  return (
    <div style={{ padding: "6px 0 10px" }}>
      <p className="muted" style={{ margin: "0 0 8px" }}>
        Propose artifact {artifact} of <code>{ksi}</code> as{" "}
        <select
          value={action}
          onChange={(e) => setAction(e.target.value as "sufficient" | "insufficient")}
        >
          <option value="sufficient">sufficient</option>
          <option value="insufficient">insufficient</option>
        </select>{" "}
        for <RepoName repo={repo} className="mono" />. The justification is what the approver signs.
      </p>
      <textarea
        rows={2}
        placeholder="why this artifact is (in)sufficient for this KSI…"
        value={justification}
        onChange={(e) => setJustification(e.target.value)}
      />
      <div style={{ marginTop: 8, display: "flex", gap: 8 }}>
        <button
          type="button"
          className="btn primary"
          disabled={busy || justification.trim().length === 0}
          onClick={submit}
        >
          file proposal
        </button>
        <button type="button" className="btn" onClick={done}>
          cancel
        </button>
      </div>
      {error && <p className="error">{error}</p>}
    </div>
  );
}

/** one method, interrogable: what walked, what it claims, where the signature is */
function MethodRowView({ method, repo }: { method: MethodCellRecord; repo: string }) {
  return (
    <tr>
      <td>
        <span className={`pill ${method.state}`}>
          {method.state === "notApplicable" ? "n/a" : method.state}
        </span>
      </td>
      <td className="mono">
        {/* a pipeline method IS its recipe's cell on this repo — one level down (L3) */}
        {method.recipeId ? (
          <EntityLink kind="check" recipe={method.recipeId} repo={repo}>
            {method.methodId}
          </EntityLink>
        ) : (
          method.methodId
        )}
      </td>
      <td className="muted">
        {method.source}
        {method.automated ? "" : " · not automated"}
        {method.collector ? ` · ${method.collector}` : ""}
        {/* the evidence-class assertion (Q3.4, G6): rendered only when the
            live bundle signed one — never inferred for unlabeled evidence */}
        {method.evidenceClass ? ` · ${method.evidenceClass}` : ""}
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
          <EntityLink kind="evidence" digest={method.bundleDigest}>
            evidence → {method.bundleDigest.slice(0, 12)}…
          </EntityLink>
        ) : (
          <span className="faint">no live evidence</span>
        )}
      </td>
    </tr>
  );
}
