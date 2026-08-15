"use client";

import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { Suspense, useMemo, useState } from "react";
import { RequireAuth } from "../../components/guard";
import { useCollection } from "../../lib/pb";
import {
  argvLine,
  formatRunDuration,
  imageDigestNote,
  redactionCount,
  runCounts,
  runtimeKind,
  sortCollectors,
  sortRuns,
  toolLabel,
} from "../../lib/runs";
import type { CollectorRunRecord, MetaRecord, ScanRunRecord } from "../../lib/types";

// The run view (plan J2): every recorded scan, and inside each one every
// collector that was dispatched — which tool resolved, at what version,
// through a binary or a pinned image, for how long, exiting how, and whether
// the answer came from cache. The board shows conclusions; this page shows the
// machinery that produced them.
//
// Read straight from the projected `scan_runs` collection (J1) — realtime like
// every other projection view, no new server route, because the projection is
// already console-readable. Every field is the signed predicate's own claim.
//
// The rule this page lives under: it renders RUNS, never states. No verdict,
// no register state and no coverage number may be computed here — that would
// make /runs a second source of truth about the board, and the board is folded
// from evidence and scoping alone.

export default function RunsPage() {
  return (
    <RequireAuth>
      {/* useSearchParams needs a Suspense boundary for the static prerender */}
      <Suspense fallback={null}>
        <Runs />
      </Suspense>
    </RequireAuth>
  );
}

function Runs() {
  const params = useSearchParams();
  // the deep link J3's board hop lands on: /runs?scan=<run_id>&collector=<name>
  const linkedScan = params.get("scan");
  const linkedCollector = params.get("collector");
  const runs = useCollection<ScanRunRecord>("scan_runs", { sort: "-run_timestamp" });
  const meta = useCollection<MetaRecord>("meta");
  const [repo, setRepo] = useState("all");
  const [expanded, setExpanded] = useState<Map<string, boolean>>(new Map());

  const metaRow = meta.records[0];
  const sorted = useMemo(() => sortRuns(runs.records), [runs.records]);
  const repos = useMemo(() => [...new Set(sorted.map((r) => r.repo))].sort(), [sorted]);
  const filtered = repo === "all" ? sorted : sorted.filter((r) => r.repo === repo);
  // recounted from the rows on screen, never typed — the same discipline every
  // register summary on this console follows
  const skippedRuns = filtered.filter((r) => runCounts(r.collectors).skipped > 0).length;

  return (
    <>
      <h1>Runs</h1>
      <p className="subtitle">
        {metaRow
          ? `dataset ${metaRow.dataset_version} · projected ${new Date(metaRow.projected_at).toLocaleString()}`
          : "waiting for a projection"}{" "}
        · what ran, from the signed run record of each scan — a run record states no verdict, so
        nothing on this page moves a board cell. The projection keeps the newest runs; the ledger
        keeps every one of them, and each row&rsquo;s record verifies offline like any bundle.
        {skippedRuns > 0 && (
          <>
            {" "}
            ·{" "}
            <span style={{ color: "var(--unevidenced)", fontWeight: 600 }}>
              {skippedRuns} of {filtered.length} recorded scan{filtered.length === 1 ? "" : "s"} had
              a collector skip
            </span>
          </>
        )}
      </p>

      {repos.length > 1 && (
        <div className="filters">
          <select value={repo} onChange={(e) => setRepo(e.target.value)}>
            <option value="all">all repos</option>
            {repos.map((r) => (
              <option key={r}>{r}</option>
            ))}
          </select>
        </div>
      )}

      {runs.error && <p className="error">{runs.error}</p>}
      <div className="panel">
        <table className="reg">
          <thead>
            <tr>
              <th style={{ width: 30 }} />
              <th>When</th>
              <th>Commit</th>
              <th>Trigger</th>
              <th>Duration</th>
              <th>Collectors</th>
              <th>Record</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((run) => (
              <RunRow
                key={run.id}
                run={run}
                showRepo={repos.length > 1 && repo === "all"}
                open={expanded.get(run.run_id) ?? run.run_id === linkedScan}
                linkedCollector={run.run_id === linkedScan ? linkedCollector : null}
                toggle={() =>
                  setExpanded((m) => {
                    const next = new Map(m);
                    next.set(run.run_id, !(m.get(run.run_id) ?? run.run_id === linkedScan));
                    return next;
                  })
                }
              />
            ))}
            {!runs.loading && filtered.length === 0 && (
              <tr>
                <td colSpan={7} className="empty">
                  {runs.records.length === 0
                    ? "no run record in the projection — every scan appends one, but scans recorded before the run record existed have none"
                    : "no recorded scan for this repo"}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </>
  );
}

/**
 * One scan. The counts are a recount of this run&rsquo;s own collector list —
 * ran + cache-hit + skipped is exactly the number dispatched — and the skip
 * count is loud on purpose: a silently absent tool quietly turning a board
 * column unevidenced is the most confusing failure mode this system has.
 */
function RunRow({
  run,
  showRepo,
  open,
  linkedCollector,
  toggle,
}: {
  run: ScanRunRecord;
  showRepo: boolean;
  open: boolean;
  linkedCollector: string | null;
  toggle: () => void;
}) {
  const counts = runCounts(run.collectors);
  return (
    <>
      <tr className="rowlink" onClick={toggle}>
        <td className="faint">{open ? "▾" : "▸"}</td>
        <td>
          {new Date(run.run_timestamp).toLocaleString()}
          {showRepo && <div className="faint">{run.repo}</div>}
        </td>
        <td className="mono">{run.commit_sha.slice(0, 12)}</td>
        <td className="mono faint">{run.trigger_kind}</td>
        <td className="muted">{formatRunDuration(run.duration_ms)}</td>
        <td>
          {counts.dispatched} collector{counts.dispatched === 1 ? "" : "s"}:{" "}
          <span className="muted">{counts.ran} ran</span>
          {counts.cacheHit > 0 && <span className="muted"> · {counts.cacheHit} cache-hit</span>}
          {counts.skipped > 0 ? (
            <span className="run-skips"> · {counts.skipped} SKIPPED ⚠</span>
          ) : (
            <span className="faint"> · 0 skipped</span>
          )}
        </td>
        <td className="mono" onClick={(e) => e.stopPropagation()}>
          {/* the run record itself — signed, addressable, verifiable offline */}
          <Link href={`/evidence/${run.digest}`}>{run.digest.slice(0, 12)}</Link>
        </td>
      </tr>
      {open && (
        <tr>
          <td colSpan={7} style={{ paddingTop: 0 }}>
            <CollectorTable
              collectors={run.collectors}
              linkedCollector={linkedCollector}
              runId={run.run_id}
            />
          </td>
        </tr>
      )}
    </>
  );
}

function CollectorTable({
  collectors,
  linkedCollector,
  runId,
}: {
  collectors: CollectorRunRecord[];
  linkedCollector: string | null;
  runId: string;
}) {
  const rows = useMemo(() => sortCollectors(collectors), [collectors]);
  return (
    <>
      <div className="faint" style={{ fontSize: 12, margin: "2px 0 8px" }}>
        run <span className="mono">{runId}</span> — skipped collectors first, because a skip is why
        a board cell is unevidenced
      </div>
      <table className="reg subtable" data-run={runId}>
        <thead>
          <tr>
            <th style={{ width: 100 }}>Runtime</th>
            <th>Collector</th>
            <th>Version</th>
            <th>Duration</th>
            <th>Exit</th>
            <th>Findings</th>
            <th>Tools &amp; artifacts</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((c) => (
            <CollectorRow key={c.collector} c={c} linked={c.collector === linkedCollector} />
          ))}
        </tbody>
      </table>
    </>
  );
}

function CollectorRow({ c, linked }: { c: CollectorRunRecord; linked: boolean }) {
  const [showArgv, setShowArgv] = useState(linked);
  const kind = runtimeKind(c);
  const redactions = redactionCount(c);
  return (
    <tr className={linked ? "hl" : undefined}>
        <td>
          <span className={`pill runtime-${kind}`}>{kind}</span>
        </td>
        <td className="mono">{c.collector}</td>
        <td className="mono faint">{c.tool_version}</td>
        <td className="muted">{formatRunDuration(c.duration_ms)}</td>
        <td className={c.exit_code === 0 ? "faint" : "assertion-fail"}>{c.exit_code}</td>
        <td className="faint">{c.findings}</td>
        <td style={{ overflowWrap: "anywhere" }}>
          {/* the named reason a tool did not run — the thing an operator
              staring at an unevidenced cell actually needs */}
          {c.skip_reason !== undefined && (
            <div className="assertion-fail">skipped: {c.skip_reason}</div>
          )}
          {c.tools.map((t) => {
            const note = imageDigestNote(t);
            return (
              <div key={t.tool} className="mono faint" style={{ fontSize: 12 }}>
                {toolLabel(t)}
                {note && <div className="run-digest">{note}</div>}
              </div>
            );
          })}
          {c.tools.length === 0 && c.skip_reason === undefined && (
            <div className="faint" style={{ fontSize: 12 }}>
              no external tool — this collector reads the repo itself
            </div>
          )}
          {c.artifacts.length > 0 && (
            <div className="faint" style={{ fontSize: 12, marginTop: 4 }}>
              {c.artifacts.map((a) => (
                <span key={a.sha256} className="run-artifact" title={a.sha256}>
                  {a.name} <span className="mono">{a.sha256.slice(0, 12)}</span>
                </span>
              ))}
            </div>
          )}
          <div className="faint" style={{ fontSize: 12, marginTop: 4 }}>
            cache <span className="mono">{c.cache.state}</span>
            {c.cache.scope && c.cache.scope.length > 0 && (
              <> · scope <span className="mono">{c.cache.scope.join(" ")}</span></>
            )}
            {c.invocations.length > 0 && (
              <>
                {" "}
                ·{" "}
                <a
                  href="#"
                  onClick={(e) => {
                    e.preventDefault();
                    setShowArgv((v) => !v);
                  }}
                >
                  {c.invocations.length} invocation{c.invocations.length === 1 ? "" : "s"}
                </a>
                {/* the cache's honesty clause: a hit spawned nothing this run,
                    so the argv below belongs to the run that produced it */}
                {c.cache.state === "hit" && <> (recorded by the run that produced this result)</>}
                {redactions > 0 && (
                  <> · {redactions} argv token{redactions === 1 ? "" : "s"} redacted</>
                )}
              </>
            )}
          </div>
          {showArgv &&
            c.invocations.map((inv, i) => (
              <div key={i} className="run-argv mono">
                {argvLine(inv)}
                <span className="faint">
                  {" "}
                  → exit {inv.exit_code} · {formatRunDuration(inv.duration_ms)}
                </span>
              </div>
            ))}
      </td>
    </tr>
  );
}
