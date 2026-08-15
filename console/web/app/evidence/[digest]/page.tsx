"use client";

import Link from "next/link";
import { use, useEffect, useState } from "react";
import { DownloadButton } from "../../../components/DownloadButton";
import { RequireAuth } from "../../../components/guard";
import { getPb } from "../../../lib/pb";
import { describePointer } from "../../../lib/pointers";
import { runCounts } from "../../../lib/runs";
import type {
  BundleRecord,
  CollectorRunRecord,
  CoverageRecord,
  MetaRecord,
  OffenderPointer,
} from "../../../lib/types";

// Evidence detail (SPEC §8.1): each row opens the evidence — artifacts,
// assertions, commit, signature, reproduce command. Everything shown here is
// the signed statement itself, read from the projection's copy of the bundle;
// `rampscan verify <digest>` re-checks it offline against the ledger.

export default function EvidencePage({ params }: { params: Promise<{ digest: string }> }) {
  const { digest } = use(params);
  return (
    <RequireAuth>
      <Evidence digest={digest} />
    </RequireAuth>
  );
}

interface AssertionResult {
  description: string;
  passed: boolean;
  detail?: string;
  /** structured fix pointers (I2c) — bundles minted since carry them */
  offenders?: OffenderPointer[];
  offender_count?: number;
}

// Pre-I2c fallback: older bundles carry no structured offenders, only the one
// example row embedded in the detail prose — scrape its call path out so old
// evidence keeps showing what it always showed. New bundles never hit this.
function callPathsIn(detail: string | undefined): string[] {
  if (!detail) return [];
  return [...detail.matchAll(/"(?:call_)?path":"([^"]+)"/g)]
    .map((m) => m[1]!)
    .filter((p) => p.includes("»"));
}

function Evidence({ digest }: { digest: string }) {
  const [bundle, setBundle] = useState<BundleRecord | null>(null);
  const [coverage, setCoverage] = useState<CoverageRecord | null>(null);
  const [meta, setMeta] = useState<MetaRecord | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const pb = getPb();
    pb.collection("bundles")
      .getFirstListItem<BundleRecord>(`digest="${digest}"`)
      .then(setBundle)
      .catch(() => setError(`no bundle with digest ${digest} in the projection`));
    pb.collection("coverage")
      .getFirstListItem<CoverageRecord>(`bundle_digest="${digest}"`)
      .then(setCoverage)
      .catch(() => {});
    pb.collection("meta")
      .getFullList<MetaRecord>()
      .then((rows) => setMeta(rows[0] ?? null))
      .catch(() => {});
  }, [digest]);

  if (error) return <p className="error">{error}</p>;
  if (!bundle) return <p className="muted">loading…</p>;

  const p = bundle.statement.predicate as Record<string, any>;
  // Three statement kinds live in the ledger now (J1), so the page branches on
  // the kind rather than on "evidence or else scoping" — a run record landing
  // in the `else` would have rendered as a notApplicable scoping, which is a
  // wrong page, not a rough one.
  const kind = bundle.statement.predicateType;
  const isEvidence = kind === "https://rampscan.dev/evidence/v1";
  const isScoping = kind === "https://rampscan.dev/scoping/v1";
  const isScanRun = kind === "https://rampscan.dev/scan-run/v1";
  const runCollectors = (p["collectors"] as Array<Record<string, any>>) ?? [];
  const assertions: AssertionResult[] = (p["assertions"] as AssertionResult[]) ?? [];
  const anchorPaths = new Set(
    ((p["anchor_paths"] as Array<{ path: string }>) ?? []).map((a) => a.path),
  );

  return (
    <>
      <p>
        <Link href="/">← board</Link>
      </p>
      <h1 className="mono" style={{ fontSize: 16 }}>
        {isScanRun ? p["run_id"] : p["recipe_id"]}{" "}
        {isEvidence && <span className={`pill ${p["verdict"]}`}>{p["verdict"]}</span>}
        {isScoping && <span className="pill notApplicable">notApplicable</span>}
        {/* a run record states no verdict, by design — it says what RAN */}
        {isScanRun && <span className="pill">scan run · {p["trigger"]}</span>}{" "}
        {coverage && <span className={`pill ${coverage.state}`}>{coverage.state}</span>}
      </h1>
      <p className="subtitle mono">{digest}</p>
      <p className="subtitle" style={{ marginTop: -14 }}>
        {/* what the bundle already carries (I3b), surfaced where an auditor
            lands — every value below is the signed predicate's own claim */}
        {isEvidence && (
          <>
            scanned commit <span className="mono">{String(p["commit"]).slice(0, 12)}</span> ·{" "}
          </>
        )}
        dataset pin <span className="mono">{p["dataset_version"]}</span>
        {isEvidence && Object.keys((p["tool_versions"] as Record<string, string>) ?? {}).length > 0 && (
          <>
            {" "}
            · tools{" "}
            <span className="mono">
              {Object.entries((p["tool_versions"] as Record<string, string>) ?? {})
                .map(([tool, version]) => `${tool} ${version}`)
                .join(", ")}
            </span>
          </>
        )}
      </p>

      <div className="panel">
        <dl className="kv">
          <dt>repo</dt>
          <dd className="mono">{p["repo"]}</dd>
          {isEvidence && (
            <>
              <dt>commit anchor</dt>
              <dd className="mono">{p["commit"]}</dd>
            </>
          )}
          {/* a run record maps to no KSI or control: it is about a scan, not
              about a requirement, and inventing a mapping would be the second
              source of truth /runs must never become */}
          {!isScanRun && (
            <>
              <dt>ksi</dt>
              <dd className="mono">
                {/* the traversal's back edge (I3a): bundle → KSI → its register rollup */}
                {((p["ksi_ids"] as string[]) ?? []).map((k) => (
                  <Link key={k} href={`/controls?reg=ksis&id=${encodeURIComponent(k)}`} style={{ marginRight: 10 }}>
                    {k}
                  </Link>
                ))}
              </dd>
              <dt>controls</dt>
              <dd className="mono">
                {((p["control_ids"] as string[]) ?? []).map((c) => (
                  <Link key={c} href={`/controls?reg=controls&id=${encodeURIComponent(c)}`} style={{ marginRight: 10 }}>
                    {c}
                  </Link>
                ))}
              </dd>
            </>
          )}
          <dt>timestamp</dt>
          <dd>{p["timestamp"]}</dd>
          {isEvidence && (
            <>
              <dt>run</dt>
              <dd className="mono">{p["run_id"]}</dd>
              <dt>tool versions</dt>
              <dd className="mono">
                {Object.entries((p["tool_versions"] as Record<string, string>) ?? {})
                  .map(([tool, version]) => `${tool} ${version}`)
                  .join(", ")}
              </dd>
              <dt>cadence</dt>
              <dd>{p["cadence"]}</dd>
            </>
          )}
          {isScoping && (
            <>
              <dt>justification</dt>
              <dd>{p["justification"]}</dd>
              <dt>proposed by</dt>
              <dd>{p["proposed_by"]}</dd>
              <dt>approved by</dt>
              <dd>{p["approved_by"]}</dd>
            </>
          )}
          {isScanRun && (
            <>
              <dt>commit</dt>
              <dd className="mono">{p["commit"]}</dd>
              <dt>trigger</dt>
              <dd className="mono">{p["trigger"]}</dd>
              <dt>started</dt>
              <dd>{p["started_at"]}</dd>
              <dt>duration</dt>
              <dd>{Math.round(Number(p["duration_ms"]) / 100) / 10}s</dd>
              <dt>collectors</dt>
              {/* counted from the rows, never typed — and counted by the SAME
                  hand /runs counts with (J2), so the two pages cannot disagree
                  about one run. The buckets partition: ran + cache-hit +
                  skipped is exactly the number dispatched. */}
              <dd>
                {(() => {
                  const counts = runCounts(runCollectors as unknown as CollectorRunRecord[]);
                  return `${counts.dispatched} dispatched · ${counts.ran} ran · ${counts.cacheHit} cache-hit · ${counts.skipped} skipped`;
                })()}
              </dd>
            </>
          )}
          <dt>dataset</dt>
          <dd className="mono">{p["dataset_version"]}</dd>
          {coverage && coverage.state === "dead" && (
            <>
              <dt>died</dt>
              <dd>
                {coverage.cause}
                {coverage.killing_commit && (
                  <>
                    {" "}
                    — killed by <span className="mono">{coverage.killing_commit.slice(0, 12)}</span>
                  </>
                )}
              </dd>
            </>
          )}
        </dl>
      </div>

      {isScanRun && (
        <>
          <div className="section-title">Collectors</div>
          <div className="panel">
            <table className="reg">
              <tbody>
                {runCollectors.map((c) => {
                  const tools = (c["tools"] as Array<Record<string, any>>) ?? [];
                  const runtime = tools
                    .map((t) => {
                      const r = t["runtime"] as Record<string, any>;
                      if (r["kind"] === "docker") return `${t["tool"]} @ ${r["image"]}`;
                      if (r["kind"] === "binary") return `${t["tool"]} @ ${r["path"] ?? "PATH"}`;
                      return `${t["tool"]} absent`;
                    })
                    .join(", ");
                  return (
                    <tr key={String(c["collector"])}>
                      <td className="mono">{c["collector"]}</td>
                      <td className="mono faint">{c["tool_version"]}</td>
                      <td className="faint">{c["cache"]?.["state"]}</td>
                      <td className="faint">{Math.round(Number(c["duration_ms"]))} ms</td>
                      <td className="faint">
                        {(c["invocations"] as unknown[])?.length ?? 0} invocation(s)
                      </td>
                      <td className="faint" style={{ overflowWrap: "anywhere" }}>
                        {/* the named reason a tool did not run — the thing an
                            operator staring at an unevidenced cell needs */}
                        {c["skip_reason"] ? (
                          <span className="assertion-fail">{c["skip_reason"]}</span>
                        ) : (
                          runtime
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </>
      )}

      {isEvidence && (
        <>
          <div className="section-title">Assertions</div>
          <div className="panel">
            <table className="reg">
              <tbody>
                {assertions.map((a, i) => (
                  <tr key={i}>
                    <td style={{ width: 40 }} className={a.passed ? "assertion-pass" : "assertion-fail"}>
                      {a.passed ? "PASS" : "FAIL"}
                    </td>
                    <td>{a.description}</td>
                    <td className="faint" style={{ overflowWrap: "anywhere" }}>
                      {a.detail ?? ""}
                      {a.offenders ? (
                        // structured offenders (I2c): every failing row's
                        // pointer, bounded — the count says what was cut
                        <>
                          {a.offenders.map((o, j) => (
                            <div key={j} className="mono" style={{ marginTop: 4 }}>
                              {describePointer(o)}
                              {/* describePointer falls back to the call path only when the
                                  pointer has nothing else — otherwise it gets its own line */}
                              {o.call_path && (o.file || o.check) && (
                                <div className="faint">call path: {o.call_path}</div>
                              )}
                            </div>
                          ))}
                          {(a.offender_count ?? 0) > a.offenders.length && (
                            <div style={{ marginTop: 4 }}>
                              +{a.offender_count! - a.offenders.length} more failing row(s) — the
                              artifact carries them all
                            </div>
                          )}
                        </>
                      ) : (
                        // pre-I2c bundle: the example row in the prose is all it carries
                        callPathsIn(a.detail).map((p, j) => (
                          <div key={j} className="mono" style={{ marginTop: 4 }}>
                            call path: {p}
                          </div>
                        ))
                      )}
                    </td>
                  </tr>
                ))}
                {assertions.length === 0 && (
                  <tr>
                    <td className="empty">no assertions recorded</td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </>
      )}

      <div className="section-title">Subjects (artifacts + anchors)</div>
      <div className="panel">
        <table className="reg">
          <thead>
            <tr>
              <th>Name</th>
              <th>Kind</th>
              <th>sha256</th>
            </tr>
          </thead>
          <tbody>
            {bundle.statement.subject.map((s, i) => (
              <tr key={i}>
                <td className="mono">{s.name}</td>
                <td className="faint">{anchorPaths.has(s.name) ? "anchor — drift here kills this evidence" : "artifact"}</td>
                <td className="mono faint">{s.digest["sha256"]}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="section-title">Signature</div>
      <div className="panel">
        <dl className="kv">
          <dt>envelope</dt>
          <dd>{bundle.envelope ? `DSSE / ${bundle.envelope.payloadType}` : "UNSIGNED (should not happen)"}</dd>
          {bundle.envelope && (
            <>
              <dt>key id</dt>
              <dd className="mono">{bundle.envelope.signatures[0]?.keyid}</dd>
              <dt>signature</dt>
              <dd className="mono faint">{bundle.envelope.signatures[0]?.sig.slice(0, 64)}…</dd>
            </>
          )}
          <dt>appended</dt>
          <dd>{bundle.appended_at}</dd>
        </dl>
      </div>

      <div className="section-title">Verify this yourself</div>
      <div className="panel" style={{ padding: "12px 14px" }}>
        <p className="muted" style={{ margin: "0 0 10px", fontSize: 13 }}>
          Don&apos;t trust this page — it renders a projection. The record is the signed envelope:
          its payload is the exact canonical statement (sha256 of those bytes is this bundle&apos;s
          digest), signed ECDSA P-256 over the DSSE PAE — the same attestation envelope cosign
          uses, verifiable with the public key and standard crypto alone.
        </p>
        <div style={{ display: "flex", gap: 8, marginBottom: 10 }}>
          <DownloadButton
            label="download DSSE bundle"
            url={`/api/verify/bundle?digest=${digest}`}
            filename={`${digest}.envelope.json`}
            disabled={!bundle.envelope}
            note="appended unsigned, nothing to verify"
          />
          <DownloadButton
            label="download public key"
            url="/api/verify/key"
            filename="rampscan.pub"
          />
        </div>
        <code className="copycmd">
          {(meta?.settings?.verifyCommand ?? "pnpm rampscan verify <digest>").replace(
            "<digest>",
            digest,
          )}
        </code>
      </div>

      <div className="section-title">Reproduce</div>
      <code className="copycmd">
        {isEvidence ? (meta?.settings?.reproduceCommand ?? "pnpm rampscan scan <repo-path>").replace("<repo-path>", String(p["repo"])) : `pnpm rampscan verify ${digest}`}
        {/* the collector's own re-run statement (I2c), when the evidence carries one */}
        {isEvidence && typeof p["reproduce"] === "string"
          ? `\n${(p["reproduce"] as string).replace("<repo>", String(p["repo"]))}`
          : ""}
      </code>

      <div className="section-title">Raw statement</div>
      <pre className="raw">{JSON.stringify(bundle.statement, null, 2)}</pre>
    </>
  );
}
