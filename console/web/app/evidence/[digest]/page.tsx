"use client";

import Link from "next/link";
import { use, useEffect, useState } from "react";
import { RequireAuth } from "../../../components/guard";
import { getPb } from "../../../lib/pb";
import type { BundleRecord, CoverageRecord, MetaRecord } from "../../../lib/types";

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
}

// M4: advisory and route rows carry the call path as the artifact; the SAST
// gate's rows carry it as `call_path` — surface every one embedded in an
// assertion's example row as its own line.
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
  const isEvidence = bundle.statement.predicateType === "https://rampscan.dev/evidence/v1";
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
        {p["recipe_id"]}{" "}
        {isEvidence ? (
          <span className={`pill ${p["verdict"]}`}>{p["verdict"]}</span>
        ) : (
          <span className="pill notApplicable">notApplicable</span>
        )}{" "}
        {coverage && <span className={`pill ${coverage.state}`}>{coverage.state}</span>}
      </h1>
      <p className="subtitle mono">{digest}</p>

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
          <dt>ksi</dt>
          <dd className="mono">{(p["ksi_ids"] as string[]).join(" ")}</dd>
          <dt>controls</dt>
          <dd className="mono">{(p["control_ids"] as string[]).join(" ")}</dd>
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
          {!isEvidence && (
            <>
              <dt>justification</dt>
              <dd>{p["justification"]}</dd>
              <dt>proposed by</dt>
              <dd>{p["proposed_by"]}</dd>
              <dt>approved by</dt>
              <dd>{p["approved_by"]}</dd>
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
                      {callPathsIn(a.detail).map((p, j) => (
                        <div key={j} className="mono" style={{ marginTop: 4 }}>
                          call path: {p}
                        </div>
                      ))}
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

      <div className="section-title">Reproduce</div>
      <code className="copycmd">
        {`pnpm rampscan verify ${digest}`}
        {isEvidence ? `\n${(meta?.settings?.reproduceCommand ?? "pnpm rampscan scan <repo-path>").replace("<repo-path>", String(p["repo"]))}` : ""}
      </code>

      <div className="section-title">Raw statement</div>
      <pre className="raw">{JSON.stringify(bundle.statement, null, 2)}</pre>
    </>
  );
}
