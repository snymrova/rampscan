"use client";

import Link from "next/link";
import { use, useEffect, useState } from "react";
import { ArtifactView } from "../../../components/ArtifactView";
import { DownloadButton } from "../../../components/DownloadButton";
import { RequireAuth } from "../../../components/guard";
import { PlainLanguage } from "../../../components/PlainLanguage";
import { Term } from "../../../components/Term";
import { getPb } from "../../../lib/pb";
import { describePointer } from "../../../lib/pointers";
import {
  basisStrength,
  callPathHops,
  entrypointSourceNote,
  provenanceChain,
} from "../../../lib/provenance";
import { runCounts } from "../../../lib/runs";
import type {
  BundleRecord,
  ClaimBasisRecord,
  CollectorRunRecord,
  CoverageRecord,
  MetaRecord,
  OffenderPointer,
  RegisterRecord,
  ScanRunRecord,
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

/**
 * One call path with every hop marked (I3f). An inferred hop is where the
 * graph matched a NAME rather than resolving an import to a file it saw —
 * the chain still stands, but that link is the one to check first, so it is
 * drawn differently rather than described in a footnote.
 */
function CallPath({ path, marks }: { path: string; marks?: Array<"exact" | "inferred"> }) {
  const hops = callPathHops(path, marks);
  const inferred = hops.filter((h) => h.resolution === "inferred").length;
  const unmarked = hops.some((h) => h.resolution === "unmarked");
  return (
    <div className="callpath mono">
      {hops.map((h, i) => (
        <span key={i}>
          {i > 0 && (
            <span
              className={`hop hop-${h.resolution}`}
              title={
                h.resolution === "inferred"
                  ? "inferred edge — matched by name, not resolved to a file the walk saw"
                  : h.resolution === "exact"
                    ? "exact edge — resolved to a file the walk saw"
                    : "unmarked — this evidence predates per-hop marking"
              }
            >
              {h.resolution === "inferred" ? " ⇢ " : h.resolution === "exact" ? " → " : " » "}
            </span>
          )}
          {h.node}
        </span>
      ))}
      <span className="faint">
        {unmarked
          ? " · hops unmarked (pre-I3f evidence)"
          : inferred > 0
            ? ` · ${inferred} of ${hops.length - 1} hop(s) ⇢ inferred by name`
            : ` · all ${hops.length - 1} hop(s) → exactly resolved`}
      </span>
    </div>
  );
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

/**
 * The ground under a graph-gated verdict (I3f). Everything here is the signed
 * predicate's own `basis` — the console computes none of it, because a page
 * that derived the entry-point set from somewhere else would be describing a
 * different walk than the one that produced the verdict above it.
 */
function BasisPanel({ basis }: { basis: ClaimBasisRecord }) {
  const strength = basisStrength(basis);
  return (
    <>
      <div className="section-title">
        What this claim rests on
        {strength === "weak" && <span className="run-skips"> · WEAK GROUND ⚠</span>}
      </div>
      {/* an identifying class, not decoration: a panel that can only be found
          by the prose inside it is one paraphrase away from being a different
          panel — K1's plain-language block, which also mentions entry points,
          proved that the hard way */}
      <div className="panel basis" style={{ padding: "12px 14px" }}>
        <p style={{ margin: "0 0 10px", fontSize: 13 }}>
          {basis.approximation === "over" ? (
            <>
              This verdict rests on an <strong>over-approximate</strong> walk of the code graph.{" "}
            </>
          ) : (
            <>
              This verdict rests on an <strong>under-approximate</strong> walk of the code graph.{" "}
            </>
          )}
          {basis.statement}
        </p>
        {basis.degraded && (
          <p className="assertion-fail" style={{ margin: "0 0 10px", fontSize: 13 }}>
            the gate ran degraded: {basis.degraded}
          </p>
        )}
        <dl className="kv">
          <dt>entry points</dt>
          <dd className="mono">
            {basis.entrypoints.length > 0 ? (
              basis.entrypoints.map((e) => (
                <div key={e}>{e}</div>
              ))
            ) : (
              <span className="assertion-fail">
                none — the walk had no root, so nothing could be proven unreachable
              </span>
            )}
            {basis.route_roots !== undefined && basis.route_roots > 0 && (
              <div className="faint">
                + {basis.route_roots} declared route{basis.route_roots === 1 ? "" : "s"} also seeded
                the walk
              </div>
            )}
          </dd>
          <dt>where they came from</dt>
          <dd>{entrypointSourceNote(basis.entrypoint_source)}</dd>
          {(basis.entrypoints_unresolved?.length ?? 0) > 0 && (
            <>
              <dt>declared but unresolved</dt>
              {/* a dropped root silently widens every not-affected claim — the
                  one thing about an entry-point set that must never be quiet */}
              <dd className="mono assertion-fail">
                {basis.entrypoints_unresolved!.join(", ")} — named as entry points but matched no
                file the walk saw, so they seeded nothing
              </dd>
            </>
          )}
          {basis.graph && (
            <>
              <dt>the graph walked</dt>
              <dd className="mono faint">
                {basis.graph.node_count} nodes · {basis.graph.edge_count} edges (
                {basis.graph.inferred_edge_count} inferred by name) · extractor{" "}
                {basis.graph.extractor_version} · commit {basis.graph.commit.slice(0, 12)}
              </dd>
            </>
          )}
        </dl>
      </div>
    </>
  );
}

function Evidence({ digest }: { digest: string }) {
  const [bundle, setBundle] = useState<BundleRecord | null>(null);
  const [coverage, setCoverage] = useState<CoverageRecord | null>(null);
  const [meta, setMeta] = useState<MetaRecord | null>(null);
  const [error, setError] = useState<string | null>(null);
  // the run record behind this bundle (J5) — the chain's middle hops live in
  // it, and its absence is a fact with two different causes, both stated
  const [run, setRun] = useState<ScanRunRecord | null>(null);
  const [runCount, setRunCount] = useState<number | null>(null);
  // the recipe's plain-language paragraphs (K1). They live in the catalog, and
  // the catalog reaches this console on the register row's catalog join — so
  // the page reads them from the row for this bundle's (repo, recipe), and
  // renders nothing at all when there is none rather than paraphrasing the id.
  const [register, setRegister] = useState<RegisterRecord | null>(null);

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

  // the chain's run hop: fetched by the run id the predicate itself carries,
  // and the projection's own size fetched beside it so "not held" can say
  // WHICH of the two reasons applies (older than the cap vs no run records at
  // all) instead of leaving the reader to guess
  const runId = bundle ? String((bundle.statement.predicate as Record<string, unknown>)["run_id"] ?? "") : "";
  useEffect(() => {
    if (runId === "") return;
    const pb = getPb();
    pb.collection("scan_runs")
      .getFirstListItem<ScanRunRecord>(`run_id="${runId}"`)
      .then(setRun)
      .catch(() => setRun(null));
    pb.collection("scan_runs")
      .getList(1, 1)
      .then((r) => setRunCount(r.totalItems))
      .catch(() => setRunCount(0));
  }, [runId]);

  // the catalog prose for this bundle's recipe, via its register row
  const predicate = bundle
    ? (bundle.statement.predicate as Record<string, unknown>)
    : null;
  const recipeId = String(predicate?.["recipe_id"] ?? "");
  const repoOfBundle = String(predicate?.["repo"] ?? "");
  useEffect(() => {
    if (recipeId === "" || repoOfBundle === "") return;
    getPb()
      .collection("registers")
      .getFirstListItem<RegisterRecord>(
        `repo="${repoOfBundle}" && recipe_id="${recipeId}"`,
      )
      .then(setRegister)
      .catch(() => setRegister(null));
  }, [recipeId, repoOfBundle]);

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
        {isEvidence && (
          <span className={`pill ${p["verdict"]}`}>
            <Term name={String(p["verdict"])}>{p["verdict"]}</Term>
          </span>
        )}
        {isScoping && (
          <span className="pill notApplicable">
            <Term>notApplicable</Term>
          </span>
        )}
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

      {/* In plain English (K1) — expanded here, unlike the board's collapsed
          row: an auditor who lands on a bundle from a link has no context at
          all, and the check's meaning is the first thing they need. A run
          record gets none: it is a record of a scan, not an answer to a
          recipe, so there is no check to explain. */}
      {!isScanRun && register?.plain && (
        <>
          <div className="section-title">In plain English</div>
          <div className="panel" style={{ padding: "12px 14px" }}>
            <PlainLanguage plain={register.plain} recipeId={recipeId} />
          </div>
        </>
      )}

      <div className="panel">
        <dl className="kv">
          <dt>repo</dt>
          <dd className="mono">{p["repo"]}</dd>
          {isEvidence && (
            <>
              <dt><Term name="anchor">commit anchor</Term></dt>
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
          {/* the chain (J5): recipe → collector → tool → artifact → bundle,
              every hop a signed fact and every gap named where the hop would
              have been */}
          <div className="section-title">How this was produced</div>
          <div className="panel" style={{ padding: "12px 14px" }}>
            <ol className="chain">
              {provenanceChain({
                recipeId: String(p["recipe_id"]),
                collector: String(p["collector"] ?? ""),
                runId: String(p["run_id"] ?? ""),
                repo: String(p["repo"]),
                digest,
                controlIds: (p["control_ids"] as string[]) ?? [],
                subjects: bundle.statement.subject.map((s) => ({
                  name: s.name,
                  sha256: s.digest["sha256"] ?? "",
                  isAnchor: anchorPaths.has(s.name),
                })),
                run,
                runsLoaded: runCount !== null,
                runCount: runCount ?? 0,
              }).map((hop, i) => (
                <li key={i} className={`chain-hop${hop.missing ? " chain-missing" : ""}`}>
                  <span className="chain-kind faint">{hop.kind}</span>
                  <span className="chain-label mono">
                    {hop.href ? <Link href={hop.href}>{hop.label}</Link> : hop.label}
                  </span>
                  {hop.digest && (
                    <span className="mono faint" title={hop.digest}>
                      {" "}
                      {hop.digest.slice(0, 12)}
                    </span>
                  )}
                  <div className={hop.missing ? "assertion-fail" : "faint"}>
                    {hop.missing ?? hop.detail}
                  </div>
                </li>
              ))}
            </ol>
          </div>

          {/* I3f: a verdict that rests on a walk says where the walk started,
              which way it errs, and over what graph — signed with the claim */}
          {p["basis"] !== undefined && <BasisPanel basis={p["basis"] as ClaimBasisRecord} />}

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
                                  pointer has nothing else — otherwise it gets its own line,
                                  with every hop marked exact or inferred (I3f) */}
                              {o.call_path && (o.file || o.check) && (
                                <CallPath path={o.call_path} marks={o.call_path_resolutions} />
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
                        callPathsIn(a.detail).map((p, j) => <CallPath key={j} path={p} />)
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
              <th>Contents</th>
            </tr>
          </thead>
          <tbody>
            {bundle.statement.subject.map((s, i) => {
              const isAnchor = anchorPaths.has(s.name);
              return (
                <tr key={i}>
                  <td className="mono">{s.name}</td>
                  <td className="faint">{isAnchor ? "anchor — drift here kills this evidence" : "artifact"}</td>
                  <td className="mono faint">{s.digest["sha256"]}</td>
                  <td>
                    {/* An anchor is the client's own source at the scanned
                        commit — this system does not serve it, and offering a
                        button that always refuses would be worse than saying
                        so. `git show` is the answer, so `git show` is here. */}
                    {isAnchor ? (
                      <code className="faint mono" style={{ fontSize: 12 }}>
                        git show {String(p["commit"] ?? "HEAD").slice(0, 12)}:{s.name}
                      </code>
                    ) : (
                      <ArtifactView name={s.name} digest={s.digest["sha256"] ?? ""} />
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      <div className="section-title">Signature</div>
      <div className="panel">
        <dl className="kv">
          <dt>envelope</dt>
          <dd>
            {bundle.envelope ? (
              <>
                <Term>DSSE</Term> / {bundle.envelope.payloadType}
              </>
            ) : (
              "UNSIGNED (should not happen)"
            )}
          </dd>
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
