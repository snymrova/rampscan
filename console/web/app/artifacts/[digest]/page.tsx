"use client";

import Link from "next/link";
import { use, useEffect, useState } from "react";
import { DownloadButton } from "../../../components/DownloadButton";
import { EntityLink, RepoName } from "../../../components/EntityLink";
import { RequireAuth } from "../../../components/guard";
import { getPb } from "../../../lib/pb";

// The artifact view (plan R1.6, SPEC §13.2) — READ-ONLY, and structurally so:
// there is no form on this page and no write route behind it. The artifact
// editor is not built, and if this page starts growing one the plan has failed
// (plan §4.2): a general document editor loses the fight with Paramify and the
// GRC platforms, and what nobody else ships is an artifact bound to evidence,
// an anchor and a review record, with a clock on it.
//
// What it shows instead is where the words came from. The "where this came
// from" drawer is the whole point of the page: an assessor should be able to
// read a sentence of compliance prose and, without leaving it, see who stood
// behind it, when its three-month clock started, which commit anchors it, what
// generated it if anything did, what it revised, and whether anyone is on
// record as having reviewed it — with the absence printed rather than assumed
// benign (§13.2).
//
// The body is shown as the BYTES THAT WERE SIGNED, not as rendered markdown.
// The digest addresses those bytes exactly; a rendering is a second version of
// the artifact, and the one place a reader might check what was signed should
// not be showing them something else. R5's reviewer surface is where a rendered
// package belongs.

interface ArtifactAnchor {
  commit: string;
  path: string;
}

interface ArtifactGenerator {
  pins: Record<string, string>;
  tool_versions: Record<string, string>;
  journal_digest?: string;
}

interface ArtifactReview {
  source: string;
  reference: string;
  approvers: string[];
  timestamp: string;
}

interface ArtifactPredicate {
  ksi_id: string;
  artifact: 1 | 2 | 3 | 4 | 5;
  repo: string;
  source: "authored" | "computed" | "attested" | "assessed";
  body: string;
  body_digest: string;
  anchor?: ArtifactAnchor;
  generator?: ArtifactGenerator;
  review?: ArtifactReview;
  supersedes?: string;
  valid_from: string;
  dataset_version: string;
  timestamp: string;
}

const SOURCE_NOTE: Record<ArtifactPredicate["source"], string> = {
  authored:
    "a file in the scanned repository, commit-anchored — it lives beside the code, moves through the same review, and dies by anchor drift when the thing it describes changes",
  computed:
    "rampscan generated these bytes from the fold. Legitimate for artifacts 2, 4 and 5 only: 1 and 3 are the provider's own claims and the schema refuses to compute them (§13.4)",
  attested: "the two-key path of §12.9 — the attestation is this body's signature",
  assessed: "ingested from an independent assessor rather than typed, so ksiAssessment has a provenance",
};

export default function ArtifactPage({ params }: { params: Promise<{ digest: string }> }) {
  const { digest } = use(params);
  return (
    <RequireAuth>
      <ArtifactBody digest={digest} />
    </RequireAuth>
  );
}

function ArtifactBody({ digest }: { digest: string }) {
  const [predicate, setPredicate] = useState<ArtifactPredicate | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    void (async () => {
      try {
        const response = await fetch(`/api/artifacts/body?digest=${digest}`, {
          headers: { Authorization: getPb().authStore.token },
        });
        const payload = (await response.json()) as {
          predicate?: ArtifactPredicate;
          error?: string;
        };
        if (!live) return;
        if (!response.ok || payload.predicate === undefined) {
          setError(payload.error ?? `${response.status} ${response.statusText}`);
          return;
        }
        setPredicate(payload.predicate);
      } catch (cause) {
        if (live) setError(cause instanceof Error ? cause.message : String(cause));
      }
    })();
    return () => {
      live = false;
    };
  }, [digest]);

  if (error !== null) {
    return (
      <>
        <h1>artifact</h1>
        <p className="muted">{error}</p>
        <p>
          <Link href="/">← the board</Link>
        </p>
      </>
    );
  }
  if (predicate === null) return <p className="muted">loading…</p>;

  const bytes = new TextEncoder().encode(predicate.body).length;

  return (
    <>
      <h1>
        <EntityLink kind="ksi" id={predicate.ksi_id} repo={predicate.repo} className="" /> · artifact{" "}
        {predicate.artifact}
      </h1>
      <p className="muted">
        <RepoName repo={predicate.repo} /> ·{" "}
        <span className="mono" data-entity="digest" title={predicate.body_digest}>
          {predicate.body_digest.slice(0, 16)}…
        </span>{" "}
        ·{" "}
        {bytes} bytes
      </p>

      <div className="section-title">the body, as it was signed</div>
      <pre
        style={{
          whiteSpace: "pre-wrap",
          wordBreak: "break-word",
          border: "1px solid var(--border)",
          borderRadius: 4,
          padding: "10px 12px",
          margin: "6px 0 14px",
          fontSize: 12.5,
          lineHeight: 1.55,
        }}
      >
        {predicate.body}
      </pre>
      <p className="faint" style={{ fontSize: 11.5, marginTop: -8 }}>
        Shown as the bytes the signature covers, not as rendered markdown: the digest above
        addresses exactly these characters, and a rendering would be a second version of the
        artifact.
      </p>

      <div className="section-title" style={{ marginTop: 18 }}>
        where this came from
      </div>
      <table className="reg">
        <tbody>
          <Row label="source">
            <span className="mono">{predicate.source}</span>
            <div className="faint" style={{ fontSize: 11.5, marginTop: 2 }}>
              {SOURCE_NOTE[predicate.source]}
            </div>
          </Row>
          <Row label="clock">
            <span className="mono">{predicate.valid_from}</span>
            <div className="faint" style={{ fontSize: 11.5, marginTop: 2 }}>
              VDR-TFR-NMV owes three months, whatever the source (§13.5). An artifact is not done
              when it is written — SDR-CSX-KSI item 2 asks for the cycle.
            </div>
          </Row>
          {predicate.anchor && (
            <Row label="anchor">
              <span className="mono">
                {predicate.anchor.path} @ {predicate.anchor.commit.slice(0, 12)}
              </span>
              <div className="faint" style={{ fontSize: 11.5, marginTop: 2 }}>
                the commit that last touched this file — not the commit that was scanned, or the
                clock would restart every time anyone ran a scan
              </div>
            </Row>
          )}
          {predicate.generator && (
            <Row label="generator">
              <div className="mono" style={{ fontSize: 12 }}>
                {Object.entries(predicate.generator.pins).map(([key, value]) => (
                  <div key={key}>
                    {key} = {value}
                  </div>
                ))}
                {Object.entries(predicate.generator.tool_versions).map(([tool, version]) => (
                  <div key={tool}>
                    {tool} {version}
                  </div>
                ))}
              </div>
              {predicate.generator.journal_digest && (
                <div className="faint" style={{ fontSize: 11.5, marginTop: 2 }}>
                  from the signed execution record{" "}
                  <span className="mono">{predicate.generator.journal_digest.slice(0, 12)}…</span> —
                  `rampscan verify` renders it
                </div>
              )}
            </Row>
          )}
          <Row label="review">
            {predicate.review ? (
              <>
                <span className="mono">{predicate.review.reference}</span>
                <div className="faint" style={{ fontSize: 11.5, marginTop: 2 }}>
                  {predicate.review.source} ·{" "}
                  {predicate.review.approvers.join(", ") || "no approvers named"} ·{" "}
                  {predicate.review.timestamp}
                </div>
              </>
            ) : (
              <>
                <span className="muted">none on record</span>
                <div className="faint" style={{ fontSize: 11.5, marginTop: 2 }}>
                  Printed rather than assumed benign (§13.2). An artifact whose review is unknown
                  and an artifact that was reviewed are different facts; the forge plane (R4) is
                  what fills this in.
                </div>
              </>
            )}
          </Row>
          {predicate.supersedes && (
            <Row label="supersedes">
              <EntityLink kind="artifact" digest={predicate.supersedes} />
              <div className="faint" style={{ fontSize: 11.5, marginTop: 2 }}>
                the body these bytes revise. An append-only ledger revises by writing again — the
                earlier statement is still in the ledger, and a judgment of it does not reach here
              </div>
            </Row>
          )}
          <Row label="signed">
            <span className="mono">{predicate.timestamp}</span>
            <div className="faint" style={{ fontSize: 11.5, marginTop: 2 }}>
              dataset {predicate.dataset_version}
            </div>
          </Row>
        </tbody>
      </table>

      <p style={{ marginTop: 14 }}>
        <DownloadButton
          label="download the signed envelope"
          url={`/api/verify/bundle?digest=${digest}`}
          filename={`${digest}.envelope.json`}
        />
      </p>
      <p className="faint" style={{ fontSize: 11.5 }}>
        The console asks to be distrusted: sha256 of the envelope&apos;s decoded payload reproduces
        this statement&apos;s address, and{" "}
        <span className="mono">rampscan verify {digest.slice(0, 12)}…</span> re-checks it offline.
      </p>
      <p>
        <Link href="/">← the board</Link>
      </p>
    </>
  );
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <tr>
      <td style={{ whiteSpace: "nowrap", verticalAlign: "top", width: 110 }} className="muted">
        {label}
      </td>
      <td>{children}</td>
    </tr>
  );
}
