import { describe, expect, it } from "vitest";
import type { IngestSubmission } from "@rampscan/schema";
import { EvidenceBundle, INGEST_SUBMISSION_TYPE } from "@rampscan/schema";
import { ingestDigest, sameEvidence, toIngestedBundle } from "../src/index.js";

// The mint (SPEC §12.8, Q4.1): an IngestSubmission becomes a regular
// EvidenceBundle — computed fields only, the handoff pinned by digest, and
// evidence identity keyed on that handoff so a different signer or different
// submitted bytes is different evidence.

const submission: IngestSubmission = {
  _type: INGEST_SUBMISSION_TYPE,
  recipe_id: "KSI-CNA-RVP.sh",
  ksi: "KSI-CNA-RVP",
  evidence_class: "process-generated",
  cadence: "daily",
  artifacts: [
    { name: "Evidence/cna/KSI-CNA-RVP/KSI-CNA-RVP.json", sha256: "a".repeat(64) },
    { name: "Evidence/cna/KSI-CNA-RVP/KSI-CNA-RVP.csv", sha256: "b".repeat(64) },
  ],
  assertions: [
    {
      description: "KSI-CNA-RVP.sh validation (exit code)",
      passed: true,
      detail: "exit 0",
      population: 2,
    },
  ],
  timestamp: "2026-09-10T14:00:00Z",
  signer_identity: "compliance-ops@synthetic-csp.example",
  tool_versions: { "aws-cli": "2.17.0" },
};

const ctx = { repo: "synthetic-csp/offering", datasetVersion: "2026.07.14.01" };

describe("toIngestedBundle", () => {
  it("mints a schema-valid bundle with every claim computed from the submission", () => {
    const bundle = toIngestedBundle(submission, ctx);
    expect(() => EvidenceBundle.parse(bundle)).not.toThrow();

    const p = bundle.predicate;
    expect(bundle.subject).toEqual([
      { name: "Evidence/cna/KSI-CNA-RVP/KSI-CNA-RVP.json", digest: { sha256: "a".repeat(64) } },
      { name: "Evidence/cna/KSI-CNA-RVP/KSI-CNA-RVP.csv", digest: { sha256: "b".repeat(64) } },
    ]);
    expect(p.method_id).toBe("aws-ingested:KSI-CNA-RVP.sh#KSI-CNA-RVP");
    expect(p.evidence_class).toBe("process-generated");
    expect(p.verdict).toBe("evidenced");
    expect(p.ksi_ids).toEqual(["KSI-CNA-RVP"]);
    expect(p.control_ids).toEqual([]);
    // no commit anchor: ingested evidence dies superseded or goes stale,
    // never by anchor drift
    expect(p.commit).toBe("");
    expect(p.anchor_paths).toEqual([]);
    expect(p.timestamp).toBe(submission.timestamp);
    // the handoff, pinned: the digest of the canonical submission, and a
    // run id derived from it — never typed
    expect(p.ingest).toEqual({
      signer_identity: "compliance-ops@synthetic-csp.example",
      ingest_digest: ingestDigest(submission),
    });
    expect(p.run_id).toBe(`ingest:${ingestDigest(submission).slice(0, 12)}`);
  });

  it("computes violated from any failing assertion", () => {
    const failing: IngestSubmission = {
      ...submission,
      assertions: [{ description: "x", passed: false, detail: "exit 3" }],
    };
    expect(toIngestedBundle(failing, ctx).predicate.verdict).toBe("violated");
  });

  it("is deterministic: same submission, same bytes, same digest", () => {
    expect(toIngestedBundle(submission, ctx)).toEqual(toIngestedBundle(submission, ctx));
    expect(ingestDigest(submission)).toBe(ingestDigest({ ...submission }));
  });
});

describe("sameEvidence over the ingest block", () => {
  it("keys on the handoff: a different signer is different evidence", () => {
    const a = toIngestedBundle(submission, ctx);
    const b = toIngestedBundle(
      { ...submission, signer_identity: "someone-else@synthetic-csp.example" },
      ctx,
    );
    expect(sameEvidence(a, a)).toBe(true);
    expect(sameEvidence(a, b)).toBe(false);
  });

  it("keys on the submitted bytes: a re-run at a new timestamp supersedes", () => {
    const a = toIngestedBundle(submission, ctx);
    const b = toIngestedBundle({ ...submission, timestamp: "2026-09-11T14:00:00Z" }, ctx);
    expect(sameEvidence(a, b)).toBe(false);
  });
});
