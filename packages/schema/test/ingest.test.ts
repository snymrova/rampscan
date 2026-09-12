import { describe, expect, it } from "vitest";
import {
  INGEST_MANIFEST_TYPE,
  INGEST_SUBMISSION_TYPE,
  IngestManifest,
  IngestSubmission,
  methodOfIngestedBundle,
  submissionVerdict,
} from "../src/index.js";

// The ingestion contract's data shape (SPEC §12.8, plan Q4.1): strict at
// every level — a misspelled field that parses to nothing is a question the
// interrogation view can no longer answer — with the verdict computed from
// assertion outcomes, never declared, and the method a pure function of the
// minted bundle's predicate.

const submission = {
  _type: INGEST_SUBMISSION_TYPE,
  recipe_id: "KSI-CNA-RVP.sh",
  ksi: "KSI-CNA-RVP",
  evidence_class: "process-generated",
  cadence: "daily",
  artifacts: [{ name: "Evidence/cna/KSI-CNA-RVP/KSI-CNA-RVP.json", sha256: "a".repeat(64) }],
  assertions: [{ description: "KSI-CNA-RVP.sh validation (exit code)", passed: true, detail: "exit 0" }],
  timestamp: "2026-09-10T14:00:00Z",
  signer_identity: "compliance-ops@synthetic-csp.example",
} satisfies IngestSubmission;

describe("IngestSubmission", () => {
  it("parses the contract shape", () => {
    expect(IngestSubmission.parse(submission)).toEqual(submission);
  });

  it("refuses an unknown field — strict, the contract rule", () => {
    expect(() => IngestSubmission.parse({ ...submission, evidenceClass: "process-generated" })).toThrow();
  });

  it("refuses empty artifacts and empty assertions structurally", () => {
    expect(() => IngestSubmission.parse({ ...submission, artifacts: [] })).toThrow();
    expect(() => IngestSubmission.parse({ ...submission, assertions: [] })).toThrow();
  });

  it("refuses a digest that is not a sha256 hex and a timestamp that is not ISO 8601", () => {
    expect(() =>
      IngestSubmission.parse({
        ...submission,
        artifacts: [{ name: "x.json", sha256: "not-a-digest" }],
      }),
    ).toThrow();
    expect(() => IngestSubmission.parse({ ...submission, timestamp: "yesterday" })).toThrow();
  });

  it("computes the verdict from assertion outcomes — never declared", () => {
    expect(submissionVerdict(submission)).toBe("evidenced");
    expect(
      submissionVerdict({
        assertions: [
          { description: "a", passed: true },
          { description: "b", passed: false },
        ],
      }),
    ).toBe("violated");
  });
});

describe("IngestManifest", () => {
  const manifest = {
    _type: INGEST_MANIFEST_TYPE,
    signer_identity: "compliance-ops@synthetic-csp.example",
    evidence_class: "process-generated",
    cadence: "daily",
    entries: [
      { ksi: "KSI-CNA-RVP", script: "KSI-CNA-RVP.sh", exit_code: 0, timestamp: "2026-09-10T14:00:00Z" },
      {
        ksi: "KSI-SVC-SIN",
        script: "KSI-SVC-SIN.sh",
        exit_code: 0,
        timestamp: "2026-09-10T14:01:30Z",
        evidence_class: "point-in-time",
      },
    ],
  } satisfies IngestManifest;

  it("parses, with the per-entry evidence-class override", () => {
    const parsed = IngestManifest.parse(manifest);
    expect(parsed.entries[1]!.evidence_class).toBe("point-in-time");
    expect(parsed.entries[0]!.evidence_class).toBeUndefined();
  });

  it("refuses an empty batch and an unknown entry field", () => {
    expect(() => IngestManifest.parse({ ...manifest, entries: [] })).toThrow();
    expect(() =>
      IngestManifest.parse({
        ...manifest,
        entries: [{ ...manifest.entries[0]!, exitCode: 0 }],
      }),
    ).toThrow();
  });
});

describe("methodOfIngestedBundle", () => {
  const predicate = {
    recipe_id: "KSI-CNA-RVP.sh",
    ksi_ids: ["KSI-CNA-RVP"],
    ingest: {
      signer_identity: "compliance-ops@synthetic-csp.example",
      ingest_digest: "b".repeat(64),
    },
  };

  it("derives the aws-ingested method from the signed predicate alone", () => {
    expect(methodOfIngestedBundle(predicate)).toEqual({
      id: "aws-ingested:KSI-CNA-RVP.sh#KSI-CNA-RVP",
      ksi: "KSI-CNA-RVP",
      source: "aws-ingested",
      automated: true,
      clock: "machine",
      standing: "full",
      provenance: {
        recipe_id: "KSI-CNA-RVP.sh",
        signer_identity: "compliance-ops@synthetic-csp.example",
        ingest_digest: "b".repeat(64),
      },
    });
  });

  it("refuses a bundle without the ingest block — no fabricated provenance", () => {
    expect(() => methodOfIngestedBundle({ ...predicate, ingest: undefined })).toThrow(
      /no ingest block/,
    );
  });

  it("refuses a multi-KSI predicate — the contract mints exactly one per submission", () => {
    expect(() =>
      methodOfIngestedBundle({ ...predicate, ksi_ids: ["KSI-CNA-RVP", "KSI-SVC-SIN"] }),
    ).toThrow(/exactly one/);
  });
});
