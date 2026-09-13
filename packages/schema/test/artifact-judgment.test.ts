import { describe, expect, it } from "vitest";
import {
  ArtifactJudgment,
  LedgerStatement,
  RAMPSCAN_ARTIFACT_JUDGMENT_TYPE,
  canonicalJson,
  isArtifactJudgment,
  isEvidenceBundle,
  isScopingEvent,
} from "../src/index.js";

// The artifact judgment's data shape (plan Q3.3, G5): an in-toto statement
// like any other ledger object — round-trips, canonicalizes stably,
// discriminates cleanly, and structurally refuses a judgment about the
// computed artifacts 2 and 5.

const judgment: ArtifactJudgment = {
  _type: "https://in-toto.io/Statement/v1",
  subject: [{ name: "justification.txt", digest: { sha256: "a".repeat(64) } }],
  predicateType: RAMPSCAN_ARTIFACT_JUDGMENT_TYPE,
  predicate: {
    action: "sufficient",
    ksi_id: "KSI-SCR-MIT",
    artifact: 4,
    repo: "fixtures/vulnerable-app",
    justification:
      "The pipeline's measurement of pinned actions covers composite actions since #23; the automation is accurate for this KSI.",
    proposed_by: "viewer@rampscan.local (pb:u1)",
    approved_by: "approver@rampscan.local (pb:u2)",
    dataset_version: "2026.07.14.01",
    timestamp: "2026-09-11T00:00:00.000Z",
  },
};

describe("ArtifactJudgment", () => {
  it("round-trips through parse", () => {
    expect(ArtifactJudgment.parse(JSON.parse(JSON.stringify(judgment)))).toEqual(judgment);
  });

  it("canonicalizes stably — key order does not change the bytes", () => {
    const reversed = (obj: Record<string, unknown>) =>
      Object.fromEntries(Object.entries(obj).reverse());
    const reordered = {
      ...reversed(judgment as unknown as Record<string, unknown>),
      predicate: reversed(judgment.predicate as unknown as Record<string, unknown>),
    };
    expect(canonicalJson(ArtifactJudgment.parse(judgment))).toBe(
      canonicalJson(ArtifactJudgment.parse(reordered)),
    );
  });

  it("refuses a judgment about the computed artifacts 2 and 5 — a signature may not override a computation", () => {
    for (const artifact of [0, 2, 5, 6]) {
      const bad = { ...judgment, predicate: { ...judgment.predicate, artifact } };
      expect(() => ArtifactJudgment.parse(bad), `artifact ${artifact}`).toThrow();
    }
    for (const artifact of [1, 3, 4]) {
      const ok = { ...judgment, predicate: { ...judgment.predicate, artifact } };
      expect(() => ArtifactJudgment.parse(ok)).not.toThrow();
    }
  });

  it("rejects an empty justification — the approver signs reasoning, not a blank", () => {
    const blank = { ...judgment, predicate: { ...judgment.predicate, justification: "" } };
    expect(() => ArtifactJudgment.parse(blank)).toThrow();
  });

  it("accepts insufficient — an append-only ledger un-decides by deciding again", () => {
    const withdrawn = {
      ...judgment,
      predicate: { ...judgment.predicate, action: "insufficient" },
    };
    expect(ArtifactJudgment.parse(withdrawn).predicate.action).toBe("insufficient");
  });

  it("names the bytes it approved, and the subject must carry them (§13.6, R1.1)", () => {
    const bodyDigest = "c".repeat(64);
    const judged = {
      ...judgment,
      subject: [...judgment.subject, { name: "artifact.md", digest: { sha256: bodyDigest } }],
      predicate: { ...judgment.predicate, body_digest: bodyDigest },
    };
    expect(ArtifactJudgment.parse(judged).predicate.body_digest).toBe(bodyDigest);
    // a pointer the signature does not cover is not an address
    const unsigned = { ...judgment, predicate: { ...judgment.predicate, body_digest: bodyDigest } };
    expect(() => ArtifactJudgment.parse(unsigned)).toThrow(/must carry the body_digest/);
  });

  it("still parses a judgment appended before the artifact plane existed", () => {
    // the ledger is append-only: a statement signed under the old shape must
    // stay readable, exactly as a pre-Q3.4 bundle carries no evidence_class
    expect(ArtifactJudgment.parse(judgment).predicate.body_digest).toBeUndefined();
  });

  it("discriminates in the LedgerStatement union", () => {
    const parsed = LedgerStatement.parse(judgment);
    expect(isArtifactJudgment(parsed)).toBe(true);
    expect(isScopingEvent(parsed)).toBe(false);
    expect(isEvidenceBundle(parsed)).toBe(false);
  });
});
