import { describe, expect, it } from "vitest";
import {
  LedgerStatement,
  RAMPSCAN_SCOPING_TYPE,
  ScopingEvent,
  canonicalJson,
  isEvidenceBundle,
  isScopingEvent,
} from "../src/index.js";

// The two-key write's data shape (plan M3 E4): a notApplicable scoping is an
// in-toto statement like any other ledger object — round-trips, canonicalizes
// stably, and discriminates cleanly from evidence bundles.

const scoping: ScopingEvent = {
  _type: "https://in-toto.io/Statement/v1",
  subject: [{ name: "justification.txt", digest: { sha256: "a".repeat(64) } }],
  predicateType: RAMPSCAN_SCOPING_TYPE,
  predicate: {
    action: "notApplicable",
    recipe_id: "container-runs-nonroot",
    ksi_ids: ["KSI-CNA-CIC"],
    control_ids: ["cm-2.2"],
    repo: "fixtures/vulnerable-app",
    justification: "This repository ships no container image; the Dockerfile is a test fixture.",
    proposed_by: "viewer@rampscan.local (pb:u1)",
    approved_by: "approver@rampscan.local (pb:u2)",
    dataset_version: "2026.07.14.01",
    timestamp: "2026-08-13T00:00:00.000Z",
  },
};

describe("ScopingEvent", () => {
  it("round-trips through parse", () => {
    expect(ScopingEvent.parse(JSON.parse(JSON.stringify(scoping)))).toEqual(scoping);
  });

  it("canonicalizes stably — key order does not change the bytes", () => {
    // rebuild with reversed key insertion order at both levels
    const reversed = (obj: Record<string, unknown>) =>
      Object.fromEntries(Object.entries(obj).reverse());
    const reordered = {
      ...reversed(scoping as unknown as Record<string, unknown>),
      predicate: reversed(scoping.predicate as unknown as Record<string, unknown>),
    };
    expect(canonicalJson(ScopingEvent.parse(scoping))).toBe(
      canonicalJson(ScopingEvent.parse(reordered)),
    );
  });

  it("rejects an empty justification — the approver signs reasoning, not a blank", () => {
    const blank = { ...scoping, predicate: { ...scoping.predicate, justification: "" } };
    expect(() => ScopingEvent.parse(blank)).toThrow();
  });

  it("discriminates from evidence bundles in the LedgerStatement union", () => {
    const parsed = LedgerStatement.parse(scoping);
    expect(isScopingEvent(parsed)).toBe(true);
    expect(isEvidenceBundle(parsed)).toBe(false);
  });
});
