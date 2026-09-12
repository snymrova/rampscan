import { describe, expect, it } from "vitest";
import {
  Attestation,
  LedgerStatement,
  RAMPSCAN_ATTESTATION_TYPE,
  canonicalJson,
  isArtifactJudgment,
  isAttestation,
  isEvidenceBundle,
  isScopingEvent,
  methodOfAttestation,
} from "../src/index.js";

// The attestation's data shape and its derivation (plan Q4.2, SPEC §12.9): the
// third two-key write, an in-toto statement like any other ledger object, plus
// `methodOfAttestation` — the pure function that makes a signed human claim
// the `source: attestation` leg of §12.2's register.

const attestation: Attestation = {
  _type: "https://in-toto.io/Statement/v1",
  subject: [{ name: "attestation.txt", digest: { sha256: "b".repeat(64) } }],
  predicateType: RAMPSCAN_ATTESTATION_TYPE,
  predicate: {
    action: "attested",
    statement_id: "incident-review",
    ksi_id: "KSI-CNA-CIC",
    attestor_role: "ciso",
    statement:
      "Incident response exercises ran in each of the last two quarters; findings were tracked to closure and the runbook was revised after each.",
    repo: "fixtures/vulnerable-app",
    proposed_by: "viewer@rampscan.local (pb:u1)",
    approved_by: "approver@rampscan.local (pb:u2)",
    dataset_version: "2026.07.14.01",
    timestamp: "2026-09-12T00:00:00.000Z",
  },
};

describe("Attestation", () => {
  it("round-trips through parse", () => {
    expect(Attestation.parse(JSON.parse(JSON.stringify(attestation)))).toEqual(attestation);
  });

  it("canonicalizes stably — key order does not change the bytes", () => {
    const reversed = (obj: Record<string, unknown>) =>
      Object.fromEntries(Object.entries(obj).reverse());
    const reordered = {
      ...reversed(attestation as unknown as Record<string, unknown>),
      predicate: reversed(attestation.predicate as unknown as Record<string, unknown>),
    };
    expect(canonicalJson(Attestation.parse(attestation))).toBe(
      canonicalJson(Attestation.parse(reordered)),
    );
  });

  it("refuses a statement_id that is not slug-shaped — it becomes part of the method id", () => {
    for (const statement_id of ["", "has space", "two#parts", "a:b", "-leading", "slash/ed"]) {
      const bad = { ...attestation, predicate: { ...attestation.predicate, statement_id } };
      expect(() => Attestation.parse(bad), `statement_id ${JSON.stringify(statement_id)}`).toThrow();
    }
    for (const statement_id of ["incident-review", "access_review", "ir.2026", "a", "SOC2"]) {
      const ok = { ...attestation, predicate: { ...attestation.predicate, statement_id } };
      expect(() => Attestation.parse(ok), statement_id).not.toThrow();
    }
  });

  it("rejects an empty statement and an empty role — an unattributed blank is not interrogable", () => {
    for (const patch of [{ statement: "" }, { attestor_role: "" }]) {
      const bad = { ...attestation, predicate: { ...attestation.predicate, ...patch } };
      expect(() => Attestation.parse(bad), JSON.stringify(patch)).toThrow();
    }
  });

  it("accepts withdrawn — an append-only ledger un-decides by deciding again", () => {
    const withdrawn = { ...attestation, predicate: { ...attestation.predicate, action: "withdrawn" } };
    expect(Attestation.parse(withdrawn).predicate.action).toBe("withdrawn");
  });

  it("discriminates in the LedgerStatement union", () => {
    const parsed = LedgerStatement.parse(attestation);
    expect(isAttestation(parsed)).toBe(true);
    expect(isArtifactJudgment(parsed)).toBe(false);
    expect(isScopingEvent(parsed)).toBe(false);
    expect(isEvidenceBundle(parsed)).toBe(false);
  });
});

describe("methodOfAttestation", () => {
  it("derives the attestation method from the signed event alone", () => {
    expect(methodOfAttestation(attestation)).toEqual({
      id: "attestation:incident-review#KSI-CNA-CIC",
      ksi: "KSI-CNA-CIC",
      source: "attestation",
      automated: false,
      clock: "non-machine",
      standing: "narrative",
      provenance: { attestor_role: "ciso", statement_ref: "b".repeat(64) },
    });
  });

  it("keys on the MECHANISM, so a renewal satisfies the clock rather than minting a method", () => {
    const renewed: Attestation = {
      ...attestation,
      subject: [{ name: "attestation.txt", digest: { sha256: "c".repeat(64) } }],
      predicate: { ...attestation.predicate, timestamp: "2026-12-01T00:00:00.000Z" },
    };
    expect(methodOfAttestation(renewed).id).toBe(methodOfAttestation(attestation).id);
    // the provenance still cites the words actually signed, which DID change
    expect(methodOfAttestation(renewed).provenance.statement_ref).toBe("c".repeat(64));
  });

  it("is never automated — no number of attestations can reach a class's FRC-CSX-VVK floor", () => {
    const roles = ["ciso", "head-of-people", "cto", "gc"].map((attestor_role, i) =>
      methodOfAttestation({
        ...attestation,
        predicate: {
          ...attestation.predicate,
          attestor_role,
          statement_id: `review-${i}`,
        },
      }),
    );
    expect(roles).toHaveLength(4);
    expect(roles.filter((m) => m.automated)).toHaveLength(0);
  });

  it("refuses a withdrawn attestation — a method from it would count a retracted claim", () => {
    const withdrawn: Attestation = {
      ...attestation,
      predicate: { ...attestation.predicate, action: "withdrawn" },
    };
    expect(() => methodOfAttestation(withdrawn)).toThrow(/retracted claim/);
  });

  it("refuses an event whose subject carries no sha256 — provenance could cite nothing", () => {
    const unaddressed = { ...attestation, subject: [{ name: "attestation.txt", digest: {} }] };
    expect(() => methodOfAttestation(unaddressed)).toThrow(/no sha256 subject digest/);
  });
});
