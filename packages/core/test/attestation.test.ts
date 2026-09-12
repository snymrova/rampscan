import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { Attestation, methodOfAttestation } from "@rampscan/schema";
import { toAttestation } from "../src/index.js";

// The attestation constructor (plan Q4.2, SPEC §12.9): pure, and its subject
// is the CLAIM — what the approver signs. That subject digest is the same
// value the derived method cites as `statement_ref`, which is the property
// that lets provenance name exactly the words two keys were turned for.

const ctx = {
  repo: "fixtures/vulnerable-app",
  statementId: "incident-review",
  ksiId: "KSI-CNA-CIC",
  attestorRole: "ciso",
  statement: "Incident response exercises ran in each of the last two quarters.",
  action: "attested" as const,
  proposedBy: "viewer@rampscan.local (pb:u1)",
  approvedBy: "approver@rampscan.local (pb:u2)",
  datasetVersion: "2026.07.14.01",
  timestamp: "2026-09-12T00:00:00.000Z",
};

describe("toAttestation", () => {
  it("builds a statement the schema accepts", () => {
    expect(() => Attestation.parse(toAttestation(ctx))).not.toThrow();
  });

  it("subjects the claim itself, by digest", () => {
    const event = toAttestation(ctx);
    expect(event.subject).toEqual([
      {
        name: "attestation.txt",
        digest: { sha256: createHash("sha256").update(ctx.statement, "utf8").digest("hex") },
      },
    ]);
  });

  it("carries both identities and the role into the signed predicate", () => {
    const p = toAttestation(ctx).predicate;
    expect(p.proposed_by).toBe(ctx.proposedBy);
    expect(p.approved_by).toBe(ctx.approvedBy);
    expect(p.attestor_role).toBe("ciso");
    expect(p.action).toBe("attested");
  });

  it("is pure — the same context yields identical bytes", () => {
    expect(toAttestation(ctx)).toEqual(toAttestation(ctx));
  });

  it("hands the derivation a statement_ref that addresses the signed words", () => {
    const event = toAttestation(ctx);
    const method = methodOfAttestation(event);
    expect(method.provenance.statement_ref).toBe(event.subject[0]!.digest.sha256);
    expect(method.id).toBe("attestation:incident-review#KSI-CNA-CIC");
    expect(method.clock).toBe("non-machine");
    expect(method.automated).toBe(false);
  });

  it("a changed claim changes the address — the same mechanism, different signed words", () => {
    const edited = toAttestation({ ...ctx, statement: `${ctx.statement} Runbook revised.` });
    expect(edited.subject[0]!.digest.sha256).not.toBe(toAttestation(ctx).subject[0]!.digest.sha256);
    expect(methodOfAttestation(edited).id).toBe(methodOfAttestation(toAttestation(ctx)).id);
  });
});
