import { describe, expect, it } from "vitest";
import { Artifact, artifactBodyDigest } from "@rampscan/schema";
import { ARTIFACT_CLOCK_RULE, toArtifact } from "../src/index.js";
import type { ArtifactContext } from "../src/index.js";

// `toArtifact` (plan R1.1, SPEC §13.2) — the same shape discipline as
// `toAttestation` and `toArtifactJudgment`: the subject digests what is being
// signed, which here is the body itself, and nothing is defaulted into
// existence. The tests below are about the two properties every ledger
// statement in this system owes: it is DETERMINISTIC (the same inputs mint the
// same bytes, so the ledger addresses it once) and it is HONEST about absence.

const ctx: ArtifactContext = {
  repo: "fixtures/vulnerable-app",
  ksiId: "KSI-SCR-MIT",
  artifact: 1,
  source: "authored",
  body: "## Vulnerability mitigation\n\nThe gate runs on every merge to main.",
  anchor: { commit: "a".repeat(40), path: "docs/ksi/KSI-SCR-MIT-1.md" },
  validFrom: "2026-09-01T00:00:00.000Z",
  datasetVersion: "2026.07.14.01",
  timestamp: "2026-09-13T00:00:00.000Z",
};

describe("toArtifact", () => {
  it("produces a statement the schema accepts", () => {
    expect(() => Artifact.parse(toArtifact(ctx))).not.toThrow();
  });

  it("digests the body into the subject — the signature covers the prose", () => {
    const statement = toArtifact(ctx);
    expect(statement.subject[0]!.digest.sha256).toBe(artifactBodyDigest(ctx.body));
    expect(statement.predicate.body_digest).toBe(statement.subject[0]!.digest.sha256);
  });

  it("is deterministic — the same context mints the same bytes", () => {
    expect(toArtifact(ctx)).toEqual(toArtifact(ctx));
  });

  it("re-digests when the body changes by one character", () => {
    const edited = toArtifact({ ...ctx, body: `${ctx.body} Reviewed.` });
    expect(edited.predicate.body_digest).not.toBe(toArtifact(ctx).predicate.body_digest);
  });

  it("omits what it was not given — absent means absent (§13.2)", () => {
    const bare = toArtifact({
      repo: ctx.repo,
      ksiId: ctx.ksiId,
      artifact: 5,
      source: "computed",
      body: "42 of 46 indicators hold live evidence at this fold.",
      generator: { pins: { dataset: "2026.07.14.01" }, tool_versions: { syft: "1.0.0" } },
      datasetVersion: ctx.datasetVersion,
      timestamp: ctx.timestamp,
    });
    expect("anchor" in bare.predicate).toBe(false);
    expect("review" in bare.predicate).toBe(false);
    expect("supersedes" in bare.predicate).toBe(false);
    expect(bare.predicate.generator?.journal_digest).toBeUndefined();
  });

  it("starts the clock at valid_from, falling back to the statement's own instant", () => {
    // an AUTHORED body dates from its anchor's commit: dating it from the scan
    // that found it would restart the three-month clock on every scan
    expect(toArtifact(ctx).predicate.valid_from).toBe("2026-09-01T00:00:00.000Z");
    const computed = toArtifact({
      repo: ctx.repo,
      ksiId: ctx.ksiId,
      artifact: 2,
      source: "computed",
      body: "weekly, per the pinned recipe cadence.",
      generator: { pins: {}, tool_versions: {} },
      datasetVersion: ctx.datasetVersion,
      timestamp: ctx.timestamp,
    });
    expect(computed.predicate.valid_from).toBe(ctx.timestamp);
  });

  it("names the rule the clock answers to, and not its number", () => {
    // §13.5 decides WHICH clock; the three months stay owed-side data, read
    // from the pinned rules as the catalog's non-machine window
    expect(ARTIFACT_CLOCK_RULE).toBe("VDR-TFR-NMV");
  });
});
