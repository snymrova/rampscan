import { describe, expect, it } from "vitest";
import {
  Artifact,
  LedgerStatement,
  MAX_ARTIFACT_BODY_BYTES,
  RAMPSCAN_ARTIFACT_TYPE,
  artifactBodyDigest,
  canonicalJson,
  isArtifact,
  isArtifactJudgment,
  isEvidenceBundle,
  isScopingEvent,
} from "../src/index.js";

// The artifact's data shape (plan R1.1, SPEC §13.2): an in-toto statement like
// any other ledger object — round-trips, canonicalizes stably, discriminates
// cleanly — plus the four refusals that are the reason this entity was locked
// in R0 before a line of it was written:
//
//   1. artifacts 1 and 3 may never be `computed` (§13.4)
//   2. an anchor is present exactly when the source is `authored` (§13.2)
//   3. the body is bounded, because the ledger is not a document store
//   4. the digest is the address, so it must be the digest OF THIS BODY
//
// Each of them is structural. A convention somebody remembers is not a
// refusal, and the first one in that list is the one an LLM in the loop makes
// trivially easy to violate.

const body = "## Access control\n\nEvery merge to main runs the pinned gate; see the register.";

const artifact: Artifact = {
  _type: "https://in-toto.io/Statement/v1",
  subject: [{ name: "artifact.md", digest: { sha256: artifactBodyDigest(body) } }],
  predicateType: RAMPSCAN_ARTIFACT_TYPE,
  predicate: {
    ksi_id: "KSI-SCR-MIT",
    artifact: 1,
    repo: "fixtures/vulnerable-app",
    source: "authored",
    body,
    body_digest: artifactBodyDigest(body),
    anchor: { commit: "a".repeat(40), path: "docs/ksi/KSI-SCR-MIT-1.md" },
    valid_from: "2026-09-01T00:00:00.000Z",
    dataset_version: "2026.07.14.01",
    timestamp: "2026-09-13T00:00:00.000Z",
  },
};

/** the same statement with one predicate field replaced, subject re-digested */
function withBody(text: string, predicate: Record<string, unknown> = {}): unknown {
  return {
    ...artifact,
    subject: [{ name: "artifact.md", digest: { sha256: artifactBodyDigest(text) } }],
    predicate: {
      ...artifact.predicate,
      body: text,
      body_digest: artifactBodyDigest(text),
      ...predicate,
    },
  };
}

describe("Artifact", () => {
  it("round-trips through parse", () => {
    expect(Artifact.parse(JSON.parse(JSON.stringify(artifact)))).toEqual(artifact);
  });

  it("canonicalizes stably — key order does not change the bytes", () => {
    const reversed = (obj: Record<string, unknown>) =>
      Object.fromEntries(Object.entries(obj).reverse());
    const reordered = {
      ...reversed(artifact as unknown as Record<string, unknown>),
      predicate: reversed(artifact.predicate as unknown as Record<string, unknown>),
    };
    expect(canonicalJson(Artifact.parse(artifact))).toBe(canonicalJson(Artifact.parse(reordered)));
  });

  it("discriminates in the LedgerStatement union", () => {
    const parsed = LedgerStatement.parse(artifact);
    expect(isArtifact(parsed)).toBe(true);
    expect(isArtifactJudgment(parsed)).toBe(false);
    expect(isScopingEvent(parsed)).toBe(false);
    expect(isEvidenceBundle(parsed)).toBe(false);
  });

  it("refuses to compute artifacts 1 and 3 — the provider's own claims (§13.4)", () => {
    for (const slot of [1, 3]) {
      const bad = withBody(body, { artifact: slot, source: "computed", anchor: undefined,
        generator: { pins: {}, tool_versions: {} } });
      expect(() => Artifact.parse(bad), `artifact ${slot}`).toThrow(/provider's own claim/);
    }
    // and the three it may compute stay open — the refusal is targeted, not a
    // blanket ban on the appliance producing prose it can honestly produce
    for (const slot of [2, 4, 5]) {
      const ok = withBody(body, { artifact: slot, source: "computed", anchor: undefined,
        generator: { pins: {}, tool_versions: {} } });
      expect(() => Artifact.parse(ok), `artifact ${slot}`).not.toThrow();
    }
  });

  it("still accepts an AUTHORED artifact 1 or 3 — the refusal is about the author, not the slot", () => {
    for (const slot of [1, 3]) {
      expect(() => Artifact.parse(withBody(body, { artifact: slot })), `artifact ${slot}`).not.toThrow();
    }
  });

  it("ties the anchor to the authored source, in both directions", () => {
    const unanchored = withBody(body, { anchor: undefined });
    expect(() => Artifact.parse(unanchored)).toThrow(/anchor drift/);
    const anchoredAttestation = withBody(body, { source: "attested" });
    expect(() => Artifact.parse(anchoredAttestation)).toThrow(/carries no commit anchor/);
  });

  it("ties the generator to the computed source, in both directions", () => {
    const ungenerated = withBody(body, { artifact: 5, source: "computed", anchor: undefined });
    expect(() => Artifact.parse(ungenerated)).toThrow(/carries its generator/);
    const generatedAuthored = withBody(body, {
      generator: { pins: {}, tool_versions: {} },
    });
    expect(() => Artifact.parse(generatedAuthored)).toThrow(/carries no generator/);
  });

  it("bounds the body at 64 KiB, quoting the rule's own words", () => {
    const long = "x".repeat(MAX_ARTIFACT_BODY_BYTES + 1);
    expect(() => Artifact.parse(withBody(long))).toThrow(/short and simple high-level summaries/);
    expect(() => Artifact.parse(withBody("x".repeat(MAX_ARTIFACT_BODY_BYTES)))).not.toThrow();
  });

  it("counts the bound in BYTES, not characters — a multi-byte body is not a loophole", () => {
    // three bytes each: a body of MAX/3 + 1 of them is over the line while
    // being a third of the length a character count would allow
    const wide = "→".repeat(Math.floor(MAX_ARTIFACT_BODY_BYTES / 3) + 1);
    expect(wide.length).toBeLessThan(MAX_ARTIFACT_BODY_BYTES);
    expect(() => Artifact.parse(withBody(wide))).toThrow(/bounded at/);
  });

  it("refuses a body_digest that is not the digest of the body", () => {
    const lying = {
      ...artifact,
      predicate: { ...artifact.predicate, body: `${body} and one more sentence.` },
    };
    expect(() => Artifact.parse(lying)).toThrow(/not the sha256 of the body/);
  });

  it("refuses a subject that does not digest the body it carries", () => {
    const mismatched = {
      ...artifact,
      subject: [{ name: "artifact.md", digest: { sha256: "b".repeat(64) } }],
    };
    expect(() => Artifact.parse(mismatched)).toThrow(/must digest the body/);
  });

  it("refuses an artifact that supersedes itself — identical bytes are one artifact", () => {
    const loop = withBody(body, { supersedes: artifactBodyDigest(body) });
    expect(() => Artifact.parse(loop)).toThrow(/cannot supersede itself/);
  });

  it("accepts a supersession of different bytes — a revision, never an edit", () => {
    const revision = withBody(`${body}\n\nRevised after the September review.`, {
      supersedes: artifactBodyDigest(body),
    });
    expect(Artifact.parse(revision).predicate.supersedes).toBe(artifactBodyDigest(body));
  });

  it("carries a review only when one is known — never defaulted (§13.2)", () => {
    expect(Artifact.parse(artifact).predicate.review).toBeUndefined();
    const reviewed = withBody(body, {
      review: {
        source: "github",
        reference: "https://github.com/o/r/pull/12",
        approvers: ["@reviewer"],
        timestamp: "2026-09-02T00:00:00.000Z",
      },
    });
    expect(Artifact.parse(reviewed).predicate.review?.approvers).toEqual(["@reviewer"]);
  });

  it("accepts all four sources and no fifth", () => {
    for (const source of ["computed", "attested", "assessed"]) {
      const ok = withBody(body, {
        artifact: 5,
        source,
        anchor: undefined,
        ...(source === "computed" ? { generator: { pins: {}, tool_versions: {} } } : {}),
      });
      expect(() => Artifact.parse(ok), source).not.toThrow();
    }
    expect(() => Artifact.parse(withBody(body, { source: "generated" }))).toThrow();
  });

  it("rejects a slot outside 1..5 — the rules' own list has five entries", () => {
    for (const slot of [0, 6, 1.5]) {
      expect(() => Artifact.parse(withBody(body, { artifact: slot })), `slot ${slot}`).toThrow();
    }
  });
});
