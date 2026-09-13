import { describe, expect, it } from "vitest";
import {
  ArtifactDeclarations,
  LedgerStatement,
  RAMPSCAN_ARTIFACT_DECLARATIONS_TYPE,
  canonicalJson,
  isArtifact,
  isArtifactDeclarations,
  isEvidenceBundle,
} from "../src/index.js";

// The declaration observation's data shape (plan R1.4, SPEC §13.3): what a scan
// saw of the repository's declared KSI artifacts.
//
// It exists because an `Artifact` has no withdrawal. A file that CHANGES is
// superseded by its new bytes; a file that is DELETED has no bytes to supersede
// it with, and without this statement a deleted artifact would keep counting
// toward its KSI's `k / 5` until the three-month clock ran out. The signed
// absence is what kills the body — and an absence with no reason attached is
// exactly what this codebase refuses everywhere else, so the schema refuses it
// here too.

const observation: ArtifactDeclarations = {
  _type: "https://in-toto.io/Statement/v1",
  subject: [{ name: "rampscan.config.json", digest: { sha256: "a".repeat(64) } }],
  predicateType: RAMPSCAN_ARTIFACT_DECLARATIONS_TYPE,
  predicate: {
    repo: "fixtures/vulnerable-app",
    commit: "c".repeat(40),
    declarations: [
      {
        ksi_id: "KSI-SVC-SIN",
        artifact: 1,
        path: "docs/ksi/svc-sin-1.md",
        resolved: true,
        body_digest: "b".repeat(64),
      },
      {
        ksi_id: "KSI-SVC-SIN",
        artifact: 3,
        path: "docs/ksi/svc-sin-3.md",
        resolved: false,
        reason: "no file at the declared path",
      },
    ],
    dataset_version: "2026.07.14.01",
    timestamp: "2026-09-13T00:00:00.000Z",
  },
};

describe("ArtifactDeclarations", () => {
  it("round-trips through parse", () => {
    expect(ArtifactDeclarations.parse(JSON.parse(JSON.stringify(observation)))).toEqual(
      observation,
    );
  });

  it("canonicalizes stably — key order does not change the bytes", () => {
    const reversed = (obj: Record<string, unknown>) =>
      Object.fromEntries(Object.entries(obj).reverse());
    const reordered = {
      ...reversed(observation as unknown as Record<string, unknown>),
      predicate: reversed(observation.predicate as unknown as Record<string, unknown>),
    };
    expect(canonicalJson(ArtifactDeclarations.parse(observation))).toBe(
      canonicalJson(ArtifactDeclarations.parse(reordered)),
    );
  });

  it("discriminates in the LedgerStatement union", () => {
    const parsed = LedgerStatement.parse(observation);
    expect(isArtifactDeclarations(parsed)).toBe(true);
    expect(isArtifact(parsed)).toBe(false);
    expect(isEvidenceBundle(parsed)).toBe(false);
  });

  it("refuses an unresolved declaration with no reason — the sentence IS the record", () => {
    const silent = {
      ...observation,
      predicate: {
        ...observation.predicate,
        declarations: [
          { ksi_id: "KSI-SVC-SIN", artifact: 1, path: "a.md", resolved: false },
        ],
      },
    };
    expect(() => ArtifactDeclarations.parse(silent)).toThrow(/recorded with its reason/);
  });

  it("refuses a resolved declaration that names no body", () => {
    const unnamed = {
      ...observation,
      predicate: {
        ...observation.predicate,
        declarations: [{ ksi_id: "KSI-SVC-SIN", artifact: 1, path: "a.md", resolved: true }],
      },
    };
    expect(() => ArtifactDeclarations.parse(unnamed)).toThrow(/names the body it resolved to/);
  });

  it("refuses two observations of one slot — a scan may not say two things", () => {
    const twice = {
      ...observation,
      predicate: {
        ...observation.predicate,
        declarations: [
          observation.predicate.declarations[0],
          { ...observation.predicate.declarations[0], path: "elsewhere.md" },
        ],
      },
    };
    expect(() => ArtifactDeclarations.parse(twice)).toThrow(/one slot, one observation/);
  });

  it("requires at least one declaration — an empty observation observed nothing", () => {
    const empty = {
      ...observation,
      predicate: { ...observation.predicate, declarations: [] },
    };
    expect(() => ArtifactDeclarations.parse(empty)).toThrow();
  });
});
