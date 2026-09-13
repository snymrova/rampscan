import type {
  Artifact,
  ArtifactAnchor,
  ArtifactDeclarations,
  DeclarationObservation,
  ArtifactGenerator,
  ArtifactReview,
  ArtifactSlot,
  ArtifactSource,
} from "@rampscan/schema";
import {
  IN_TOTO_STATEMENT_TYPE,
  RAMPSCAN_ARTIFACT_DECLARATIONS_TYPE,
  RAMPSCAN_ARTIFACT_TYPE,
  artifactBodyDigest,
} from "@rampscan/schema";

// Artifact → in-toto statement (plan R1.1, SPEC §13.2). Same shape discipline
// as `toAttestation` and `toArtifactJudgment`: the subject digests the body,
// because the body is what is signed. Unlike those two this is NOT a two-key
// write — §13.3 is explicit that appending an authored artifact is a collector
// observation signed like evidence, since the repository's own review is the
// second key and adding a ceremony the pull request already performed would
// teach people to click through it.

/**
 * The artifact clock (SPEC §13.5). An artifact is non-machine validation and
 * answers to `VDR-TFR-NMV` WHATEVER its source: not `VDR-TFR-MVX` (7 days
 * class b, 3 days class c), which is the machine cadence of §12.2's
 * `clock: "machine"` family, and not `FRC-APP-FCP`'s flat 7-day application
 * window (§12.12). Three clocks that each read a number is three clocks; the
 * artifact one gets `valid_from` and nothing else.
 *
 * What is DECIDED here is which rule applies — the number it states stays on
 * the owed side, read from the pinned rules as `catalog.nonMachineWindow`, the
 * same window the attestation methods are already judged against. A three
 * written into this file would be a second copy of a pinned fact, and the one
 * that never gets re-read when the rules are republished.
 */
export const ARTIFACT_CLOCK_RULE = "VDR-TFR-NMV" as const;

export interface ArtifactContext {
  repo: string;
  ksiId: string;
  artifact: ArtifactSlot;
  source: ArtifactSource;
  /** Markdown, bounded at 64 KiB by the schema — a summary, not a document */
  body: string;
  /** authored only: where the body lives, and what kills it when it moves */
  anchor?: ArtifactAnchor;
  /** computed only: the pin set, the tool versions, the exec-journal digest */
  generator?: ArtifactGenerator;
  /** R4's forge plane, when it knows — never asserted, never defaulted */
  review?: ArtifactReview;
  /** the body_digest this revises, when it revises one */
  supersedes?: string;
  /**
   * The clock's start. Omit and it falls to `timestamp`, which is right for a
   * computed body (its clock restarts at the generation that produced it) and
   * for an attested or assessed one (the statement IS the act). An AUTHORED
   * body should pass its anchor commit's date: the file was written when it
   * was written, and dating it from the scan that found it would restart a
   * three-month clock every time anyone ran a scan — the exact reading
   * `SDR-CSX-KSI` item 2 asks the cycle question to prevent.
   */
  validFrom?: string; // ISO 8601
  datasetVersion: string;
  timestamp: string; // ISO 8601
}

export function toArtifact(ctx: ArtifactContext): Artifact {
  const bodyDigest = artifactBodyDigest(ctx.body);
  return {
    _type: IN_TOTO_STATEMENT_TYPE,
    subject: [{ name: "artifact.md", digest: { sha256: bodyDigest } }],
    predicateType: RAMPSCAN_ARTIFACT_TYPE,
    predicate: {
      ksi_id: ctx.ksiId,
      artifact: ctx.artifact,
      repo: ctx.repo,
      source: ctx.source,
      body: ctx.body,
      body_digest: bodyDigest,
      // Absent means absent (§13.2): these three are spread in only when the
      // caller has one, never defaulted to an empty shape that would read as
      // "anchored to nothing" or "reviewed by no one".
      ...(ctx.anchor !== undefined ? { anchor: ctx.anchor } : {}),
      ...(ctx.generator !== undefined ? { generator: ctx.generator } : {}),
      ...(ctx.review !== undefined ? { review: ctx.review } : {}),
      ...(ctx.supersedes !== undefined ? { supersedes: ctx.supersedes } : {}),
      valid_from: ctx.validFrom ?? ctx.timestamp,
      dataset_version: ctx.datasetVersion,
      timestamp: ctx.timestamp,
    },
  };
}

// ---------------------------------------------------------------------------
// The declaration observation (plan R1.4, SPEC §13.3)

export interface ArtifactDeclarationsContext {
  repo: string;
  /** the commit this observation was made at — it is a claim about a tree */
  commit: string;
  /** the declaration file that was read, and its digest */
  source: { path: string; sha256: string };
  declarations: readonly DeclarationObservation[];
  datasetVersion: string;
  timestamp: string; // ISO 8601
}

/**
 * The subject is the DECLARATION FILE, not the artifacts: what this statement
 * observed is a config block, and the bodies it resolved are named inside it by
 * their own digests. Signing the file that was read is what lets a reader check
 * that the observation was made over the declarations they are looking at.
 */
export function toArtifactDeclarations(
  ctx: ArtifactDeclarationsContext,
): ArtifactDeclarations {
  return {
    _type: IN_TOTO_STATEMENT_TYPE,
    subject: [{ name: ctx.source.path, digest: { sha256: ctx.source.sha256 } }],
    predicateType: RAMPSCAN_ARTIFACT_DECLARATIONS_TYPE,
    predicate: {
      repo: ctx.repo,
      commit: ctx.commit,
      declarations: [...ctx.declarations].sort((a, b) =>
        `${a.ksi_id} ${a.artifact}`.localeCompare(`${b.ksi_id} ${b.artifact}`),
      ),
      dataset_version: ctx.datasetVersion,
      timestamp: ctx.timestamp,
    },
  };
}
