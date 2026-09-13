import { createHash } from "node:crypto";
import { z } from "zod";
import { IN_TOTO_STATEMENT_TYPE, Subject } from "./bundle.js";

// Artifact: the artifact plane's object (plan R1.1, SPEC §13.2). `SDR-CSX-KSI`
// (MUST) makes five artifacts the required content of every KSI in the
// Security Decision Record, and until now this system could sign that one of
// them was SUFFICIENT while having no bytes to show for it. This statement is
// those bytes, signed and addressed like everything else in the ledger.
//
// An artifact fills a slot, and the slot is `(repo, ksi_id, artifact)`. A
// later artifact for the same slot SUPERSEDES the earlier one: an append-only
// ledger revises by writing again, never by editing — the same rule scoping,
// judgment and attestation already keep.
//
// THE BODY RIDES THE PREDICATE AND THE SUBJECT DIGESTS IT, exactly as an
// attestation carries the attestor's statement. The alternative — a digest
// pointing at bytes in the output dir, the J4 arrangement for tool artifacts —
// was rejected in R0 for one reason: R2 must render `ksiImplementation` INTO a
// document and R3 must refold a year of them, and a plane whose prose is only
// reachable through a directory that a later run overwrites would make the SDR
// unreproducible from the record. What the ledger holds, an assessor holding
// the ledger can read.

export const RAMPSCAN_ARTIFACT_TYPE = "https://rampscan.dev/artifact/v1" as const;

/**
 * The owed artifacts, 1-based into `info.default_artifacts.KSI` — the rules'
 * own order. OPEN to all five, unlike `JudgedArtifact`'s closed `1 | 3 | 4`:
 * every slot can hold a body, and what differs between them is who is allowed
 * to have written it (`ArtifactPredicate` below) and who may judge it
 * (`artifact-judgment.ts`, unchanged).
 */
export const ArtifactSlot = z.union([
  z.literal(1),
  z.literal(2),
  z.literal(3),
  z.literal(4),
  z.literal(5),
]);
export type ArtifactSlot = z.infer<typeof ArtifactSlot>;

/**
 * Who stood behind these bytes (SPEC §13.3). The distinction is load-bearing
 * rather than decorative: it is what an assessor reads to know who stands
 * behind a sentence.
 *
 * - `authored`   a file in the scanned repository, commit-anchored, found by
 *                the documents collector (R1.4) — the CSP engineer's habitat
 * - `computed`   rampscan generated it from the fold; legitimate for 2, 4 and
 *                5 ONLY, and refused for 1 and 3 below
 * - `attested`   the existing two-key path of §12.9, for the acts-on-people
 *                remainder — the attestation IS the body's signature
 * - `assessed`   the `IVV-IAS-SUM` inbound (R4.5): the independent assessor's
 *                summary, ingested like a client-run result rather than typed
 */
export const ArtifactSource = z.enum(["authored", "computed", "attested", "assessed"]);
export type ArtifactSource = z.infer<typeof ArtifactSource>;

/**
 * Where an authored body lives in the repository. Present when — and only
 * when — `source` is `authored`, and ABSENT MEANS ABSENT: never a commit that
 * merely happened to be checked out when a generator ran.
 */
export const ArtifactAnchor = z.object({
  commit: z.string().min(1),
  /** repo-relative path to the file whose bytes are the body */
  path: z.string().min(1),
});
export type ArtifactAnchor = z.infer<typeof ArtifactAnchor>;

/**
 * What produced a computed body, so that "rampscan wrote this" is an
 * interrogable claim rather than a brand. A computed artifact is a function of
 * the fold: two generations over the same ledger at the same instant produce
 * the same `body_digest`, which is the same reproducibility R3's metrics are
 * held to.
 */
export const ArtifactGenerator = z.object({
  /** the inputs this body is a function of — dataset pin, recipe set, class */
  pins: z.record(z.string(), z.string()),
  /** tool id → version, as the journal resolved them */
  tool_versions: z.record(z.string(), z.string()),
  /**
   * The exec journal these bytes were assembled from (R1.2, artifact 4).
   * Optional because artifacts 2 and 5 are folded from the register rather
   * than from a run's journal — an absent journal digest is the honest
   * statement that no run's execution record is behind these bytes, and a
   * fabricated one would be the opposite.
   */
  journal_digest: z.string().optional(),
});
export type ArtifactGenerator = z.infer<typeof ArtifactGenerator>;

/**
 * The record that this body was reviewed (SPEC §13.2). NEVER asserted and
 * never defaulted: R4's forge plane fills it from pull-request approval
 * metadata through the `RepoSource` port, and until then its absence is
 * PRINTED rather than assumed benign. An artifact whose review is unknown and
 * an artifact that was reviewed are different facts.
 */
export const ArtifactReview = z.object({
  /** where the review record came from — R4 names the forge sources */
  source: z.string().min(1),
  /** the review's address in that source, e.g. a pull request URL */
  reference: z.string().min(1),
  /** who approved, in the source's own identity terms */
  approvers: z.array(z.string()),
  timestamp: z.string(), // ISO 8601
});
export type ArtifactReview = z.infer<typeof ArtifactReview>;

/**
 * A body is prose, and the ledger is not a document store (SPEC §13.2).
 * `SDR-CSX-KSI` asks for "short and simple high-level summaries"; a longer
 * body is REFUSED at append with that sentence quoted. A document larger than
 * its own summary is a document, and a document belongs behind an
 * `evidenceLocation` — served through J4's digest addressing, the one place in
 * this system bytes are served from.
 */
export const MAX_ARTIFACT_BODY_BYTES = 64 * 1024;

/**
 * The canonical body bytes are the body's UTF-8 encoding, and their sha256 is
 * the artifact's address — what `ArtifactJudgment`'s subject names (§13.6),
 * what a supersession points back at, and what the SDR resolves in R2. One
 * function, so no caller can invent a second answer.
 */
export function artifactBodyDigest(body: string): string {
  return createHash("sha256").update(body, "utf8").digest("hex");
}

export const ArtifactPredicate = z
  .object({
    /** exactly one KSI id, mnemonic form ("KSI-SVC-SIN") */
    ksi_id: z.string().min(1),
    artifact: ArtifactSlot,
    /** the offering this speaks for — one offering per document (§12.11) */
    repo: z.string(),
    source: ArtifactSource,
    /** Markdown: the SDR's statements are Markdown-typed, so the artifact is
     * stored in the form the document wants it */
    body: z.string().min(1),
    /** sha256 over the body's UTF-8 bytes — the subject, and the address
     * everywhere else, `ArtifactJudgment`'s subject included (§13.6) */
    body_digest: z.string().regex(/^[0-9a-f]{64}$/),
    anchor: ArtifactAnchor.optional(),
    generator: ArtifactGenerator.optional(),
    review: ArtifactReview.optional(),
    /** the body_digest this revises, when it revises one */
    supersedes: z.string().regex(/^[0-9a-f]{64}$/).optional(),
    /** the clock's start (§13.5): VDR-TFR-NMV, three months, whatever the source */
    valid_from: z.string(), // ISO 8601
    dataset_version: z.string(),
    timestamp: z.string(), // ISO 8601
  })
  .superRefine((p, ctx) => {
    // RAMPSCAN WILL NEVER AUTHOR ARTIFACTS 1 AND 3 (SPEC §13.4), and the
    // refusal is structural rather than a convention somebody remembers.
    // Artifact 1 (the explanation of the measures, or of the reason and
    // resulting customer risk for not having them) and artifact 3
    // (verification that the measures demonstrate the indicator, or that the
    // reason is accepted) are the PROVIDER's own claims. An LLM in the loop
    // makes authoring them trivially possible and that is exactly why this
    // check is here: the moment this appliance emits plausible compliance
    // narrative, `SDR-CSX-KSI` becomes a text-generation benchmark and every
    // signature in the ledger is worth less.
    if (p.source === "computed" && (p.artifact === 1 || p.artifact === 3)) {
      ctx.addIssue({
        code: "custom",
        path: ["source"],
        message:
          `artifact ${p.artifact} may not be computed — it is the provider's own claim ` +
          `(SPEC §13.4). The generator's output for an unwritten artifact is an absence ` +
          `with a reason, never a draft.`,
      });
    }
    // Absent means absent, in both directions. An anchor on a computed body
    // would be the commit that happened to be checked out when a generator
    // ran, which is the one thing §13.2 names and refuses.
    if (p.source === "authored" && p.anchor === undefined) {
      ctx.addIssue({
        code: "custom",
        path: ["anchor"],
        message:
          "an authored artifact is a file in the repository: without a commit anchor it " +
          "cannot die by anchor drift, which is the whole discipline of this source",
      });
    }
    if (p.source !== "authored" && p.anchor !== undefined) {
      ctx.addIssue({
        code: "custom",
        path: ["anchor"],
        message: `a ${p.source} artifact carries no commit anchor (SPEC §13.2)`,
      });
    }
    if (p.source === "computed" && p.generator === undefined) {
      ctx.addIssue({
        code: "custom",
        path: ["generator"],
        message:
          "a computed artifact carries its generator — the pin set, the tool versions and " +
          "the exec-journal digest that produced these bytes (SPEC §13.2)",
      });
    }
    if (p.source !== "computed" && p.generator !== undefined) {
      ctx.addIssue({
        code: "custom",
        path: ["generator"],
        message: `a ${p.source} artifact was not generated, so it carries no generator`,
      });
    }
    const bytes = Buffer.byteLength(p.body, "utf8");
    if (bytes > MAX_ARTIFACT_BODY_BYTES) {
      ctx.addIssue({
        code: "custom",
        path: ["body"],
        message:
          `an artifact body is bounded at ${MAX_ARTIFACT_BODY_BYTES} bytes and this one is ` +
          `${bytes}: SDR-CSX-KSI asks for "short and simple high-level summaries", and a ` +
          `document larger than its own summary belongs behind an evidenceLocation`,
      });
    }
    // The digest is the ADDRESS, so it is checked rather than trusted. A
    // statement carrying bytes that hash to something else would be signed,
    // well-formed, and unresolvable by every reader downstream of it.
    if (p.body_digest !== artifactBodyDigest(p.body)) {
      ctx.addIssue({
        code: "custom",
        path: ["body_digest"],
        message: "body_digest is not the sha256 of the body it accompanies",
      });
    }
    if (p.supersedes === p.body_digest) {
      ctx.addIssue({
        code: "custom",
        path: ["supersedes"],
        message: "an artifact cannot supersede itself — identical bytes are the same artifact",
      });
    }
  });
export type ArtifactPredicate = z.infer<typeof ArtifactPredicate>;

export const Artifact = z
  .object({
    _type: z.literal(IN_TOTO_STATEMENT_TYPE),
    subject: z.array(Subject).min(1),
    predicateType: z.literal(RAMPSCAN_ARTIFACT_TYPE),
    predicate: ArtifactPredicate,
  })
  .superRefine((s, ctx) => {
    // The subject IS the body digest. Checked here rather than trusted,
    // because every downstream address — the judgment's subject (§13.6), the
    // SDR's rendering (R2), the supersession chain — reads one of the two and
    // assumes the other. A statement whose signature covers a digest of
    // different bytes than the ones it carries is the one shape this plane
    // must never hold.
    if (!s.subject.some((sub) => sub.digest.sha256 === s.predicate.body_digest)) {
      ctx.addIssue({
        code: "custom",
        path: ["subject"],
        message:
          "the statement's subject must digest the body it carries — no subject matches " +
          "predicate.body_digest",
      });
    }
  });
export type Artifact = z.infer<typeof Artifact>;
