import { z } from "zod";
import { Cadence } from "./recipe.js";

// EvidenceBundle: an in-toto Statement (v1) whose subject is the artifact
// digests and whose predicate carries the join — recipe ID, commit anchor,
// dataset version, tool versions, assertion results, run ID (SPEC §4.7).
// Signing wraps this statement in a DSSE envelope; that lives with the
// Signer port, not here — the statement is what gets signed.

export const IN_TOTO_STATEMENT_TYPE = "https://in-toto.io/Statement/v1";
export const RAMPSCAN_PREDICATE_TYPE =
  "https://rampscan.dev/evidence/v1" as const;

export const Verdict = z.enum(["evidenced", "violated", "unevidenced"]);
export type Verdict = z.infer<typeof Verdict>;

export const Subject = z.object({
  name: z.string(), // artifact name, e.g. "sbom.cdx.json"
  digest: z.record(z.string(), z.string()), // { sha256: "..." }
});
export type Subject = z.infer<typeof Subject>;

/**
 * A fix pointer (I2c): where one failing observation row lives, in the
 * operator's terms — file, line, check id, call path — so a violation can be
 * acted on without a context switch. Every field is optional because rows
 * carry what their producer carries (a package-level advisory has no file);
 * an extractable-but-empty pointer is dropped rather than recorded as `{}`.
 */
export const OffenderPointer = z.object({
  /** repo-relative file the failing row points at */
  file: z.string().optional(),
  line: z.number().int().optional(),
  /** the failing check/rule/advisory id, under whichever name its producer uses */
  check: z.string().optional(),
  /** entry point » … » sink, as the graph labeled it */
  call_path: z.string().optional(),
});
export type OffenderPointer = z.infer<typeof OffenderPointer>;

export const AssertionResult = z.object({
  description: z.string(),
  passed: z.boolean(),
  detail: z.string().optional(), // what failed / matched, human-readable
  /**
   * Fix pointers for the failing rows (I2c), bounded — the first few
   * offenders with any pointer fields at all. Deliberately EXCLUDED from
   * evidence identity (`sameEvidence`): existing bundles survive unchanged
   * and gain pointers only when real drift re-keys them.
   */
  offenders: z.array(OffenderPointer).optional(),
  /** total failing rows, so a bounded `offenders` can honestly say "+N more" */
  offender_count: z.number().int().optional(),
});
export type AssertionResult = z.infer<typeof AssertionResult>;

export const AnchorPath = z.object({
  path: z.string(), // repo-relative
  contentHash: z.string(), // sha256 of blob at the scanned commit
});

export const EvidencePredicate = z.object({
  recipe_id: z.string(),
  ksi_ids: z.array(z.string()),
  control_ids: z.array(z.string()),
  verdict: Verdict,
  repo: z.string(),
  commit: z.string(), // the anchor for everything downstream
  anchor_paths: z.array(AnchorPath), // the content this evidence is about; drift here kills the bundle
  dataset_version: z.string(),
  tool_versions: z.record(z.string(), z.string()), // { syft: "1.x", ... }
  assertions: z.array(AssertionResult),
  /**
   * How to re-run the check that produced this verdict (I2c), as the
   * collector itself stated it — never typed elsewhere. Optional: older
   * bundles predate it, and a collector may not state one. Excluded from
   * evidence identity, like `offenders`.
   */
  reproduce: z.string().optional(),
  cadence: Cadence,
  run_id: z.string(),
  timestamp: z.string(), // ISO 8601
});
export type EvidencePredicate = z.infer<typeof EvidencePredicate>;

export const EvidenceBundle = z.object({
  _type: z.literal(IN_TOTO_STATEMENT_TYPE),
  subject: z.array(Subject).min(1),
  predicateType: z.literal(RAMPSCAN_PREDICATE_TYPE),
  predicate: EvidencePredicate,
});
export type EvidenceBundle = z.infer<typeof EvidenceBundle>;
