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
  /**
   * How each HOP of `call_path` was resolved — "exact" (the import/call was
   * lexically resolved to a file the walk saw) or "inferred" (matched by
   * name). One entry per hop, so this array is always one shorter than the
   * path's node count (I3f).
   *
   * A path is only as good as its weakest edge, and a single "inferred" hop
   * is the difference between "this call chain exists" and "a chain of these
   * names exists". Rendering the path without the marking asks the reader to
   * trust every hop equally, which is exactly what the graph cannot promise.
   */
  call_path_resolutions: z.array(z.enum(["exact", "inferred"])).optional(),
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

/**
 * The ground a graph-gated claim stands on (I3f, folded into J5). A verdict
 * that rests on reachability is a claim about a WALK — where it started, which
 * way it errs, and over what graph — and none of that is recoverable from the
 * rows: `graph.db` is a binary artifact the reader's browser cannot parse, and
 * for `no-reachable-dangerous-code` it is not even a subject of the bundle.
 *
 * So the basis is signed with the claim. "Not affected" without its entry-point
 * set is an assertion; with it, it is an argument the reader can check and
 * disagree with — which is the only version of a not-affected claim this
 * system is willing to make.
 */
export const ClaimBasis = z.object({
  /**
   * Which way the walk errs, and therefore which claims it is allowed to make.
   *   over  — every edge kind counts, so "unreachable" is only claimed when
   *           even the loose walk cannot get there; unknowns count against us.
   *   under — only real call chains count, so a positive claim ("this route
   *           reaches an auth check") rests on an actual path.
   */
  approximation: z.enum(["over", "under"]),
  /** the collector's own sentence, rendered inline wherever the claim is shown */
  statement: z.string(),
  /** repo-relative files the walk started from */
  entrypoints: z.array(z.string()),
  /** where those came from: "config" | "package.json" | "fallback" | "none" | "unavailable" */
  entrypoint_source: z.string(),
  /** declared entries that resolved to no file the walk saw — silently dropped roots, named */
  entrypoints_unresolved: z.array(z.string()).optional(),
  /** declared routes seeded the walk too (the gates root at entry points AND routes) */
  route_roots: z.number().int().optional(),
  /** what the walk was over — the graph's own identity and shape */
  graph: z
    .object({
      commit: z.string(),
      extractor_version: z.string(),
      node_count: z.number().int(),
      edge_count: z.number().int(),
      /** edges matched by name rather than lexically resolved */
      inferred_edge_count: z.number().int(),
    })
    .optional(),
  /** set when the gate ran degraded (no graph, no entry points) — the rows say so too */
  degraded: z.string().optional(),
});
export type ClaimBasis = z.infer<typeof ClaimBasis>;

export const AnchorPath = z.object({
  path: z.string(), // repo-relative
  contentHash: z.string(), // sha256 of blob at the scanned commit
});

export const EvidencePredicate = z.object({
  recipe_id: z.string(),
  /**
   * The collector that produced this evidence (J5). Optional because bundles
   * minted before J5 carry no such field — but on everything minted since,
   * this is what makes the provenance chain rest on signed data rather than
   * on today's catalog: a bundle read years later says which collector
   * produced it, not which collector the catalog would name now.
   */
  collector: z.string().optional(),
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
  /**
   * The walk this verdict rests on, when it rests on one (I3f). Absent for
   * every recipe that is not graph-gated, which is most of them — a basis
   * invented for a collector that did no walk would be the worst kind of
   * provenance: confident and made up.
   */
  basis: ClaimBasis.optional(),
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
