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

/**
 * What kind of evidence this bundle carries (Q3.4, G6) — asserted where the
 * bundle enters the ledger, never inferred later. `process-generated` is the
 * output of a repeatable process over declared inputs (everything the
 * pipeline mints, by construction); `point-in-time` is a captured state — a
 * screenshot, a config dump — which FRR-PVA-AA-06 instructs assessors to
 * reject as STANDALONE evidence. The label exists so Q4's ingested bundles
 * can be classified at ingestion and judged by that rule.
 */
export const EvidenceClass = z.enum(["process-generated", "point-in-time"]);
export type EvidenceClass = z.infer<typeof EvidenceClass>;

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
   * lexically resolved to a file the walk saw), "inferred" (matched by
   * name), or "sbom" (S1-2: a `dependsOn` edge declared in a package
   * manifest and read from the CycloneDX SBOM — the code graph never saw the
   * hop at all). One entry per hop, so this array is always one shorter than
   * the path's node count (I3f).
   *
   * A path is only as good as its weakest edge, and a single "inferred" hop
   * is the difference between "this call chain exists" and "a chain of these
   * names exists". An "sbom" hop is a third thing again: a manifest's word
   * that one package declares another, which proves presence in the
   * dependency tree and says nothing about a call. Rendering the path
   * without the marking asks the reader to trust every hop equally, which is
   * exactly what the graph cannot promise.
   */
  call_path_resolutions: z.array(z.enum(["exact", "inferred", "sbom"])).optional(),
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
  /**
   * The domain this assertion was evaluated over (N0-T1): the number of
   * observation rows the collector emitted for the recipe, BEFORE the
   * assertion's own `where` filter narrowed them.
   *
   * It exists because `count 0` is ambiguous and the ambiguity is the whole
   * failure mode N0 is built to catch: "0 of 412" and "0 of 0" are different
   * facts and only one of them is evidence. Carried on EVERY assertion, not
   * only the count ops the plan named — a row-wise op over an empty filtered
   * set passes vacuously too (`assert.ts`'s own doc comment says so), so the
   * discrimination has to be available wherever a pass can be vacuous.
   *
   * Deliberately EXCLUDED from evidence identity (`sameEvidence`), like the
   * I2c additions: it restates the size of what `detail` already witnesses, so
   * keying on it would re-key every pre-N0 bundle for zero informational
   * change. Old evidence honestly carries no population until real drift
   * refreshes it.
   */
  population: z.number().int().optional(),
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
  /**
   * The width of every negative claim in this bundle (S1-3): each application
   * root the tree declares — a directory with its own package.json that owns
   * source files — with how many of its files the walk reached. A root with
   * `reached_file_count: 0` is an application the walk never entered, and
   * while any such root exists the gate refuses `not_affected` for the whole
   * run (`degraded` then says so). Signed with the claim for the same reason
   * the entry-point set is: "not reachable from the entry points" is only a
   * statement about the repository if the entry points cover the repository,
   * and this is where a reader checks that they do.
   */
  application_roots: z
    .array(
      z.object({
        dir: z.string(),
        name: z.string().optional(),
        file_count: z.number().int(),
        reached_file_count: z.number().int(),
      }),
    )
    .optional(),
  /**
   * What entry-point detection found that the config left out (S1-4), each
   * with whether the walk reached it anyway. Config still decides where the
   * walk starts; this is the record of what it decided against, signed with
   * the claim so a reader can see the narrowing rather than infer it. One
   * not reached is a place the program starts that no walk covered, and the
   * gate refuses `not_affected` for the run while one exists.
   */
  entrypoints_excluded: z
    .array(
      z.object({
        file: z.string(),
        via: z.string(),
        root: z.string(),
        reached: z.boolean(),
      }),
    )
    .optional(),
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
  /**
   * The SBOM's declared dependency graph the walk continued through (S1-2),
   * signed with the claim for the same reason the code graph's shape is: a
   * reader of an sbom-marked hop is owed how partial the manifest graph was.
   * `components_with_edges` against `component_count` is that measure — and
   * the reason this graph proves presence only. Absent when no SBOM was
   * available to the gate, in which case no hop can be marked `sbom`.
   */
  sbom: z
    .object({
      component_count: z.number().int(),
      /** npm components carrying at least one outgoing dependsOn edge */
      components_with_edges: z.number().int(),
      /** npm → npm dependsOn edges the walk could continue through */
      edge_count: z.number().int(),
    })
    .optional(),
  /**
   * The declared contract rules this gate evaluated (L1), as canonical JSON —
   * one string per rule, exactly the rules of THIS recipe's kind, normalized
   * so two spellings of the same declaration compare equal. Signed with the
   * claim for the same reason the entry-point set is: the verdict is "the code
   * holds to THESE rules", and a console fetching the rule text from today's
   * config would render a contract other than the one the walk checked.
   * Because `sameEvidence` compares the basis whole, editing a rule re-keys
   * its recipe's evidence and kills the stale claim — the L0 identity
   * decision, inherited rather than re-implemented.
   */
  contract_rules: z.array(z.string()).optional(),
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
   * The ValidationMethod this evidence attaches to (SPEC §12.2) — the join
   * the post-pivot register reads, beside the recipe ID it already carries.
   * Optional because bundles minted before the pivot carry none; a superset,
   * nothing existing breaks. Excluded from evidence identity like `offenders`
   * (`sameEvidence` enumerates its fields): the id is derived from
   * recipe × KSI, so keying on it would re-key every pre-pivot bundle for
   * zero informational change.
   */
  method_id: z.string().optional(),
  /**
   * The collector that produced this evidence (J5). Optional because bundles
   * minted before J5 carry no such field — but on everything minted since,
   * this is what makes the provenance chain rest on signed data rather than
   * on today's catalog: a bundle read years later says which collector
   * produced it, not which collector the catalog would name now.
   */
  collector: z.string().optional(),
  /**
   * The evidence-class assertion (Q3.4, G6): process-generated vs
   * point-in-time, asserted at ingestion — minting for pipeline bundles,
   * the ingestion contract for Q4's. Optional because bundles minted before
   * Q3.4 carry none, and an absent assertion stays absent: a classification
   * an assessor can rely on is one that is signed, not one filled in later.
   * Excluded from evidence identity (`sameEvidence`), like `method_id`:
   * everything the pipeline mints is process-generated by construction, so
   * keying on it would re-key every pre-Q3.4 bundle for zero informational
   * change.
   */
  evidence_class: EvidenceClass.optional(),
  /**
   * The ingestion handoff (SPEC §12.8, Q4.1), present exactly on bundles
   * minted from an IngestSubmission: who ran the upstream recipe and stands
   * behind the result, and the sha256 of the canonical submission — the
   * address of exactly what was accepted. Strict, because this is the
   * provenance an assessor pulls on for evidence the appliance never
   * produced. INCLUDED in evidence identity (`sameEvidence`), on the
   * `collector`/`basis` side of that line: the same verdict handed over by a
   * different signer, or derived from different submitted bytes, is
   * different evidence. Pipeline bundles carry no block on either side of
   * the comparison, so nothing existing re-keys.
   */
  ingest: z
    .strictObject({
      signer_identity: z.string().min(1),
      ingest_digest: z.string().min(1),
      /**
       * The submission's own `automated` (S3-1), copied when it declared one
       * so the method the register derives from this bundle carries the
       * FRC-CSX-VVK numerator the submitter stated. Absent on every bundle
       * minted before it and on every submission that did not declare it,
       * and absent reads true — the value all of those were.
       */
      automated: z.boolean().optional(),
    })
    .optional(),
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
