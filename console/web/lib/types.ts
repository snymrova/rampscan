// Record shapes as the projector writes them (packages/projector/src/pocketbase.ts).
// The projection is the only source — these types mirror, never invent.

export type RegisterState = "evidenced" | "violated" | "unevidenced" | "notApplicable";

export interface ScopingInfo {
  digest: string;
  justification: string;
  proposedBy: string;
  approvedBy: string;
  timestamp: string;
}

/**
 * A fix pointer (I2c): where a failing observation row lives, as the
 * evaluator extracted it from the real producer's row shape. Every field
 * optional — rows carry what their producer carries.
 */
export interface OffenderPointer {
  file?: string;
  line?: number;
  check?: string;
  call_path?: string;
  /** how each HOP of call_path resolved (I3f) — always one shorter than its node count */
  call_path_resolutions?: Array<"exact" | "inferred">;
}

/**
 * The walk a graph-gated verdict rests on (I3f), exactly as the signed
 * predicate carries it. `graph.db` is a binary artifact no browser can parse
 * and is not even a subject of the SAST bundle, so this is the only place the
 * ground under a "not affected" claim is readable — which is why it is signed
 * with the claim rather than looked up beside it.
 */
export interface ClaimBasisRecord {
  approximation: "over" | "under";
  statement: string;
  entrypoints: string[];
  entrypoint_source: string;
  entrypoints_unresolved?: string[];
  route_roots?: number;
  graph?: {
    commit: string;
    extractor_version: string;
    node_count: number;
    edge_count: number;
    inferred_edge_count: number;
  };
  /**
   * The declared architecture rules this verdict was checked against (L1), as
   * canonical JSON — one string per rule. Rendered as the rules themselves and
   * never paraphrased: the reader is checking whether the verdict matches the
   * declaration, and a summary of the declaration is not the declaration.
   */
  contract_rules?: string[];
  degraded?: string;
}

/**
 * A recipe's operator English (K1), authored in the recipe JSON and carried
 * onto the row by the fold's catalog join. Prose about the CHECK — identical
 * on every repo's row for that recipe, and never about this cell's verdict.
 * Null when the recipe left the catalog or carries none.
 */
export interface PlainLanguageRecord {
  checks: string;
  violation: string;
  fix: string;
}

export interface RegisterRecord {
  id: string;
  repo: string;
  recipe_id: string;
  ksi_ids: string[];
  control_ids: string[];
  state: RegisterState;
  cadence: string;
  /** the collector the catalog says evidences this recipe (J3); "" when the recipe left the catalog */
  collector: string;
  /** the catalog's plain-language paragraphs (K1); null when the recipe has none */
  plain: PlainLanguageRecord | null;
  /** the run that produced the live evidence (J3); "" when the cell has no live evidence */
  run_id: string;
  bundle_digest: string;
  fresh_as_of: string;
  commit_sha: string;
  /** fix pointers (I2c) — violated rows whose evidence carries them; null before that */
  pointers: OffenderPointer[] | null;
  /**
   * How many observation rows this cell's verdict was reached over (N0-T1).
   * Null when the live evidence predates it — never 0 by default, because
   * "counted over nothing" is the one thing this field exists to say out loud.
   */
  population: number | null;
  /** start of the current violated streak — first scanned commit the violation appeared at */
  introduced_at: string;
  introducing_commit: string;
  scoping: ScopingInfo | null;
}

export interface RollupCounts {
  evidenced: number;
  violated: number;
  unevidenced: number;
  notApplicable: number;
  /** mapped recipes for this (repo, id) — the sum of the four states */
  total: number;
}

/**
 * One row of the control or KSI register (I1a) as the projector writes the
 * `controls` / `ksis` collections: every mapped recipe folded to a single
 * verdict (violated beats unevidenced beats evidenced; notApplicable only
 * when every mapped recipe is). Counts are attributable — an independent
 * recount from the register rows always reproduces them.
 */
export interface RollupRecord {
  id: string;
  repo: string;
  /** a control id ("si-7.1") or a KSI id ("KSI-SCR-MIT") — "id" collides with PB's record id */
  rollup_id: string;
  state: RegisterState;
  recipe_ids: string[];
  counts: RollupCounts;
}

/**
 * Scan scope as declared method provenance (SPEC §12.6): what the method's
 * mechanism walked — the axis an assessor pulls on when a green depends on
 * what was NOT read.
 */
export interface MethodScopeRecord {
  population: "checkout" | "checkout+generated";
  history: boolean;
  gitignored: "excluded" | "included";
}

/**
 * One validation method's standing (Q2.3), as the projector folds it inside
 * a method_registers row. A pipeline method's state is its recipe cell's
 * state — one bundle evidences every method its recipe derives.
 */
export interface MethodCellRecord {
  methodId: string;
  source: "pipeline" | "aws-ingested" | "attestation";
  automated: boolean;
  /** which cadence family owns this method (Q3.2): machine → VDR-TFR-MVX, non-machine → VDR-TFR-NMV */
  clock: "machine" | "non-machine";
  standing: "full" | "partial" | "narrative";
  recipeId?: string;
  collector?: string;
  scope?: MethodScopeRecord;
  state: RegisterState;
  bundleDigest?: string;
  freshAsOf?: string;
  /**
   * What kind of evidence stands live on this method (Q3.4, G6) — the live
   * bundle's signed assertion, lifted by the fold. Absent when there is no
   * live evidence or the bundle predates the assertion: this app renders
   * only what was signed.
   */
  evidenceClass?: "process-generated" | "point-in-time";
  /**
   * The owed re-validation window for this method's clock family (Q3.2) —
   * owed-side data carried by the fold, never typed into this app. Null when
   * the rules define none for the class (machine at class d).
   */
  window: { num: number; unit: "days" | "months" } | null;
  /**
   * Inside the window at the fold's projected_at; null when no window is
   * owed or the cell is scoped notApplicable. Missing evidence judges false.
   */
  freshMet: boolean | null;
}

/**
 * One of the five owed KSI artifacts (Q3.3, G5), as the fold computes it
 * inside a method_registers row. Presence of 2 and 5 is computed (artifact 5
 * is the methods' own live evidence; artifact 2 the scheduler's cadence
 * record); 1, 3, and 4 are present only while a signed two-key judgment
 * says sufficient.
 */
export interface ArtifactCellRecord {
  /** 1-based into default_artifacts.KSI — the rules' own order */
  artifact: 1 | 2 | 3 | 4 | 5;
  basis: "computed" | "judged";
  present: boolean;
  /** judged artifacts only: the live judgment, when one is recorded */
  judgment?: {
    digest: string;
    action: "sufficient" | "insufficient";
    justification: string;
    proposedBy: string;
    approvedBy: string;
    timestamp: string;
  };
}

/**
 * One (repo, KSI) row of the method register — the board's row after the
 * pivot (SPEC §12.1 invariant 4′: 46 rows, always). Floor and floor_met are
 * null when the class owes no number; never coerced to 0/false.
 */
export interface MethodRegisterRecord {
  id: string;
  repo: string;
  ksi: string;
  methods: MethodCellRecord[];
  automated_methods: number;
  method_floor: number | null;
  floor_met: boolean | null;
  fresh_as_of: string;
  /** methods whose owed clock is unmet — stale or missing evidence (Q3.2) */
  stale_methods: number;
  /** where this KSI's ledger history begins (Q3.1); "" when it holds nothing */
  history_since: string;
  /** the FRC-CSX-MOT floor in months; null when the class owes no number */
  history_floor_months: number | null;
  /** null exactly when history_floor_months is null */
  history_met: boolean | null;
  /** the five owed artifacts, ascending (Q3.3) */
  artifacts: ArtifactCellRecord[];
  /** how many of the five are present */
  artifacts_present: number;
  /**
   * Methods whose live evidence asserts point-in-time (Q3.4) — the G6
   * numerator. G6 fires when such evidence stands alone: nothing asserting
   * process-generated beside it (FRR-PVA-AA-06).
   */
  point_in_time_methods: number;
  gap: "" | "G1" | "G2" | "G3" | "G4" | "G5" | "G6";
}

/**
 * The owed-side KSI catalog as `rampscan serve` mirrors it (Q2.5): the
 * crosswalk drawer's source — read from the pinned dataset port, never
 * typed into this app.
 */
export interface KsiCatalogRecord {
  id: string;
  ksi: string;
  theme_key: string;
  theme_name: string;
  name: string;
  /** null where the rules vary the statement by class at this pin */
  statement: string | null;
  controls: string[];
  /** the five owed artifact texts (default_artifacts.KSI), rules' order (Q3.3) */
  artifacts: string[];
  /**
   * The classes that do NOT oblige this indicator (R0.2, SPEC §13.7) — read
   * from the rules JSON's own `**Optional:**` prefix by the catalog loader,
   * mirrored here so the board divides by the denominator the CLI prints
   * rather than computing a second one.
   */
  optional_at: string[];
}

export interface CoverageRecord {
  id: string;
  repo: string;
  recipe_id: string;
  ksi_ids: string[];
  control_ids: string[];
  verdict: string;
  bundle_digest: string;
  state: "live" | "dead";
  cause: string;
  killing_commit: string;
  fresh_as_of: string;
}

export interface DriftRecord {
  id: string;
  at: string;
  repo: string;
  recipe_id: string;
  kind: "born" | "died" | "verdict-flipped" | "scoped";
  cause: string;
  killing_commit: string;
  from_verdict: string;
  to_verdict: string;
  bundle_digest: string;
}

/**
 * One vulnerability-shaped record (Q3.5, G13 — VDR-CSO-FAV), as the
 * projector writes the `vulnerabilities` collection: an episode of a cell
 * standing violated, detected at the violating bundle's own timestamp and
 * resolved only by a later evidenced bundle in the same chain. A violated
 * chain that merely died (anchor drift) stays open — evidence that died
 * unfixed is not a fix.
 */
export interface VulnerabilityRecord {
  id: string;
  repo: string;
  recipe_id: string;
  ksi_ids: string[];
  detected_at: string;
  commit_sha: string;
  bundle_digest: string;
  vuln_status: "open" | "resolved";
  resolved_at: string;
  resolving_digest: string;
  resolving_commit: string;
}

export interface BundleRecord {
  id: string;
  digest: string;
  statement: {
    _type: string;
    subject: Array<{ name: string; digest: Record<string, string> }>;
    predicateType: string;
    predicate: Record<string, unknown>;
  };
  envelope: {
    payload: string;
    payloadType: string;
    signatures: Array<{ keyid: string; sig: string }>;
  } | null;
  appended_at: string;
}

export interface MetaRecord {
  id: string;
  dataset_version: string;
  projected_at: string;
  settings: {
    certClass: "b" | "c";
    reproduceCommand: string;
    /** the offline verify invocation with the serve's real dirs (I3b); older serves omit it */
    verifyCommand?: string;
  } | null;
}

/**
 * One daemon event as `rampscan serve` tails it out of daemon-events.jsonl —
 * operational telemetry, not a projection: the FILE stays the record, this
 * copy exists so the console can see the machinery (divergence alerts,
 * cadence warnings, scan records). `payload` is the whole event line.
 */
export interface DaemonEventRecord {
  id: string;
  at: string;
  kind: string;
  repo: string;
  payload: Record<string, unknown>;
}

/**
 * The daemon's heartbeat snapshot as `rampscan serve` mirrors it out of
 * daemon-status.json — same row shape as an event, but the collection holds
 * at most one row per repo and is replaced wholesale on every tick: latest
 * state, not history. An empty collection means no daemon heartbeat exists,
 * and the status strip says so instead of guessing.
 */
export type DaemonStatusRecord = DaemonEventRecord;

export interface ProposalRecord {
  id: string;
  repo: string;
  recipe_id: string;
  justification: string;
  status: "pending" | "approved" | "rejected";
  proposed_by: string;
  decided_by: string;
  scoping_digest: string;
  created: string;
  updated: string;
}

/**
 * An artifact-sufficiency proposal (Q3.3, G5) — the judgment queue beside
 * the scoping one, same two-key discipline: anyone drafts, an approver's
 * key turn appends the signed ArtifactJudgment to the ledger.
 */
export interface JudgmentProposalRecord {
  id: string;
  repo: string;
  ksi_id: string;
  /** 1 | 3 | 4 — the judged artifacts; 2 and 5 are computed */
  artifact: number;
  action: "sufficient" | "insufficient";
  justification: string;
  status: "pending" | "approved" | "rejected";
  proposed_by: string;
  decided_by: string;
  ledger_digest: string;
  created: string;
  updated: string;
}

/**
 * An attestation proposal (Q4.2, SPEC §12.9) — the third queue, same two keys:
 * anyone drafts, an approver's key turn appends the signed Attestation to the
 * ledger, and a `source: attestation` method appears on the register when the
 * projector folds it. The claim is the signed text; there is no separate
 * justification field, because the claim is what both keys are turned for.
 */
export interface AttestationProposalRecord {
  id: string;
  repo: string;
  /** the MECHANISM's name ("incident-review") — becomes the method's source_ref */
  statement_id: string;
  ksi_id: string;
  /** the accountable role, not a person: the method survives the post-holder */
  attestor_role: string;
  statement: string;
  action: "attested" | "withdrawn";
  status: "pending" | "approved" | "rejected";
  proposed_by: string;
  decided_by: string;
  ledger_digest: string;
  created: string;
  updated: string;
}

/**
 * One recorded scan (J1) as the projector writes the `scan_runs` collection.
 * `trigger` and `timestamp` carry suffixed field names for the same reason
 * `rollup_id` does — a store's own vocabulary claims the short ones.
 *
 * What a run record is NOT: a source of truth about verdicts. It carries no
 * verdict, no register state and no coverage number, and `/runs` may not
 * compute one — the board is folded from evidence and scoping alone.
 */
export type ToolRuntimeRecord =
  | { kind: "binary"; path?: string }
  | { kind: "docker"; image: string; digest: string | null; digest_reason?: string }
  | { kind: "absent"; reason: string };

export interface ToolResolutionRecord {
  tool: string;
  /** the version the resolution reported; absent when nothing resolved */
  version?: string;
  runtime: ToolRuntimeRecord;
}

/**
 * One process the collector spawned. `argv` was ALLOWLIST-redacted before the
 * statement was signed — anything that did not match a known-safe shape reads
 * `<redacted:N bytes>`, and the page renders that token rather than hiding it.
 */
export interface ToolInvocationRecord {
  command: string;
  argv: string[];
  duration_ms: number;
  exit_code: number;
}

/**
 * The scan cache's answer for this collector. `hit` means nothing was spawned
 * this run: the invocations recorded are the ones of the run that PRODUCED the
 * cached result, replayed with it, and this field is what says so.
 */
export interface CacheStateRecord {
  state: "hit" | "miss" | "bypass" | "uncachable" | "none";
  key?: string;
  scope?: string[];
}

export interface CollectorRunRecord {
  collector: string;
  tool_version: string;
  duration_ms: number;
  exit_code: number;
  findings: number;
  /** every tool this collector asked for, in resolution order; empty for pure collectors */
  tools: ToolResolutionRecord[];
  invocations: ToolInvocationRecord[];
  artifacts: Array<{ name: string; sha256: string; bytes?: number }>;
  /** artifact names this collector ate from earlier collectors in the same run (J5) */
  consumes?: string[];
  cache: CacheStateRecord;
  /** set when the collector could not run at all — the reason an operator needs */
  skip_reason?: string;
}

export interface ScanRunRecord {
  id: string;
  /** the ledger address of the signed run record — verifiable like any bundle */
  digest: string;
  run_id: string;
  repo: string;
  commit_sha: string;
  trigger_kind: "manual" | "daemon-incremental" | "daemon-full" | "serve" | "test";
  started_at: string;
  run_timestamp: string;
  duration_ms: number;
  dataset_version: string;
  collectors: CollectorRunRecord[];
}

/**
 * The "since baseline" diff (I2d) as /api/board/diff returns it — the exact
 * shape `computeBoardDiff` in @rampscan/cli produces (camelCase: this is the
 * projector's own output serialized, not a PocketBase record). Mirror, never
 * invent.
 */
export type RegisterChangeKind =
  | "newly-violated"
  | "evidence-lapsed"
  | "unscoped"
  | "removed"
  | "appeared"
  | "scoped"
  | "newly-evidenced"
  | "resolved";

export interface RegisterChange {
  repo: string;
  recipeId: string;
  kind: RegisterChangeKind;
  from?: RegisterState;
  to?: RegisterState;
  bundleDigest?: string;
  baselineDigest?: string;
  pointers?: OffenderPointer[];
  introducedAt?: string;
  introducingCommit?: string;
}

export interface BoardDiffResponse {
  /** present when the diff computed */
  scans?: string[];
  baseline?: string;
  baselineIsScan?: boolean;
  diff?: {
    baseline: string;
    changes: RegisterChange[];
    counts: Record<RegisterChangeKind, number>;
    unchanged: number;
  };
  /** present when the ledger cannot answer (e.g. only one scan recorded) */
  reason?: string;
  /** present on a real failure (not signed in, bad request, server error) */
  error?: string;
}

/**
 * The as-of board (I3d) as /api/board/asof returns it — the exact shape
 * `computeBoardAsOf` in @rampscan/cli produces (camelCase: the projector's
 * own output serialized, not a PocketBase record). One as-of fold of the
 * ledger (I1b); the register rows and rollups here are the projector's, so
 * a mapping to the live record shapes is mechanical renaming, never
 * recomputation. Mirror, never invent. Only the fields the pages render are
 * mirrored — the fold also carries chains and drift, which stay server-side.
 */
export interface AsOfRegisterRow {
  repo: string;
  recipeId: string;
  ksiIds: string[];
  controlIds: string[];
  state: RegisterState;
  cadence?: string;
  collector?: string;
  plain?: PlainLanguageRecord;
  runId?: string;
  bundleDigest?: string;
  freshAsOf?: string;
  commit?: string;
  pointers?: OffenderPointer[];
  /** the domain the historical verdict was reached over (N0-T1) */
  population?: number;
  introducedAt?: string;
  introducingCommit?: string;
  scoping?: ScopingInfo;
}

export interface AsOfRollupRow {
  repo: string;
  id: string;
  state: RegisterState;
  recipeIds: string[];
  counts: RollupCounts;
}

export interface BoardAsOfResponse {
  /** present when the fold computed */
  scans?: string[];
  asOf?: string;
  asOfIsScan?: boolean;
  projection?: {
    registers: AsOfRegisterRow[];
    controls: AsOfRollupRow[];
    ksis: AsOfRollupRow[];
    datasetVersion: string;
    projectedAt: string;
  };
  /** present on a real failure (not signed in, bad request, server error) */
  error?: string;
}

/**
 * One cadence lapse (I1d) as the projector writes the `gaps` collection: an
 * interval where a (repo, recipe) sat past its MVX window unrefreshed,
 * derived from the bundle chain × the class window — never a wall clock. An
 * ongoing lapse ends at the fold's projected_at.
 */
export interface GapRecord {
  id: string;
  repo: string;
  recipe_id: string;
  /** the bundle whose window closed unrefreshed */
  bundle_digest: string;
  gap_start: string;
  gap_end: string;
  duration_ms: number;
  ongoing: boolean;
}

/**
 * The scoping register (I3c) as /api/scoping/register returns it — the exact
 * shape `computeScopingRegister` in @rampscan/cli produces (camelCase: the
 * compute's own output serialized, not a PocketBase record). Approved rows
 * come from the LEDGER's signed events, re-verified server-side; rejected and
 * pending rows come from the proposals collection, the only place they exist.
 * Mirror, never invent.
 */
export type ScopingSignatureStatus = "verified" | "failed" | "unsigned" | "missing";

export interface ScopingRegisterRow {
  decision: "approved" | "rejected" | "pending";
  repo: string;
  recipeId: string;
  ksiIds: string[];
  controlIds: string[];
  justification: string;
  proposedBy: string;
  decidedBy: string;
  timestamp: string;
  digest?: string;
  signature?: ScopingSignatureStatus;
  /** honesty flags the compute raised — rendered, never smoothed over */
  problems: string[];
}

export interface ScopingRegisterResponse {
  rows?: ScopingRegisterRow[];
  counts?: { approved: number; rejected: number; pending: number };
  /** present on a real failure (not signed in, server error) */
  error?: string;
}

/** KSI theme = the middle segment: KSI-SVC-CLS → SVC. */
export function ksiTheme(id: string): string {
  const parts = id.split("-");
  return parts.length >= 2 ? parts[1]! : id;
}

/** Control family = the leading alpha token: si-7.1 → si. */
export function controlFamily(id: string): string {
  const match = /^[a-z]+/i.exec(id);
  return match ? match[0]!.toLowerCase() : id;
}
