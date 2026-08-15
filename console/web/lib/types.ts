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
  degraded?: string;
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
  /** the run that produced the live evidence (J3); "" when the cell has no live evidence */
  run_id: string;
  bundle_digest: string;
  fresh_as_of: string;
  commit_sha: string;
  /** fix pointers (I2c) — violated rows whose evidence carries them; null before that */
  pointers: OffenderPointer[] | null;
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
  runId?: string;
  bundleDigest?: string;
  freshAsOf?: string;
  commit?: string;
  pointers?: OffenderPointer[];
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
