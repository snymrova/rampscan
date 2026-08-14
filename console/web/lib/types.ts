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
}

export interface RegisterRecord {
  id: string;
  repo: string;
  recipe_id: string;
  ksi_ids: string[];
  control_ids: string[];
  state: RegisterState;
  cadence: string;
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
