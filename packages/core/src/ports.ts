import type {
  Cadence,
  ClaimBasis,
  CollectorManifest,
  CollectorRun,
  Finding,
  LedgerStatement,
  OffenderPointer,
  PlainLanguage,
  ScanRunTrigger,
  ToolInvocation,
  ToolResolution,
  Verdict,
} from "@rampscan/schema";

// The six ports — plan §2. Every AWS dependency in the spec is an interface
// here, with a local adapter now and the AWS adapter later. Business logic
// never touches fs / child_process / the network except through these.

/** sha256 hex digest of canonicalized bundle JSON — the ledger's address. */
export type Digest = string;

export interface LedgerQuery {
  recipeId?: string;
  repo?: string;
  commit?: string;
  verdict?: Verdict;
  since?: string; // ISO 8601
}

export interface LedgerEntry {
  digest: Digest;
  /** the stored statement: an evidence bundle or (M3) a scoping event */
  bundle: LedgerStatement;
  /** the DSSE envelope over the bundle, when the append was signed (M2 always signs) */
  envelope?: SignedEnvelope;
  appendedAt: string; // ISO 8601
}

/** Append-only evidence ledger. local: content-addressed dir → later: S3 + Object Lock. */
export interface LedgerStore {
  append(bundle: LedgerStatement, envelope?: SignedEnvelope): Promise<Digest>;
  get(digest: Digest): Promise<LedgerEntry | undefined>;
  list(query?: LedgerQuery): Promise<LedgerEntry[]>;
}

/** DSSE envelope over a serialized in-toto statement. */
export interface SignedEnvelope {
  payload: string; // base64(statement JSON)
  payloadType: string;
  signatures: Array<{ keyid: string; sig: string }>;
}

/** local: cosign keypair on disk → later: cosign + KMS. */
export interface Signer {
  sign(statement: LedgerStatement): Promise<SignedEnvelope>;
  verify(envelope: SignedEnvelope): Promise<boolean>;
}

/** A fetched repo snapshot, pinned to the commit that anchors everything downstream. */
export interface Workspace {
  root: string; // absolute path of the checkout
  repo: string; // identifier, e.g. "ramprules.com/fedramp-rules-hub"
  commit: string; // full sha the workspace is pinned to
  /**
   * Which tree of that checkout the collectors should read. Absent (=
   * "committed") everywhere evidence is produced: a signed claim is about a
   * commit, and a collector reading a gitignored or uncommitted file would
   * anchor evidence to bytes no commit can name.
   *
   * `"worktree"` is set ONLY by the L3a dry run (`rampscan check`), whose
   * output is structurally labeled as not-evidence for exactly this reason.
   * Mirrors @rampscan/graph's `TreeMode` (core does not depend on graph).
   */
  tree?: "committed" | "worktree";
}

/**
 * Rows a collector observed for one recipe — what the join evaluates recipe
 * assertions against. Always an array: single-object observations are one row,
 * per-item observations (leaks, advisories, actions) are one row each, so
 * `where`-filtered and count assertions read the same way they do in
 * aws-evidence.json.
 */
export type ObservationRows = Array<Record<string, unknown>>;

/**
 * What the runner observed about HOW a collector ran (plan J1) — never about
 * what it concluded. Attached by the journaling Runner decorator, not by the
 * collector: run telemetry is not part of the collector contract, precisely
 * so no collector can under-report its own provenance.
 *
 * It rides RunResult deliberately, which means the scan cache persists and
 * restores it: on a cache hit these are the recorded invocations of the run
 * that PRODUCED the cached result, and the run record's `cache.state` is what
 * tells a reader so.
 */
export interface CollectorTelemetry {
  /** wall time the runner measured around collect() */
  durationMs: number;
  /** every tool the collector asked for, in resolution order — empty for pure collectors */
  tools: ToolResolution[];
  /** every process spawned inside the collector's journal, argv already redacted */
  invocations: ToolInvocation[];
}

export interface RunResult {
  findings: Finding[];
  /** artifacts produced, relative to the run's artifact dir, e.g. sbom.cdx.json */
  artifacts: Array<{ name: string; path: string; sha256: string }>;
  /** recipeId → rows; a recipe the collector could not observe is absent */
  observations: Record<string, ObservationRows>;
  /** recipeId → repo paths (with content hash) this evidence is about — M2 anchor death reads these */
  anchors: Record<string, Array<{ path: string; contentHash: string }>>;
  toolVersion: string;
  exitCode: number;
  /** how to re-run this collector's check (I2c) — stated by the collector, when it did */
  reproduce?: string;
  /**
   * recipeId → the walk a graph-gated verdict rests on (I3f). Keyed per recipe
   * like `anchors`, because one collector can gate several claims and each is
   * entitled to say what its own ground was.
   */
  basis?: Record<string, ClaimBasis>;
  /** set when the collector could not run at all (tool missing, no Dockerfile, …) */
  skipped?: { reason: string };
  /** how the run went (J1) — attached by the journaling runner, absent when none wrapped it */
  telemetry?: CollectorTelemetry;
}

/** local: child process / Docker → later: Fargate task. */
export interface Runner {
  run(manifest: CollectorManifest, workspace: Workspace): Promise<RunResult>;
}

/**
 * The collector extension contract: adding a collector is adding a manifest
 * plus this implementation — the pipeline itself is untouched (SPEC §7).
 * Implementations live in @rampscan/collectors; the Runner adapter executes
 * them. Everything a collector returns is Zod-enforced at the wrapper
 * boundary by the runner.
 */
export interface CollectContext {
  workspace: Workspace;
  /** absolute, collector-specific dir; every artifact the collector writes goes here */
  artifactDir: string;
  /** artifacts produced by earlier collectors this run: name → absolute path */
  inputs: ReadonlyMap<string, string>;
  runId: string;
}

export interface CollectOutput {
  findings: Finding[];
  /** name → absolute path inside artifactDir; the runner hashes and relativizes */
  artifacts: Array<{ name: string; path: string }>;
  observations: Record<string, ObservationRows>;
  anchors?: Record<string, Array<{ path: string; contentHash: string }>>;
  toolVersion: string;
  exitCode: number;
  /** how to re-run this collector's check (I2c) — rides every recipe this collector evidences */
  reproduce?: string;
  /** recipeId → the walk this collector's verdict for that recipe rests on (I3f) */
  basis?: Record<string, ClaimBasis>;
  skipped?: { reason: string };
}

export interface Collector {
  manifest: CollectorManifest;
  collect(ctx: CollectContext): Promise<CollectOutput>;
}

export type CertClass = "b" | "c"; // class d has no MVX window — SPEC §11 q6

export interface ScanTarget {
  repo: string;
  ref?: string;
}

/** local: node-cron + CLI → later: EventBridge. */
export interface Scheduler {
  /** Guarantee re-scans land inside the class's MVX window (b=7d, c=3d). */
  ensureCadence(cls: CertClass, target: ScanTarget): Promise<void>;
}

/** local: path or git clone → later: GitHub App. */
export interface RepoSource {
  fetch(target: ScanTarget): Promise<Workspace>;
}

// The seventh port (plan L4a). A local model DRAFTS text a human edits and
// signs; it has no standing in the verdict path, and nothing here is ever
// called by a collector, a gate, or the fold.
//
// Resolution does NOT follow the `tools.ts` binary → Docker ladder, and the
// difference is worth reading before assuming it does: what serves inference
// is a DAEMON, not the binary on PATH. It may be stopped, may run as another
// user, may be remote (OLLAMA_HOST). So the ladder is:
//
//   1. probe the runtime  → not answering            → "absent"
//   2. pinned weights present per models.json?  no   → "unprovisioned"
//   3. both                                          → "ready"
//
// Two absences, not one, because the operator's fix differs: install the
// runtime vs pull the pinned weights. I15 says an absence states its reason;
// collapsing these would state the wrong one.

export type ModelResolution =
  | { state: "ready"; runtime: string; runtimeVersion: string; model: string; weightsDigest: string }
  /** the runtime answers but the pinned weights are not on this machine */
  | { state: "unprovisioned"; runtime: string; runtimeVersion: string; reason: string }
  /** no runtime answered at all */
  | { state: "absent"; reason: string };

/** What a draft is FOR. Each task owns a prompt whose text is grep-tested (I1). */
export type DraftTask = "scoping-justification";

export interface DraftRequest {
  task: DraftTask;
  /**
   * Facts already on some signed statement or in the catalog. The adapter
   * renders these; it never reads the repo, the ledger or the network itself,
   * so what a draft can be about is decided by the caller and is auditable.
   */
  context: Record<string, string>;
}

export interface Draft {
  text: string;
  model: string;
  /**
   * The digest the RUNTIME REPORTS for its weights — deliberately not named
   * `weights_sha256`. rampscan cannot verify it: ollama's blob store is owned
   * by the daemon's service user and is unreadable by the calling uid, so this
   * is a claim rampscan relays and not one it checked. Fine while drafts are
   * advisory; re-decide before any drafted text becomes a signed subject (L5).
   */
  weightsDigest: string;
  costTokens?: number;
}

/**
 * local: a model daemon on this machine → later: the same, deliberately. There
 * is no cloud adapter behind this port; I8 makes the offline path the only one.
 */
export interface ModelRunner {
  resolve(): Promise<ModelResolution>;
  /** Only callable when `resolve()` said "ready"; adapters throw otherwise. */
  draft(req: DraftRequest): Promise<Draft>;
}

export type EvidenceStatus =
  | { state: "live" }
  | { state: "dead"; cause: "anchor-drift" | "superseded"; killingCommit?: string };

export interface CoverageRow {
  repo: string;
  recipeId: string;
  ksiIds: string[];
  controlIds: string[];
  verdict: Verdict;
  bundleDigest?: Digest;
  status: EvidenceStatus;
  freshAsOf?: string; // ISO 8601 — bundle timestamp, for the clock view
}

/**
 * The console's register states (M3). Verdicts come from scans; the two extra
 * states are computed by the projector: `unevidenced` from the recipe-catalog
 * join (the honest default — a recipe nobody evidenced is visible, never
 * hidden), `notApplicable` from a live scoping event in the ledger.
 */
export type RegisterState = Verdict | "notApplicable";

export interface ScopingInfo {
  digest: Digest;
  justification: string;
  proposedBy: string;
  approvedBy: string;
  timestamp: string; // ISO 8601
}

/**
 * One (repo, recipe) cell of the coverage board: the *current* answer, joined
 * from live evidence, live scoping, and the recipe catalog.
 */
export interface RegisterRow {
  repo: string;
  recipeId: string;
  ksiIds: string[];
  controlIds: string[];
  state: RegisterState;
  /** the recipe's declared cadence, when the catalog knows it */
  cadence?: Cadence;
  /**
   * The collector whose manifest declares this recipe (J3), from the same
   * catalog join that supplies ksiIds and controlIds. Absent when the recipe
   * fell out of the catalog — never inferred from the ledger, because a
   * bundle names TOOLS, not the collector that ran them, and guessing the
   * collector from a tool name would put a wrong name on the one hop an
   * operator follows to find out why a cell is empty.
   */
  collector?: string;
  /**
   * The recipe's plain-language paragraphs (K1), from the same catalog join.
   * AUTHORED prose about the CHECK, never about this cell: it says what the
   * recipe looks at, what a violation of it means and what fixing it looks
   * like, and it is identical on every repo's row for that recipe. Absent when
   * the recipe left the catalog or has not been written yet — the surfaces
   * render nothing rather than a paraphrase of the recipe id.
   *
   * Deliberately NOT signed into any bundle: it is a definition maintained in
   * the catalog, not a fact about a scan, and signing it would re-key every
   * bundle each time a sentence got clearer (J5 already spent that once).
   */
  plain?: PlainLanguage;
  /**
   * The run that produced this cell's live evidence (J3) — the live bundle
   * predicate's own `run_id`, carried onto the row so the board can point at
   * the run record without re-reading the bundle. Absent when the cell has no
   * live evidence, which is the honest shape: an unevidenced cell was
   * produced by no run at all, so there is no run id to state.
   */
  runId?: string;
  /** set when state is evidenced/violated */
  bundleDigest?: Digest;
  freshAsOf?: string; // ISO 8601 — bundle timestamp, for the clock view
  commit?: string;
  /**
   * Fix pointers (I2c): where the violation lives, lifted from the live
   * bundle's failing assertions at fold time — set only when state is
   * violated AND the evidence carries them (pre-I2c bundles do not).
   */
  pointers?: OffenderPointer[];
  /**
   * The start of the current violated streak (I2c), walked back through the
   * cell's bundle chain: the first consecutive violated bundle's timestamp
   * and scanned commit. "Scanned" said honestly — scans sample commits, so
   * this is the first commit rampscan SAW the violation at, and the streak
   * spans evidence gaps (it breaks only on a clean bundle).
   */
  introducedAt?: string; // ISO 8601
  introducingCommit?: string;
  /** set when state is notApplicable */
  scoping?: ScopingInfo;
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
 * One row of the control or KSI register (I1a): every mapped recipe for the
 * id folded to a single verdict. Precedence: violated beats unevidenced beats
 * evidenced; notApplicable rows never drag the rollup down, and the rollup is
 * notApplicable only when every mapped recipe is — scoping honored exactly as
 * the per-recipe registers honor it. Computed from the register rows, so an
 * independent recount from those rows must always reproduce these counts.
 */
export interface RollupRow {
  repo: string;
  /** a control id ("si-7.1") or a KSI id ("KSI-SCR-MIT") */
  id: string;
  state: RegisterState;
  /** the mapped recipes, sorted — every count is attributable */
  recipeIds: string[];
  counts: RollupCounts;
}

/**
 * One interval where a (repo, recipe) sat past its MVX window without
 * re-verification (I1d) — derived from the bundle chain × the class window,
 * never from a wall clock. An ongoing gap ends at the fold's projectedAt.
 */
export interface CadenceGap {
  repo: string;
  recipeId: string;
  /** the bundle whose window closed unrefreshed */
  bundleDigest: Digest;
  start: string; // ISO 8601 — when the window closed
  end: string; // ISO 8601 — the refreshing bundle's timestamp, or projectedAt when ongoing
  durationMs: number;
  ongoing: boolean;
}

/** One movement the drift view explains: evidence born, died, or flipped. */
export interface DriftEvent {
  at: string; // ISO 8601 — when the change was observed
  repo: string;
  recipeId: string;
  kind: "born" | "died" | "verdict-flipped" | "scoped";
  /** died only */
  cause?: "anchor-drift" | "superseded";
  killingCommit?: string;
  from?: Verdict;
  to?: Verdict;
  bundleDigest: Digest;
}

/**
 * How one (repo, recipe) cell moved between a baseline fold and the current
 * one (I2d). Classified from the two register states alone — the classifier
 * is total over every (from, to) pair and pinned by test, so no transition
 * can fall through unnamed.
 */
export type RegisterChangeKind =
  | "newly-violated" // → violated, from any prior state or a new cell
  | "evidence-lapsed" // evidenced|violated → unevidenced (the evidence died, nothing replaced it)
  | "unscoped" // notApplicable → unevidenced (the scoping no longer holds the cell)
  | "removed" // the cell existed at baseline and is gone (recipe or repo left the projection)
  | "appeared" // a new cell since baseline, in any non-violated state
  | "scoped" // → notApplicable (a two-key scoping landed)
  | "newly-evidenced" // unevidenced|notApplicable → evidenced (first passing evidence)
  | "resolved"; // violated → evidenced

/** One cell's movement between the baseline board and the current one. */
export interface RegisterChange {
  repo: string;
  recipeId: string;
  kind: RegisterChangeKind;
  /** absent when the cell appeared since baseline */
  from?: RegisterState;
  /** absent when the cell was removed since baseline */
  to?: RegisterState;
  /** the current side's live bundle, when it has one */
  bundleDigest?: Digest;
  /** the baseline side's live bundle, when it had one */
  baselineDigest?: Digest;
  /** on newly-violated cells: the current row's fix pointers (I2c), when the evidence carries them */
  pointers?: OffenderPointer[];
  introducedAt?: string; // ISO 8601
  introducingCommit?: string;
}

/**
 * The board diffed against a prior as-of fold (I2d). Both sides are folds of
 * the same append-only ledger, so the diff is exactly as deterministic as the
 * folds. Cells whose STATE held still count as unchanged even when their
 * evidence refreshed — bundle-level movement is the drift view's story.
 */
export interface RegisterDiff {
  /** the instant the baseline was folded as-of */
  baseline: string; // ISO 8601
  /** every cell whose state moved, severity-sorted (bad news first) */
  changes: RegisterChange[];
  counts: Record<RegisterChangeKind, number>;
  unchanged: number;
}

/**
 * One recorded scan (I1/J1): the run record's predicate, projected. Rendered
 * by `/runs` and nothing else — a scan run explains HOW evidence was produced
 * and may never contribute a verdict, a register state, or a coverage number.
 * The board is folded from evidence and scoping alone, and stays that way.
 */
export interface ScanRunRow {
  /** the ledger address of the signed run record — verify it like any bundle */
  digest: Digest;
  runId: string;
  repo: string;
  commit: string;
  trigger: ScanRunTrigger;
  startedAt: string; // ISO 8601
  /** the run's clock — the same instant its evidence bundles carry */
  timestamp: string; // ISO 8601
  durationMs: number;
  datasetVersion: string;
  /** structural, straight off the signed predicate — never re-derived */
  collectors: CollectorRun[];
}

export interface Projection {
  /** every evidence bundle ever recorded, live or dead — the chain view */
  rows: CoverageRow[];
  /** the current board: (repo, recipe) → state, incl. unevidenced + notApplicable */
  registers: RegisterRow[];
  /** movement, oldest first — the drift view reads this newest first */
  drift: DriftEvent[];
  /** the control register: control id → mapped recipes rolled up (I1a) */
  controls: RollupRow[];
  /** the KSI register — same rollup keyed by KSI id */
  ksis: RollupRow[];
  /** cadence-adherence history: MVX-window lapses, empty when no window was given (I1d) */
  gaps: CadenceGap[];
  /**
   * The run records, newest first, capped (J1): the ledger keeps every run,
   * the projection keeps the newest N — the projection is rebuildable and the
   * ledger is the record, so an unbounded per-tick projection would buy
   * nothing and cost the drop-and-refill.
   */
  scanRuns: ScanRunRow[];
  datasetVersion: string;
  projectedAt: string;
}

/** Pure fold: ledger → projection. Identical in prototype and appliance. */
export interface Projector {
  fold(ledger: LedgerStore): Promise<Projection>;
}
