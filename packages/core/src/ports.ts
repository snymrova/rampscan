import type {
  Cadence,
  CollectorManifest,
  Finding,
  LedgerStatement,
  OffenderPointer,
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
}

/**
 * Rows a collector observed for one recipe — what the join evaluates recipe
 * assertions against. Always an array: single-object observations are one row,
 * per-item observations (leaks, advisories, actions) are one row each, so
 * `where`-filtered and count assertions read the same way they do in
 * aws-evidence.json.
 */
export type ObservationRows = Array<Record<string, unknown>>;

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
  /** set when the collector could not run at all (tool missing, no Dockerfile, …) */
  skipped?: { reason: string };
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
  datasetVersion: string;
  projectedAt: string;
}

/** Pure fold: ledger → projection. Identical in prototype and appliance. */
export interface Projector {
  fold(ledger: LedgerStore): Promise<Projection>;
}
