import type {
  CollectorManifest,
  EvidenceBundle,
  Finding,
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
  bundle: EvidenceBundle;
  appendedAt: string; // ISO 8601
}

/** Append-only evidence ledger. local: content-addressed dir → later: S3 + Object Lock. */
export interface LedgerStore {
  append(bundle: EvidenceBundle): Promise<Digest>;
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
  sign(statement: EvidenceBundle): Promise<SignedEnvelope>;
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
  recipeId: string;
  ksiIds: string[];
  controlIds: string[];
  verdict: Verdict;
  bundleDigest?: Digest;
  status: EvidenceStatus;
  freshAsOf?: string; // ISO 8601 — bundle timestamp, for the clock view
}

export interface Projection {
  rows: CoverageRow[];
  datasetVersion: string;
  projectedAt: string;
}

/** Pure fold: ledger → projection. Identical in prototype and appliance. */
export interface Projector {
  fold(ledger: LedgerStore): Promise<Projection>;
}
