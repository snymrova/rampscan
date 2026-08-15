import { z } from "zod";
import { IN_TOTO_STATEMENT_TYPE, Subject } from "./bundle.js";

// ScanRun: the run record (plan J1) — the *how* behind every bundle, and the
// third member of the ledger's statement union.
//
// An evidence bundle says what was concluded. Nothing durable said how the
// run that concluded it went: which tool resolved, at which version, through
// a binary or a pinned image, with what argv, for how long, exiting how, and
// whether the answer came from cache. Auditors ask for exactly that, and an
// operator staring at an unevidenced cell needs the named reason a tool did
// not run. So it is recorded here — signed and appended like everything else,
// because a console-side collection would be the only operator-facing record
// that could not be verified or rebuilt.
//
// What this statement is NOT: a source of truth about verdicts. It carries no
// verdict, no register state, no coverage number. Those are the registers'
// job, folded from evidence and scoping alone — a run record must never be
// able to move a board cell (SPEC §6 rule 1's spirit, PLAN J risk table).

export const RAMPSCAN_SCAN_RUN_TYPE = "https://rampscan.dev/scan-run/v1" as const;

/**
 * How a tool resolved for this run. `docker` records the image digest the
 * pinned tag actually pointed at — never the tag quoted as a digest; when the
 * daemon cannot be asked, `digest` is null and `digest_reason` says why.
 */
export const ToolRuntime = z.discriminatedUnion("kind", [
  z.object({
    kind: z.literal("binary"),
    /** absolute path the binary resolved to on PATH, when it could be located */
    path: z.string().optional(),
  }),
  z.object({
    kind: z.literal("docker"),
    /** the pinned image reference from tools.json */
    image: z.string(),
    /** the repo digest the tag resolved to, or null with a stated reason */
    digest: z.string().nullable(),
    digest_reason: z.string().optional(),
  }),
  z.object({
    kind: z.literal("absent"),
    /** why nothing resolved — the same fact the collector's skip reason states */
    reason: z.string(),
  }),
]);
export type ToolRuntime = z.infer<typeof ToolRuntime>;

export const ToolResolution = z.object({
  tool: z.string(),
  /** the version the resolution reported; absent when nothing resolved */
  version: z.string().optional(),
  runtime: ToolRuntime,
});
export type ToolResolution = z.infer<typeof ToolResolution>;

/**
 * One process this collector spawned. `argv` is ALLOWLIST-redacted before it
 * is signed: a signed statement is permanent, so anything that does not match
 * a known-safe shape is replaced with `<redacted:N bytes>` rather than
 * recorded forever. A denylist is the tempting version and it is the one that
 * eventually leaks.
 */
export const ToolInvocation = z.object({
  /** the spawned executable: "syft", "docker", "git" */
  command: z.string(),
  argv: z.array(z.string()),
  duration_ms: z.number().int(),
  exit_code: z.number().int(),
});
export type ToolInvocation = z.infer<typeof ToolInvocation>;

/**
 * The scan cache's answer for this collector (M5 G2 states, quoted rather
 * than re-named): `hit` means nothing was spawned this run — the invocations
 * and runtimes below are the recorded ones of the run that PRODUCED the
 * cached result, replayed with it. `none` means no cache was configured.
 */
export const CacheRecord = z.object({
  state: z.enum(["hit", "miss", "bypass", "uncachable", "none"]),
  key: z.string().optional(),
  /** the manifest's DECLARED cacheScope terms, e.g. ["@tree"] — not the resolved file list */
  scope: z.array(z.string()).optional(),
});
export type CacheRecord = z.infer<typeof CacheRecord>;

export const CollectorRun = z.object({
  collector: z.string(),
  /** the version the collector itself reported, as it lands in every bundle */
  tool_version: z.string(),
  duration_ms: z.number().int(),
  exit_code: z.number().int(),
  /** how many findings the collector emitted — a count about the run, never a verdict */
  findings: z.number().int(),
  /** every tool this collector asked for, in resolution order; empty for pure collectors */
  tools: z.array(ToolResolution),
  invocations: z.array(ToolInvocation),
  artifacts: z.array(
    z.object({
      name: z.string(),
      sha256: z.string(),
      bytes: z.number().int().optional(),
    }),
  ),
  /**
   * Artifacts this collector consumed from earlier collectors in the same run,
   * by name (J5). Without it the provenance chain dead-ends at every gate:
   * `sast-reachability` spawns no tool of its own, so a chain built from
   * `tools` alone would say "no external tool" about a verdict that rests
   * entirely on semgrep's output. With it, the reader follows the artifact
   * name to the collector in THIS run whose `artifacts` produced it, and the
   * line runs from the verdict all the way back to the tool that spoke.
   *
   * A fact about the run, not a re-statement of the catalog: it is what the
   * manifest declared at the moment the run dispatched.
   */
  consumes: z.array(z.string()).optional(),
  cache: CacheRecord,
  /** set when the collector could not run at all — the reason an operator needs */
  skip_reason: z.string().optional(),
});
export type CollectorRun = z.infer<typeof CollectorRun>;

/**
 * What caused this scan. The daemon distinguishes its two cache modes, because
 * a full cache-bypassing pass and an incremental one are different evidence
 * about the same repo. `serve` is reserved: `rampscan serve` does not scan
 * today — the daemon does — and the member is here so the vocabulary does not
 * have to change the day it does.
 */
export const ScanRunTrigger = z.enum([
  "manual",
  "daemon-incremental",
  "daemon-full",
  "serve",
  "test",
]);
export type ScanRunTrigger = z.infer<typeof ScanRunTrigger>;

export const ScanRunPredicate = z.object({
  run_id: z.string(),
  repo: z.string(),
  commit: z.string(),
  trigger: ScanRunTrigger,
  started_at: z.string(), // ISO 8601 — when the first collector was dispatched
  duration_ms: z.number().int(),
  dataset_version: z.string(),
  collectors: z.array(CollectorRun),
  /**
   * The run's single clock — the SAME instant every bundle of this scan
   * carries, so the fold's time ordering and the as-of selector treat a run
   * record and its evidence as one event.
   */
  timestamp: z.string(), // ISO 8601
});
export type ScanRunPredicate = z.infer<typeof ScanRunPredicate>;

export const ScanRun = z.object({
  _type: z.literal(IN_TOTO_STATEMENT_TYPE),
  /** the run's artifacts, plus scan-result.json — the same subject discipline every bundle uses */
  subject: z.array(Subject).min(1),
  predicateType: z.literal(RAMPSCAN_SCAN_RUN_TYPE),
  predicate: ScanRunPredicate,
});
export type ScanRun = z.infer<typeof ScanRun>;
