import { z } from "zod";
import { IN_TOTO_STATEMENT_TYPE, Subject } from "./bundle.js";

// The runner contract (docs/PLAN-CLOUD-RUNNER.md §2, SPEC §12.11): the two
// documents that cross between the appliance and a client-deployed runner.
// The appliance mints a RunRequest and later receives a RunTranscript plus
// the raw bytes each step printed. Nothing in either document is a verdict —
// the runner reports what it ran and what came back (ground rule 3), and the
// appliance evaluates the recipe's assertions over the bytes itself, the way
// the tree adapter does since #147.
//
// Strict at every level, like the ingestion contract it feeds: an assessor
// pulls on the transcript to learn which role, in which account, received
// which bytes, and a field that parses to nothing is a question the
// interrogation view can no longer answer.

export const RUN_REQUEST_TYPE = "https://rampscan.dev/run-request/v1" as const;
export const RUN_TRANSCRIPT_TYPE = "https://rampscan.dev/run-transcript/v1" as const;

const Sha256 = z.string().regex(/^[0-9a-f]{64}$/);

/**
 * What the appliance asks a runner to do: one recipe, bound parameters, a
 * single-use nonce and a window. Signed into the ledger when minted (T4-1);
 * the transcript binds back to it by digest, so a run for a request the
 * appliance never made, or made for a different recipe, is refused at intake.
 */
export const RunRequest = z.strictObject({
  _type: z.literal(RUN_REQUEST_TYPE),
  /** single-use; a transcript replaying a nonce already accepted is refused */
  nonce: z.string().min(16),
  /** upstream's recipe id and the digest of the recipe as pinned */
  recipe_id: z.string().min(1),
  recipe_digest: Sha256,
  ksi: z.string().min(1),
  /** the reviewed parameter bindings (T1-3), never an example literal */
  params: z.record(z.string(), z.string()),
  issued_at: z.iso.datetime({ offset: true }),
  expires_at: z.iso.datetime({ offset: true }),
  /** the console identity that clicked */
  requester: z.string().min(1),
});
export type RunRequest = z.infer<typeof RunRequest>;

/**
 * The runner's reading of what the CLI wrote to stderr — a class, never the
 * bytes, because stderr can carry account detail into logs. `none` is a
 * step that wrote nothing there. Only `none` beside exit 0 is a step the
 * appliance may evaluate (T2-2); every other class is a failed run.
 */
export const StderrClass = z.enum([
  "none",
  "access-denied",
  "throttled",
  "not-enabled",
  "incomplete",
  "other",
]);
export type StderrClass = z.infer<typeof StderrClass>;

/** one CLI invocation, as argv — the command run is the command published */
export const TranscriptStep = z.strictObject({
  argv: z.array(z.string().min(1)).min(1),
  exit_code: z.number().int(),
  started_at: z.iso.datetime({ offset: true }),
  finished_at: z.iso.datetime({ offset: true }),
  /** the bytes the step printed to stdout, by digest; the bytes ride beside the transcript */
  stdout_sha256: Sha256,
  stdout_bytes: z.number().int().nonnegative(),
  stderr_class: StderrClass,
});
export type TranscriptStep = z.infer<typeof TranscriptStep>;

/**
 * The self-check the runner performs at start-up (T3-3): a probe set of
 * mutating actions simulated against its own role, every one of which must
 * be denied. Carried in every transcript so the reader can see the role was
 * read-only when the run happened, not merely when the policy was generated.
 */
export const RunnerSelfCheck = z.strictObject({
  probes: z.array(z.string().min(1)).min(1),
  all_denied: z.boolean(),
});
export type RunnerSelfCheck = z.infer<typeof RunnerSelfCheck>;

/**
 * What the runner hands back. Signed by the runner's own key (T3-2) as a
 * DSSE envelope; this is the payload. The appliance checks the signature,
 * the nonce, the request digest, the caller account and the window before
 * it reads a single output byte — and refuses the run, visibly, if any of
 * those fails.
 */
export const RunTranscript = z.strictObject({
  _type: z.literal(RUN_TRANSCRIPT_TYPE),
  /** sha256 of the canonical RunRequest this run answers */
  request_digest: Sha256,
  nonce: z.string().min(16),
  recipe_id: z.string().min(1),
  ksi: z.string().min(1),
  runner: z.strictObject({
    /** the registered runner name (T3-2) */
    name: z.string().min(1),
    /** what `sts get-caller-identity` returned, as the runner saw it */
    caller_arn: z.string().min(1),
    account: z.string().regex(/^\d{12}$/),
    partition: z.enum(["aws", "aws-us-gov"]),
    region: z.string().min(1),
  }),
  self_check: RunnerSelfCheck.optional(),
  steps: z.array(TranscriptStep).min(1),
  started_at: z.iso.datetime({ offset: true }),
  finished_at: z.iso.datetime({ offset: true }),
});
export type RunTranscript = z.infer<typeof RunTranscript>;

// ---------------------------------------------------------------------------
// The ledger's record of a run (T4-1, T4-3): the request as the click minted
// it, and the states it passes through. Ledger first, projection follows —
// the Runs page is folded from these, never written directly.

export const RAMPSCAN_RUN_REQUEST_EVENT_TYPE = "https://rampscan.dev/run-request-event/v1" as const;
export const RAMPSCAN_RUN_EVENT_TYPE = "https://rampscan.dev/run-event/v1" as const;

/** the DSSE payload type of a `once` token — signed by the appliance's own key, never a ledger statement */
export const RUN_TOKEN_PAYLOAD_TYPE = "application/vnd.rampscan.run-token+json" as const;

export const RunRequestEventPredicate = z.strictObject({
  /** the request exactly as the runner receives it — `request_digest` is sha256 over its canonical bytes */
  request: RunRequest,
  request_digest: z.string().regex(/^[0-9a-f]{64}$/),
  /** the argv the appliance classified (T1-2), bound; what the runner executes and nothing else */
  steps: z.array(z.array(z.string().min(1)).min(1)).min(1),
  /** per step: the transform (T1-4) and the label (T2-5) intake applies */
  transforms: z.array(z.enum(["base64-decode"]).nullable()),
  labels: z.array(z.string().min(1)),
  /** the recipe's cadence, for the submission */
  cadence: z.string().min(1),
  repo: z.string(),
  dataset_version: z.string(),
  timestamp: z.iso.datetime({ offset: true }),
});
export type RunRequestEventPredicate = z.infer<typeof RunRequestEventPredicate>;

export const RunRequestEvent = z.object({
  _type: z.literal(IN_TOTO_STATEMENT_TYPE),
  subject: z.array(Subject).min(1),
  predicateType: z.literal(RAMPSCAN_RUN_REQUEST_EVENT_TYPE),
  predicate: RunRequestEventPredicate,
});
export type RunRequestEvent = z.infer<typeof RunRequestEvent>;

/**
 * One state change of one request, by nonce. `accepted` names the evidence
 * bundle intake minted; `failed` carries the class; `refused` the reason.
 * `expired` is written by the fold's reader, never appended: a request past
 * its window with no other event reads as expired.
 */
export const RunEventPredicate = z.strictObject({
  nonce: z.string().min(16),
  state: z.enum(["claimed", "submitted", "accepted", "refused", "failed"]),
  /** the runner that claimed or submitted, as the registry or the token named it */
  runner: z.string().min(1).optional(),
  reason: z.string().min(1).optional(),
  class: z.enum(["denied", "not-enabled", "throttled", "incomplete", "error"]).optional(),
  /** `accepted`: the evidence bundle's ledger digest */
  evidence_digest: z.string().regex(/^[0-9a-f]{64}$/).optional(),
  repo: z.string(),
  dataset_version: z.string(),
  timestamp: z.iso.datetime({ offset: true }),
});
export type RunEventPredicate = z.infer<typeof RunEventPredicate>;

export const RunEvent = z.object({
  _type: z.literal(IN_TOTO_STATEMENT_TYPE),
  subject: z.array(Subject).min(1),
  predicateType: z.literal(RAMPSCAN_RUN_EVENT_TYPE),
  predicate: RunEventPredicate,
});
export type RunEvent = z.infer<typeof RunEvent>;
