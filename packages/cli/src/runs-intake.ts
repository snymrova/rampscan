import { createHash } from "node:crypto";
import { evaluateAssertions, evaluateLabeledAssertions, labeledField } from "@rampscan/core";
import type { LabeledDocuments, ObservationRows } from "@rampscan/core";
import { INGEST_SUBMISSION_TYPE, canonicalJson } from "@rampscan/schema";
import type {
  Cadence,
  IngestSubmission,
  RecipeAssertion,
  RunRequest,
  RunTranscript,
  StderrClass,
  TranscriptStep,
} from "@rampscan/schema";
import type { StepTransform } from "./aws-classify.js";
import { derivedStepLabel } from "./aws-labels.js";

// The appliance side of the runner contract (docs/PLAN-CLOUD-RUNNER.md T2-2,
// T2-3; SPEC §14.2): a signed transcript and the bytes it names come in; a
// native IngestSubmission for the existing `ingest` path comes out — or a
// failed run with its class, or a refusal with its reason. Never a verdict
// the runner wrote (ground rule 3), and never a bundle over bytes the
// account did not actually yield (ground rule 2).
//
// The envelope's signature is the intake route's to verify (T4-2) against
// the registered runner key, before the payload reaches here. Everything
// after the signature is refused here, in the order §14.2 states, and
// before a single output byte is read.
//
// Written first as the cases it must refuse (T0-4, packages/cli/test/
// runs-intake.test.ts); those five turned green with this file.

/** why a run produced no bundle — the Runs page shows the class, never an absence */
export type FailureClass = "denied" | "not-enabled" | "throttled" | "incomplete" | "error";

export type IntakeOutcome =
  /** every check passed and the bytes were evaluated: hand this to `ingest` */
  | { kind: "submission"; submission: IngestSubmission }
  /** the account was not seen: a visible failed run, no bundle */
  | { kind: "failed"; class: FailureClass; reason: string }
  /** the transcript does not answer a request this appliance made, or answers one twice */
  | { kind: "refused"; reason: string };

export interface IntakeContext {
  /** the request as the ledger recorded it when the button was clicked */
  request: RunRequest;
  /** the configured `aws.account_id` and partition (T1-3) the transcript must have been taken in */
  account: string;
  partition: "aws" | "aws-us-gov";
  /** the pinned recipe's structured assertions, evaluated here and nowhere else */
  assertions: readonly RecipeAssertion[];
  /** the transform the classifier attached to each step (T1-4), by step index; absent = none */
  transforms?: ReadonlyArray<StepTransform | undefined>;
  /**
   * The label each step's document carries for upstream's `<label>.<path>`
   * assertions (T2-5), by step index — the reviewed row or the rule
   * (`stepLabels`). Absent: the rule alone, from each step's argv.
   */
  labels?: readonly string[];
  /** the cycle the method runs on — the recipe's */
  cadence: Cadence;
  /**
   * Whether a transcript without a self-check is refused (T3-3). True unless
   * the appliance is configured for an emulator that cannot answer
   * simulate-principal-policy; a real account's runner always checks.
   */
  requireSelfCheck?: boolean;
  /** nonces already accepted into the ledger — a second transcript for one is a replay */
  acceptedNonces: ReadonlySet<string>;
  /** the appliance's clock at receipt; the run's own timestamps must fall inside the request window before it */
  receivedAt: string;
}

/** the request's address: sha256 over its canonical bytes, what a transcript binds to */
export function requestDigest(request: RunRequest): string {
  return createHash("sha256").update(canonicalJson(request)).digest("hex");
}

const CLASS_OF: Record<Exclude<StderrClass, "none">, FailureClass> = {
  "access-denied": "denied",
  throttled: "throttled",
  "not-enabled": "not-enabled",
  incomplete: "incomplete",
  other: "error",
};

/**
 * T2-2: one class per step, `ok` only for exit 0 with nothing on stderr.
 * A non-zero exit with a clean stderr is `error` — the CLI said nothing
 * about why, and "nothing printed" is not a population.
 */
export function classifyStep(step: TranscriptStep): FailureClass | "ok" {
  if (step.stderr_class !== "none") return CLASS_OF[step.stderr_class];
  return step.exit_code === 0 ? "ok" : "error";
}

/**
 * The rows an assertion reads from one step's bytes: a JSON array of
 * objects; a JSON object with exactly one array-valued key (the CLI's
 * unprojected shape, `{"EvaluationResults":[…]}`); a single object as one
 * row; or, after the base64 transform, a CSV with a header. Anything else
 * is zero rows — recorded as such, never invented.
 */
export function rowsOfOutput(bytes: Uint8Array, transform?: StepTransform): ObservationRows {
  const shape = outputShape(bytes, transform);
  return shape.kind === "record" ? [shape.row] : shape.rows;
}

/**
 * What one step printed, by shape: a `collection` (an array, the CLI's
 * one-array object, or a CSV) is a population; a `record` (a single object
 * — a status, a vault's configuration) is one row that is NOT a population
 * beside a collection, so `generate-credential-report`'s `{"State": …}`
 * never counts among the report's principals.
 */
export function outputShape(
  bytes: Uint8Array,
  transform?: StepTransform,
): { kind: "collection"; rows: ObservationRows } | { kind: "record"; row: Record<string, unknown> } | { kind: "none"; rows: [] } {
  let text = new TextDecoder().decode(bytes);
  if (transform === "base64-decode") text = Buffer.from(text.trim(), "base64").toString("utf8");
  const trimmed = text.trim();
  if (trimmed === "") return { kind: "none", rows: [] };
  if (trimmed.startsWith("[") || trimmed.startsWith("{")) {
    try {
      const parsed: unknown = JSON.parse(trimmed);
      if (Array.isArray(parsed)) return { kind: "collection", rows: parsed.filter(isRow) };
      if (isRow(parsed)) {
        const arrays = Object.entries(parsed).filter(([, v]) => Array.isArray(v));
        if (arrays.length === 1) return { kind: "collection", rows: (arrays[0]![1] as unknown[]).filter(isRow) };
        return { kind: "record", row: parsed };
      }
      return { kind: "none", rows: [] };
    } catch {
      return { kind: "none", rows: [] };
    }
  }
  const rows = csvRows(trimmed);
  return rows.length > 0 ? { kind: "collection", rows } : { kind: "none", rows: [] };
}

function isRow(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

/** a plain CSV with a header row; quoted fields honoured, no embedded newlines */
function csvRows(text: string): ObservationRows {
  const lines = text.split(/\r?\n/).filter((l) => l.length > 0);
  if (lines.length < 2) return [];
  const header = csvLine(lines[0]!);
  return lines.slice(1).map((line) => {
    const cells = csvLine(line);
    const row: Record<string, unknown> = {};
    header.forEach((h, i) => {
      row[h] = cells[i] ?? "";
    });
    return row;
  });
}

function csvLine(line: string): string[] {
  const out: string[] = [];
  let cell = "";
  let quoted = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i]!;
    if (quoted) {
      if (c === '"' && line[i + 1] === '"') {
        cell += '"';
        i++;
      } else if (c === '"') quoted = false;
      else cell += c;
    } else if (c === '"') quoted = true;
    else if (c === ",") {
      out.push(cell);
      cell = "";
    } else cell += c;
  }
  out.push(cell);
  return out;
}

/**
 * A step's whole document for the labeled vocabulary: the parsed JSON as
 * printed (an object keeps its keys — `{"EvaluationResults": […]}` is read
 * by that key), a CSV as its rows, nothing as null.
 */
function documentOf(bytes: Uint8Array, transform: StepTransform | undefined, shape: ReturnType<typeof outputShape>): unknown {
  let text = new TextDecoder().decode(bytes).trim();
  if (transform === "base64-decode") text = Buffer.from(text, "base64").toString("utf8").trim();
  if (text.startsWith("[") || text.startsWith("{")) {
    try {
      return JSON.parse(text) as unknown;
    } catch {
      return null;
    }
  }
  return shape.kind === "collection" ? shape.rows : null;
}

/** two steps under one label read as one document: objects shallow-merge, arrays concatenate, else the later */
function mergeDocuments(a: unknown, b: unknown): unknown {
  if (a === undefined) return b;
  if (Array.isArray(a) && Array.isArray(b)) return [...a, ...b];
  if (isRow(a) && isRow(b)) return { ...a, ...b };
  return b;
}

function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function extOf(step: TranscriptStep, transform?: StepTransform): string {
  if (transform === "base64-decode") return "b64";
  const i = step.argv.indexOf("--output");
  return i !== -1 && step.argv[i + 1] === "text" ? "txt" : "json";
}

/**
 * Read a runner's transcript into a native submission, or say why not.
 * Refusals first (nonce, request, account, window), then the failure
 * classes over every step, then — and only then — the bytes.
 */
export function intakeTranscript(
  transcript: RunTranscript,
  outputs: ReadonlyMap<string, Uint8Array>,
  ctx: IntakeContext,
): IntakeOutcome {
  const refuse = (reason: string): IntakeOutcome => ({ kind: "refused", reason });
  const { request } = ctx;

  // the nonce: single-use, and this appliance's
  if (transcript.nonce !== request.nonce) {
    return refuse(`nonce ${transcript.nonce} is not the request's (${request.nonce})`);
  }
  if (ctx.acceptedNonces.has(transcript.nonce)) {
    return refuse(`nonce ${transcript.nonce} was already accepted — a replay, refused before any byte is read`);
  }
  // the request: the digest, the recipe, the KSI
  const expected = requestDigest(request);
  if (transcript.request_digest !== expected) {
    return refuse(`request digest ${transcript.request_digest.slice(0, 12)}… does not address the request this appliance made (${expected.slice(0, 12)}…)`);
  }
  if (transcript.recipe_id !== request.recipe_id || transcript.ksi !== request.ksi) {
    return refuse(`transcript answers ${transcript.recipe_id}#${transcript.ksi}; the request was ${request.recipe_id}#${request.ksi}`);
  }
  // the account: what STS said, against what is configured
  if (transcript.runner.account !== ctx.account || transcript.runner.partition !== ctx.partition) {
    return refuse(
      `the runner observed account ${transcript.runner.account} (${transcript.runner.partition}); ` +
        `this appliance is configured for ${ctx.account} (${ctx.partition}) — evidence about some other account`,
    );
  }
  if (!transcript.runner.caller_arn.includes(`:${transcript.runner.account}:`)) {
    return refuse(`caller ARN ${transcript.runner.caller_arn} does not belong to account ${transcript.runner.account}`);
  }
  // the role: shown read-only when the run happened — required, unless the
  // appliance is configured for an emulator that cannot answer the simulation
  if (transcript.self_check === undefined && ctx.requireSelfCheck !== false) {
    return refuse("the transcript carries no self-check: the role was not shown read-only when the run happened");
  }
  if (transcript.self_check !== undefined && !transcript.self_check.all_denied) {
    return refuse("the runner's self-check found a mutating probe allowed to its role; a run under that role is refused");
  }
  // the window: issued ≤ started ≤ finished ≤ expires, and before receipt
  const t = (iso: string) => Date.parse(iso);
  if (!(t(request.issued_at) <= t(transcript.started_at) && t(transcript.started_at) <= t(transcript.finished_at))) {
    return refuse(`run ${transcript.started_at}→${transcript.finished_at} does not start after the request was issued (${request.issued_at})`);
  }
  if (t(transcript.finished_at) > t(request.expires_at)) {
    return refuse(`run finished ${transcript.finished_at}, after the request expired (${request.expires_at})`);
  }
  if (t(transcript.finished_at) > t(ctx.receivedAt)) {
    return refuse(`run finished ${transcript.finished_at}, after it was received (${ctx.receivedAt})`);
  }
  for (const [i, step] of transcript.steps.entries()) {
    if (t(step.started_at) < t(transcript.started_at) || t(step.finished_at) > t(transcript.finished_at)) {
      return refuse(`step ${i + 1} ran outside the transcript's own window`);
    }
  }

  // T2-2: the classes, over every step, before any byte is read
  for (const [i, step] of transcript.steps.entries()) {
    const cls = classifyStep(step);
    if (cls !== "ok") {
      return {
        kind: "failed",
        class: cls,
        reason:
          `step ${i + 1} (${step.argv.slice(0, 3).join(" ")}) exited ${step.exit_code} with stderr ${step.stderr_class}: ` +
          "the account was not seen, so there is nothing to attest to and nothing to violate",
      };
    }
  }

  // the bytes: every step's, by the digest the transcript names
  const artifacts: IngestSubmission["artifacts"] = [];
  const collections: ObservationRows = [];
  const records: ObservationRows = [];
  const documents: Record<string, unknown> = {};
  for (const [i, step] of transcript.steps.entries()) {
    const bytes = outputs.get(step.stdout_sha256);
    if (bytes === undefined) {
      return refuse(`step ${i + 1}: no output bytes for digest ${step.stdout_sha256.slice(0, 12)}…`);
    }
    if (bytes.byteLength !== step.stdout_bytes || sha256Hex(bytes) !== step.stdout_sha256) {
      return refuse(`step ${i + 1}: the output bytes do not match the digest the transcript names`);
    }
    const transform = ctx.transforms?.[i];
    artifacts.push({ name: `step-${i + 1}.${extOf(step, transform)}`, sha256: step.stdout_sha256 });
    const shape = outputShape(bytes, transform);
    if (shape.kind === "collection") collections.push(...shape.rows);
    else if (shape.kind === "record") records.push(shape.row);
    const label = ctx.labels?.[i] ?? derivedStepLabel(step.argv);
    documents[label] = mergeDocuments(documents[label], documentOf(bytes, transform, shape));
  }
  // the population: every collection the run printed; a lone record only
  // when the run printed no collection at all (a recipe whose output IS one
  // object). Row-wise assertions (the tree adapter's vocabulary) read this;
  // upstream's labeled JMESPath vocabulary is T2-5's, over the shapes above
  const rows = collections.length > 0 ? collections : records;

  // the verdict is the bytes', judged at the run's own clock — never the
  // runner's word. Two vocabularies (SPEC §14.4a): a field that names a
  // step's label is a JMESPath over that document; any other is a column
  // of the rows. Results keep the recipe's order
  const now = new Date(transcript.finished_at);
  const labels = Object.keys(documents);
  const assertions = ctx.assertions.map((a) =>
    labeledField(a.field, labels) !== undefined
      ? evaluateLabeledAssertions([a], documents as LabeledDocuments, now)[0]!
      : evaluateAssertions([a], rows, now)[0]!,
  );

  return {
    kind: "submission",
    submission: {
      _type: INGEST_SUBMISSION_TYPE,
      recipe_id: transcript.recipe_id,
      ksi: transcript.ksi,
      // a runner is a repeatable process over declared inputs, by construction
      evidence_class: "process-generated",
      cadence: ctx.cadence,
      artifacts,
      assertions,
      timestamp: transcript.finished_at,
      signer_identity: `runner:${transcript.runner.name} (${transcript.runner.caller_arn})`,
      // a machine validated this only if an assertion was evaluated over it (T0-2)
      automated: ctx.assertions.length > 0,
      reproduce: transcript.steps.map((s) => s.argv.join(" ")).join(" && "),
      runner: {
        name: transcript.runner.name,
        caller_arn: transcript.runner.caller_arn,
        account: transcript.runner.account,
        partition: transcript.runner.partition,
        region: transcript.runner.region,
        request_digest: transcript.request_digest,
      },
    },
  };
}
