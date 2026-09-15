import type { ObservationRows } from "@rampscan/core";
import type { Cadence, IngestSubmission, RecipeAssertion, RunRequest, RunTranscript, TranscriptStep } from "@rampscan/schema";
import type { StepTransform } from "./aws-classify.js";
/** why a run produced no bundle — the Runs page shows the class, never an absence */
export type FailureClass = "denied" | "not-enabled" | "throttled" | "incomplete" | "error";
export type IntakeOutcome = 
/** every check passed and the bytes were evaluated: hand this to `ingest` */
{
    kind: "submission";
    submission: IngestSubmission;
}
/** the account was not seen: a visible failed run, no bundle */
 | {
    kind: "failed";
    class: FailureClass;
    reason: string;
}
/** the transcript does not answer a request this appliance made, or answers one twice */
 | {
    kind: "refused";
    reason: string;
};
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
    /** nonces already accepted into the ledger — a second transcript for one is a replay */
    acceptedNonces: ReadonlySet<string>;
    /** the appliance's clock at receipt; the run's own timestamps must fall inside the request window before it */
    receivedAt: string;
}
/** the request's address: sha256 over its canonical bytes, what a transcript binds to */
export declare function requestDigest(request: RunRequest): string;
/**
 * T2-2: one class per step, `ok` only for exit 0 with nothing on stderr.
 * A non-zero exit with a clean stderr is `error` — the CLI said nothing
 * about why, and "nothing printed" is not a population.
 */
export declare function classifyStep(step: TranscriptStep): FailureClass | "ok";
/**
 * The rows an assertion reads from one step's bytes: a JSON array of
 * objects; a JSON object with exactly one array-valued key (the CLI's
 * unprojected shape, `{"EvaluationResults":[…]}`); a single object as one
 * row; or, after the base64 transform, a CSV with a header. Anything else
 * is zero rows — recorded as such, never invented.
 */
export declare function rowsOfOutput(bytes: Uint8Array, transform?: StepTransform): ObservationRows;
/**
 * What one step printed, by shape: a `collection` (an array, the CLI's
 * one-array object, or a CSV) is a population; a `record` (a single object
 * — a status, a vault's configuration) is one row that is NOT a population
 * beside a collection, so `generate-credential-report`'s `{"State": …}`
 * never counts among the report's principals.
 */
export declare function outputShape(bytes: Uint8Array, transform?: StepTransform): {
    kind: "collection";
    rows: ObservationRows;
} | {
    kind: "record";
    row: Record<string, unknown>;
} | {
    kind: "none";
    rows: [];
};
/**
 * Read a runner's transcript into a native submission, or say why not.
 * Refusals first (nonce, request, account, window), then the failure
 * classes over every step, then — and only then — the bytes.
 */
export declare function intakeTranscript(transcript: RunTranscript, outputs: ReadonlyMap<string, Uint8Array>, ctx: IntakeContext): IntakeOutcome;
//# sourceMappingURL=runs-intake.d.ts.map