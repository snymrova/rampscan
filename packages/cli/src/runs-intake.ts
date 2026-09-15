import type { IngestSubmission, RecipeAssertion, RunRequest, RunTranscript } from "@rampscan/schema";

// The appliance side of the runner contract (docs/PLAN-CLOUD-RUNNER.md T2-2,
// T2-3): a signed transcript and the bytes it names come in; a native
// IngestSubmission for the existing `ingest` path comes out — or a failed
// run with its class, or a refusal with its reason. Never a verdict the
// runner wrote (ground rule 3), and never a bundle over bytes the account
// did not actually yield (ground rule 2).
//
// Written first as the cases it must refuse (T0-4, packages/cli/test/
// runs-intake.test.ts); the function below is the hole those cases fall
// through until T2-2 and T2-3 fill it.

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
  /** nonces already accepted into the ledger — a second transcript for one is a replay */
  acceptedNonces: ReadonlySet<string>;
  /** the appliance's clock at receipt; the run's own timestamps must fall inside the request window before it */
  receivedAt: string;
}

/**
 * Read a runner's transcript into a native submission, or say why not.
 *
 * Not implemented: this is the appliance reading a transcript, and T2-2 /
 * T2-3 (#172, #173) are where it learns to. Until then every caller falls
 * through here, which is the failure T0-4's cases record.
 */
export function intakeTranscript(
  _transcript: RunTranscript,
  _outputs: ReadonlyMap<string, Uint8Array>,
  _ctx: IntakeContext,
): IntakeOutcome {
  throw new Error(
    "T2-2/T2-3 (#172, #173): the appliance does not read a run transcript yet — " +
      "no intake exists, so no case in runs-intake.test.ts can pass until one does",
  );
}
