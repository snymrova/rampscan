import { createHash } from "node:crypto";
import { IN_TOTO_STATEMENT_TYPE, RAMPSCAN_RUNNER_REGISTRATION_TYPE } from "@rampscan/schema";
import type { RunnerRegistration } from "@rampscan/schema";

// The fourth two-key write (docs/PLAN-CLOUD-RUNNER.md T3-2): an approver's
// key turn over a runner's public key. Pure shaping, like toAttestation;
// the CLI signs and appends.

export interface RunnerRegistrationContext {
  action: "registered" | "revoked";
  runnerName: string;
  publicKeyPem: string;
  keyid: string;
  host: string;
  account: string;
  partition: "aws" | "aws-us-gov";
  repo: string;
  proposedBy: string;
  approvedBy: string;
  datasetVersion: string;
  timestamp: string;
}

export function toRunnerRegistration(ctx: RunnerRegistrationContext): RunnerRegistration {
  return {
    _type: IN_TOTO_STATEMENT_TYPE,
    // the subject is the key itself: what the approver admits, by digest
    subject: [{ name: `${ctx.runnerName}.pub`, digest: { sha256: createHash("sha256").update(ctx.publicKeyPem, "utf8").digest("hex") } }],
    predicateType: RAMPSCAN_RUNNER_REGISTRATION_TYPE,
    predicate: {
      action: ctx.action,
      runner_name: ctx.runnerName,
      public_key: ctx.publicKeyPem,
      keyid: ctx.keyid,
      host: ctx.host,
      account: ctx.account,
      partition: ctx.partition,
      repo: ctx.repo,
      proposed_by: ctx.proposedBy,
      approved_by: ctx.approvedBy,
      dataset_version: ctx.datasetVersion,
      timestamp: ctx.timestamp,
    },
  };
}
