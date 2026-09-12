import { toAttestation } from "@rampscan/core";
import type { Digest } from "@rampscan/core";
import { loadKsiCatalogFromSlices } from "@rampscan/dataset";
import { createLocalLedger } from "@rampscan/ledger";
import { StatementId } from "@rampscan/schema";
import { createLocalSigner } from "@rampscan/signer";

// The attestation's second key turn (plan Q4.2, SPEC §12.9) — `recordScoping`
// and `recordArtifactJudgment`'s third sibling. A proposal drafted in the
// console becomes a SIGNED LEDGER EVENT here: statement text and role
// present, statement id slug-checked (it becomes part of the method id), KSI
// resolved against the pinned catalog, approver identity recorded in the
// predicate, DSSE envelope over the statement, appended like any other
// statement. The register moves only when the projector re-folds this.

export interface RecordAttestationOptions {
  repo: string;
  /** the mechanism's name ("incident-review"), not the occasion's */
  statementId: string;
  ksiId: string;
  attestorRole: string;
  statement: string;
  /** `withdrawn` retracts a standing `attested` — same two keys */
  action: "attested" | "withdrawn";
  proposedBy: string;
  approvedBy: string;
  datasetDir: string;
  datasetPin: string;
  ledgerDir: string;
  keysDir: string;
  now?: Date;
  log?: (line: string) => void;
}

export async function recordAttestation(
  options: RecordAttestationOptions,
): Promise<{ digest: Digest }> {
  const log = options.log ?? (() => {});
  const statement = options.statement.trim();
  if (statement.length === 0) {
    throw new Error("an attestation requires a statement — the approver signs a claim, not a blank");
  }
  const attestorRole = options.attestorRole.trim();
  if (attestorRole.length === 0) {
    throw new Error(
      "an attestation requires an attestor role — an unattributed claim is not interrogable",
    );
  }
  const parsedId = StatementId.safeParse(options.statementId);
  if (!parsedId.success) {
    throw new Error(
      `statement id "${options.statementId}" is not slug-shaped — it becomes part of the ` +
        `method id (attestation:<statement_id>#<ksi>), so ':' and '#' would make that id ambiguous`,
    );
  }

  const catalog = await loadKsiCatalogFromSlices(options.datasetDir, options.datasetPin);
  if (!catalog.ksis.some((k) => k.id === options.ksiId)) {
    throw new Error(
      `unknown KSI ${options.ksiId} — an attestation must reference the pinned catalog`,
    );
  }

  const event = toAttestation({
    repo: options.repo,
    statementId: parsedId.data,
    ksiId: options.ksiId,
    attestorRole,
    statement,
    action: options.action,
    proposedBy: options.proposedBy,
    approvedBy: options.approvedBy,
    datasetVersion: catalog.datasetVersion,
    timestamp: (options.now ?? new Date()).toISOString(),
  });

  const signer = createLocalSigner(options.keysDir, { log });
  const envelope = await signer.sign(event);
  const digest = await createLocalLedger(options.ledgerDir).append(event, envelope);
  log(
    `attestation recorded: ${options.ksiId} ${options.action} by ${attestorRole} ` +
      `(${parsedId.data}) for ${options.repo} → ${digest.slice(0, 12)}…`,
  );
  return { digest };
}
