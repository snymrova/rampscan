import { toArtifactJudgment } from "@rampscan/core";
import type { Digest } from "@rampscan/core";
import { loadKsiCatalogFromSlices } from "@rampscan/dataset";
import { createLocalLedger } from "@rampscan/ledger";
import type { JudgedArtifact } from "@rampscan/schema";
import { JudgedArtifact as JudgedArtifactSchema } from "@rampscan/schema";
import { createLocalSigner } from "@rampscan/signer";

// The artifact judgment's second key turn (plan Q3.3, G5) — `recordScoping`'s
// sibling. A proposal drafted in the console becomes a SIGNED LEDGER EVENT
// here: KSI resolved against the pinned catalog, artifact index checked
// against the judged set (1 | 3 | 4 — the computed artifacts 2 and 5 accept
// no judgment, structurally), approver identity recorded in the predicate,
// DSSE envelope over the statement, appended like any other statement. The
// checklist moves only when the projector re-folds this.

export interface RecordArtifactJudgmentOptions {
  repo: string;
  ksiId: string;
  artifact: number;
  action: "sufficient" | "insufficient";
  justification: string;
  proposedBy: string;
  approvedBy: string;
  datasetDir: string;
  datasetPin: string;
  ledgerDir: string;
  keysDir: string;
  now?: Date;
  log?: (line: string) => void;
}

export async function recordArtifactJudgment(
  options: RecordArtifactJudgmentOptions,
): Promise<{ digest: Digest }> {
  const log = options.log ?? (() => {});
  const justification = options.justification.trim();
  if (justification.length === 0) {
    throw new Error("an artifact judgment requires a justification — the approver signs reasoning");
  }
  const parsedArtifact = JudgedArtifactSchema.safeParse(options.artifact);
  if (!parsedArtifact.success) {
    throw new Error(
      `artifact ${options.artifact} accepts no judgment — sufficiency is judged for 1, 3, and 4; ` +
        `artifacts 2 and 5 are computed by the fold`,
    );
  }
  const artifact: JudgedArtifact = parsedArtifact.data;

  const catalog = await loadKsiCatalogFromSlices(options.datasetDir, options.datasetPin);
  if (!catalog.ksis.some((k) => k.id === options.ksiId)) {
    throw new Error(`unknown KSI ${options.ksiId} — a judgment must reference the pinned catalog`);
  }

  const statement = toArtifactJudgment({
    repo: options.repo,
    ksiId: options.ksiId,
    artifact,
    action: options.action,
    justification,
    proposedBy: options.proposedBy,
    approvedBy: options.approvedBy,
    datasetVersion: catalog.datasetVersion,
    timestamp: (options.now ?? new Date()).toISOString(),
  });

  const signer = createLocalSigner(options.keysDir, { log });
  const envelope = await signer.sign(statement);
  const digest = await createLocalLedger(options.ledgerDir).append(statement, envelope);
  log(
    `artifact judgment recorded: ${options.ksiId} artifact ${artifact} ${options.action} ` +
      `for ${options.repo} → ${digest.slice(0, 12)}…`,
  );
  return { digest };
}
