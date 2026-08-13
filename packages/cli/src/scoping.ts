import { toScopingEvent } from "@rampscan/core";
import type { Digest } from "@rampscan/core";
import { loadLocalDataset } from "@rampscan/dataset";
import { createLocalLedger } from "@rampscan/ledger";
import { createLocalSigner } from "@rampscan/signer";
import { loadRecipes } from "./recipes.js";

// The two-key write's second key turn (plan M3 E4): a proposal drafted in the
// console becomes a SIGNED LEDGER EVENT here — recipe resolved against the
// catalog, dataset version pinned, approver identity recorded in the
// predicate, DSSE envelope over the statement, appended like any other
// evidence object. PocketBase never holds a fact the ledger doesn't: the
// register flips to notApplicable only when the projector re-folds this.

export interface RecordScopingOptions {
  repo: string;
  recipeId: string;
  justification: string;
  proposedBy: string;
  approvedBy: string;
  recipesDir: string;
  datasetDir: string;
  datasetPin: string;
  ledgerDir: string;
  keysDir: string;
  now?: Date;
  log?: (line: string) => void;
}

export async function recordScoping(options: RecordScopingOptions): Promise<{ digest: Digest }> {
  const log = options.log ?? (() => {});
  const justification = options.justification.trim();
  if (justification.length === 0) {
    throw new Error("a notApplicable scoping requires a justification — the approver signs reasoning");
  }

  const recipes = await loadRecipes(options.recipesDir);
  const recipe = recipes.find((r) => r.id === options.recipeId);
  if (!recipe) {
    throw new Error(`unknown recipe ${options.recipeId} — a scoping must reference the catalog`);
  }
  const dataset = await loadLocalDataset(options.datasetDir, options.datasetPin);

  const statement = toScopingEvent(recipe, {
    repo: options.repo,
    justification,
    proposedBy: options.proposedBy,
    approvedBy: options.approvedBy,
    datasetVersion: dataset.version(),
    timestamp: (options.now ?? new Date()).toISOString(),
  });

  const signer = createLocalSigner(options.keysDir, { log });
  const envelope = await signer.sign(statement);
  const digest = await createLocalLedger(options.ledgerDir).append(statement, envelope);
  log(`scoping recorded: ${options.recipeId} notApplicable for ${options.repo} → ${digest.slice(0, 12)}…`);
  return { digest };
}
