import { canonicalJson, isScopingEvent } from "@rampscan/schema";
import { bundleDigest, createLocalLedger } from "@rampscan/ledger";
import { createLocalSigner, statementFromEnvelope } from "@rampscan/signer";
import { loadRecipes } from "./recipes.js";

// The scoping register (plan I3c): every scoping decision — approved AND
// rejected — in one auditable list. The sources are deliberately split by
// what each one honestly is:
//
//   approved  → THE LEDGER. A signed scoping event is the record; its
//               predicate supplies justification, identities, timestamp, and
//               the ksi/control ids removed from scope. Each event's DSSE
//               envelope is re-verified here with the same primitives
//               `rampscan verify` uses — the register never asserts
//               "verified" it didn't just check.
//   rejected/ → the console's `proposals` collection, passed in by the
//   pending     caller. A rejected scope-out never touches the ledger — it
//               exists nowhere but the console's workflow state, and the row
//               says so instead of dressing up.
//
// The two are cross-checked, never merged blindly: a proposal claiming
// `approved` whose digest the ledger cannot produce is surfaced as a problem
// row — the register refuses to launder workflow state into a record.

/**
 * `verified`  — envelope present, signature checks out, and the signed payload
 *               is byte-for-byte the stored statement at its address
 * `failed`    — an envelope exists but the check does not pass (wrong key,
 *               tampered payload, payload/statement mismatch)
 * `unsigned`  — the ledger holds the statement but no envelope was appended
 * `missing`   — the proposal claims approval but the ledger has no scoping
 *               event at its digest (or records no digest at all)
 */
export type ScopingSignatureStatus = "verified" | "failed" | "unsigned" | "missing";

/** A `proposals` row as the console's PocketBase collection stores it. */
export interface ScopingProposalInput {
  id: string;
  repo: string;
  recipe_id: string;
  justification: string;
  status: "pending" | "approved" | "rejected";
  proposed_by: string;
  decided_by: string;
  scoping_digest: string;
  created: string;
  updated: string;
}

export interface ScopingRegisterRow {
  decision: "approved" | "rejected" | "pending";
  repo: string;
  recipeId: string;
  /** what the decision removes (approved) or declined to remove (rejected) from scope */
  ksiIds: string[];
  controlIds: string[];
  justification: string;
  proposedBy: string;
  /** approver identity — the signed predicate's for approved, the proposal row's otherwise */
  decidedBy: string;
  /** signed timestamp for approved rows; the proposal's decision/creation time otherwise */
  timestamp: string;
  /** ledger digest of the signed scoping event (approved rows only) */
  digest?: string;
  /** approved rows only — the register just checked, it is not quoting anyone */
  signature?: ScopingSignatureStatus;
  /** honest flags a renderer must surface, never smooth over */
  problems: string[];
}

export interface ScopingRegister {
  rows: ScopingRegisterRow[];
  counts: { approved: number; rejected: number; pending: number };
}

export interface ScopingRegisterOptions {
  ledgerDir: string;
  keysDir: string;
  recipesDir: string;
  proposals: ScopingProposalInput[];
}

export async function computeScopingRegister(
  options: ScopingRegisterOptions,
): Promise<ScopingRegister> {
  const ledger = createLocalLedger(options.ledgerDir);
  const signer = createLocalSigner(options.keysDir);
  const recipes = await loadRecipes(options.recipesDir);
  const rows: ScopingRegisterRow[] = [];

  // approved decisions: the ledger's scoping events, each one re-verified
  const scopings = (await ledger.list()).filter((entry) => isScopingEvent(entry.bundle));
  const ledgerDigests = new Set(scopings.map((entry) => entry.digest));
  const proposalByDigest = new Map(
    options.proposals
      .filter((p) => p.scoping_digest)
      .map((p) => [p.scoping_digest, p] as const),
  );

  for (const entry of scopings) {
    if (!isScopingEvent(entry.bundle)) continue;
    const p = entry.bundle.predicate;
    let signature: ScopingSignatureStatus;
    if (!entry.envelope) {
      signature = "unsigned";
    } else {
      // the same three checks `rampscan verify` performs: DSSE signature,
      // signed payload = stored statement, payload hashes to its address
      let ok = false;
      try {
        const signedStatement = statementFromEnvelope(entry.envelope);
        ok =
          (await signer.verify(entry.envelope)) &&
          canonicalJson(signedStatement) === canonicalJson(entry.bundle) &&
          bundleDigest(signedStatement) === entry.digest;
      } catch {
        ok = false;
      }
      signature = ok ? "verified" : "failed";
    }

    const problems: string[] = [];
    if (signature === "failed") problems.push("the DSSE envelope does not verify against the key");
    if (signature === "unsigned") problems.push("the event was appended without a signature");
    if (!proposalByDigest.has(entry.digest)) {
      problems.push("no matching proposal row — recorded outside the console's two-key flow");
    }

    rows.push({
      decision: "approved",
      repo: p.repo,
      recipeId: p.recipe_id,
      // the SIGNED predicate is the record — never the catalog, never the proposal
      ksiIds: p.ksi_ids,
      controlIds: p.control_ids,
      justification: p.justification,
      proposedBy: p.proposed_by,
      decidedBy: p.approved_by,
      timestamp: p.timestamp,
      digest: entry.digest,
      signature,
      problems,
    });
  }

  // rejected + pending proposals — and approved claims the ledger cannot back
  for (const proposal of options.proposals) {
    if (proposal.status === "approved" && ledgerDigests.has(proposal.scoping_digest)) {
      continue; // already on the register from its ledger event
    }
    const recipe = recipes.find((r) => r.id === proposal.recipe_id);
    const problems: string[] = [];
    if (!recipe) problems.push(`recipe ${proposal.recipe_id} is not in the catalog`);

    let signature: ScopingSignatureStatus | undefined;
    if (proposal.status === "approved") {
      // the workflow claims a record the ledger cannot produce — say so loudly
      signature = "missing";
      problems.push(
        proposal.scoping_digest
          ? `the proposal claims approval but the ledger has no scoping event at ${proposal.scoping_digest.slice(0, 16)}…`
          : "the proposal claims approval but records no ledger digest",
      );
    }

    rows.push({
      decision: proposal.status,
      repo: proposal.repo,
      recipeId: proposal.recipe_id,
      ksiIds: recipe?.ksi_ids ?? [],
      controlIds: recipe?.control_ids ?? [],
      justification: proposal.justification,
      proposedBy: proposal.proposed_by,
      decidedBy: proposal.decided_by,
      timestamp: proposal.updated || proposal.created,
      ...(signature ? { signature } : {}),
      problems,
    });
  }

  rows.sort((a, b) => (a.timestamp < b.timestamp ? 1 : a.timestamp > b.timestamp ? -1 : 0));
  return {
    rows,
    counts: {
      approved: rows.filter((r) => r.decision === "approved").length,
      rejected: rows.filter((r) => r.decision === "rejected").length,
      pending: rows.filter((r) => r.decision === "pending").length,
    },
  };
}
