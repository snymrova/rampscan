import { NextResponse } from "next/server";
import { recordAttestation } from "@rampscan/cli";
import { PocketBaseAdmin } from "@rampscan/projector";

// The attestation's second key turn (Q4.2, SPEC §12.9) — the scoping and
// judgment decide routes' third sibling, same discipline: this route writes
// exactly one thing of record, a signed Attestation appended to the LEDGER.
// The proposal row is bookkeeping; the register gains its `source: attestation`
// method when `rampscan serve`'s ledger watcher re-folds. Ledger first,
// projection follows.
//
// Environment (set by `rampscan serve`): RAMPSCAN_PB_URL, RAMPSCAN_PB_SUPERUSER_*,
// RAMPSCAN_LEDGER_DIR, RAMPSCAN_KEYS_DIR, RAMPSCAN_DATASET_DIR, RAMPSCAN_DATASET_PIN.

export const runtime = "nodejs";

function env(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is not set — start the console via \`rampscan serve\``);
  return value;
}

export async function POST(request: Request): Promise<NextResponse> {
  try {
    const { proposalId, action } = (await request.json()) as {
      proposalId?: string;
      action?: "approve" | "reject";
    };
    if (!proposalId || (action !== "approve" && action !== "reject")) {
      return NextResponse.json(
        { error: "proposalId and action (approve|reject) required" },
        { status: 400 },
      );
    }

    const pbUrl = env("RAMPSCAN_PB_URL");
    const userToken = request.headers.get("authorization") ?? "";

    // whose key is turning? verify the console identity against PocketBase
    const refresh = await fetch(`${pbUrl}/api/collections/users/auth-refresh`, {
      method: "POST",
      headers: { Authorization: userToken },
    });
    if (!refresh.ok) {
      return NextResponse.json({ error: "not signed in" }, { status: 401 });
    }
    const { record: user } = (await refresh.json()) as {
      record: { id: string; email: string; role?: string };
    };
    if (user.role !== "approver") {
      return NextResponse.json(
        {
          error: `the second key belongs to an approver — ${user.email} is ${user.role || "roleless"}`,
        },
        { status: 403 },
      );
    }
    const approverIdentity = `${user.email} (pb:${user.id})`;

    const pb = new PocketBaseAdmin(pbUrl);
    await pb.auth(env("RAMPSCAN_PB_SUPERUSER_EMAIL"), env("RAMPSCAN_PB_SUPERUSER_PASSWORD"));
    const proposal = (await pb.request(
      "GET",
      `/api/collections/attestation_proposals/records/${proposalId}`,
    )) as {
      id: string;
      repo: string;
      statement_id: string;
      ksi_id: string;
      attestor_role: string;
      statement: string;
      action: "attested" | "withdrawn";
      status: string;
      proposed_by: string;
    };
    if (proposal.status !== "pending") {
      return NextResponse.json({ error: `proposal already ${proposal.status}` }, { status: 409 });
    }

    if (action === "reject") {
      await pb.request("PATCH", `/api/collections/attestation_proposals/records/${proposalId}`, {
        status: "rejected",
        decided_by: approverIdentity,
      });
      return NextResponse.json({ ok: true, status: "rejected" });
    }

    // approve: the ledger gets the signed event FIRST; everything else follows
    const { digest } = await recordAttestation({
      repo: proposal.repo,
      statementId: proposal.statement_id,
      ksiId: proposal.ksi_id,
      attestorRole: proposal.attestor_role,
      statement: proposal.statement,
      action: proposal.action,
      proposedBy: proposal.proposed_by,
      approvedBy: approverIdentity,
      datasetDir: env("RAMPSCAN_DATASET_DIR"),
      datasetPin: env("RAMPSCAN_DATASET_PIN"),
      ledgerDir: env("RAMPSCAN_LEDGER_DIR"),
      keysDir: env("RAMPSCAN_KEYS_DIR"),
    });
    await pb.request("PATCH", `/api/collections/attestation_proposals/records/${proposalId}`, {
      status: "approved",
      decided_by: approverIdentity,
      ledger_digest: digest,
    });
    return NextResponse.json({ ok: true, status: "approved", digest });
  } catch (error) {
    return NextResponse.json(
      { error: error instanceof Error ? error.message : String(error) },
      { status: 500 },
    );
  }
}
