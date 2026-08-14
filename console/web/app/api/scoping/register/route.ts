import { NextResponse } from "next/server";
import { computeScopingRegister } from "@rampscan/cli";
import type { ScopingProposalInput } from "@rampscan/cli";
import { PocketBaseAdmin } from "@rampscan/projector";

// The scoping register (plan I3c), read-only — the decide route's sibling in
// the diff route's posture (auth-refresh gate, `runtime: nodejs`, structurally
// unable to write). Approved decisions are read from the LEDGER's signed
// scoping events, each re-verified server-side against the serving key with
// the same primitives `rampscan verify` uses; rejected and pending proposals
// come from the console's `proposals` collection, which is the only place a
// rejection exists. One hand computes: `computeScopingRegister` in
// @rampscan/cli does all of it, this route only feeds it the proposal rows.
//
// Environment (set by `rampscan serve`): RAMPSCAN_PB_URL,
// RAMPSCAN_PB_SUPERUSER_*, RAMPSCAN_LEDGER_DIR, RAMPSCAN_KEYS_DIR,
// RAMPSCAN_RECIPES_DIR.

export const runtime = "nodejs";

function env(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is not set — start the console via \`rampscan serve\``);
  return value;
}

export async function GET(request: Request): Promise<NextResponse> {
  try {
    // reading the register requires being signed in, same as every projection
    const refresh = await fetch(`${env("RAMPSCAN_PB_URL")}/api/collections/users/auth-refresh`, {
      method: "POST",
      headers: { Authorization: request.headers.get("authorization") ?? "" },
    });
    if (!refresh.ok) {
      return NextResponse.json({ error: "not signed in" }, { status: 401 });
    }

    const pb = new PocketBaseAdmin(env("RAMPSCAN_PB_URL"));
    await pb.auth(env("RAMPSCAN_PB_SUPERUSER_EMAIL"), env("RAMPSCAN_PB_SUPERUSER_PASSWORD"));
    const { items } = (await pb.request(
      "GET",
      "/api/collections/proposals/records?perPage=500&sort=-created",
    )) as { items: ScopingProposalInput[] };

    const register = await computeScopingRegister({
      ledgerDir: env("RAMPSCAN_LEDGER_DIR"),
      keysDir: env("RAMPSCAN_KEYS_DIR"),
      recipesDir: env("RAMPSCAN_RECIPES_DIR"),
      proposals: items,
    });
    return NextResponse.json(register);
  } catch (error) {
    return NextResponse.json(
      { error: error instanceof Error ? error.message : String(error) },
      { status: 500 },
    );
  }
}
