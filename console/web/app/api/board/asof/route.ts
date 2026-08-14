import { NextResponse } from "next/server";
import { computeBoardAsOf } from "@rampscan/cli";

// The as-of board (plan I3d), read-only. The console cannot fold the ledger
// client-side, so this route runs the SAME computation the CLI's
// `rampscan board --as-of` runs — computeBoardAsOf, one as-of fold of the
// append-only ledger (I1b) — and returns it. One hand computes; terminal and
// browser can never disagree about what the past board looked like. Nothing
// here writes anything, anywhere.
//
// Environment (set by `rampscan serve`): RAMPSCAN_PB_URL,
// RAMPSCAN_LEDGER_DIR, RAMPSCAN_RECIPES_DIR.

export const runtime = "nodejs";

function env(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is not set — start the console via \`rampscan serve\``);
  return value;
}

export async function GET(request: Request): Promise<NextResponse> {
  try {
    // reading the board requires being signed in, same as the board itself
    const refresh = await fetch(`${env("RAMPSCAN_PB_URL")}/api/collections/users/auth-refresh`, {
      method: "POST",
      headers: { Authorization: request.headers.get("authorization") ?? "" },
    });
    if (!refresh.ok) {
      return NextResponse.json({ error: "not signed in" }, { status: 401 });
    }

    const at = new URL(request.url).searchParams.get("at");
    if (at === null || Number.isNaN(Date.parse(at))) {
      return NextResponse.json(
        { error: `at is not a parseable instant: ${at ?? "(missing)"}` },
        { status: 400 },
      );
    }

    const outcome = await computeBoardAsOf({
      ledgerDir: env("RAMPSCAN_LEDGER_DIR"),
      recipesDir: env("RAMPSCAN_RECIPES_DIR"),
      asOf: new Date(at).toISOString(),
    });
    return NextResponse.json(outcome);
  } catch (error) {
    return NextResponse.json(
      { error: error instanceof Error ? error.message : String(error) },
      { status: 500 },
    );
  }
}
