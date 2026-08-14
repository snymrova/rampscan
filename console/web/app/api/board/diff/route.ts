import { NextResponse } from "next/server";
import { computeBoardDiff } from "@rampscan/cli";

// The "since baseline" diff (plan I2d), read-only. The console cannot fold
// the ledger client-side, so this route runs the SAME computation the CLI's
// `rampscan board --since` runs — computeBoardDiff, two as-of folds plus a
// pure register diff — and returns it. One hand computes; terminal and
// browser can never disagree. Nothing here writes anything, anywhere.
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

    const since = new URL(request.url).searchParams.get("since") ?? "previous";
    if (since !== "previous" && Number.isNaN(Date.parse(since))) {
      return NextResponse.json(
        { error: `since is not \`previous\` or a parseable instant: ${since}` },
        { status: 400 },
      );
    }

    try {
      const outcome = await computeBoardDiff({
        ledgerDir: env("RAMPSCAN_LEDGER_DIR"),
        recipesDir: env("RAMPSCAN_RECIPES_DIR"),
        since: since === "previous" ? since : new Date(since).toISOString(),
      });
      return NextResponse.json(outcome);
    } catch (error) {
      // an honest refusal (no previous scan to diff against) is an answer,
      // not a failure — the toggle shows the reason instead of a diff
      return NextResponse.json({
        reason: error instanceof Error ? error.message : String(error),
      });
    }
  } catch (error) {
    return NextResponse.json(
      { error: error instanceof Error ? error.message : String(error) },
      { status: 500 },
    );
  }
}
