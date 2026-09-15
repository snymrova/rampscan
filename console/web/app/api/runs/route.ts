import { NextResponse } from "next/server";
import { runsLifecycleAt } from "@rampscan/cli";
import { env, fail, isResponse, session } from "./_deps";

// T4-3: the lifecycle, folded from the ledger on every read — the Runs
// page's cloud section is this, never a row a route wrote.

export const runtime = "nodejs";

export async function GET(request: Request): Promise<NextResponse> {
  try {
    const who = await session(request);
    if (isResponse(who)) return who;
    return NextResponse.json({ runs: await runsLifecycleAt(env("RAMPSCAN_LEDGER_DIR")) });
  } catch (error) {
    return fail(error);
  }
}
