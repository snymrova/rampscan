import { NextResponse } from "next/server";
import { mintOnceToken } from "@rampscan/cli";
import { deps, fail, isResponse, session } from "../_deps";

// T4-4: the CloudShell path. For a request with no registered sidecar, a
// signed-in user asks for the one-shot token and the dialog shows the
// paste. The token names this console by the origin the request came in
// on — what the paste will reach the console at.

export const runtime = "nodejs";

export async function POST(request: Request): Promise<NextResponse> {
  try {
    const who = await session(request);
    if (isResponse(who)) return who;
    const { nonce } = (await request.json()) as { nonce?: string };
    if (!nonce) return NextResponse.json({ error: "nonce required" }, { status: 400 });
    const d = await deps();
    if (isResponse(d)) return d;
    const consoleUrl = process.env["RAMPSCAN_CONSOLE_URL"] ?? new URL(request.url).origin;
    const token = await mintOnceToken(d, consoleUrl, nonce);
    return NextResponse.json({ token, command: `rampscan-runner once --request ${token}` });
  } catch (error) {
    return fail(error);
  }
}
