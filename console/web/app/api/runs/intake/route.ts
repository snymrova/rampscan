import { NextResponse } from "next/server";
import { intakeRun } from "@rampscan/cli";
import { deps, fail, isResponse } from "../_deps";

// T4-2: a runner hands back a transcript and the bytes. Strict and
// size-limited; idempotent on nonce (a second transcript is a replay,
// refused); ledger first — the evidence bundle or the failed/refused
// event is appended before this replies, and the projection follows.

export const runtime = "nodejs";

/** a credential report for a large account is a few MB; a transcript is never more than this */
const MAX_BYTES = 32 * 1024 * 1024;

export async function POST(request: Request): Promise<NextResponse> {
  try {
    const length = Number(request.headers.get("content-length") ?? "0");
    if (length > MAX_BYTES) return NextResponse.json({ kind: "refused", reason: `intake accepts at most ${MAX_BYTES} bytes` }, { status: 413 });
    const d = await deps();
    if (isResponse(d)) return d;
    const post = (await request.json()) as Parameters<typeof intakeRun>[1];
    if (!post || typeof post !== "object" || !post.envelope || !post.outputs) {
      return NextResponse.json({ kind: "refused", reason: "an intake carries an envelope and the outputs" }, { status: 400 });
    }
    const r = await intakeRun(d, post);
    return NextResponse.json(r, { status: r.status });
  } catch (error) {
    return fail(error);
  }
}
