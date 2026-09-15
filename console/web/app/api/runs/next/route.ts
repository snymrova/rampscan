import { NextResponse } from "next/server";
import { nextRun, nextRunByToken } from "@rampscan/cli";
import { deps, fail, isResponse } from "../_deps";

// T4-2: a runner asks for work. No console session — the caller is a
// runner, authenticated inside the handler by its signature (a claim
// under a registered key, or the appliance's own signature on a `once`
// token). 204 when nothing is open.

export const runtime = "nodejs";

export async function POST(request: Request): Promise<NextResponse> {
  try {
    const d = await deps();
    if (isResponse(d)) return d;
    const body = (await request.json()) as Record<string, unknown>;
    const r = typeof body["token"] === "string" ? await nextRunByToken(d, body["token"]) : await nextRun(d, body as never);
    if (r.status === 200) return NextResponse.json(r.assignment);
    if (r.status === 204) return new NextResponse(null, { status: 204 });
    return NextResponse.json({ reason: r.reason }, { status: r.status });
  } catch (error) {
    return fail(error);
  }
}
