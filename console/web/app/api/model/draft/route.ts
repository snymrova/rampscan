import { NextResponse } from "next/server";
import { OllamaRunner } from "@rampscan/model";

// Drafting a scoping justification with the local model (plan L4b). The one
// console route that reaches a model, and it is deliberately the ONLY one:
// the evidence path never touches this file, nothing here is signed, and the
// text it returns has no standing until a human edits it and an approver's key
// turn signs what the human left behind (`core/src/scoping.ts` is unchanged).
//
// GET  → the resolution, so the UI can decide whether the affordance exists at
//        all. A button that appears and then fails is worse than one that was
//        never drawn, and I15 wants the reason on screen either way.
// POST → the draft.
//
// This route can consume real CPU for a minute, so it is auth-gated like every
// other route here: an unauthenticated caller cannot make this machine think.

export const runtime = "nodejs";

function env(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is not set — start the console via \`rampscan serve\``);
  return value;
}

async function signedIn(request: Request): Promise<boolean> {
  const refresh = await fetch(`${env("RAMPSCAN_PB_URL")}/api/collections/users/auth-refresh`, {
    method: "POST",
    headers: { Authorization: request.headers.get("authorization") ?? "" },
  });
  return refresh.ok;
}

export async function GET(request: Request): Promise<NextResponse> {
  try {
    if (!(await signedIn(request))) return NextResponse.json({ error: "not signed in" }, { status: 401 });
    return NextResponse.json(await new OllamaRunner().resolve());
  } catch (error) {
    // A resolution failure is itself an absence with a reason — the affordance
    // hides and says why, rather than the page erroring over an optional tool.
    return NextResponse.json({
      state: "absent",
      reason: error instanceof Error ? error.message : String(error),
    });
  }
}

export async function POST(request: Request): Promise<NextResponse> {
  try {
    if (!(await signedIn(request))) return NextResponse.json({ error: "not signed in" }, { status: 401 });

    const body = (await request.json()) as { context?: Record<string, string> };
    const runner = new OllamaRunner();
    const resolution = await runner.resolve();
    if (resolution.state !== "ready") {
      // Re-checked here and not trusted from the GET: a daemon can stop between
      // the page loading and the operator clicking.
      return NextResponse.json({ error: `model is ${resolution.state}` }, { status: 409 });
    }

    const draft = await runner.draft({
      task: "scoping-justification",
      // Only what the caller sent, and the caller sends only what is already on
      // the board or in the catalog. This route reads no repo, no ledger and no
      // network, so what a draft can be about stays auditable from the client.
      context: body.context ?? {},
    });
    return NextResponse.json(draft);
  } catch (error) {
    return NextResponse.json(
      { error: error instanceof Error ? error.message : String(error) },
      { status: 500 },
    );
  }
}
