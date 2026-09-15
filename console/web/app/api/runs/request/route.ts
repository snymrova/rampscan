import { NextResponse } from "next/server";
import { mintRunRequest, recipesForKsi, runnerRegistryAt } from "@rampscan/cli";
import { deps, env, fail, isResponse, session } from "../_deps";

// T4-1: the click. GET ?ksi= lists what the row can ask for — runnable
// recipes, and the manual ones with every reason beneath; POST mints the
// signed RunRequest. Single-key: any signed-in user, because it requests
// a read and nothing else.

export const runtime = "nodejs";

function window(): { start: string; end: string } {
  const end = new Date();
  return { start: new Date(end.getTime() - 30 * 86_400_000).toISOString(), end: end.toISOString() };
}

export async function GET(request: Request): Promise<NextResponse> {
  try {
    const who = await session(request);
    if (isResponse(who)) return who;
    const ksi = new URL(request.url).searchParams.get("ksi");
    if (!ksi) return NextResponse.json({ error: "ksi required" }, { status: 400 });
    const d = await deps();
    if (isResponse(d)) return d;
    const registry = await runnerRegistryAt(env("RAMPSCAN_LEDGER_DIR"));
    return NextResponse.json({ ksi, recipes: recipesForKsi(d, ksi, window()), registered_runners: registry.size });
  } catch (error) {
    return fail(error);
  }
}

export async function POST(request: Request): Promise<NextResponse> {
  try {
    const who = await session(request);
    if (isResponse(who)) return who;
    const { recipe_id, ksi } = (await request.json()) as { recipe_id?: string; ksi?: string };
    if (!recipe_id || !ksi) return NextResponse.json({ error: "recipe_id and ksi required" }, { status: 400 });
    const d = await deps();
    if (isResponse(d)) return d;
    // ledger first: the signed request is the record; the Runs page folds it
    const minted = await mintRunRequest(d, { recipeId: recipe_id, ksi, requester: who.identity, window: window() });
    return NextResponse.json(minted, { status: minted.kind === "requested" ? 200 : 409 });
  } catch (error) {
    return fail(error);
  }
}
