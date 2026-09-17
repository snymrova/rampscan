import { resolve } from "node:path";
import { NextResponse } from "next/server";
import { DEFAULT_ALLOWLIST_PATH, DEFAULT_BINDINGS_PATH, loadRunsDeps } from "@rampscan/cli";
import type { RunsDeps } from "@rampscan/cli";

// Shared by the runs routes (docs/PLAN-CLOUD-RUNNER.md T4-2): the
// dependencies from the environment `rampscan serve` sets, and the two
// kinds of caller — a console session (the click, the token, the page)
// and a runner (next, intake), which is authenticated by its signature
// inside the handler and never by a session.

export const runtime = "nodejs";

export function env(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is not set — start the console via \`rampscan serve\``);
  return value;
}

/** the repository root the allowlist and bindings live under — this checkout, where `rampscan serve` runs */
const REPO_ROOT = resolve(process.cwd(), "../..");

export async function deps(): Promise<RunsDeps | NextResponse> {
  const loaded = await loadRunsDeps({
    repoRoot: env("RAMPSCAN_REPO_ROOT"),
    ledgerDir: env("RAMPSCAN_LEDGER_DIR"),
    keysDir: env("RAMPSCAN_KEYS_DIR"),
    datasetDir: env("RAMPSCAN_DATASET_DIR"),
    datasetPin: env("RAMPSCAN_DATASET_PIN"),
    allowlistPath: resolve(REPO_ROOT, DEFAULT_ALLOWLIST_PATH),
    bindingsPath: resolve(REPO_ROOT, DEFAULT_BINDINGS_PATH),
    // an emulator's runner cannot show its role read-only (SPEC §14.4); only a serve told so accepts that
    ...(process.env["RAMPSCAN_RUNNER_EMULATOR"] === "1" ? { requireSelfCheck: false } : {}),
  });
  if ("missing" in loaded) return NextResponse.json({ error: loaded.missing }, { status: 409 });
  return loaded;
}

export function isResponse(v: unknown): v is NextResponse {
  return v instanceof NextResponse;
}

/** whose console session is this — any signed-in user may request a read; the registry's key turn stays an approver's */
export async function session(request: Request): Promise<{ identity: string; role: string } | NextResponse> {
  const refresh = await fetch(`${env("RAMPSCAN_PB_URL")}/api/collections/users/auth-refresh`, {
    method: "POST",
    headers: { Authorization: request.headers.get("authorization") ?? "" },
  });
  if (!refresh.ok) return NextResponse.json({ error: "not signed in" }, { status: 401 });
  const { record: user } = (await refresh.json()) as { record: { id: string; email: string; role?: string } };
  return { identity: `${user.email} (pb:${user.id})`, role: user.role ?? "" };
}

export function fail(error: unknown): NextResponse {
  return NextResponse.json({ error: error instanceof Error ? error.message : String(error) }, { status: 500 });
}
