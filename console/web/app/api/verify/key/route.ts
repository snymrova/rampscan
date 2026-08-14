import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { NextResponse } from "next/server";

// The public key download (plan I3b), read-only: the exact SPKI PEM the
// signer wrote to disk — the auditor verifies every DSSE envelope with this
// key alone, no rampscan required (the envelope format is the one cosign
// uses for attestations: ECDSA P-256 / SHA-256 over the DSSE PAE).
//
// Environment (set by `rampscan serve`): RAMPSCAN_PB_URL, RAMPSCAN_KEYS_DIR.

export const runtime = "nodejs";

function env(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is not set — start the console via \`rampscan serve\``);
  return value;
}

export async function GET(request: Request): Promise<NextResponse> {
  try {
    // downloading the key requires being signed in, same as reading the board
    const refresh = await fetch(`${env("RAMPSCAN_PB_URL")}/api/collections/users/auth-refresh`, {
      method: "POST",
      headers: { Authorization: request.headers.get("authorization") ?? "" },
    });
    if (!refresh.ok) {
      return NextResponse.json({ error: "not signed in" }, { status: 401 });
    }

    const pem = await readFile(join(env("RAMPSCAN_KEYS_DIR"), "rampscan.pub"), "utf8");
    return new NextResponse(pem, {
      headers: {
        "Content-Type": "application/x-pem-file",
        "Content-Disposition": 'attachment; filename="rampscan.pub"',
      },
    });
  } catch (error) {
    return NextResponse.json(
      { error: error instanceof Error ? error.message : String(error) },
      { status: 500 },
    );
  }
}
