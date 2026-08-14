import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { NextResponse } from "next/server";

// The raw DSSE bundle download (plan I3b), read-only: the envelope file's
// EXACT bytes from the ledger's object store — not a re-serialization of the
// projection's copy. The envelope's base64 payload IS the canonical statement:
// sha256 of the decoded payload bytes reproduces this bundle's digest, and the
// signature verifies against the downloaded public key with standard crypto
// alone. The console asks to be distrusted; this download is how.
//
// Environment (set by `rampscan serve`): RAMPSCAN_PB_URL, RAMPSCAN_LEDGER_DIR.

export const runtime = "nodejs";

function env(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is not set — start the console via \`rampscan serve\``);
  return value;
}

export async function GET(request: Request): Promise<NextResponse> {
  try {
    // downloading a bundle requires being signed in, same as reading it
    const refresh = await fetch(`${env("RAMPSCAN_PB_URL")}/api/collections/users/auth-refresh`, {
      method: "POST",
      headers: { Authorization: request.headers.get("authorization") ?? "" },
    });
    if (!refresh.ok) {
      return NextResponse.json({ error: "not signed in" }, { status: 401 });
    }

    const digest = new URL(request.url).searchParams.get("digest") ?? "";
    // the digest is the whole address — a strict match is also the path guard
    if (!/^[0-9a-f]{64}$/.test(digest)) {
      return NextResponse.json({ error: `not a sha256 digest: ${digest}` }, { status: 400 });
    }

    let bytes: Buffer;
    try {
      bytes = await readFile(
        join(env("RAMPSCAN_LEDGER_DIR"), "objects", `${digest}.envelope.json`),
      );
    } catch {
      return NextResponse.json(
        { error: `no signed envelope for ${digest} in the ledger — nothing to verify` },
        { status: 404 },
      );
    }
    return new NextResponse(new Uint8Array(bytes), {
      headers: {
        "Content-Type": "application/json",
        "Content-Disposition": `attachment; filename="${digest}.envelope.json"`,
      },
    });
  } catch (error) {
    return NextResponse.json(
      { error: error instanceof Error ? error.message : String(error) },
      { status: 500 },
    );
  }
}
