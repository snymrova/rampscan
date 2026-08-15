import { NextResponse } from "next/server";
import { ArtifactNotAttestedError, resolveArtifact } from "@rampscan/cli";

// The artifact route (plan J4), read-only. Digest → the bytes a signed
// statement attests, or a stated reason there are none.
//
// Same posture as the diff and export routes: auth-refresh gate,
// `runtime: nodejs`, and structurally unable to write anything, anywhere.
//
// The load-bearing rule lives in `resolveArtifact` and is worth restating at
// the door: bytes are matched by DIGEST and RE-HASHED before they are served.
// Serving an artifact by path without re-hashing would let a modified file on
// disk render under a signed bundle's digest — the exact confusion the whole
// architecture exists to prevent. A file that no longer matches is refused
// WITH the reason; it is never quietly served under the attested digest.
//
// The response echoes the verified hash in `X-Rampscan-Sha256` so the browser
// can check the same thing itself — which the evidence page does, because a
// page that says "don't trust this page" should not ask to be trusted here.
//
// Environment (set by `rampscan serve`): RAMPSCAN_PB_URL, RAMPSCAN_LEDGER_DIR,
// RAMPSCAN_OUT_DIR (optional — without it the route says why nothing is here).

export const runtime = "nodejs";

function env(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is not set — start the console via \`rampscan serve\``);
  return value;
}

/** JSON renders in the viewer; everything else is bytes to take away. */
function contentType(name: string): string {
  if (name.endsWith(".json")) return "application/json";
  if (name.endsWith(".yaml") || name.endsWith(".yml")) return "text/yaml";
  if (name.endsWith(".txt") || name.endsWith(".md")) return "text/plain";
  return "application/octet-stream";
}

export async function GET(request: Request): Promise<NextResponse> {
  try {
    // reading an artifact requires being signed in, same as reading the
    // evidence that attests it
    const refresh = await fetch(`${env("RAMPSCAN_PB_URL")}/api/collections/users/auth-refresh`, {
      method: "POST",
      headers: { Authorization: request.headers.get("authorization") ?? "" },
    });
    if (!refresh.ok) {
      return NextResponse.json({ error: "not signed in" }, { status: 401 });
    }

    const digest = new URL(request.url).searchParams.get("digest") ?? "";
    if (!digest) {
      return NextResponse.json({ error: "digest is required" }, { status: 400 });
    }

    const outDir = process.env["RAMPSCAN_OUT_DIR"];
    let resolution;
    try {
      resolution = await resolveArtifact({
        ledgerDir: env("RAMPSCAN_LEDGER_DIR"),
        ...(outDir ? { artifactsDir: `${outDir}/artifacts` } : {}),
        digest,
      });
    } catch (error) {
      if (error instanceof ArtifactNotAttestedError) {
        // "no statement attests this" is an answer, not a server failure
        return NextResponse.json({ error: error.message }, { status: 404 });
      }
      throw error;
    }

    if (!resolution.bytes) {
      // 409: the digest is real and attested — the BYTES are the problem, and
      // the reason is the useful part of this response
      return NextResponse.json(
        {
          error: resolution.reason ?? "no bytes available",
          name: resolution.name,
          kind: resolution.kind,
          digest: resolution.digest,
          attestedBy: resolution.attestedBy,
        },
        { status: 409 },
      );
    }

    return new NextResponse(new Uint8Array(resolution.bytes), {
      headers: {
        "Content-Type": contentType(resolution.name),
        "Content-Disposition": `attachment; filename="${resolution.name}"`,
        // the hash these exact bytes produced on the way out, for the browser
        // to re-check without trusting this route
        "X-Rampscan-Sha256": resolution.digest,
        "X-Rampscan-Artifact-Name": resolution.name,
      },
    });
  } catch (error) {
    return NextResponse.json(
      { error: error instanceof Error ? error.message : String(error) },
      { status: 500 },
    );
  }
}
