import { NextResponse } from "next/server";
import { computeEvidencePackage } from "@rampscan/cli";

// The per-control evidence package (plan I3e), read-only. The auditor's
// take-it-with-you artifact: every mapped recipe's signed envelope byte-for-byte
// from the ledger's object store, the artifacts those envelopes attest, the
// public key, a manifest, and instructions — assembled server-side because it
// needs ledger object-store reads the browser cannot do.
//
// Same posture as the diff route: auth-refresh gate, `runtime: nodejs`, and
// structurally unable to write anything, anywhere.
//
// Environment (set by `rampscan serve`): RAMPSCAN_PB_URL, RAMPSCAN_LEDGER_DIR,
// RAMPSCAN_KEYS_DIR, RAMPSCAN_RECIPES_DIR, RAMPSCAN_OUT_DIR (optional — without
// it the package ships bundles and says why artifacts are absent).

export const runtime = "nodejs";

function env(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is not set — start the console via \`rampscan serve\``);
  return value;
}

export async function GET(request: Request): Promise<NextResponse> {
  try {
    // exporting evidence requires being signed in, same as reading it
    const refresh = await fetch(`${env("RAMPSCAN_PB_URL")}/api/collections/users/auth-refresh`, {
      method: "POST",
      headers: { Authorization: request.headers.get("authorization") ?? "" },
    });
    if (!refresh.ok) {
      return NextResponse.json({ error: "not signed in" }, { status: 401 });
    }

    const params = new URL(request.url).searchParams;
    const register = params.get("reg") ?? "controls";
    if (register !== "controls" && register !== "ksis") {
      return NextResponse.json(
        { error: `reg is not \`controls\` or \`ksis\`: ${register}` },
        { status: 400 },
      );
    }
    const id = params.get("id") ?? "";
    if (!id) {
      return NextResponse.json({ error: "id is required" }, { status: 400 });
    }

    const ledgerDir = env("RAMPSCAN_LEDGER_DIR");
    const keysDir = env("RAMPSCAN_KEYS_DIR");
    const outDir = process.env["RAMPSCAN_OUT_DIR"];

    let pkg;
    try {
      pkg = await computeEvidencePackage({
        ledgerDir,
        keysDir,
        recipesDir: env("RAMPSCAN_RECIPES_DIR"),
        ...(outDir ? { artifactsDir: `${outDir}/artifacts` } : {}),
        register,
        id,
        ...(params.get("repo") ? { repo: params.get("repo")! } : {}),
        // the same string `serve` stamps into the projection's settings, built
        // from the same env — this quotes the serve's own dirs, never a guess
        verifyCommand: `pnpm rampscan verify <digest> --ledger ${ledgerDir} --keys ${keysDir}`,
      });
    } catch (error) {
      // "no such control in the register" is an answer, not a server failure
      return NextResponse.json(
        { error: error instanceof Error ? error.message : String(error) },
        { status: 404 },
      );
    }

    return new NextResponse(new Uint8Array(pkg.bytes), {
      headers: {
        "Content-Type": "application/x-tar",
        "Content-Disposition": `attachment; filename="${pkg.filename}"`,
      },
    });
  } catch (error) {
    return NextResponse.json(
      { error: error instanceof Error ? error.message : String(error) },
      { status: 500 },
    );
  }
}
