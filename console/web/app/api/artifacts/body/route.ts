import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { NextResponse } from "next/server";

// The artifact body, read from the LEDGER (plan R1.6, SPEC §13.2) — read-only,
// and structurally so: this file has a GET and nothing else.
//
// Why the ledger rather than the projection. An artifact's prose is the one
// thing in this system a person had to write, and §13.2 put it in the predicate
// precisely so that what the ledger holds, an assessor holding the ledger can
// read. The projection carries the body's ADDRESS — digest, source, clock — and
// deliberately not its bytes; serving the bytes from the record means the
// console shows what was signed rather than a copy of it that could drift.
//
// THERE IS NO WRITE ROUTE, AND THAT IS THE FEATURE. The artifact editor is not
// built (plan §4.2, R1.6): a general document editor loses the fight with
// Paramify and the GRC platforms, and what nobody else ships is artifacts bound
// to evidence, an anchor and a review record, with a clock. If this route ever
// grows a POST, the plan has failed.
//
// Environment (set by `rampscan serve`): RAMPSCAN_PB_URL, RAMPSCAN_LEDGER_DIR.

export const runtime = "nodejs";

const RAMPSCAN_ARTIFACT_TYPE = "https://rampscan.dev/artifact/v1";

function env(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is not set — start the console via \`rampscan serve\``);
  return value;
}

export async function GET(request: Request): Promise<NextResponse> {
  try {
    // reading an artifact requires being signed in, same as reading evidence
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

    let raw: string;
    try {
      raw = await readFile(join(env("RAMPSCAN_LEDGER_DIR"), "objects", `${digest}.json`), "utf8");
    } catch {
      return NextResponse.json(
        { error: `no statement at ${digest} in the ledger` },
        { status: 404 },
      );
    }

    const statement = JSON.parse(raw) as { predicateType?: string; predicate?: unknown };
    if (statement.predicateType !== RAMPSCAN_ARTIFACT_TYPE) {
      // a digest that addresses something else is not an error of this route's
      // making, and saying WHICH kind of statement it found beats "not found"
      return NextResponse.json(
        {
          error: `${digest.slice(0, 12)}… is not an artifact — it is ${statement.predicateType ?? "an unrecognised statement"}`,
        },
        { status: 409 },
      );
    }

    // the predicate verbatim: body, source, anchor, generator, review, clock.
    // Nothing is reshaped here — the page renders what was signed, and a
    // transformation in the middle would be a second version of the artifact.
    return NextResponse.json({ digest, predicate: statement.predicate });
  } catch (error) {
    return NextResponse.json(
      { error: error instanceof Error ? error.message : String(error) },
      { status: 500 },
    );
  }
}
