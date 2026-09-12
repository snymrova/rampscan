import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { GRAPH_CONFIG_FILE } from "@rampscan/graph";
import { OfferingConfig } from "@rampscan/schema";

// The declared `offering` block, read from the scanned repo's
// rampscan.config.json (plan Q5.1).
//
// Same three-state contract as `loadDocuments`, and for the same reason:
//
//   file absent, or the key absent → `undefined`. An offering nobody declared
//     is a claim never made. No exports are generated and the caller says so.
//   key PRESENT but malformed     → throw. A mistyped declaration must not
//     silently waive itself; the strict schema is what turns a typo into an
//     exit instead of a field that quietly declared nothing.
//   key present and valid         → the parsed block.
//
// The middle case is the one worth being loud about here. These two documents
// are published to assessors. A config whose `contactInformation` key was
// spelled `contacts` would, under a permissive parse, generate a package
// overview missing the Security and Sales contacts CDS-CSO-PUB requires — and
// the conformance check would then report the schema violation instead of the
// typo, one layer away from the person who can fix it.

export async function loadOffering(root: string): Promise<OfferingConfig | undefined> {
  let raw: string;
  try {
    raw = await readFile(join(root, GRAPH_CONFIG_FILE), "utf8");
  } catch {
    return undefined;
  }
  const parsed = JSON.parse(raw) as Record<string, unknown>;
  if (parsed["offering"] === undefined) return undefined;
  try {
    return OfferingConfig.parse(parsed["offering"]);
  } catch (cause) {
    const issue =
      cause instanceof Error && "issues" in cause
        ? (cause as { issues: Array<{ path: Array<string | number>; message: string }> }).issues
            .map((i) => `${["offering", ...i.path].join(".")}: ${i.message}`)
            .join("; ")
        : String(cause);
    throw new Error(
      `the offering block in ${GRAPH_CONFIG_FILE} failed validation (exit refused): ${issue} — a mistyped declaration must not silently waive itself`,
      { cause },
    );
  }
}
