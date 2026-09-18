import { readFile } from "node:fs/promises";

// The Security Decision Record, read for coverage (P2-1,
// docs/RESEARCH-REJECTION-LINTER.md §9).
//
// WHY THIS MODULE EXISTS. `SDR-CSO-FRR` is the rule community #167's reason 3
// restates. It requires a Security Decision Record carrying, for each
// applicable FedRAMP rule, an "explanation of how the rule is followed, OR an
// explanation of the reason and resulting risk to customers for NOT following
// the rule" — and the published schema makes that machine-readable, with
// `frrImplementationStatus` an enum over Implemented / Not Implemented /
// Partially Implemented.
//
// So "Not Implemented" is schema-valid, and the defect FedRAMP rejects on is a
// MISSING ROW, never the status inside one. That makes reason 3 a diff:
//
//     applicable rule ids  −  frrIDs present  =  the omissions
//
// decidable over one document, with no judgement about what a local appliance
// can or cannot verify. §9.2 records why the earlier design — a reviewed
// `outside` set over 120 rules — was answering a question reason 3 never asks.
//
// WHAT THIS DOES NOT DO. It does not validate the document against the pinned
// schema. That is `FRC-CSO-JSN`, it is reason 4, and the register reprojects
// `checkConformance` for it rather than re-deriving it (§5: one fact computed
// twice is a bug here). This module reads coverage and refuses only what would
// make a coverage claim dishonest — a document that is not an SDR at all, an
// id that names no rule, and the same id claimed twice.

/** the schema's own status vocabulary, plus the absence the schema permits */
export type SdrStatus =
  | "Implemented"
  | "Not Implemented"
  | "Partially Implemented"
  | "unstated";

const STATUSES: ReadonlySet<string> = new Set([
  "Implemented",
  "Not Implemented",
  "Partially Implemented",
]);

/** a rule id at the pin: three uppercase triples. `KSI-` shares the shape and is not one. */
const RULE_ID = /^[A-Z]{3}-[A-Z]{3}-[A-Z]{3}$/;
const KSI_ID = /^KSI-[A-Z]{3}-[A-Z]{3}$/;

export interface SdrProblem {
  /** the id the problem is about, or the array index when there is no usable id */
  subject: string;
  detail: string;
}

export interface SdrCoverage {
  /** where it was read from, so the register can name its source */
  path: string;
  /** the `frrID`s the document claims, deduped */
  ruleIds: ReadonlySet<string>;
  /** the `ksiId`s the document claims, deduped */
  ksiIds: ReadonlySet<string>;
  /** status per id, for both halves; `unstated` where the row omits it */
  statuses: ReadonlyMap<string, SdrStatus>;
  /** rows this reader refused, each with the reason — never silently dropped */
  problems: readonly SdrProblem[];
}

interface Row {
  id: unknown;
  status: unknown;
}

/**
 * Read one row array into ids and statuses, recording every refusal.
 *
 * `kind` picks the half; the two differ only in which field carries the id and
 * which shape that id must have, so they share the walk rather than diverging
 * into two nearly-identical loops that drift apart.
 */
function collect(
  rows: readonly Row[],
  kind: "rule" | "ksi",
  ids: Set<string>,
  statuses: Map<string, SdrStatus>,
  problems: SdrProblem[],
): void {
  const field = kind === "rule" ? "frrID" : "ksiId";
  const shape = kind === "rule" ? RULE_ID : KSI_ID;
  rows.forEach((row, index) => {
    const id = row.id;
    if (typeof id !== "string" || id.length === 0) {
      problems.push({
        subject: `${field}[${index}]`,
        detail: `row ${index} has no ${field} — a row that names no subject covers nothing, and the schema requires the field`,
      });
      return;
    }
    // The P2-2 refusal, arriving from the document side rather than the config
    // side: a KSI indicator is the same shape as a rule id, so a KSI in the
    // rule array would be counted as covering a rule that is still omitted.
    if (kind === "rule" && KSI_ID.test(id)) {
      problems.push({
        subject: id,
        detail:
          "a Key Security Indicator is claimed in fedRampRequirements — the KSI half of reason 3 is keySecurityIndicators, and counting this as a rule row would cover a rule that is still omitted",
      });
      return;
    }
    if (!shape.test(id)) {
      problems.push({
        subject: id,
        detail: `${field} is not shaped like ${kind === "rule" ? "a FedRAMP rule id" : "a Key Security Indicator"} — the row it meant is still omitted while the document reads as answered`,
      });
      return;
    }
    if (ids.has(id)) {
      problems.push({
        subject: id,
        detail: `claimed more than once in ${field} — two rows for one subject, and this reader counts the subject once`,
      });
      return;
    }
    ids.add(id);
    const status = row.status;
    if (status === undefined) {
      statuses.set(id, "unstated");
      return;
    }
    if (typeof status !== "string" || !STATUSES.has(status)) {
      problems.push({
        subject: id,
        detail: `status ${JSON.stringify(status)} is outside the schema's enum (Implemented, Not Implemented, Partially Implemented)`,
      });
      statuses.set(id, "unstated");
      return;
    }
    statuses.set(id, status as SdrStatus);
  });
}

/**
 * Read a Security Decision Record for what it covers.
 *
 * Throws only when the file is not an SDR at all — unreadable, not JSON, or
 * missing the array `SDR-CSO-FRR` is about. Everything else is a recorded
 * problem, because a document with one bad row still covers the other rows and
 * refusing the whole file would hide that.
 */
export async function readSdrCoverage(path: string): Promise<SdrCoverage> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(await readFile(path, "utf8"));
  } catch (cause) {
    throw new Error(
      `${path} could not be read as a Security Decision Record: ${(cause as Error).message}`,
    );
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error(`${path} is not a JSON object, so it is not a Security Decision Record`);
  }
  const doc = parsed as Record<string, unknown>;
  const rules = doc["fedRampRequirements"];
  if (!Array.isArray(rules)) {
    throw new Error(
      `${path} has no fedRampRequirements array — that field is required by the Security Decision Record schema and is the whole of reason 3's rule half, so a document without it cannot be read for coverage`,
    );
  }
  const ksis = Array.isArray(doc["keySecurityIndicators"]) ? doc["keySecurityIndicators"] : [];

  const ruleIds = new Set<string>();
  const ksiIds = new Set<string>();
  const statuses = new Map<string, SdrStatus>();
  const problems: SdrProblem[] = [];

  collect(
    rules.map((r) => ({
      id: (r as Record<string, unknown>)?.["frrID"],
      status: (r as Record<string, unknown>)?.["frrImplementationStatus"],
    })),
    "rule",
    ruleIds,
    statuses,
    problems,
  );
  collect(
    ksis.map((r) => ({
      id: (r as Record<string, unknown>)?.["ksiId"],
      status: (r as Record<string, unknown>)?.["ksiImplementationStatus"],
    })),
    "ksi",
    ksiIds,
    statuses,
    problems,
  );

  return { path, ruleIds, ksiIds, statuses, problems };
}
