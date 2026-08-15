import type { AssertionResult, OffenderPointer, RecipeAssertion } from "@rampscan/schema";
import type { ObservationRows } from "./ports.js";

// Assertion evaluation over observation rows — the same semantics
// aws-evidence.json's recipes use against CLI output:
//
//   - row-wise ops (eq, exists, not_exists, in, lte, gte, max_age_days):
//     after the `where` filter, EVERY remaining row must satisfy the clause;
//     an empty filtered set passes vacuously ("every active key is rotated"
//     is true when there are no active keys).
//   - count ops (count_eq, count_lte): the size of the filtered set is
//     compared to the value ("zero leaks" is `count_eq 0`).
//
// Field paths are dotted lookups into the row object.

function lookup(row: Record<string, unknown>, path: string): unknown {
  let cur: unknown = row;
  for (const part of path.split(".")) {
    if (cur === null || typeof cur !== "object") return undefined;
    cur = (cur as Record<string, unknown>)[part];
  }
  return cur;
}

function clauseHolds(
  row: Record<string, unknown>,
  clause: { field: string; op: string; value?: unknown },
  now: Date,
): boolean {
  const actual = lookup(row, clause.field);
  switch (clause.op) {
    case "eq":
      return actual === clause.value;
    case "exists":
      return actual !== undefined && actual !== null;
    case "not_exists":
      return actual === undefined || actual === null;
    case "in":
      return Array.isArray(clause.value) && clause.value.includes(actual as string);
    case "lte":
      return typeof actual === "number" && typeof clause.value === "number" && actual <= clause.value;
    case "gte":
      return typeof actual === "number" && typeof clause.value === "number" && actual >= clause.value;
    case "max_age_days": {
      if (typeof actual !== "string" || typeof clause.value !== "number") return false;
      const then = Date.parse(actual);
      if (Number.isNaN(then)) return false;
      return now.getTime() - then <= clause.value * 86_400_000;
    }
    default:
      throw new Error(`row-wise evaluation does not support op "${clause.op}"`);
  }
}

function describeRow(row: Record<string, unknown>): string {
  // 400, not 200: M4 rows carry call paths, and a truncated path is no artifact
  const s = JSON.stringify(row);
  return s.length > 400 ? `${s.slice(0, 400)}…` : s;
}

/** first `MAX_OFFENDER_POINTERS` rows ride the assertion result as pointers */
export const MAX_OFFENDER_POINTERS = 5;

/**
 * The fix pointer of one failing row (I2c), extracted from the field names
 * the real observation producers use — assert.test.ts pins the extraction to
 * every producer's actual row shape, so a renamed field breaks a test instead
 * of a violation silently losing its pointer. One ambiguity carried from M4:
 * `path` is a FILE for semgrep/sast-gate rows but the CALL PATH for
 * reachability rows — the "»" separator is the discriminator, same as the
 * console has read it since M4. Returns undefined when the row carries no
 * pointer field at all (e.g. a summary row like `{workflow_count: 0}`).
 */
export function offenderPointer(row: Record<string, unknown>): OffenderPointer | undefined {
  const str = (v: unknown): string | undefined =>
    typeof v === "string" && v !== "" ? v : undefined;
  const pathish = str(row["path"]);
  const pathIsCallPath = pathish?.includes("»") ?? false;

  const pointer: OffenderPointer = {};
  const file = (pathIsCallPath ? undefined : pathish) ?? str(row["file"]) ?? str(row["workflow"]);
  if (file !== undefined) pointer.file = file;
  const line = [row["line"], row["start_line"]].find((v) => typeof v === "number");
  if (line !== undefined) pointer.line = line as number;
  const check =
    str(row["check_id"]) ??
    str(row["rule_id"]) ??
    str(row["code"]) ??
    str(row["advisory"]) ??
    str(row["action"]);
  if (check !== undefined) pointer.check = check;
  const callPath = str(row["call_path"]) ?? (pathIsCallPath ? pathish : undefined);
  if (callPath !== undefined) pointer.call_path = callPath;
  // per-hop resolution marking (I3f), carried only when it MATCHES the path it
  // claims to describe: a marks array of the wrong length would silently
  // misattribute which hop is inferred, and a wrong mark on a call path is
  // worse than no mark at all
  const marks = row["call_path_resolutions"];
  if (
    callPath !== undefined &&
    Array.isArray(marks) &&
    marks.every((m): m is "exact" | "inferred" => m === "exact" || m === "inferred") &&
    marks.length === callPath.split(" » ").length - 1
  ) {
    pointer.call_path_resolutions = marks;
  }

  return Object.keys(pointer).length > 0 ? pointer : undefined;
}

/**
 * Attach fix pointers for the failing rows to an assertion result — mutating
 * `result`, never its `detail`: detail participates in evidence identity
 * (`sameEvidence`) and must stay byte-identical to what it always was.
 */
function attachOffenders(result: AssertionResult, failing: ObservationRows): void {
  const pointers = failing
    .slice(0, MAX_OFFENDER_POINTERS)
    .map(offenderPointer)
    .filter((p): p is OffenderPointer => p !== undefined);
  if (pointers.length > 0) result.offenders = pointers;
  if (failing.length > 0) result.offender_count = failing.length;
}

export function evaluateAssertion(
  assertion: RecipeAssertion,
  rows: ObservationRows,
  now: Date,
): AssertionResult {
  const filtered = assertion.where
    ? rows.filter((row) => assertion.where!.every((w) => clauseHolds(row, w, now)))
    : rows;

  if (assertion.op === "count_eq" || assertion.op === "count_lte") {
    const expected = assertion.value;
    if (typeof expected !== "number") {
      return {
        description: assertion.description,
        passed: false,
        detail: `${assertion.op} requires a numeric value, got ${JSON.stringify(expected)}`,
      };
    }
    const passed =
      assertion.op === "count_eq" ? filtered.length === expected : filtered.length <= expected;
    const result: AssertionResult = {
      description: assertion.description,
      passed,
      detail: passed
        ? `count ${filtered.length}`
        : `expected count ${assertion.op === "count_eq" ? "==" : "<="} ${expected}, got ${filtered.length}` +
          (filtered.length > 0 ? `; e.g. ${describeRow(filtered[0]!)}` : ""),
    };
    // a failing count assertion's offenders are the counted rows themselves
    // ("zero leaks" failing means every filtered row is a leak)
    if (!passed) attachOffenders(result, filtered);
    return result;
  }

  const offenders = filtered.filter((row) => !clauseHolds(row, assertion, now));
  const passed = offenders.length === 0;
  const result: AssertionResult = {
    description: assertion.description,
    passed,
    detail: passed
      ? `${filtered.length} row(s) satisfy ${assertion.field} ${assertion.op}`
      : `${offenders.length} of ${filtered.length} row(s) fail ${assertion.field} ${assertion.op}; e.g. ${describeRow(offenders[0]!)}`,
  };
  if (!passed) attachOffenders(result, offenders);
  return result;
}

export function evaluateAssertions(
  assertions: RecipeAssertion[],
  rows: ObservationRows,
  now: Date,
): AssertionResult[] {
  return assertions.map((a) => evaluateAssertion(a, rows, now));
}
