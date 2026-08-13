import type { AssertionResult, RecipeAssertion } from "@rampscan/schema";
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
  const s = JSON.stringify(row);
  return s.length > 200 ? `${s.slice(0, 200)}…` : s;
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
    return {
      description: assertion.description,
      passed,
      detail: passed
        ? `count ${filtered.length}`
        : `expected count ${assertion.op === "count_eq" ? "==" : "<="} ${expected}, got ${filtered.length}` +
          (filtered.length > 0 ? `; e.g. ${describeRow(filtered[0]!)}` : ""),
    };
  }

  const offenders = filtered.filter((row) => !clauseHolds(row, assertion, now));
  const passed = offenders.length === 0;
  return {
    description: assertion.description,
    passed,
    detail: passed
      ? `${filtered.length} row(s) satisfy ${assertion.field} ${assertion.op}`
      : `${offenders.length} of ${filtered.length} row(s) fail ${assertion.field} ${assertion.op}; e.g. ${describeRow(offenders[0]!)}`,
  };
}

export function evaluateAssertions(
  assertions: RecipeAssertion[],
  rows: ObservationRows,
  now: Date,
): AssertionResult[] {
  return assertions.map((a) => evaluateAssertion(a, rows, now));
}
