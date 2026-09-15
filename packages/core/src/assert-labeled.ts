import jmespath from "jmespath";
import type { AssertionResult, OffenderPointer, RecipeAssertion } from "@rampscan/schema";

// Upstream's second assertion vocabulary (SPEC §14.4a, plan T2-5). The
// pipeline's evaluator (assert.ts) reads ROWS: `field` is a column, `where`
// filters rows, `population` is the row count. Twenty of the twenty-two
// pinned AWS recipes with assertions write `field` as
//
//     <label>.<JMESPath>
//
// where the label names one step of the recipe (its Config rule name, its
// CLI operation, or a reviewed name — `identity-pool`) and the path is
// evaluated over that step's whole JSON document. The op then applies to
// what the path yields: an array's length for the count ops, a scalar or
// every element for the rest. Same AssertionResult shape, same discipline:
// `population` stated wherever the path yields a collection, a pass over an
// empty collection never silently, offenders named where a cloud resource
// can be.

/** every step's parsed document, by the label an assertion may name it with */
export type LabeledDocuments = Readonly<Record<string, unknown>>;

/**
 * Split `<label>.<path>` at the first label the documents carry. The label
 * may itself contain dots and dashes (`s3-bucket-ssl-requests-only`), so
 * the longest known label that prefixes the field wins; a field whose
 * prefix is no label is not labeled (it is a row-wise field).
 */
export function labeledField(field: string, labels: Iterable<string>): { label: string; path: string } | undefined {
  let best: string | undefined;
  for (const label of labels) {
    if (field.startsWith(`${label}.`) && (best === undefined || label.length > best.length)) best = label;
  }
  return best === undefined ? undefined : { label: best, path: field.slice(best.length + 1) };
}

/** the value a path yields, or a failure the caller can report — a syntax error is the recipe's, not the account's */
function search(doc: unknown, path: string): { ok: true; value: unknown } | { ok: false; error: string } {
  try {
    return { ok: true, value: jmespath.search(doc, path) as unknown };
  } catch (cause) {
    return { ok: false, error: cause instanceof Error ? cause.message : String(cause) };
  }
}

/** loose scalar equality: upstream writes booleans as JSON booleans and enums as strings; a number may arrive as either */
function scalarEq(actual: unknown, expected: unknown): boolean {
  if (actual === expected) return true;
  if (typeof actual === "boolean" && typeof expected === "string") return String(actual) === expected.toLowerCase();
  if (typeof actual === "number" && typeof expected === "string") return String(actual) === expected;
  return false;
}

/**
 * A cloud-shaped offender pointer: the resource a failing element names,
 * under the keys AWS uses (a Config evaluation's qualifier, a finding's
 * resource, a bare Id/Arn). Nothing invented — an element that names no
 * resource yields no pointer and is counted only.
 */
export function cloudOffender(element: unknown): OffenderPointer | undefined {
  if (element === null || typeof element !== "object") return undefined;
  const e = element as Record<string, unknown>;
  const qualifier = ((e["EvaluationResultIdentifier"] as Record<string, unknown> | undefined)?.["EvaluationResultQualifier"] ??
    undefined) as Record<string, unknown> | undefined;
  const pick = (...keys: string[]): string | undefined => {
    for (const k of keys) {
      const v = qualifier?.[k] ?? e[k];
      if (typeof v === "string" && v.length > 0) return v;
    }
    return undefined;
  };
  const pointer: OffenderPointer = {};
  const id = pick(
    "ResourceId",
    "ResourceArn",
    "Arn",
    "Id",
    "arn",
    "id",
    "RoleName",
    "UserName",
    "VpcPeeringConnectionId",
    "TransitGatewayAttachmentId",
    "SecurityGroupRuleId",
    "SubscriptionArn",
    "Name",
  );
  if (id !== undefined) pointer.resource_id = id;
  const type = pick("ResourceType", "resourceType");
  if (type !== undefined) pointer.resource_type = type;
  const region = pick("Region", "awsRegion", "region");
  if (region !== undefined) pointer.region = region;
  return Object.keys(pointer).length > 0 ? pointer : undefined;
}

const MAX_OFFENDERS = 20;

function fail(a: RecipeAssertion, detail: string, extra: Partial<AssertionResult> = {}): AssertionResult {
  return { description: a.description, passed: false, detail, ...extra };
}

function withOffenders(result: AssertionResult, failing: unknown[]): AssertionResult {
  const pointers = failing.slice(0, MAX_OFFENDERS).map(cloudOffender).filter((p): p is OffenderPointer => p !== undefined);
  if (pointers.length > 0) result.offenders = pointers;
  if (failing.length > 0) result.offender_count = failing.length;
  return result;
}

/** one element against one op — the element-wise half of every non-count op */
function holdsOp(op: RecipeAssertion["op"], v: unknown, expected: unknown, now: Date): boolean {
  switch (op) {
    case "eq":
      return scalarEq(v, expected);
    case "in":
      return Array.isArray(expected) && expected.some((x) => scalarEq(v, x));
    case "lte":
      return typeof expected === "number" && Number(v) <= expected;
    case "gte":
      return typeof expected === "number" && Number(v) >= expected;
    case "max_age_days": {
      if (typeof v !== "string" || typeof expected !== "number") return false;
      const then = Date.parse(v);
      return !Number.isNaN(then) && now.getTime() - then <= expected * 86_400_000;
    }
    case "exists":
      return v !== null && v !== undefined;
    case "not_exists":
      return v === null || v === undefined;
    default:
      return false;
  }
}

/** the elements a path yields: an array's, a scalar as one, nothing for null */
function elementsAt(doc: unknown, path: string): unknown[] | undefined {
  const found = search(doc, path);
  if (!found.ok) return undefined;
  const v = found.value;
  if (Array.isArray(v)) return v.flat(1);
  return v === null || v === undefined ? [] : [v];
}

/**
 * Whether a `where` clause holds over the documents. A labeled where names
 * its own path, which cannot be aligned element-for-element with the
 * assertion's path (SPEC §14.4a), so it is a GUARD: it holds when any
 * element at its path satisfies the op. One pinned assertion uses this
 * (`temporary-account-automatic-revocation`, CreateDate within 90 days
 * where a user is tagged temporary); the field is then judged over every
 * element, and the detail says so.
 */
function whereHolds(clause: NonNullable<RecipeAssertion["where"]>[number], docs: LabeledDocuments, now: Date): boolean {
  const lf = labeledField(clause.field, Object.keys(docs));
  if (lf === undefined) return false;
  const elements = elementsAt(docs[lf.label], lf.path);
  return elements !== undefined && elements.some((v) => holdsOp(clause.op, v, clause.value, now));
}

/**
 * Evaluate one labeled assertion over the documents. `field` must resolve
 * to a label the documents carry; otherwise the assertion fails with the
 * label named — a recipe whose step the run did not produce is not a pass.
 */
export function evaluateLabeledAssertion(a: RecipeAssertion, docs: LabeledDocuments, now: Date): AssertionResult {
  const lf = labeledField(a.field, Object.keys(docs));
  if (lf === undefined) {
    return fail(a, `field ${a.field} names no step of this run (labels: ${Object.keys(docs).join(", ") || "none"})`);
  }
  if (a.where !== undefined && a.where.length > 0 && !a.where.every((w) => whereHolds(w, docs, now))) {
    // the guard did not hold: the assertion does not apply, and says so — a
    // pass, because upstream's `where` narrows the population to nothing here
    return { description: a.description, passed: true, detail: "where (a guard over its own path) did not hold; nothing to assert over", population: 0 };
  }
  const found = search(docs[lf.label], lf.path);
  if (!found.ok) return fail(a, `JMESPath ${JSON.stringify(lf.path)} does not parse: ${found.error}`);
  const value = found.value;
  const isArray = Array.isArray(value);
  // a projection over a projection (`UserDetailList[].Tags[…].Value`) yields nested arrays; one level is flattened so every leaf is judged
  const elements: unknown[] = isArray ? value.flat(1) : value === null || value === undefined ? [] : [value];
  const population = elements.length;

  switch (a.op) {
    case "count_eq":
    case "count_lte": {
      if (typeof a.value !== "number") return fail(a, `${a.op} requires a numeric value, got ${JSON.stringify(a.value)}`, { population });
      const n = elements.length;
      const ok = a.op === "count_eq" ? n === a.value : n <= a.value;
      const r: AssertionResult = { description: a.description, passed: ok, detail: `${lf.label}: ${n} at ${lf.path} (${a.op} ${a.value})`, population };
      return ok ? r : withOffenders(r, elements);
    }
    case "exists": {
      const ok = elements.length > 0;
      return { description: a.description, passed: ok, detail: ok ? `${lf.label}: ${lf.path} present` : `${lf.label}: nothing at ${lf.path}`, population };
    }
    case "not_exists": {
      const ok = elements.length === 0;
      const r: AssertionResult = { description: a.description, passed: ok, detail: ok ? `${lf.label}: nothing at ${lf.path}` : `${lf.label}: ${elements.length} at ${lf.path}, expected none`, population };
      return ok ? r : withOffenders(r, elements);
    }
    case "eq":
    case "in":
    case "lte":
    case "gte":
    case "max_age_days": {
      if (elements.length === 0) {
        // `every element` over nothing is the vacuous pass ground rule 7 forbids
        return fail(a, `${lf.label}: nothing at ${lf.path} to hold ${a.op} ${JSON.stringify(a.value)}`, { population });
      }
      const failing = elements.filter((v) => !holdsOp(a.op, v, a.value, now));
      const ok = failing.length === 0;
      const r: AssertionResult = {
        description: a.description,
        passed: ok,
        detail: ok
          ? `${lf.label}: ${elements.length} at ${lf.path} hold ${a.op} ${JSON.stringify(a.value)}`
          : `${lf.label}: ${failing.length} of ${elements.length} at ${lf.path} fail ${a.op} ${JSON.stringify(a.value)}`,
        population,
      };
      return ok ? r : withOffenders(r, failing);
    }
    default:
      return fail(a, `labeled evaluation does not support op "${String(a.op)}"`, { population });
  }
}

/** every labeled assertion of a recipe over the run's documents */
export function evaluateLabeledAssertions(assertions: readonly RecipeAssertion[], docs: LabeledDocuments, now: Date): AssertionResult[] {
  return assertions.map((a) => evaluateLabeledAssertion(a, docs, now));
}
