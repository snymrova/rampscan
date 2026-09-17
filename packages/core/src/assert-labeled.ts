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
 * Split a field into the step whose document it reads and the JMESPath over
 * it. Three forms, all of which the overlay writes now that upstream names
 * its own steps:
 *
 *   `<label>.<path>`   the common one — `restricted-ssh.EvaluationResults`
 *   `<label>[<path>`   the path opens on a projection, bracket kept —
 *                      `credential-report[].mfa_active`
 *   `<label>`          the document itself, which is `@` in JMESPath —
 *                      `credential-report-generated-time max_age_days 1`
 *
 * The label may itself contain dots and dashes (`s3-bucket-ssl-requests-only`),
 * so the longest known label that prefixes the field wins; a field whose
 * prefix is no label is not labeled (it is a row-wise field).
 */
export function labeledField(field: string, labels: Iterable<string>): { label: string; path: string } | undefined {
  let best: string | undefined;
  for (const label of labels) {
    const fits = field === label || field.startsWith(`${label}.`) || field.startsWith(`${label}[`);
    if (fits && (best === undefined || label.length > best.length)) best = label;
  }
  if (best === undefined) return undefined;
  const rest = field.slice(best.length);
  return { label: best, path: rest === "" ? "@" : rest.startsWith(".") ? rest.slice(1) : rest };
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
 * Whether a `where` clause holds over ONE element the assertion's own
 * projection yielded. Upstream writes a labeled assertion's `where` as a
 * path relative to that element, not as a second labeled path:
 * `credential-report[].mfa_active where password_enabled eq TRUE` is "for
 * each row of the credential report, if it has a console password then MFA
 * is active". So the clause is aligned element-for-element, exactly as the
 * row evaluator aligns a column with its row — the earlier reading, a guard
 * over the whole document, both let a narrowing clause pass vacuously when
 * it resolved to nothing AND judged the elements the clause excluded.
 *
 * The clause's own path may itself project (`Tags[?Key=='AccountType'].Value`),
 * so it holds when any value it yields satisfies the op, and fails when it
 * yields nothing — an element missing the key the clause names is not in the
 * narrowed population.
 */
function whereHoldsOn(element: unknown, clause: NonNullable<RecipeAssertion["where"]>[number], now: Date): boolean {
  const values = elementsAt(element, clause.field);
  if (values === undefined || values.length === 0) return clause.op === "not_exists";
  return values.some((v) => holdsOp(clause.op, v, clause.value, now));
}

/**
 * Split a labeled path into the projection that yields the elements a
 * `where` filters and the leaf read from each survivor — the last flatten
 * projection is the boundary, because that is where upstream's element
 * begins. `credential-report[].mfa_active` is rows `credential-report[]` and
 * leaf `mfa_active`; `unused-access-findings.findings[]` is rows
 * `findings[]` and leaf `@`, the element itself.
 */
function splitProjection(path: string): { base: string; leaf: string } | undefined {
  const at = path.lastIndexOf("[]");
  if (at === -1) return undefined;
  const base = path.slice(0, at + 2);
  const rest = path.slice(at + 2);
  return { base, leaf: rest === "" ? "@" : rest.startsWith(".") ? rest.slice(1) : rest };
}

/**
 * A labeled assertion with a `where`: row-wise over its own projection. The
 * base yields the elements, each clause filters them one by one, and the op
 * is applied to what the leaf reads from each survivor.
 *
 * `population` is the count BEFORE the filter, the way the row evaluator
 * states it (`assert.ts`): the population is a property of the observation,
 * not of the clause, so "no temporary account among 412 users" reads as
 * `0 of 412` rather than as a verdict. An element whose leaf yields nothing
 * fails — `every survivor holds` over a missing key is the vacuous pass
 * ground rule 7 forbids.
 */
function narrowed(
  a: RecipeAssertion,
  where: NonNullable<RecipeAssertion["where"]>,
  lf: { label: string; path: string },
  docs: LabeledDocuments,
  now: Date,
): AssertionResult {
  const split = splitProjection(lf.path);
  if (split === undefined) {
    return fail(a, `${lf.label}: ${JSON.stringify(lf.path)} has no projection for its where to align on — the clause names a path over each element, and there are no elements`);
  }
  const elements = elementsAt(docs[lf.label], split.base);
  if (elements === undefined) return fail(a, `JMESPath ${JSON.stringify(split.base)} does not parse`);
  const population = elements.length;
  const survivors = elements.filter((el) => where.every((w) => whereHoldsOn(el, w, now)));
  const scope = `${lf.label}: ${survivors.length} of ${population} at ${split.base} in scope`;

  if (a.op === "count_eq" || a.op === "count_lte") {
    if (typeof a.value !== "number") return fail(a, `${a.op} requires a numeric value, got ${JSON.stringify(a.value)}`, { population });
    const ok = a.op === "count_eq" ? survivors.length === a.value : survivors.length <= a.value;
    const r: AssertionResult = { description: a.description, passed: ok, detail: `${scope} (${a.op} ${a.value})`, population };
    return ok ? r : withOffenders(r, survivors);
  }
  const failing = survivors.filter((el) => {
    const values = elementsAt(el, split.leaf);
    if (values === undefined || values.length === 0) return a.op !== "not_exists";
    return !values.every((v) => holdsOp(a.op, v, a.value, now));
  });
  const ok = failing.length === 0;
  const r: AssertionResult = {
    description: a.description,
    passed: ok,
    detail: ok
      ? `${scope}, all holding ${split.leaf} ${a.op} ${JSON.stringify(a.value)}`
      : `${scope}, ${failing.length} failing ${split.leaf} ${a.op} ${JSON.stringify(a.value)}`,
    population,
  };
  return ok ? r : withOffenders(r, failing);
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
  if (a.where !== undefined && a.where.length > 0) return narrowed(a, a.where, lf, docs, now);
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
