import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";

// The pinned FedRAMP JSON schemas, and a validator that fails CLOSED (plan
// Q5.1, gating Q5.2 — G10 / `FRC-CSO-JSN`).
//
// Two halves, and the second one needs its reasoning on the record.
//
// THE PINS. FedRAMP semvers each CR26 draft schema independently: the three
// files here read 0.1.4, 0.3.0 and 0.2.0 off the same 2026-06-24 date stamp, so
// the pin is per file, exactly as `DEFAULT_OVERLAY_PINS` is per slice and for
// the same reason — one global constant would have been wrong the day it was
// written. Each is pinned on `$schemaVersion` AND on the sha256 of the bytes,
// because these are DRAFTS: a re-publication under an unchanged date and an
// unchanged version is a move a draft can make, and it is precisely the class
// of move `packages/dataset/src/pins.ts` was written to complain about — a
// version we reason against that nothing was checking.
//
// THE VALIDATOR, AND WHY IT IS NOT AJV. The house has declined a dependency for
// a bounded, testable job before — ustar by hand in `export.ts`, DSSE without
// cosign, `setTimeout` without node-cron — and the job here is bounded twice
// over: it validates against THREE PINNED FILES, whose complete keyword set is
// enumerable and enumerated below. What makes that safe rather than merely
// smaller is the failure direction:
//
//     AN UNRECOGNISED KEYWORD IS AN EXIT, NOT A PASS.
//
// A validator that skips what it does not implement reports "schema-valid"
// while having checked less than it claimed — a green that does not survive
// interrogation, which is the one bug this product may not ship. So the
// supported set is closed, every keyword in a pinned schema must be in it, and
// a schema that grows one fails the pin check before it can fail silently.
//
// If a future target needs a keyword this does not implement, the honest moves
// are to implement it or to take the ajv dependency deliberately. Both are
// reviewed changes. Neither is "it passed".

export const FEDRAMP_SCHEMA_DIR = join("docs", "context", "fedramp-schemas");

/** The stamp every one of the three pinned files shares. */
export const FEDRAMP_SCHEMA_DATE = "2026-06-24";

export interface SchemaPin {
  /** the file's own `$schemaVersion` — semver'd per schema, not per set */
  schemaVersion: string;
  /** sha256 of the vendored bytes — the draft-republication guard */
  sha256: string;
}

/**
 * Keyed by filename, because the file IS what carries `$schemaVersion`.
 * Bumping one means re-reading a diff, never refreshing a file.
 */
export const FEDRAMP_SCHEMA_PINS: Readonly<Record<string, SchemaPin>> = {
  "fedramp-certification-package-overview-schema-2026-06-24.json": {
    schemaVersion: "0.1.4",
    sha256: "0fa563b23e48f8f670ac8fe3d87ac49bb7099f68e1e54a17ba03424e787d60e0",
  },
  "fedramp-ongoing-certification-report-schema-2026-06-24.json": {
    schemaVersion: "0.2.0",
    sha256: "3c2209b87509516d33f6e4651b432fbc62d38578c389cd3f4ef47562196708ff",
  },
  "fedramp-common-definitions-schema-2026-06-24.json": {
    schemaVersion: "0.3.0",
    sha256: "1d2468ace4f2e9f08471ec2dae38e9f7847b04cd12ac54b61b0923319d16622d",
  },
};

export const PACKAGE_OVERVIEW_SCHEMA =
  "fedramp-certification-package-overview-schema-2026-06-24.json";
export const OCR_SCHEMA = "fedramp-ongoing-certification-report-schema-2026-06-24.json";
export const COMMON_SCHEMA = "fedramp-common-definitions-schema-2026-06-24.json";

type Json = unknown;
type SchemaNode = Record<string, Json>;

/**
 * Every keyword the three pinned schemas use, split by what we do with it.
 * Derived from the files, not from memory: the enumeration is a test.
 */
const ASSERTIONS = new Set([
  "type",
  "required",
  "properties",
  "items",
  "enum",
  "const",
  "pattern",
  "format",
  "minItems",
  "maxItems",
  "allOf",
  "contains",
  "if",
  "then",
  "$ref",
]);

/**
 * Keywords that assert nothing. Listed rather than ignored-by-default, so a
 * new keyword lands in neither set and trips the closed-set check.
 */
const ANNOTATIONS = new Set([
  "$schema",
  "$id",
  "$schemaVersion",
  "$defs",
  "title",
  "description",
  "examples",
]);

const FORMATS: Record<string, (value: string) => boolean> = {
  // a calendar date, and a real one: 2026-02-30 matches the shape and is not a day
  date: (v) => {
    if (!/^\d{4}-\d{2}-\d{2}$/.test(v)) return false;
    const [y, m, d] = v.split("-").map(Number) as [number, number, number];
    const probe = new Date(Date.UTC(y, m - 1, d));
    return (
      probe.getUTCFullYear() === y && probe.getUTCMonth() === m - 1 && probe.getUTCDate() === d
    );
  },
  "date-time": (v) => /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/.test(v)
    && !Number.isNaN(Date.parse(v)),
  // absolute only: a relative reference in a published document is a dead link
  uri: (v) => {
    try {
      return new URL(v).protocol.length > 1;
    } catch {
      return false;
    }
  },
  email: (v) => /^[^\s@]+@[^\s@.]+(\.[^\s@.]+)+$/.test(v),
};

export interface LoadedSchema {
  filename: string;
  schema: SchemaNode;
  /** the sibling schemas a `$ref` may reach, keyed by `$id` */
  registry: Map<string, SchemaNode>;
}

/**
 * Read one pinned schema and its `$ref` neighbours, refusing on any pin
 * mismatch and on any keyword outside the closed set above.
 *
 * `repoRoot` is passed rather than derived so a test can point at a fixture
 * tree — the same shape `loadRecipes` takes, for the same reason.
 */
export async function loadPinnedSchema(
  repoRoot: string,
  filename: string,
): Promise<LoadedSchema> {
  const registry = new Map<string, SchemaNode>();
  const wanted = [filename, COMMON_SCHEMA];
  let primary: SchemaNode | undefined;

  for (const name of wanted) {
    const pin = FEDRAMP_SCHEMA_PINS[name];
    if (pin === undefined) {
      throw new Error(
        `${name} is not a pinned FedRAMP schema — a validation target with no pin is a target nobody is checking`,
      );
    }
    const path = join(repoRoot, FEDRAMP_SCHEMA_DIR, name);
    const bytes = await readFile(path);
    const digest = createHash("sha256").update(bytes).digest("hex");
    if (digest !== pin.sha256) {
      throw new Error(
        `${name} does not match its pinned bytes (sha256 ${digest.slice(0, 16)}… vs pinned ${pin.sha256.slice(0, 16)}…) — a draft schema was republished or the file was edited; re-read the diff and bump the pin in fedramp-schemas.ts deliberately`,
      );
    }
    const parsed = JSON.parse(bytes.toString("utf8")) as SchemaNode;
    const declared = parsed["$schemaVersion"];
    if (declared !== pin.schemaVersion) {
      throw new Error(
        `${name} declares $schemaVersion ${String(declared)} but this checkout is pinned to ${pin.schemaVersion} — bumping it is a reviewed change`,
      );
    }
    assertClosedKeywordSet(parsed, name);
    const id = parsed["$id"];
    if (typeof id === "string") registry.set(id, parsed);
    if (name === filename) primary = parsed;
  }

  if (primary === undefined) throw new Error(`${filename} did not load`);
  return { filename, schema: primary, registry };
}

/**
 * Walk a pinned schema and refuse on the first keyword we neither assert on nor
 * knowingly ignore. This is the guard that makes a hand-rolled validator
 * honest: the closed set is only closed if something closes it.
 */
function assertClosedKeywordSet(node: Json, filename: string, path = "#"): void {
  if (Array.isArray(node)) {
    node.forEach((child, i) => assertClosedKeywordSet(child, filename, `${path}/${i}`));
    return;
  }
  if (node === null || typeof node !== "object") return;
  for (const [key, value] of Object.entries(node as SchemaNode)) {
    if (!ASSERTIONS.has(key) && !ANNOTATIONS.has(key)) {
      throw new Error(
        `${filename} uses JSON Schema keyword "${key}" at ${path}, which this validator does not implement — an unrecognised keyword is refused rather than skipped, because skipping it would report conformance nobody checked. Implement it in fedramp-schemas.ts, or take the ajv dependency deliberately`,
      );
    }
    if (key === "properties" || key === "$defs") {
      for (const [prop, sub] of Object.entries(value as SchemaNode)) {
        assertClosedKeywordSet(sub, filename, `${path}/${key}/${prop}`);
      }
    } else if (key === "examples") {
      // instance values, not schemas — nothing under here is a keyword
    } else if (key === "enum" || key === "const" || key === "required") {
      // instance values too
    } else {
      assertClosedKeywordSet(value, filename, `${path}/${key}`);
    }
  }
}

export interface SchemaViolation {
  /** JSON Pointer into the INSTANCE, so a reader can find the field */
  path: string;
  message: string;
}

/**
 * Validate an instance against a loaded pinned schema. Returns every violation
 * rather than the first: a document with four missing fields should cost one
 * run to fix, not four.
 */
export function validateAgainst(loaded: LoadedSchema, instance: Json): SchemaViolation[] {
  const out: SchemaViolation[] = [];
  check(loaded.schema, instance, "", { loaded, root: loaded.schema }, out);
  return out;
}

/**
 * Where a `$ref` resolves FROM. `root` is the enclosing DOCUMENT, not the
 * enclosing node — `#/$defs/repository` is rooted at the schema file that
 * contains it, and resolving it against whatever subschema happened to carry
 * the `$ref` would walk into a node with no `$defs` and find nothing. A
 * cross-document `$ref` re-roots to the document it names, so a local pointer
 * inside that document then resolves there.
 */
interface RefScope {
  loaded: LoadedSchema;
  root: SchemaNode;
}

function resolveRef(ref: string, scope: RefScope): { schema: SchemaNode; scope: RefScope } {
  const hash = ref.indexOf("#");
  const base = hash === -1 ? ref : ref.slice(0, hash);
  const pointer = hash === -1 ? "" : ref.slice(hash + 1);
  const root = base === "" ? scope.root : scope.loaded.registry.get(base);
  if (root === undefined) {
    throw new Error(
      `$ref "${ref}" names a schema this checkout did not load — the pinned set is ${[...scope.loaded.registry.keys()].join(", ")}`,
    );
  }
  let node: Json = root;
  for (const rawSegment of pointer.split("/")) {
    if (rawSegment === "") continue;
    const segment = rawSegment.replaceAll("~1", "/").replaceAll("~0", "~");
    if (node === null || typeof node !== "object") {
      throw new Error(`$ref "${ref}" walks through a non-object at "${segment}"`);
    }
    node = (node as SchemaNode)[segment];
  }
  if (node === null || typeof node !== "object") {
    throw new Error(`$ref "${ref}" resolves to nothing`);
  }
  return { schema: node as SchemaNode, scope: { loaded: scope.loaded, root } };
}

function typeOf(value: Json): string {
  if (value === null) return "null";
  if (Array.isArray(value)) return "array";
  if (typeof value === "number") return Number.isInteger(value) ? "integer" : "number";
  return typeof value;
}

function matchesType(declared: string, value: Json): boolean {
  const actual = typeOf(value);
  if (declared === "number") return actual === "number" || actual === "integer";
  return declared === actual;
}

/** True when `value` satisfies `schema` — the `contains`/`if` predicate form. */
function satisfies(schema: SchemaNode, value: Json, scope: RefScope): boolean {
  const probe: SchemaViolation[] = [];
  check(schema, value, "", scope, probe);
  return probe.length === 0;
}

function check(
  schema: SchemaNode,
  value: Json,
  path: string,
  scope: RefScope,
  out: SchemaViolation[],
): void {
  const ref = schema["$ref"];
  if (typeof ref === "string") {
    const resolved = resolveRef(ref, scope);
    check(resolved.schema, value, path, resolved.scope, out);
    // a $ref alongside siblings is 2020-12 legal; keep checking them
  }

  const declaredType = schema["type"];
  if (typeof declaredType === "string" && !matchesType(declaredType, value)) {
    out.push({ path, message: `expected ${declaredType}, got ${typeOf(value)}` });
    return; // every keyword below assumes the type held
  }

  const enumValues = schema["enum"];
  if (Array.isArray(enumValues)) {
    const hit = enumValues.some((candidate) => JSON.stringify(candidate) === JSON.stringify(value));
    if (!hit) {
      out.push({
        path,
        message: `${JSON.stringify(value)} is not one of ${enumValues.map((v) => JSON.stringify(v)).join(", ")}`,
      });
    }
  }

  if ("const" in schema && JSON.stringify(schema["const"]) !== JSON.stringify(value)) {
    out.push({ path, message: `must equal ${JSON.stringify(schema["const"])}` });
  }

  if (typeof value === "string") {
    const pattern = schema["pattern"];
    if (typeof pattern === "string" && !new RegExp(pattern).test(value)) {
      out.push({ path, message: `does not match pattern ${pattern}` });
    }
    const format = schema["format"];
    if (typeof format === "string") {
      const test = FORMATS[format];
      if (test === undefined) {
        throw new Error(
          `pinned schema asks for format "${format}", which this validator does not implement — refused rather than skipped`,
        );
      }
      if (!test(value)) out.push({ path, message: `is not a valid ${format}` });
    }
  }

  if (Array.isArray(value)) {
    const minItems = schema["minItems"];
    if (typeof minItems === "number" && value.length < minItems) {
      out.push({ path, message: `needs at least ${minItems} item(s), has ${value.length}` });
    }
    const maxItems = schema["maxItems"];
    if (typeof maxItems === "number" && value.length > maxItems) {
      out.push({ path, message: `allows at most ${maxItems} item(s), has ${value.length}` });
    }
    const items = schema["items"];
    if (items !== null && typeof items === "object" && !Array.isArray(items)) {
      value.forEach((item, i) =>
        check(items as SchemaNode, item, `${path}/${i}`, scope, out),
      );
    }
    const contains = schema["contains"];
    if (contains !== null && typeof contains === "object" && !Array.isArray(contains)) {
      if (!value.some((item) => satisfies(contains as SchemaNode, item, scope))) {
        out.push({
          path,
          message: `no item satisfies the required "contains" shape (${describe(contains as SchemaNode)})`,
        });
      }
    }
  }

  if (value !== null && typeof value === "object" && !Array.isArray(value)) {
    const object = value as Record<string, Json>;
    const required = schema["required"];
    if (Array.isArray(required)) {
      for (const key of required) {
        if (typeof key === "string" && object[key] === undefined) {
          out.push({ path: `${path}/${key}`, message: "required field is absent" });
        }
      }
    }
    const properties = schema["properties"];
    if (properties !== null && typeof properties === "object") {
      for (const [key, sub] of Object.entries(properties as SchemaNode)) {
        if (object[key] === undefined) continue; // absence is `required`'s business
        check(sub as SchemaNode, object[key], `${path}/${key}`, scope, out);
      }
    }
  }

  const allOf = schema["allOf"];
  if (Array.isArray(allOf)) {
    for (const sub of allOf) check(sub as SchemaNode, value, path, scope, out);
  }

  const ifSchema = schema["if"];
  const thenSchema = schema["then"];
  if (
    ifSchema !== null &&
    typeof ifSchema === "object" &&
    thenSchema !== null &&
    typeof thenSchema === "object"
  ) {
    if (satisfies(ifSchema as SchemaNode, value, scope)) {
      check(thenSchema as SchemaNode, value, path, scope, out);
    }
  }
}

/** A one-line rendering of a `contains` predicate, for the violation message. */
function describe(schema: SchemaNode): string {
  const properties = schema["properties"];
  if (properties !== null && typeof properties === "object") {
    const parts = Object.entries(properties as SchemaNode).map(([key, sub]) => {
      const node = sub as SchemaNode;
      return "const" in node ? `${key}=${JSON.stringify(node["const"])}` : key;
    });
    if (parts.length > 0) return parts.join(", ");
  }
  return JSON.stringify(schema);
}
