import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";

// The pinned Prowler KSI framework (P3-0, docs/RESEARCH-PROWLER-INGEST.md
// §4d/§6) — the FIFTH pin, beside the dataset, the per-slice overlays, the
// pipeline plane and the four FedRAMP schemas.
//
// WHAT THIS IS. Prowler publishes a compliance framework mapping each of the
// 46 FedRAMP 20x Key Security Indicators to the check ids it runs per cloud
// provider. rampscan ingests a Prowler scan as an `aws-ingested` source (§4a),
// and this file is the join table that ingest resolves against.
//
// WHY IT IS VENDORED RATHER THAN COPIED INTO A TABLE OF OUR OWN. The tempting
// artifact was a rampscan-owned check→KSI map, and that is the `labels.json`
// mistake: P1 deleted `recipes/aws-actions/labels.json` because upstream had
// begun publishing the same mapping, and a hand-kept row that looked current
// was one upstream renumbering away from naming the wrong thing
// (`aws-labels.ts:1-19`). Prowler owns this mapping. rampscan keeps the FILE,
// pinned, and re-derives every number it states from it.
//
// WHY THE PIN IS ON THE BYTES. The framework's own `version` says
// `2026.07.14.01` while this checkout pins the dataset at `2026.09.13.02`;
// that is a non-event for the KSIs, because P1 established that the 46
// indicators, their statements and their control mappings are byte-identical
// across those two dataset versions — and the golden test in
// `test/prowler-framework.test.ts` checks it both ways rather than trusting
// it. What `version` cannot do is notice a republication, and there is not
// even a release to lean on: no published Prowler release ships this file
// (5.42.0 predates its only commit by three days, §10f), so the artifact is
// `master` at a commit. A commit plus a sha256 is what makes a change to it
// arrive as a refusal to be read instead of as a quiet new mapping.
//
// WHY UNKNOWN KEYS ARE REFUSED. Same rule as `fedramp-schemas.ts`: an
// unrecognised key is an exit, not a pass. A reader that drops a field it has
// never seen turns "re-read the diff when the pin moves" into "re-stamp the
// pin", and the fields here are load-bearing — `ClassApplicability` is a
// class-b denominator (§13.7) and `checks` is the mapping itself.

/** where the vendored framework lives, relative to the repo root */
export const PROWLER_FRAMEWORK_DIR = join("docs", "context", "prowler");
export const PROWLER_FRAMEWORK_FILE = "fedramp_20x_ksi_2026.json";

/** the reviewed record of what the framework leaves uncovered (§4d) */
export const PROWLER_UNCOVERED_PATH = join("recipes", "prowler", "uncovered.json");

/**
 * The pin. `commit` rather than a release tag because no release carries the
 * file; `sha256` and `bytes` because a draft artifact on a moving branch can
 * be rewritten under an unchanged `version`, which is exactly the class of
 * move `packages/dataset/src/pins.ts` exists to complain about.
 */
export const PROWLER_FRAMEWORK_PIN = {
  repository: "https://github.com/prowler-cloud/prowler",
  /** the path inside that repository — one cross-provider file, not five */
  path: "prowler/compliance/fedramp_20x_ksi_2026.json",
  commit: "1b228d590b5faa92d9e0bbbab7d6c2c38d3cfeda",
  committed: "2026-09-14",
  /** the file's own `framework` and `version` fields, checked on load */
  framework: "FedRAMP-20x-KSI",
  version: "2026.07.14.01",
  sha256: "cc1a5fa8c88ee4e327c84ae871b8e51553b4d0c614193a25a0d5490449a8e766",
  bytes: 89892,
} as const;

/**
 * The providers the framework maps checks for. CLOSED, because a sixth one is
 * not a new column — §4a scopes P3 to AWS inside the existing `aws-ingested`
 * source precisely so that a second provider is a reviewed change with its own
 * `MethodSource` and its own `automated` decision (`method.ts:144-149`), never
 * a key that appeared in a file and started deriving methods.
 */
export const PROWLER_PROVIDERS = ["aws", "azure", "gcp", "kubernetes", "m365"] as const;
export type ProwlerProvider = (typeof PROWLER_PROVIDERS)[number];

/**
 * The two values `ClassApplicability` takes, interpreted. CLOSED for the
 * reason the provider set is: this field is a denominator. The 41/5 split is
 * the same five indicators the pinned rules make optional at class b, and a
 * third value would change what a class-b meter divides by.
 *
 * Note what is NOT here: class A. The framework states the class-A subset in
 * prose — "Class A authorizations mandate a subset of seven KSIs via
 * FRC-CLA-MFR" — and in no field of any row, so class A is not derivable from
 * this file and nothing here pretends otherwise. Reading the silence would be
 * the `varies_by_class` trap of P2-0 §2a, one file over.
 */
const CLASS_APPLICABILITY: Readonly<Record<string, ClassApplicability>> = {
  "Required for Classes B and C": "required-b-and-c",
  "Optional for Class B, required for Class C": "optional-b-required-c",
};
export type ClassApplicability = "required-b-and-c" | "optional-b-required-c";

/**
 * One row of a requirement's `config_requirements`: the framework's own
 * statement of the scan-config threshold a check must have been run under for
 * its result to mean what the KSI asks. rampscan does not evaluate these yet —
 * §10d's effective-status rule is what P3-3 reads — so the KEYS are closed and
 * the `operator` VOCABULARY is not. Closing a vocabulary nothing interprets
 * would be ceremony: the refusal earns its place where a claim rests on it.
 */
export interface ProwlerConfigRequirement {
  check: string;
  configKey: string;
  operator: string;
  value: unknown;
  provider: ProwlerProvider;
}

export interface ProwlerRequirement {
  /** the KSI id, e.g. `KSI-CED-RAT` — must resolve at rampscan's dataset pin */
  id: string;
  name: string;
  description: string;
  /** `KSI-CED: Cybersecurity Education` — the framework's own theme label */
  theme: string;
  /** the NIST SP 800-53 control ids, as one comma-separated string upstream */
  nistControls: string;
  classApplicability: ClassApplicability;
  /** check ids per provider, in upstream's order; every provider key present */
  checks: Readonly<Record<ProwlerProvider, readonly string[]>>;
  /**
   * Present on 24 of the 46 rows, and EMPTY on four of those. An empty array
   * is a row that declares no threshold, which is not the same as a row that
   * declares nothing — `undefined` and `[]` are kept apart here so no consumer
   * tests truthiness and counts 24 as 20.
   */
  configRequirements?: readonly ProwlerConfigRequirement[];
}

export interface ProwlerKsiFramework {
  framework: string;
  name: string;
  version: string;
  description: string;
  requirements: readonly ProwlerRequirement[];
}

class ProwlerFrameworkError extends Error {}

const REQUIREMENT_KEYS = new Set([
  "id",
  "name",
  "description",
  "attributes",
  "checks",
  "config_requirements",
]);
const ATTRIBUTE_KEYS = new Set(["Theme", "NISTControls", "ClassApplicability"]);
const CONFIG_KEYS = new Set(["Check", "ConfigKey", "Operator", "Value", "Provider"]);
const TOP_LEVEL_KEYS = new Set([
  "framework",
  "name",
  "version",
  "description",
  "icon",
  "attributes_metadata",
  "outputs",
  "requirements",
]);

function closedKeys(node: unknown, allowed: ReadonlySet<string>, at: string, origin: string): void {
  for (const key of Object.keys(node as Record<string, unknown>)) {
    if (!allowed.has(key)) {
      throw new ProwlerFrameworkError(
        `${origin}: ${at} carries "${key}", which this reader has never read — an unrecognised key is refused rather than dropped, because dropping it turns re-pinning into re-stamping. Read what upstream added, then teach prowler-framework.ts about it deliberately`,
      );
    }
  }
}

function str(node: Record<string, unknown>, key: string, at: string, origin: string): string {
  const v = node[key];
  if (typeof v !== "string" || v.length === 0) {
    throw new ProwlerFrameworkError(`${origin}: ${at} has no ${key}`);
  }
  return v;
}

/**
 * Parse a Prowler KSI framework document, refusing anything it cannot read.
 *
 * Split from the loader so a test can plant a defect into the real file's
 * shape without a pin to satisfy — the same reason `loadPinnedSchema` takes a
 * `repoRoot`.
 */
export function parseProwlerKsiFramework(doc: unknown, origin: string): ProwlerKsiFramework {
  if (doc === null || typeof doc !== "object" || Array.isArray(doc)) {
    throw new ProwlerFrameworkError(`${origin}: not a Prowler compliance framework document`);
  }
  const root = doc as Record<string, unknown>;
  closedKeys(root, TOP_LEVEL_KEYS, "the document", origin);

  // The file publishes its OWN enum for ClassApplicability in
  // `attributes_metadata`. Checking our interpreted set against it means a
  // third value arrives as a refusal at the metadata, one level before a row
  // uses it — and it means the two are never silently out of step.
  const metadata = root["attributes_metadata"];
  if (!Array.isArray(metadata)) {
    throw new ProwlerFrameworkError(`${origin}: attributes_metadata is not an array`);
  }
  const declared = metadata.find(
    (m) => (m as Record<string, unknown>)["key"] === "ClassApplicability",
  ) as Record<string, unknown> | undefined;
  const declaredEnum = declared?.["enum"];
  if (!Array.isArray(declaredEnum)) {
    throw new ProwlerFrameworkError(
      `${origin}: attributes_metadata states no enum for ClassApplicability — the field is a class-b denominator and an unstated vocabulary is one nobody is checking`,
    );
  }
  for (const value of declaredEnum) {
    if (typeof value !== "string" || CLASS_APPLICABILITY[value] === undefined) {
      throw new ProwlerFrameworkError(
        `${origin}: attributes_metadata declares ClassApplicability value "${String(value)}", which this reader cannot interpret — it decides which indicators a class owes, so a new value is read by a person before it moves a denominator`,
      );
    }
  }

  const rows = root["requirements"];
  if (!Array.isArray(rows)) {
    throw new ProwlerFrameworkError(`${origin}: requirements is not an array`);
  }

  const requirements = rows.map((row, i): ProwlerRequirement => {
    const at = `requirements[${i}]`;
    if (row === null || typeof row !== "object" || Array.isArray(row)) {
      throw new ProwlerFrameworkError(`${origin}: ${at} is not an object`);
    }
    const r = row as Record<string, unknown>;
    closedKeys(r, REQUIREMENT_KEYS, at, origin);
    const id = str(r, "id", at, origin);

    const attributes = r["attributes"];
    if (attributes === null || typeof attributes !== "object" || Array.isArray(attributes)) {
      throw new ProwlerFrameworkError(`${origin}: ${id} has no attributes`);
    }
    closedKeys(attributes, ATTRIBUTE_KEYS, `${id}.attributes`, origin);
    const a = attributes as Record<string, unknown>;
    const rawClass = str(a, "ClassApplicability", `${id}.attributes`, origin);
    const classApplicability = CLASS_APPLICABILITY[rawClass];
    if (classApplicability === undefined) {
      throw new ProwlerFrameworkError(
        `${origin}: ${id} states ClassApplicability "${rawClass}", which this reader cannot interpret — see prowler-framework.ts's CLASS_APPLICABILITY`,
      );
    }

    const rawChecks = r["checks"];
    if (rawChecks === null || typeof rawChecks !== "object" || Array.isArray(rawChecks)) {
      throw new ProwlerFrameworkError(`${origin}: ${id} has no checks`);
    }
    closedKeys(rawChecks, new Set(PROWLER_PROVIDERS), `${id}.checks`, origin);
    const checks = {} as Record<ProwlerProvider, readonly string[]>;
    for (const provider of PROWLER_PROVIDERS) {
      const list = (rawChecks as Record<string, unknown>)[provider];
      if (!Array.isArray(list) || list.some((c) => typeof c !== "string")) {
        throw new ProwlerFrameworkError(
          `${origin}: ${id}.checks.${provider} is not a list of check ids — a provider the framework stops carrying is a mapping that silently empties, so it is refused rather than defaulted to none`,
        );
      }
      checks[provider] = list as string[];
    }

    const rawConfig = r["config_requirements"];
    let configRequirements: ProwlerConfigRequirement[] | undefined;
    if (rawConfig !== undefined) {
      if (!Array.isArray(rawConfig)) {
        throw new ProwlerFrameworkError(`${origin}: ${id}.config_requirements is not an array`);
      }
      configRequirements = rawConfig.map((entry, j): ProwlerConfigRequirement => {
        const where = `${id}.config_requirements[${j}]`;
        if (entry === null || typeof entry !== "object" || Array.isArray(entry)) {
          throw new ProwlerFrameworkError(`${origin}: ${where} is not an object`);
        }
        const c = entry as Record<string, unknown>;
        closedKeys(c, CONFIG_KEYS, where, origin);
        const provider = str(c, "Provider", where, origin);
        if (!(PROWLER_PROVIDERS as readonly string[]).includes(provider)) {
          throw new ProwlerFrameworkError(`${origin}: ${where} names provider "${provider}"`);
        }
        return {
          check: str(c, "Check", where, origin),
          configKey: str(c, "ConfigKey", where, origin),
          operator: str(c, "Operator", where, origin),
          value: c["Value"],
          provider: provider as ProwlerProvider,
        };
      });
    }

    return {
      id,
      name: str(r, "name", at, origin),
      description: str(r, "description", at, origin),
      theme: str(a, "Theme", `${id}.attributes`, origin),
      nistControls: str(a, "NISTControls", `${id}.attributes`, origin),
      classApplicability,
      checks,
      ...(configRequirements === undefined ? {} : { configRequirements }),
    };
  });

  const seen = new Set<string>();
  for (const r of requirements) {
    if (seen.has(r.id)) {
      throw new ProwlerFrameworkError(`${origin}: ${r.id} appears twice`);
    }
    seen.add(r.id);
  }

  return {
    framework: str(root, "framework", "the document", origin),
    name: str(root, "name", "the document", origin),
    version: str(root, "version", "the document", origin),
    description: str(root, "description", "the document", origin),
    requirements,
  };
}

/**
 * Read the vendored framework at its pin, refusing on any mismatch.
 *
 * `repoRoot` is passed rather than derived for the reason `loadPinnedSchema`
 * takes it: a test points at a planted tree and gets the real refusals.
 */
export async function loadPinnedProwlerFramework(repoRoot: string): Promise<ProwlerKsiFramework> {
  const path = join(repoRoot, PROWLER_FRAMEWORK_DIR, PROWLER_FRAMEWORK_FILE);
  let bytes: Buffer;
  try {
    bytes = await readFile(path);
  } catch {
    throw new ProwlerFrameworkError(
      `${PROWLER_FRAMEWORK_FILE} is not vendored at ${PROWLER_FRAMEWORK_DIR} — the framework is pinned, not fetched, so an ingest never depends on a network round trip to decide what a check means`,
    );
  }
  const digest = createHash("sha256").update(bytes).digest("hex");
  if (digest !== PROWLER_FRAMEWORK_PIN.sha256) {
    throw new ProwlerFrameworkError(
      `${PROWLER_FRAMEWORK_FILE} does not match its pinned bytes (sha256 ${digest.slice(0, 16)}… vs pinned ${PROWLER_FRAMEWORK_PIN.sha256.slice(0, 16)}…) — the framework was republished or the file was edited. Re-read the diff, re-read recipes/prowler/uncovered.json against it, and bump the pin in prowler-framework.ts deliberately`,
    );
  }
  const parsed = parseProwlerKsiFramework(
    JSON.parse(bytes.toString("utf8")),
    PROWLER_FRAMEWORK_FILE,
  );
  if (parsed.framework !== PROWLER_FRAMEWORK_PIN.framework) {
    throw new ProwlerFrameworkError(
      `${PROWLER_FRAMEWORK_FILE} declares framework ${parsed.framework}, pinned ${PROWLER_FRAMEWORK_PIN.framework} — Prowler ships more than one FedRAMP framework and they are pinned to different dataset versions (§2e)`,
    );
  }
  if (parsed.version !== PROWLER_FRAMEWORK_PIN.version) {
    throw new ProwlerFrameworkError(
      `${PROWLER_FRAMEWORK_FILE} declares version ${parsed.version}, pinned ${PROWLER_FRAMEWORK_PIN.version} — bumping it is a reviewed change`,
    );
  }
  return parsed;
}

/** the check ids this requirement maps on one provider, in upstream's order */
export function checksFor(
  requirement: ProwlerRequirement,
  provider: ProwlerProvider,
): readonly string[] {
  return requirement.checks[provider];
}

/**
 * The indicators the framework maps no check to — on one provider, or on every
 * provider when none is named. Ascending, which is the order the reviewed
 * record is kept in.
 *
 * At this pin the two answers are the same thirteen: AWS covers every KSI any
 * provider covers. That is a fact about the artifact, not a rule, which is why
 * the golden test asserts it rather than the code assuming it.
 */
export function uncoveredKsis(
  fw: ProwlerKsiFramework,
  provider?: ProwlerProvider,
): readonly string[] {
  const providers = provider === undefined ? PROWLER_PROVIDERS : [provider];
  return fw.requirements
    .filter((r) => providers.every((p) => r.checks[p].length === 0))
    .map((r) => r.id)
    .sort();
}

/** the indicators the framework states are optional at class b, ascending */
export function optionalAtClassB(fw: ProwlerKsiFramework): readonly string[] {
  return fw.requirements
    .filter((r) => r.classApplicability === "optional-b-required-c")
    .map((r) => r.id)
    .sort();
}

/**
 * The both-ways join check (§4d), in the place the adapter calls it rather
 * than only in a test.
 *
 * Both directions are refusals and they fail differently on purpose. An id in
 * the framework that rampscan cannot resolve would mint a method for an
 * indicator off the 46-row board; an indicator in the catalog that the
 * framework does not carry is one the adapter can never reach, which is a
 * coverage claim quietly capped below the board. §2e establishes that at this
 * pin neither happens — this is what keeps that true rather than remembered.
 */
export function assertFrameworkMatchesCatalog(
  fw: ProwlerKsiFramework,
  catalogKsiIds: readonly string[],
): void {
  const catalog = new Set(catalogKsiIds);
  const framework = new Set(fw.requirements.map((r) => r.id));
  const unresolvable = [...framework].filter((id) => !catalog.has(id)).sort();
  if (unresolvable.length > 0) {
    throw new ProwlerFrameworkError(
      `the pinned Prowler framework maps ${unresolvable.length} indicator(s) this checkout's dataset pin does not have — ${unresolvable.join(", ")}. Ingesting them would derive methods for rows that are not on the board; re-read both pins before moving either`,
    );
  }
  const unreachable = [...catalog].filter((id) => !framework.has(id)).sort();
  if (unreachable.length > 0) {
    throw new ProwlerFrameworkError(
      `${unreachable.length} indicator(s) in the pinned catalog are absent from the Prowler framework — ${unreachable.join(", ")}. A Prowler ingest could never reach them, so the gap is named here rather than read later as coverage nobody claimed`,
    );
  }
}
