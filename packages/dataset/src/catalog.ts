import { readFile } from "node:fs/promises";
import { basename } from "node:path";
import { z } from "zod";
import { loadSlice } from "./client.js";
import { DatasetVersionMismatchError } from "./client.js";

/**
 * The KSI catalog port (SPEC §12.4) — the owed side's single surface: 46 KSIs
 * × statements × controls crosswalk × the five default artifacts, plus floors
 * and windows as data. Loadable from either of two sources at one pin:
 *
 *   Path A — `loadKsiCatalogFromSlices`: the ramprules derived-slice snapshot,
 *            the same directory `loadLocalDataset` reads.
 *   Path B — `loadKsiCatalogFromRules`: `fedramp-consolidated-rules.json`
 *            direct, the canonical upstream ramprules itself derives from.
 *
 * One pin covers both: ramprules' `dataset_version` IS the FedRAMP/rules
 * dataset version, so `DEFAULT_DATASET_PIN` guards Path B with no fourth pin
 * (§12.4 rule 1). Both loaders canonicalize to the same value, proven by the
 * equivalence test; `assertCatalogsEquivalent` is the loader-side arm of §12.4
 * rule 2 — two paths disagreeing on an owed fact at the same pin is a broken
 * port, not a resolvable preference.
 *
 * Owed NUMBERS are sourced from the pinned JSON, never typed into logic
 * (plan Q1.2). Where a source carries a number only as prose — the rules
 * JSON's method floors ("at least 2 automated methods"), the history floors
 * ("over at least the past 6 months"), the non-machine window ("once every
 * 3 months") — a deliberately narrow parser extracts it and HARD-FAILS when
 * a MUST/SHOULD statement stops matching, so a re-pin that rewords an owed
 * sentence refuses to run rather than silently owing nothing.
 */

/**
 * All four 20x certification classes. Deliberately wider than core's
 * `CertClass` ("b" | "c"): §12.3 makes class an explicit config value the
 * owed-side and reporting layers compute against for ALL four classes —
 * `frontier --class d` is a legitimate what-if — while the scheduler's refusal
 * of class d stands until RFC-0033 or a cadence derivation settles §11 q6.
 */
export type OfferingClass = "a" | "b" | "c" | "d";
export const OFFERING_CLASSES: readonly OfferingClass[] = ["a", "b", "c", "d"];

export interface KsiTheme {
  /** short key, e.g. "CED" */
  key: string;
  name: string;
}

export interface KsiEntry {
  /** indicator id, e.g. "KSI-CED-RAT" — the 46-row board's row key */
  id: string;
  themeKey: string;
  name: string;
  /**
   * The indicator's statement, or null where the rules vary it by class
   * (five indicators at this pin: optional wording at class b, mandatory
   * at c — KSI-CNA-EIS, KSI-MLA-ALA, KSI-SVC-PRR, KSI-SVC-RUD, KSI-SVC-VCM).
   * Null is the honest shared surface — the derived slices do not carry the
   * class variants, so a flat string here would be one path guessing. The
   * variants live in the rules JSON's `varies_by_class` until ramprules
   * serves them, at which point this grows a per-class field in a reviewed
   * change, on both paths at once.
   */
  statement: string | null;
  /** canonical control ids this KSI reaches, ascending */
  controls: readonly string[];
}

/**
 * Which indicators a class does not oblige — the R0.2 denominator fix
 * (SPEC §13.7).
 *
 * Five indicators carry `varies_by_class` with a class-`b` statement that
 * begins `**Optional:**` and a class-`c` statement that does not, so class B
 * owes 41 of the 46 and every meter that divides by 46 at class b overstates
 * what a provider is on the hook for.
 *
 * Read, never inferred, in three parts (§13.7):
 *   1. the prefix at the START of the class statement is the only signal the
 *      pinned JSON gives, so it is the only signal read — and the five
 *      indicators carrying it are pinned in a test, so a republication that
 *      changes the vocabulary fails there rather than quietly restoring 46;
 *   2. a class the map does not name is REQUIRED. Under-counting the
 *      denominator flatters the provider and over-counting only ever creates
 *      work, and only one of those errors is found by an assessor;
 *   3. `stated: false` is a source saying nothing, which is NOT the same as a
 *      source saying "none are optional". The ramprules derived slices carry
 *      no class variants at this pin (`checks[].statement` is null for exactly
 *      those five and the variants are not served), so Path A alone cannot
 *      answer and says so. `loadKsiCatalog` is what closes that by loading
 *      both sources — the arrangement §12.4 rule 1 always allowed and R0.2
 *      makes the default.
 */
export type ClassApplicability =
  | {
      stated: true;
      /** ids optional at each class, ascending; the rest are required */
      optionalAt: Readonly<Record<OfferingClass, readonly string[]>>;
      /** which source stated it, for the line a reader sees under a number */
      source: string;
    }
  | { stated: false; reason: string };

/** FRC-CSX-VVK, per class: automated methods owed per KSI. */
export interface MethodFloor {
  requirementId: string;
  force: string;
  /** null where the class owes no number (class a: MAY, unquantified) */
  minPerKsi: number | null;
}

/** FRC-CSX-MOT, per class: months of persistent-validation history owed. */
export interface HistoryFloor {
  requirementId: string;
  force: string;
  /** null where the class owes no number (a and b: unquantified) */
  months: number | null;
}

/** A verification/validation clock: VDR-TFR-MVX per class, VDR-TFR-NMV flat. */
export interface ValidationWindow {
  requirementId: string;
  force: string;
  num: number;
  unit: "days" | "months";
}

export interface KsiCatalog {
  datasetVersion: string;
  /** the 10 themes, ascending by key */
  themes: readonly KsiTheme[];
  /** the 46 indicators, ascending by id */
  ksis: readonly KsiEntry[];
  /** the five KSI default artifacts, in the rules' own order */
  defaultArtifacts: readonly string[];
  floors: Readonly<Record<OfferingClass, MethodFloor>>;
  historyFloors: Readonly<Record<OfferingClass, HistoryFloor>>;
  /**
   * The MVX machine-validation window per class; null for class d because the
   * rules define none (VDR-TFR-MVX has entries for a, b, c only — SPEC §11
   * open question 6, still open under §12.3). A null here is the dataset's
   * honest answer, not a gap in this port.
   */
  windows: Readonly<Record<OfferingClass, ValidationWindow | null>>;
  /** VDR-TFR-NMV: the non-machine validation clock, not class-varied */
  nonMachineWindow: ValidationWindow;
  /**
   * Which indicators each class does not oblige (§13.7). Unlike every other
   * field here this one is NOT an owed fact both paths state — the slices do
   * not carry the class variants — so it is excluded from the §12.4
   * equivalence walk and carries its own `stated` discriminant instead.
   */
  applicability: ClassApplicability;
}

/**
 * An owed number failed to come out of the pinned JSON — a statement a parser
 * relies on stopped matching, a rule id moved, a class went missing. Always a
 * refusal: the alternative is a catalog that silently owes less than the
 * rules say, which is the exact failure class this port exists to prevent.
 */
export class CatalogSourceError extends Error {
  constructor(
    readonly where: string,
    detail: string,
  ) {
    super(
      `KSI catalog cannot be read from ${where}: ${detail}. ` +
        `Refusing to run — an owed fact that fails to parse is owed all the same; ` +
        `re-read the source at the pin before touching the parser.`,
    );
    this.name = "CatalogSourceError";
  }
}

/**
 * The two paths disagreed on an owed fact at the same pin — §12.4 rule 2's
 * hard failure. Names the first differing path so the reader starts at the
 * fact, not at a diff of two 46-row catalogs.
 */
export class CatalogDivergenceError extends Error {
  constructor(readonly at: string, aValue: unknown, bValue: unknown) {
    super(
      `KSI catalog divergence at ${at}: path A has ${JSON.stringify(aValue)}, ` +
        `path B has ${JSON.stringify(bValue)}, at the SAME dataset pin. ` +
        `Refusing to run — this is a broken port, not a resolvable preference (SPEC §12.4).`,
    );
    this.name = "CatalogDivergenceError";
  }
}

// ---------------------------------------------------------------------------
// The narrow prose parsers. Each extracts ONE owed number from ONE sentence
// shape the pinned rules actually use, and refuses on a quantified force it
// cannot read. They are not NLP: a re-pin that rewords a sentence SHOULD fail
// here, loudly, because the reword may have moved the number.

function parseMinMethods(statement: string, force: string, where: string): number | null {
  const m = /at least (\d+) automated methods?/.exec(statement);
  if (m) return Number(m[1]);
  // class a: "MAY implement automated methods" — permission, no floor
  if (force === "MAY") return null;
  throw new CatalogSourceError(
    where,
    `a ${force} method-floor statement carries no "at least N automated methods" phrase: "${statement}"`,
  );
}

function parseHistoryMonths(statement: string, force: string, where: string): number | null {
  const m = /past (\d+) months/.exec(statement);
  if (m) return Number(m[1]);
  // a MAY / b SHOULD "supply historical metrics" — unquantified, no floor
  if (force === "MAY" || force === "SHOULD") return null;
  throw new CatalogSourceError(
    where,
    `a ${force} history-floor statement carries no "past N months" phrase: "${statement}"`,
  );
}

function parseEveryNMonths(statement: string, where: string): number {
  const m = /once every (\d+) months/.exec(statement);
  if (m) return Number(m[1]);
  throw new CatalogSourceError(
    where,
    `the non-machine window statement carries no "once every N months" phrase: "${statement}"`,
  );
}

const WindowUnit = z.enum(["days", "months"]);

function canonicalKsis(ksis: KsiEntry[]): KsiEntry[] {
  return ksis
    .map((k) => ({ ...k, controls: [...k.controls].sort() }))
    .sort((a, b) => a.id.localeCompare(b.id));
}

function canonicalThemes(themes: KsiTheme[]): KsiTheme[] {
  return [...themes].sort((a, b) => a.key.localeCompare(b.key));
}

// ---------------------------------------------------------------------------
// Path A — the ramprules derived slices. Four slices, each already guarded by
// the envelope pin check the client uses; the owed fields read from each are
// facts ramprules itself derives from the rules JSON (§12.4 rule 2), and the
// overlay-derived enrichment beside them (class-overview's authored-method
// counts) has no slot in `KsiCatalog` at all — refusal by structure, rule 3.

const ChecksSlice = z.object({
  checks: z.array(
    z
      .object({
        id: z.string(),
        themeKey: z.string(),
        themeName: z.string(),
        name: z.string(),
        statement: z.string().nullable(),
        controls: z.array(z.string()),
      })
      .passthrough(),
  ),
});

const EvidenceSlice = z.object({
  ksiDefaultArtifacts: z.array(z.string()),
});

const ClassOverviewSlice = z.object({
  classes: z.array(
    z
      .object({
        class: z.enum(["a", "b", "c", "d"]),
        quota: z
          .object({
            requirementId: z.string(),
            force: z.string(),
            statement: z.string(),
            minPerKsi: z.number().nullable(),
          })
          .passthrough(),
        metrics: z
          .object({
            requirementId: z.string(),
            force: z.string(),
            statement: z.string(),
          })
          .passthrough(),
      })
      .passthrough(),
  ),
});

const ObligationsSlice = z.object({
  deadlines: z.array(
    z
      .object({
        requirementId: z.string(),
        force: z.string(),
        class: z.string().nullish(),
        num: z.number(),
        type: z.string(),
      })
      .passthrough(),
  ),
});

const RolesSlice = z.object({
  parties: z.array(
    z
      .object({
        party: z.string(),
        requirements: z.array(
          z
            .object({
              requirementId: z.string(),
              statement: z.string().nullable(),
              force: z.string().nullable(),
            })
            .passthrough(),
        ),
      })
      .passthrough(),
  ),
});

export async function loadKsiCatalogFromSlices(
  derivedDir: string,
  pin: string,
): Promise<KsiCatalog> {
  const checks = ChecksSlice.parse(await loadSlice(derivedDir, "checks.json", pin, {}));
  const evidence = EvidenceSlice.parse(await loadSlice(derivedDir, "evidence.json", pin, {}));
  const overview = ClassOverviewSlice.parse(
    await loadSlice(derivedDir, "class-overview.json", pin, {}),
  );
  const obligations = ObligationsSlice.parse(
    await loadSlice(derivedDir, "obligations.json", pin, {}),
  );
  const roles = RolesSlice.parse(await loadSlice(derivedDir, "roles.json", pin, {}));

  const themesByKey = new Map<string, KsiTheme>();
  const ksis: KsiEntry[] = checks.checks.map((c) => {
    themesByKey.set(c.themeKey, { key: c.themeKey, name: c.themeName });
    return {
      id: c.id,
      themeKey: c.themeKey,
      name: c.name,
      statement: c.statement,
      controls: c.controls,
    };
  });

  const floors = {} as Record<OfferingClass, MethodFloor>;
  const historyFloors = {} as Record<OfferingClass, HistoryFloor>;
  for (const cls of overview.classes) {
    if (cls.quota.requirementId !== "FRC-CSX-VVK") {
      throw new CatalogSourceError(
        "class-overview.json",
        `class ${cls.class} quota cites ${cls.quota.requirementId}, expected FRC-CSX-VVK`,
      );
    }
    if (cls.metrics.requirementId !== "FRC-CSX-MOT") {
      throw new CatalogSourceError(
        "class-overview.json",
        `class ${cls.class} metrics cite ${cls.metrics.requirementId}, expected FRC-CSX-MOT`,
      );
    }
    floors[cls.class] = {
      requirementId: cls.quota.requirementId,
      force: cls.quota.force,
      minPerKsi: cls.quota.minPerKsi,
    };
    historyFloors[cls.class] = {
      requirementId: cls.metrics.requirementId,
      force: cls.metrics.force,
      // the slice carries the months only as the statement's own words, so
      // they are parsed here exactly as Path B parses the rules JSON
      months: parseHistoryMonths(
        cls.metrics.statement,
        cls.metrics.force,
        `class-overview.json (class ${cls.class})`,
      ),
    };
  }
  for (const cls of OFFERING_CLASSES) {
    if (!(cls in floors)) {
      throw new CatalogSourceError("class-overview.json", `no entry for class ${cls}`);
    }
  }

  const windows: Record<OfferingClass, ValidationWindow | null> = {
    a: null,
    b: null,
    c: null,
    d: null,
  };
  for (const deadline of obligations.deadlines) {
    if (deadline.requirementId !== "VDR-TFR-MVX") continue;
    const cls = deadline.class as OfferingClass | undefined;
    if (cls === undefined || !OFFERING_CLASSES.includes(cls)) {
      throw new CatalogSourceError(
        "obligations.json",
        `a VDR-TFR-MVX deadline carries class ${String(deadline.class)}`,
      );
    }
    windows[cls] = {
      requirementId: deadline.requirementId,
      force: deadline.force,
      num: deadline.num,
      unit: WindowUnit.parse(deadline.type),
    };
  }
  if (windows.a === null && windows.b === null && windows.c === null) {
    throw new CatalogSourceError("obligations.json", "no VDR-TFR-MVX deadlines found");
  }

  const providers = roles.parties.find((p) => p.party === "Providers");
  const nmv = providers?.requirements.find((r) => r.requirementId === "VDR-TFR-NMV");
  if (!nmv || nmv.statement === null || nmv.force === null) {
    throw new CatalogSourceError(
      "roles.json",
      "VDR-TFR-NMV missing from the Providers party, or carries no statement",
    );
  }
  const nonMachineWindow: ValidationWindow = {
    requirementId: "VDR-TFR-NMV",
    force: nmv.force,
    num: parseEveryNMonths(nmv.statement, "roles.json (VDR-TFR-NMV)"),
    unit: "months",
  };

  return {
    datasetVersion: pin,
    themes: canonicalThemes([...themesByKey.values()]),
    ksis: canonicalKsis(ksis),
    defaultArtifacts: evidence.ksiDefaultArtifacts,
    floors,
    historyFloors,
    windows,
    nonMachineWindow,
    // Path A cannot answer this and says so rather than returning an empty
    // list, which a reader would take for "none are optional" (§13.7).
    applicability: {
      stated: false,
      reason:
        "the ramprules derived slices carry no class variants at this pin — checks.json nulls the statement for the five class-varying indicators and serves neither variant",
    },
  };
}

// ---------------------------------------------------------------------------
// Path B — fedramp-consolidated-rules.json direct. The canonical upstream:
// the file ramprules itself derives from, vendored under
// docs/context/fedramp-rules/ at the same pin.

// string-keyed on purpose: an enum-keyed record demands every class, and
// VDR-TFR-MVX legitimately carries no class d (SPEC §11 q6)
/**
 * The class-varied form a KSI INDICATOR carries: statements only, no `force`
 * and no timeframe — unlike the FRR floors below, which is why it gets its own
 * shape rather than reusing `VariesByClass`.
 */
const IndicatorVariesByClass = z.record(
  z.string(),
  z.object({ statement: z.string() }).passthrough(),
);

/**
 * The rules JSON marks an indicator a class does not oblige by prefixing that
 * class's statement — there is no `optional` field to read. The prefix is
 * matched at the START of the statement and nowhere else: a sentence that
 * merely mentions the word somewhere in its body is prose, not a marker, and
 * a checker that matched it anywhere would turn a rewording into a silent
 * exemption (§13.7 rule 1).
 */
const OPTIONAL_PREFIX = "**Optional:**";

function optionalClassesOf(variesByClass: unknown, id: string, where: string): OfferingClass[] {
  const parsed = IndicatorVariesByClass.parse(variesByClass);
  const optional: OfferingClass[] = [];
  for (const [cls, variant] of Object.entries(parsed)) {
    if (!OFFERING_CLASSES.includes(cls as OfferingClass)) {
      throw new CatalogSourceError(where, `${id} varies by class ${cls}, which is not a 20x class`);
    }
    if (variant.statement.trimStart().startsWith(OPTIONAL_PREFIX)) {
      optional.push(cls as OfferingClass);
    }
  }
  // A class the map does not name is REQUIRED, not optional — §13.7 rule 2.
  return optional;
}

const VariesByClass = z.record(
  z.string(),
  z
    .object({
      statement: z.string(),
      force: z.string(),
      timeframe_num: z.number().optional(),
      timeframe_type: z.string().optional(),
    })
    .passthrough(),
);

const RulesFile = z
  .object({
    info: z
      .object({
        version: z.string(),
        default_artifacts: z.object({ KSI: z.array(z.string()) }).passthrough(),
      })
      .passthrough(),
    KSI: z.record(
      z.string(),
      z
        .object({
          name: z.string(),
          short_name: z.string(),
          indicators: z.record(
            z.string(),
            z
              .object({
                name: z.string(),
                statement: z.string().optional(),
                varies_by_class: z.unknown().optional(),
                controls: z.array(z.string()),
              })
              .passthrough(),
          ),
        })
        .passthrough(),
    ),
    FRR: z.record(z.string(), z.object({ data: z.unknown() }).passthrough()),
  })
  .passthrough();

function ruleAt(
  frr: Record<string, { data: unknown }>,
  document: string,
  scope: string,
  group: string,
  id: string,
  where: string,
): unknown {
  const data = frr[document]?.data as
    | Record<string, Record<string, Record<string, unknown>>>
    | undefined;
  const rule = data?.[scope]?.[group]?.[id];
  if (rule === undefined) {
    throw new CatalogSourceError(where, `${id} not found at FRR.${document}.${scope}.${group}`);
  }
  return rule;
}

export async function loadKsiCatalogFromRules(
  rulesFile: string,
  pin: string,
): Promise<KsiCatalog> {
  const where = basename(rulesFile);
  const rules = RulesFile.parse(JSON.parse(await readFile(rulesFile, "utf8")));
  if (rules.info.version !== pin) {
    throw new DatasetVersionMismatchError(pin, rules.info.version, where);
  }

  const themes: KsiTheme[] = [];
  const ksis: KsiEntry[] = [];
  const optionalAt: Record<OfferingClass, string[]> = { a: [], b: [], c: [], d: [] };
  for (const theme of Object.values(rules.KSI)) {
    themes.push({ key: theme.short_name, name: theme.name });
    for (const [id, indicator] of Object.entries(theme.indicators)) {
      if (indicator.statement === undefined && indicator.varies_by_class === undefined) {
        throw new CatalogSourceError(where, `${id} carries neither a statement nor varies_by_class`);
      }
      if (indicator.varies_by_class !== undefined) {
        for (const cls of optionalClassesOf(indicator.varies_by_class, id, where)) {
          optionalAt[cls].push(id);
        }
      }
      ksis.push({
        id,
        themeKey: theme.short_name,
        name: indicator.name,
        // class-varied statements canonicalize to null — see KsiEntry.statement
        statement: indicator.statement ?? null,
        controls: indicator.controls,
      });
    }
  }

  const vvk = VariesByClass.parse(
    (ruleAt(rules.FRR, "FRC", "20x", "CSX", "FRC-CSX-VVK", where) as { varies_by_class?: unknown })
      .varies_by_class,
  );
  const mot = VariesByClass.parse(
    (ruleAt(rules.FRR, "FRC", "20x", "CSX", "FRC-CSX-MOT", where) as { varies_by_class?: unknown })
      .varies_by_class,
  );
  const mvx = VariesByClass.parse(
    (ruleAt(rules.FRR, "VDR", "20x", "TFR", "VDR-TFR-MVX", where) as { varies_by_class?: unknown })
      .varies_by_class,
  );
  const nmvRule = z
    .object({ statement: z.string(), force: z.string() })
    .passthrough()
    .parse(ruleAt(rules.FRR, "VDR", "all", "TFR", "VDR-TFR-NMV", where));

  const floors = {} as Record<OfferingClass, MethodFloor>;
  const historyFloors = {} as Record<OfferingClass, HistoryFloor>;
  for (const cls of OFFERING_CLASSES) {
    const v = vvk[cls];
    const m = mot[cls];
    if (v === undefined || m === undefined) {
      throw new CatalogSourceError(where, `FRC-CSX-VVK/MOT carry no class ${cls} entry`);
    }
    floors[cls] = {
      requirementId: "FRC-CSX-VVK",
      force: v.force,
      minPerKsi: parseMinMethods(v.statement, v.force, `${where} (FRC-CSX-VVK class ${cls})`),
    };
    historyFloors[cls] = {
      requirementId: "FRC-CSX-MOT",
      force: m.force,
      months: parseHistoryMonths(m.statement, m.force, `${where} (FRC-CSX-MOT class ${cls})`),
    };
  }

  const windows: Record<OfferingClass, ValidationWindow | null> = {
    a: null,
    b: null,
    c: null,
    d: null,
  };
  for (const cls of OFFERING_CLASSES) {
    const entry = mvx[cls];
    if (entry === undefined) continue; // class d: the rules define no MVX window
    if (entry.timeframe_num === undefined || entry.timeframe_type === undefined) {
      throw new CatalogSourceError(
        where,
        `VDR-TFR-MVX class ${cls} carries no structured timeframe`,
      );
    }
    windows[cls] = {
      requirementId: "VDR-TFR-MVX",
      force: entry.force,
      num: entry.timeframe_num,
      unit: WindowUnit.parse(entry.timeframe_type),
    };
  }

  return {
    datasetVersion: pin,
    themes: canonicalThemes(themes),
    ksis: canonicalKsis(ksis),
    defaultArtifacts: rules.info.default_artifacts.KSI,
    floors,
    historyFloors,
    windows,
    nonMachineWindow: {
      requirementId: "VDR-TFR-NMV",
      force: nmvRule.force,
      num: parseEveryNMonths(nmvRule.statement, `${where} (VDR-TFR-NMV)`),
      unit: "months",
    },
    applicability: {
      stated: true,
      optionalAt: {
        a: [...optionalAt.a].sort(),
        b: [...optionalAt.b].sort(),
        c: [...optionalAt.c].sort(),
        d: [...optionalAt.d].sort(),
      },
      source: where,
    },
  };
}

// ---------------------------------------------------------------------------

/**
 * §12.4 rule 2's enforcement arm: walk two catalogs and throw
 * `CatalogDivergenceError` at the FIRST owed fact they disagree on. The
 * equivalence test calls this so a failure names one fact; a consumer that
 * loads both paths (belt-and-suspenders at startup) can call it too.
 */
export function assertCatalogsEquivalent(a: KsiCatalog, b: KsiCatalog): void {
  const walk = (x: unknown, y: unknown, at: string): void => {
    // `applicability` is the one field here a path may legitimately not state
    // (§13.7 rule 3): the slices carry no class variants, so Path A answers
    // `stated: false`. Rule 2's hard-fail is for two sources DISAGREEING about
    // an owed fact, and silence is not disagreement — walking it would refuse
    // a load over a difference that means "one of us cannot see this".
    if (at === "applicability") return;
    if (Array.isArray(x) && Array.isArray(y)) {
      if (x.length !== y.length) throw new CatalogDivergenceError(`${at}.length`, x.length, y.length);
      x.forEach((v, i) => walk(v, y[i], `${at}[${i}]`));
      return;
    }
    if (x !== null && y !== null && typeof x === "object" && typeof y === "object") {
      const keys = new Set([...Object.keys(x), ...Object.keys(y)]);
      for (const k of keys) {
        walk(
          (x as Record<string, unknown>)[k],
          (y as Record<string, unknown>)[k],
          at === "" ? k : `${at}.${k}`,
        );
      }
      return;
    }
    if (x !== y) throw new CatalogDivergenceError(at, x, y);
  };
  walk(a, b, "");
}

// ---------------------------------------------------------------------------

/** Where a catalog's two sources live. Both are vendored at the same pin. */
export interface KsiCatalogSources {
  /** the ramprules derived-slice directory — Path A */
  derivedDir: string;
  /** fedramp-consolidated-rules.json — Path B, the canonical upstream */
  rulesFile: string;
  pin: string;
}

/**
 * Load BOTH paths and cross-check them — the default catalog surface from R0.2
 * (SPEC §13.7).
 *
 * §12.4 always allowed this ("a consumer that loads both paths can call it
 * too"); what makes it the default rather than a belt-and-suspenders option is
 * that class applicability is an owed fact only the canonical source states,
 * and a tool that printed a 46 denominator at class b because its default path
 * could not see the five optional indicators would be typing a number the
 * rules JSON owns.
 *
 * The cross-check is the point, not a cost: two independent parses of the same
 * pin disagreeing on an owed fact is a broken port, and this is where that is
 * discovered — at load, naming the fact, rather than in a document an assessor
 * reads. Everything except `applicability` must be identical; that one field
 * is taken from whichever source states it, and it is an error for BOTH to be
 * silent, because then nothing is stating the denominator.
 */
export async function loadKsiCatalog(sources: KsiCatalogSources): Promise<KsiCatalog> {
  const [slices, rules] = await Promise.all([
    loadKsiCatalogFromSlices(sources.derivedDir, sources.pin),
    loadKsiCatalogFromRules(sources.rulesFile, sources.pin),
  ]);
  assertCatalogsEquivalent(slices, rules);
  const applicability = rules.applicability.stated ? rules.applicability : slices.applicability;
  if (!applicability.stated) {
    throw new CatalogSourceError(
      basename(sources.rulesFile),
      `neither source states class applicability at ${sources.pin} — ${applicability.reason}. Every class denominator would have to assume all 46 indicators are required, which is a number neither source owns`,
    );
  }
  return { ...slices, applicability };
}

/**
 * The indicators a class does not oblige, and the ones it does — the shape
 * every denominator divides by. Kept beside the loader so no consumer
 * re-derives "required" from "not optional" and gets the empty-list case
 * wrong.
 */
export function requiredKsis(catalog: KsiCatalog, cls: OfferingClass): readonly KsiEntry[] {
  if (!catalog.applicability.stated) return catalog.ksis;
  const optional = new Set(catalog.applicability.optionalAt[cls]);
  return catalog.ksis.filter((k) => !optional.has(k.id));
}

/** The ids this class leaves optional, ascending; empty when none or unstated. */
export function optionalKsis(catalog: KsiCatalog, cls: OfferingClass): readonly string[] {
  return catalog.applicability.stated ? catalog.applicability.optionalAt[cls] : [];
}

// ---------------------------------------------------------------------------
// The FRR rule register (P2-0, docs/RESEARCH-REJECTION-LINTER.md §2).
//
// The KSI loaders above read the 46 indicators. This reads the OTHER half of
// the same file: the 246 FedRAMP Requirements rules, which until now nothing
// in this repository enumerated — roughly sixteen rule ids were hardcoded at
// the sites that needed them, and the `CPO-*` rules had no TypeScript
// reference at all. FedRAMP/community#167's reason 3 ("ALL MUSTs and SHOULDs
// applicable to your class need to be addressed") cannot be checked without
// the denominator, so this is where the denominator comes from.
//
// One reader, in the package where rule text is read, for the reason
// `ksi-register.ts:44` and `catalog.ts:196` give: one fact computed twice is
// a bug here.
// ---------------------------------------------------------------------------

/**
 * A rule's scope inside its document: `all` applies to every certification
 * type, `20x` to 20x only, `rev5` to Rev5 only. Validated against this closed
 * set so a republication that introduces a fourth scope arrives as a refused
 * load rather than as rules silently counted in or out (§13.7 rule 1).
 */
const RULE_SCOPES = ["all", "20x", "rev5"] as const;
export type RuleScope = (typeof RULE_SCOPES)[number];

/** Applicability as the SUBSET declares it — no rule carries its own. */
export interface RuleApplicability {
  readonly types: readonly string[];
  readonly paths: readonly string[];
  readonly classes: readonly OfferingClass[];
  readonly affects: readonly string[];
}

export interface FrrRule {
  readonly id: string;
  /** the FRR document key, e.g. `FRC` */
  readonly document: string;
  readonly documentName: string;
  readonly scope: RuleScope;
  /** the subset key, e.g. `CSX` */
  readonly subset: string;
  readonly name: string;
  /** the statement, or null when the rule states one per class — read it with `effectiveStatement` */
  readonly statement: string | null;
  /** the per-class statement, or null when the rule states a single one */
  readonly statementByClass: Readonly<Partial<Record<OfferingClass, string>>> | null;
  /** the single force, or null when the rule carries `varies_by_class` */
  readonly force: string | null;
  /** the per-class force, or null when the rule carries a single one */
  readonly forceByClass: Readonly<Partial<Record<OfferingClass, string>>> | null;
  readonly affects: readonly string[];
  /**
   * The subset's declared applicability, or **null when the subset declares
   * none** — never coerced to an empty applicability, because the two mean
   * opposite things (§2b).
   */
  readonly applicability: RuleApplicability | null;
  /** the schema this rule names, if any — 24 rules do */
  readonly schemaUrl: string | null;
}

export interface RuleRegister {
  readonly datasetVersion: string;
  readonly rules: readonly FrrRule[];
  readonly source: string;
  /**
   * `DOCUMENT/SUBSET` for every subset that carries rules a 20x register can
   * address and declares no applicability, ascending. Named out loud rather
   * than absorbed, the twin of `KsiRegisterView.summary.applicabilityUnstated`.
   */
  readonly applicabilityUnstated: readonly string[];
  /** why that list is not empty, in words a report can print */
  readonly applicabilityUnstatedReason: string;
  /**
   * Upstream publishes this same distribution in `obligations.json`, over both
   * arms, from the other leg of §12.4. Computing it here means the enumeration
   * is checked against a number this repository did not derive: `requirement`
   * counts each rule's single force and therefore omits the class-varied
   * rules, which is what upstream's own arm does; `withClass` counts every
   * class variant. The equality is asserted in the test, not assumed.
   */
  readonly forceDistribution: {
    readonly requirement: Readonly<Record<string, number>>;
    readonly withClass: Readonly<Record<string, number>>;
  };
}

const RuleApplicabilitySchema = z
  .object({
    types: z.array(z.string()),
    paths: z.array(z.string()),
    classes: z.array(z.string()),
    affects: z.array(z.string()),
  })
  .passthrough();

const FrrRuleSchema = z
  .object({
    name: z.string(),
    statement: z.string().optional(),
    force: z.string().optional(),
    varies_by_class: z.unknown().optional(),
    affects: z.array(z.string()),
    schema: z.object({ url: z.string() }).passthrough().optional(),
  })
  .passthrough();

const FrrDocumentSchema = z
  .object({
    info: z
      .object({
        name: z.string(),
        subsets: z
          .record(z.string(), z.object({ applicability: RuleApplicabilitySchema.optional() }).passthrough())
          .optional(),
      })
      .passthrough(),
    data: z.record(z.string(), z.record(z.string(), z.record(z.string(), z.unknown()))),
  })
  .passthrough();

const RuleRegisterFile = z
  .object({
    info: z.object({ version: z.string() }).passthrough(),
    FRR: z.record(z.string(), FrrDocumentSchema),
  })
  .passthrough();

function classesOf(declared: readonly string[], subset: string, where: string): OfferingClass[] {
  return declared.map((c) => {
    const cls = c.toLowerCase() as OfferingClass;
    if (!OFFERING_CLASSES.includes(cls)) {
      throw new CatalogSourceError(where, `subset ${subset} declares class ${c}, which is not a 20x class`);
    }
    return cls;
  });
}

/**
 * The per-class variants of a `varies_by_class` rule — force AND statement
 * together, because they vary together.
 *
 * Reading only the force was P2-0's own version of the trap §2a warns about:
 * `FRC-CSX-VVK`'s force came out right and its statement came out `null`,
 * along with 28 others, because a rule that states one sentence per class has
 * no sentence at the top level to read. The same `varies_by_class` block holds
 * both, so taking one and discarding the other is the bug, not the schema's.
 */
function variantsByClassOf(
  variesByClass: unknown,
  id: string,
  where: string,
): Partial<Record<OfferingClass, { force: string; statement: string }>> {
  const parsed = VariesByClass.parse(variesByClass);
  const byClass: Partial<Record<OfferingClass, { force: string; statement: string }>> = {};
  for (const [cls, variant] of Object.entries(parsed)) {
    if (!OFFERING_CLASSES.includes(cls as OfferingClass)) {
      throw new CatalogSourceError(where, `${id} varies by class ${cls}, which is not a 20x class`);
    }
    byClass[cls as OfferingClass] = { force: variant.force, statement: variant.statement };
  }
  return byClass;
}

/**
 * The force this rule carries AT THIS CLASS, which for 29 of the 246 rules is
 * not the same as its force.
 *
 * This function is the whole of §2a's trap, closed. `FRC-CSX-VVK` reads
 * MAY / SHOULD / MUST / MUST across classes a–d; a reader that took the
 * top-level `force` would get `null` for it and for 28 others, and every
 * class would come out with the same denominator. Returns null when the rule
 * states no force at this class — which is a rule the class does not oblige,
 * not a rule with no force.
 */
export function effectiveForce(rule: FrrRule, cls: OfferingClass): string | null {
  return rule.forceByClass ? (rule.forceByClass[cls] ?? null) : rule.force;
}

/**
 * The rule's own sentence AT THIS CLASS — `effectiveForce`'s other half, and
 * necessary for the same reason.
 *
 * 21 of the 129 rules addressable at class b state a sentence per class and
 * none at the top level, so a reader taking `statement` gets `null` for them:
 * `CDS-CSO-AVR` is SHOULD at class a and MUST at b and says so in each
 * variant's own words. Whoever reviews these rules needs the sentence that
 * binds THIS class, not the absence of one.
 */
export function effectiveStatement(rule: FrrRule, cls: OfferingClass): string | null {
  return rule.statementByClass ? (rule.statementByClass[cls] ?? null) : rule.statement;
}

/**
 * The rules a provider seeking certification at this class must or should
 * address — reason 3's denominator, and the number nobody in this field
 * publishes (129 at class b, 131 at c, 132 at d).
 *
 * The filter, stated so a reader can re-derive it rather than trust it:
 *
 *   1. the rule's scope is not `rev5` — a 20x certification does not owe the
 *      Rev5-only rules;
 *   2. its subset's applicability, WHEN DECLARED, names type `20x` and names
 *      this class. When the subset declares none, the rule is **kept** (§2b):
 *      the four subsets in that state are all `20x` subsets, and dropping
 *      them would drop the method floor, the history floor and the five owed
 *      artifacts — the three rules this repository is built on;
 *   3. the rule's own `affects` names `Providers` — the register also holds
 *      rules addressed to FedRAMP, Agencies, Assessors and Advisors, which a
 *      provider's submission is not judged against;
 *   4. its effective force at this class is MUST or SHOULD. MAY is not owed,
 *      and MUST NOT / SHOULD NOT are prohibitions rather than things a
 *      package addresses.
 */
export function addressableRules(register: RuleRegister, cls: OfferingClass): readonly FrrRule[] {
  return register.rules.filter((rule) => {
    if (rule.scope === "rev5") return false;
    if (rule.applicability !== null) {
      if (!rule.applicability.types.includes("20x")) return false;
      if (!rule.applicability.classes.includes(cls)) return false;
    }
    if (!rule.affects.includes("Providers")) return false;
    const force = effectiveForce(rule, cls);
    return force === "MUST" || force === "SHOULD";
  });
}

/**
 * Read the FRR rule set from `fedramp-consolidated-rules.json` at the pin —
 * Path B of §12.4, the same file `loadKsiCatalogFromRules` reads for the
 * indicators.
 */
export async function loadRuleRegister(rulesFile: string, pin: string): Promise<RuleRegister> {
  const where = basename(rulesFile);
  const file = RuleRegisterFile.parse(JSON.parse(await readFile(rulesFile, "utf8")));
  if (file.info.version !== pin) {
    throw new DatasetVersionMismatchError(pin, file.info.version, where);
  }

  const rules: FrrRule[] = [];
  const requirement: Record<string, number> = {};
  const withClass: Record<string, number> = {};
  const unstated = new Set<string>();

  for (const [document, doc] of Object.entries(file.FRR)) {
    const subsets = doc.info.subsets ?? {};
    for (const [scope, groups] of Object.entries(doc.data)) {
      if (!RULE_SCOPES.includes(scope as RuleScope)) {
        throw new CatalogSourceError(where, `FRR.${document}.data carries scope ${scope}, which is not a known rule scope`);
      }
      for (const [subset, group] of Object.entries(groups)) {
        const declared = subsets[subset]?.applicability;
        const applicability: RuleApplicability | null = declared
          ? {
              types: declared.types,
              paths: declared.paths,
              classes: classesOf(declared.classes, subset, where),
              affects: declared.affects,
            }
          : null;
        if (applicability === null && scope !== "rev5") unstated.add(`${document}/${subset}`);

        for (const [id, raw] of Object.entries(group)) {
          const rule = FrrRuleSchema.parse(raw);
          if (rule.force === undefined && rule.varies_by_class === undefined) {
            throw new CatalogSourceError(where, `${id} carries neither a force nor varies_by_class`);
          }
          const variants =
            rule.varies_by_class === undefined
              ? null
              : variantsByClassOf(rule.varies_by_class, id, where);
          const forceByClass =
            variants === null
              ? null
              : (Object.fromEntries(
                  Object.entries(variants).map(([cls, v]) => [cls, v.force]),
                ) as Partial<Record<OfferingClass, string>>);
          const statementByClass =
            variants === null
              ? null
              : (Object.fromEntries(
                  Object.entries(variants).map(([cls, v]) => [cls, v.statement]),
                ) as Partial<Record<OfferingClass, string>>);

          // Upstream's `requirement` arm counts a rule's single force and so
          // omits the class-varied rules; `withClass` counts every variant.
          // Reproducing both is what proves this walk against a number this
          // repository did not derive.
          if (forceByClass === null) {
            requirement[rule.force as string] = (requirement[rule.force as string] ?? 0) + 1;
            withClass[rule.force as string] = (withClass[rule.force as string] ?? 0) + 1;
          } else {
            for (const force of Object.values(forceByClass)) {
              withClass[force] = (withClass[force] ?? 0) + 1;
            }
          }

          rules.push({
            id,
            document,
            documentName: doc.info.name,
            scope: scope as RuleScope,
            subset,
            name: rule.name,
            statement: rule.statement ?? null,
            statementByClass,
            force: rule.force ?? null,
            forceByClass,
            affects: rule.affects,
            applicability,
            schemaUrl: rule.schema?.url ?? null,
          });
        }
      }
    }
  }

  const applicabilityUnstated = [...unstated].sort();
  return {
    datasetVersion: pin,
    rules,
    source: where,
    applicabilityUnstated,
    applicabilityUnstatedReason:
      applicabilityUnstated.length === 0
        ? "every subset carrying rules declares its applicability"
        : `${applicabilityUnstated.join(", ")} carry rules with no declared applicability — ` +
          `the subset is absent from its document's own \`info.subsets\`, and every one of them is a 20x subset. ` +
          `Those rules are counted as APPLICABLE at every class and named here, because reading the gap as ` +
          `"does not apply" would silently drop FRC-CSX-VVK, FRC-CSX-MOT and SDR-CSX-KSI (ground rule 7). ` +
          `Rev5-scope subsets carry the same gap and are outside any 20x register.`,
    forceDistribution: { requirement, withClass },
  };
}
