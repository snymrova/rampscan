import { readdir } from "node:fs/promises";
import type { DeclaredRuleCoverage, OfferingConfig } from "@rampscan/schema";
import {
  addressableRules,
  effectiveForce,
  effectiveStatement,
  type FrrRule,
  type OfferingClass,
  type RuleRegister,
} from "@rampscan/dataset";
import { FEDRAMP_SCHEMA_PINS } from "./fedramp-schemas.js";
import type { ConformanceResult } from "./fedramp-conformance.js";
import type { KsiRegisterView } from "./ksi-register.js";

// `rampscan submission` — the rejection register (P2-3,
// docs/RESEARCH-REJECTION-LINTER.md §4).
//
// FedRAMP/community#167, 2026-08-31, announcing the submission form going
// live, lists "a few top reasons why your submission might get rejected".
// This register is one section per reason, each carrying the reason's own
// words, the rule ids that make it binding, and rows.
//
// `gaps.ts` is the shape copied — sections keyed to a rule id and its force,
// with a first-class `unmeasured` channel — because "nothing found" and
// "never checked" are different facts and a register that blurred them would
// be the vacuous pass ground rule 7 exists to refuse.
//
// §5's constraint holds throughout: one fact computed twice is a bug here, so
// the schema-invalid section READS `checkConformance` and the flagged rules
// read the exports' own `problems` channel. The one computation this module
// adds is the rule-coverage sweep, which had no denominator before P2-0.

export type RejectionSection =
  | "trust-center-gate"
  | "unaddressed-rules"
  | "unaddressed-ksis"
  | "missing-example"
  | "schema-invalid"
  | "assessment-content";

/**
 * The rule ids this appliance itself answers, and the surface that answers
 * each. "Answers" means produces a verdict, pass or fail: `CDS-CSO-UTC` is
 * here because the exports' `problems` channel reports its absence by name,
 * which is an answer, where a rule nothing mentions is silence.
 *
 * Declared rather than grepped at runtime, and guarded against drift by
 * `submission.test.ts`, which greps the shipped sources for rule-id-shaped
 * strings and fails when this map and the code disagree. Both directions
 * matter: a rule that gains a surface and not an entry would be counted
 * unaddressed while the tool answers it, and an entry whose surface was
 * deleted would be counted computed while nothing computes it.
 */
export const COMPUTED_RULES: Readonly<Record<string, string>> = {
  "CCM-OCR-AVL": "`rampscan exports` builds the Ongoing Certification Report and validates it against the pinned schema",
  "CCM-OCR-NRD": "the exports' problems channel reports an undeclared next-OCR date — a calendar commitment the ledger cannot compute",
  "CDS-CSO-PUB": "the exports' problems channel reports an undeclared independent assessment service",
  "CDS-CSO-UTC": "the exports' problems channel reports an undeclared trust center; serving it is out of scope for a local appliance",
  "FRC-APP-FCP": "`applicationFreshness` computes the package's age from the register, with no config key that could have asserted it",
  "FRC-CSO-JSN": "`rampscan conformance` validates each document against its pinned schema, and cross-checks the document's own stamp",
  "FRC-CSO-PKG": "`rampscan exports` builds the certification package overview",
  "FRC-CSX-MOT": "the history meter walks the KSI's instants across the owed span (#159)",
  "FRC-CSX-VVK": "the method floor — the KSI register's automated-method numerator, and gaps G1/G2",
  "SDR-CSX-KSI": "the artifact plane (R0/R1): the five artifacts owed per KSI",
  "VDR-CSO-FAV": "the failure-to-vulnerability feed — gaps G13",
  "VDR-TFR-MVX": "the machine validation window meter for the reporting class",
  "VDR-TFR-NMV": "the non-machine validation window, three months, for attested methods",
};

/**
 * Which section each rule the exports' `problems` channel cites belongs under.
 *
 * Declared rather than inferred, because inferring it from a section's own
 * `ruleIds` silently drops every problem whose rule no section happens to
 * list — which is what the first draft of this module did, reprojecting
 * nothing while looking like it reprojected everything. `submission.test.ts`
 * greps `fedramp-exports.ts` for rule-id-shaped strings and fails when one is
 * not a key here, so a new problem cannot be added upstream of this map and
 * vanish.
 */
const PROBLEM_RULE_SECTIONS: Readonly<Record<string, RejectionSection>> = {
  // the trust center the exports cannot serve — reason 1's own rule
  "CDS-CSO-UTC": "trust-center-gate",
  // an undeclared next-OCR date and a stale application are both reason 2's
  // "incomplete package", judged over what the package contains
  "CCM-OCR-NRD": "missing-example",
  "FRC-APP-FCP": "missing-example",
  // the assessor is what carries reason 5's assessed content
  "CDS-CSO-PUB": "assessment-content",
};

/** the rule ids a reprojected problem may cite — the map's keys, for the drift guard */
export const PROBLEM_RULE_IDS: readonly string[] = Object.keys(PROBLEM_RULE_SECTIONS).sort();

/** How a rule resolves for reason 3. §4b: getting this wrong either way is worse than not shipping it. */
export type RuleState = "computed" | "declared" | "outside" | "unaddressed";

export interface RejectionRow {
  /** what the row is about: a rule id, a KSI, a document */
  subject: string;
  /** the computed fact, one line */
  detail: string;
  /** the rule THIS row cites, when it differs from its section's */
  ruleId?: string;
  /** the force at the reporting class, where the row is a rule */
  force?: string;
  /**
   * The rule's own sentence at the reporting class, on a rule row. Carried in
   * `--json` and not printed: 116 statements is a document, not a register,
   * and a reader working the queue down needs the text the moment they pick a
   * row. `effectiveStatement`, because 18 of them state one per class.
   */
  statement?: string;
  /**
   * Set when the row is a rejection this appliance can stand behind, which is
   * what the exit code counts. An `unaddressed` rule is NOT one: with P2-1
   * unbuilt there is no reviewed `outside` set, so a rule no local appliance
   * could ever see — a FedRAMP Marketplace listing is not a property of a git
   * checkout — is indistinguishable from one the provider simply omitted, and
   * reporting 116 rows as rejections is the false accusation at scale §4b
   * warns about.
   */
  rejection?: true;
}

export interface RejectionRegisterSection {
  section: RejectionSection;
  /** the reason's number in #167, or null for the KSI half of reason 3 */
  reason: number | null;
  /** FedRAMP's own words, so the register carries its provenance */
  quote: string;
  /** the rules that make this section binding */
  ruleIds: readonly string[];
  /** set when the section cannot be measured — never omitted to look clean */
  unmeasured?: string;
  rows: RejectionRow[];
  /** reason 3 only: the four states and their counts */
  states?: Readonly<Record<RuleState, number>>;
  /** a note the section owes its reader, printed under the heading */
  note?: string;
}

export interface RejectionRegisterView {
  offeringClass: OfferingClass;
  datasetVersion: string;
  sections: RejectionRegisterSection[];
  /** rows the appliance can stand behind as rejections — the exit code's number */
  rejections: number;
  /** sections that could not be measured at all */
  unmeasured: number;
}

export interface RejectionRegisterInput {
  register: RuleRegister;
  offeringClass: OfferingClass;
  /** the offering declaration; absent when none was supplied */
  offering?: OfferingConfig;
  /** the KSI register — reason 3's KSI half; absent when not computed */
  ksis?: KsiRegisterView;
  /** `checkConformance`'s result over the exports directory; absent when not run */
  conformance?: ConformanceResult;
  /** the exports' own problems channel, read rather than recomputed (§5) */
  problems?: readonly string[];
  /** the directory the exports were written to; absent when none */
  outDir?: string;
}

/** the documents present in the exports directory, or null when there is no directory to read */
async function documentsIn(outDir: string | undefined): Promise<string[] | null> {
  if (outDir === undefined) return null;
  try {
    return (await readdir(outDir)).filter((f) => f.endsWith(".json")).sort();
  } catch {
    return null;
  }
}

/** the schema file a rule's url names, for comparison against the pins */
export function schemaFileOf(url: string): string {
  return url.split("/").pop() ?? url;
}

function ruleRow(rule: FrrRule, cls: OfferingClass, detail: string): RejectionRow {
  const force = effectiveForce(rule, cls);
  const statement = effectiveStatement(rule, cls);
  return {
    subject: rule.id,
    detail,
    ...(force !== null ? { force } : {}),
    ...(statement !== null ? { statement } : {}),
  };
}

export async function buildRejectionRegister(
  input: RejectionRegisterInput,
): Promise<RejectionRegisterView> {
  const { register, offeringClass: cls } = input;
  const addressable = addressableRules(register, cls);
  const byId = new Map(register.rules.map((r) => [r.id, r]));
  const sections: RejectionRegisterSection[] = [];

  // ---- reason 1 — the trust center -------------------------------------
  //
  // The most important section in the register, and the only one that is
  // unmeasured by construction. It is FedRAMP's FIRST listed reason; it is a
  // property of a live URL that no package reveals; and this appliance makes
  // no fetch. A register that omitted it would be a vacuous pass on the most
  // likely rejection, so it prints, always, as unmeasured until P4 (#213).
  const declaredTrustCenter = input.offering?.trustCenter;
  sections.push({
    section: "trust-center-gate",
    reason: 1,
    quote:
      "Your Trust Center requires acknowledgement and/or acceptance of a privacy policy, terms of service or non-disclosure agreement",
    ruleIds: ["CDS-TRC-USH", "CDS-TRC-PAC", "CDS-TRC-HMR", "CDS-CSO-UTC"],
    unmeasured:
      `this appliance does not fetch — whether a gate stands in front of ${declaredTrustCenter?.url ?? "an undeclared trust center"} ` +
      `is not a property of any file it reads. P4 (#213) is the probe; until it exists this is the reason FedRAMP listed first ` +
      `and the one rampscan measures least, which is worth saying out loud rather than scoring`,
    rows:
      declaredTrustCenter === undefined
        ? [
            {
              subject: "CDS-CSO-UTC",
              detail:
                "no trust center declared in the offering — there is not even a URL to probe, which the exports' problems channel already reports",
              ruleId: "CDS-CSO-UTC",
              rejection: true,
            },
          ]
        : [
            {
              subject: declaredTrustCenter.url,
              detail: `declared${declaredTrustCenter.authenticationRequired === true ? " — and declares that it requires authentication, which is the gate #167 names" : ""}`,
              ...(declaredTrustCenter.authenticationRequired === true ? { rejection: true as const } : {}),
            },
          ],
  });

  // ---- reason 3, the rule half -----------------------------------------
  //
  // P2-2: the offering's own `ruleCoverage` declaration, which is where #167's
  // "say so and tell us why" lands. Three things a declaration must not be
  // allowed to do, each handled below rather than in the loop, because each is
  // about the declaration and not about the rule:
  //
  //   - OVERRIDE A COMPUTATION. A rule this appliance answers itself stays
  //     `computed` whatever the config says, the same refusal SPEC §12.4 rule 3
  //     makes of an overlay carrying an owed number. The note reports the
  //     overlap rather than silently preferring one of two answers.
  //   - COVER A RULE THAT DOES NOT EXIST. A mistyped id is not a harmless
  //     no-op: it means the rule the provider MEANT is still unaddressed while
  //     the config looks answered. It prints as a rejection.
  //   - INFLATE THE NUMERATOR. A declaration for a rule the class does not
  //     oblige is harmless — a provider may be declaring toward class c — but
  //     it is counted in the note, never against a denominator it is not in.
  const coverage = new Map<string, DeclaredRuleCoverage>(
    (input.offering?.ruleCoverage ?? []).map((entry) => [entry.ruleId, entry]),
  );
  const addressableIds = new Set(addressable.map((r) => r.id));
  const declaredOverComputed: string[] = [];
  const declaredNotAddressable: string[] = [];
  const unresolvableDeclarations: RejectionRow[] = [];
  for (const [id, entry] of coverage) {
    if (!byId.has(id)) {
      unresolvableDeclarations.push({
        subject: id,
        detail:
          `declared ${entry.status} in the offering's ruleCoverage, but no rule with this id exists at dataset ` +
          `${register.datasetVersion} — a mistyped id leaves the rule it meant unaddressed while the config reads as answered`,
        ruleId: id,
        rejection: true,
      });
    } else if (COMPUTED_RULES[id] !== undefined) {
      declaredOverComputed.push(id);
    } else if (!addressableIds.has(id)) {
      declaredNotAddressable.push(id);
    }
  }

  const states: Record<RuleState, number> = {
    computed: 0,
    declared: 0,
    outside: 0,
    unaddressed: 0,
  };
  const unaddressed: RejectionRow[] = [];
  let declaredAddressed = 0;
  let declaredNotImplemented = 0;
  for (const rule of addressable) {
    if (COMPUTED_RULES[rule.id] !== undefined) {
      states.computed += 1;
      continue;
    }
    const declared = coverage.get(rule.id);
    if (declared !== undefined) {
      states.declared += 1;
      if (declared.status === "addressed") declaredAddressed += 1;
      else declaredNotImplemented += 1;
      continue;
    }
    // `outside` stays unreachable until P2-1 exists. It is counted rather than
    // omitted so the register's arithmetic has the same shape before and after
    // that lands, and a reader can see the zero is a missing surface and not a
    // measured absence.
    states.unaddressed += 1;
    // The rule's own NAME, not a sentence about rampscan: every row in this
    // section is a rule nothing answers, the note says so once, and 116 copies
    // of the same clause is how a queue stops being read. The full statement
    // at this class rides in `--json` for a reader working the queue down.
    unaddressed.push(ruleRow(rule, cls, rule.name));
  }
  sections.push({
    section: "unaddressed-rules",
    reason: 3,
    quote:
      "Remember that ALL MUSTs and SHOULDs applicable to your class need to be addressed. If you don't have something implemented, say so and tell us why, don't just omit the KSI or rule altogether",
    ruleIds: ["FRC-CSX-VVK", "FRC-CSX-MAS"],
    states,
    note:
      `${addressable.length} rules are addressable at class ${cls}` +
      (register.applicabilityUnstated.length > 0
        ? `, including the rules of ${register.applicabilityUnstated.join(", ")}, whose subsets declare no applicability at all and which are therefore counted as owed`
        : "") +
      `. ${states.computed} this appliance answers itself. ` +
      (input.offering === undefined
        ? "No offering declaration was supplied, so no rule can be declared addressed. "
        : coverage.size === 0
          ? "The offering declares no ruleCoverage, so no rule can be declared addressed. "
          : `${declaredAddressed} declared addressed by citation and ${declaredNotImplemented} declared not implemented with a reason — ` +
            `which #167 asks for explicitly and which this appliance does NOT verify: it checks that an answer exists, never that it is true. ` +
            (declaredOverComputed.length > 0
              ? `${declaredOverComputed.length} declaration(s) name a rule this appliance computes (${declaredOverComputed.sort().join(", ")}) and are counted as computed, not declared: a declaration does not overwrite a measurement. `
              : "") +
            (declaredNotAddressable.length > 0
              ? `${declaredNotAddressable.length} declaration(s) name a rule class ${cls} does not oblige (${declaredNotAddressable.sort().join(", ")}), counted here against no denominator. `
              : "")) +
      `The ${states.unaddressed} unaddressed is an UPPER BOUND and not a finding: with P2-1 unbuilt no rule can yet ` +
      `be ruled structurally outside a local appliance's reach — a FedRAMP Marketplace listing is not a property of a ` +
      `git checkout — so a rule nobody could answer here is indistinguishable from one a provider omitted. That is why ` +
      `these rows are printed as the queue rather than counted as rejections: reporting them as rejections would be a ` +
      `false accusation at scale, and reporting them as fine would be the vacuous pass`,
    // The unresolvable declarations lead, ahead of the queue: the renderer
    // prints the first rows in full and groups the tail, and a typo'd rule id
    // buried under 116 queue rows is a finding nobody reads.
    rows: [...unresolvableDeclarations, ...unaddressed],
  });

  // ---- reason 3, the KSI half ------------------------------------------
  const ksiSection: RejectionRegisterSection = {
    section: "unaddressed-ksis",
    reason: 3,
    quote: "don't just omit the KSI or rule altogether",
    ruleIds: ["FRC-CSX-VVK", "SDR-CSX-KSI"],
    rows: [],
  };
  if (input.ksis === undefined) {
    ksiSection.unmeasured =
      "the KSI register was not computed for this run — it needs a catalog and a frontier, and an empty list here would read as full coverage";
  } else {
    // The OBLIGED rows only, which is the KSI register's own denominator
    // (§13.7: every meter counts the obliged rows). Filtering on `methods`
    // alone recomputed a fact the register already judges and disagreed with
    // it — 33 against its 28 — because a class leaves some indicators
    // optional and an optional KSI with no method is not an omission the
    // class obliges. The optional ones are counted in the note rather than
    // dropped in silence.
    for (const row of input.ksis.rows) {
      if (row.optional || row.methods > 0) continue;
      ksiSection.rows.push({
        subject: row.ksi,
        detail: "no validation method derives — the KSI is omitted rather than declared unimplemented",
        rejection: true,
      });
    }
    const optionalBare = input.ksis.rows.filter((r) => r.optional && r.methods === 0).length;
    ksiSection.note =
      `${input.ksis.rows.length} KSI(s) in the catalog, ${input.ksis.summary.noMethod} obliged at class ${cls} with no method` +
      (optionalBare > 0
        ? `; a further ${optionalBare} the class leaves optional also have none, which is not an omission it obliges`
        : "");
  }
  sections.push(ksiSection);

  // ---- reason 2, second clause — an example per schema-bearing rule ----
  //
  // Cheap, and complete for all eight schemas: NAMING a schema-bearing rule
  // with no supplied document needs no vendored schema. It is the VALIDATING
  // question below that is answerable for only the two this checkout pins,
  // and §2c is the note that must never let the two blur.
  const present = await documentsIn(input.outDir);
  const missing: RejectionRow[] = [];
  const schemaBearing = addressable.filter((r) => r.schemaUrl !== null);
  const missingSection: RejectionRegisterSection = {
    section: "missing-example",
    reason: 2,
    quote:
      "any rule that calls out a specific schema should have at least an example provided",
    ruleIds: ["FRC-CSO-PKG", "CPO-CSO-OVR"],
    rows: [],
  };
  if (present === null) {
    missingSection.unmeasured =
      `no exports directory was read, so which of the ${schemaBearing.length} schema-bearing rules have a document ` +
      `supplied is unknown — run \`rampscan exports\` first and pass --out`;
  } else {
    for (const rule of schemaBearing) {
      const file = schemaFileOf(rule.schemaUrl as string);
      const vendored = FEDRAMP_SCHEMA_PINS[file] !== undefined;
      // A document is matched to a schema by the pins, never by guessing at a
      // document's shape — the same refusal `resolveSchema` makes.
      const supplied = vendored && present.length > 0;
      if (!supplied) {
        missing.push({
          ...ruleRow(rule, cls, vendored
            ? "names a schema this checkout pins, and no document was supplied"
            : `names ${file}, which this checkout does not vendor — the example is owed and cannot be validated here`),
          rejection: true,
        });
      }
    }
    missingSection.rows = missing;
    missingSection.note = `${present.length} document(s) in the exports directory; ${schemaBearing.length} rules name a schema`;
  }
  sections.push(missingSection);

  // ---- reason 4 — the JSON validates ----------------------------------
  const schemaSection: RejectionRegisterSection = {
    section: "schema-invalid",
    reason: 4,
    quote: "our minimal structure and required fields should be present",
    ruleIds: ["FRC-CSO-JSN"],
    rows: [],
  };
  if (input.conformance === undefined) {
    schemaSection.unmeasured =
      "`rampscan conformance` was not run over the exports — this section reprojects its verdict rather than re-validating, so with no verdict there is nothing to report (§5)";
  } else {
    for (const finding of input.conformance.findings) {
      if (finding.conformant) continue;
      schemaSection.rows.push({
        subject: finding.path,
        detail:
          finding.stampDisagreement ??
          `${finding.violations.length} violation(s) against ${finding.schemaFile} @ ${finding.schemaVersion}`,
        rejection: true,
      });
    }
    const unvalidatable = [
      ...new Set(
        schemaBearing
          .map((r) => schemaFileOf(r.schemaUrl as string))
          .filter((f) => FEDRAMP_SCHEMA_PINS[f] === undefined),
      ),
    ].sort();
    schemaSection.note =
      `${input.conformance.findings.length} document(s) judged` +
      (unvalidatable.length > 0
        ? `; ${unvalidatable.length} schema(s) named by the rules are not vendored here and print as unvalidatable rather than clean: ${unvalidatable.join(", ")}`
        : "");
  }
  sections.push(schemaSection);

  // ---- reason 5 — the independent assessment's content -----------------
  const assessment: RejectionRegisterSection = {
    section: "assessment-content",
    reason: 5,
    quote: "Independent Assessment Service's content not included in CPO and SDR",
    ruleIds: ["IVV-CSO-ICP", "CPO-CSO-OVR"],
    rows: [],
  };
  if (input.offering === undefined) {
    assessment.unmeasured =
      "no offering declaration was supplied, so whether an independent assessment service is named is unknown";
  } else if (input.offering.assessor === undefined) {
    assessment.rows.push({
      subject: "IVV-CSO-ICP",
      detail:
        "no independent assessment service declared, so no assessed content can be carried into the overview or the SDR",
      rejection: true,
    });
  } else {
    assessment.note = `assessment service declared: ${input.offering.assessor.name}`;
  }
  sections.push(assessment);

  // The exports' own problems, reprojected under the reason each belongs to
  // rather than recomputed. Cited by rule id where the problem names one, so
  // a reader can follow the citation back into the rule register.
  if (input.problems !== undefined && input.problems.length > 0) {
    for (const problem of input.problems) {
      const cited = problem.match(/\b[A-Z]{3}-[A-Z]{3}-[A-Z]{3}\b/)?.[0];
      // A problem citing no rule, or a rule this pin does not carry, is a
      // finding about rampscan's own prose rather than about the submission —
      // so it is not printed as a rejection here, and `submission.test.ts`
      // asserts that every rule the exports cite resolves in the register and
      // has a home in the map above. That check belongs at test time: a
      // register that printed rampscan's typos beside FedRAMP's reasons would
      // be reporting the wrong subject.
      if (cited === undefined || !byId.has(cited)) continue;
      const home = PROBLEM_RULE_SECTIONS[cited];
      if (home === undefined) continue;
      const target = sections.find((s) => s.section === home);
      if (target === undefined) continue;
      // Deduplicated by the rule cited, not by the sentence: the trust-center
      // section already computes a row for CDS-CSO-UTC from the offering, and
      // matching on prose would print the same fact twice in two wordings.
      if (target.rows.some((r) => r.subject === cited || r.ruleId === cited)) continue;
      target.rows.push({ subject: cited, detail: problem, ruleId: cited, rejection: true });
    }
  }

  return {
    offeringClass: cls,
    datasetVersion: register.datasetVersion,
    sections,
    rejections: sections.reduce(
      (n, s) => n + s.rows.filter((r) => r.rejection === true).length,
      0,
    ),
    unmeasured: sections.filter((s) => s.unmeasured !== undefined).length,
  };
}

/** How many rule rows a section prints in full before grouping the tail by document. */
const ROWS_IN_FULL = 12;

/** the register as text — one section per #167 reason, in the order #167 lists them */
export function renderRejectionRegister(view: RejectionRegisterView, useColor: boolean): string {
  const paint = (code: string, s: string) => (useColor ? `[${code}m${s}[0m` : s);
  const dim = (s: string) => paint("2", s);
  const bold = (s: string) => paint("1", s);
  const red = (s: string) => paint("31", s);
  const lines: string[] = [];

  lines.push(
    bold("rampscan submission — the rejection register"),
    `class ${view.offeringClass} · dataset ${view.datasetVersion}`,
    dim(
      "  the five reasons FedRAMP published for rejecting a 20x submission (FedRAMP/community#167, 2026-08-31), plus the KSI half of reason 3",
    ),
    "",
  );

  for (const section of view.sections) {
    const reason = section.reason === null ? "—" : `reason ${section.reason}`;
    lines.push(
      bold(`  ${section.section}`) +
        dim(` — ${reason} · ${section.ruleIds.join(" ")} · ${section.rows.length} row(s)`),
    );
    lines.push(dim(`    "${section.quote}"`));
    if (section.states !== undefined) {
      lines.push(
        `    ${section.states.computed} computed · ${section.states.declared} declared · ` +
          `${section.states.outside} outside · ${red(String(section.states.unaddressed))} unaddressed`,
      );
    }
    if (section.note !== undefined) lines.push(dim(`    ${section.note}`));
    if (section.unmeasured !== undefined) {
      lines.push(dim(`    unmeasured: ${section.unmeasured}`));
    }

    const shown = section.rows.slice(0, ROWS_IN_FULL);
    for (const row of shown) {
      const force = row.force !== undefined ? dim(` ${row.force.padEnd(6)}`) : "";
      lines.push(
        `      ${(row.rejection === true ? red : dim)(row.subject.padEnd(38))}${force} ${dim(row.detail)}`,
      );
    }
    if (section.rows.length > shown.length) {
      // The tail grouped by document rather than truncated: a reader needs to
      // know WHERE the remaining rules are, and 116 lines of rule id is how a
      // register stops being read.
      const rest = section.rows.slice(ROWS_IN_FULL);
      const byDoc = new Map<string, number>();
      for (const row of rest) {
        const parts = row.subject.split("-");
        // The segment that actually discriminates: an FRR id's document is
        // its first (`CDS-TRC-USH` → CDS), but every KSI id's first segment
        // is `KSI`, and "KSI×21" tells a reader nothing. Theirs is the theme.
        const key = (parts[0] === "KSI" ? parts[1] : parts[0]) ?? row.subject;
        byDoc.set(key, (byDoc.get(key) ?? 0) + 1);
      }
      lines.push(
        dim(
          `      … ${rest.length} more: ` +
            [...byDoc.entries()]
              .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
              .map(([doc, n]) => `${doc}×${n}`)
              .join(" "),
        ),
      );
    }
    if (section.rows.length === 0 && section.unmeasured === undefined) {
      lines.push(dim("      none"));
    }
    lines.push("");
  }

  lines.push(
    dim(
      `  ${view.rejections} rejection(s) this appliance can stand behind · ${view.unmeasured} section(s) unmeasured. ` +
        `An unmeasured section is not a pass: reason 1 is FedRAMP's first and needs a live fetch this appliance does not make (#213)`,
    ),
  );
  return lines.join("\n");
}
