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
import type { SdrCoverage } from "./sdr.js";
import type { TrustCenterProbe } from "./trust-center-probe.js";

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
  // P4 earned this one: `rampscan probe` reads the trust center as an
  // anonymous reviewer would, gated only on positive evidence and open only on
  // a document proven by its bytes. It answers the rule for the URLs it was
  // pointed at, which the register says every time it prints the result.
  "CDS-TRC-USH": "`rampscan probe` fetches the declared trust center and named certification documents anonymously; a gate is reported on positive evidence, and `submission --trust-center-probe` reads the transcript",
  "FRC-APP-FCP": "`applicationFreshness` computes the package's age from the register, with no config key that could have asserted it",
  "FRC-CSO-JSN": "`rampscan conformance` validates each document against its pinned schema, and cross-checks the document's own stamp",
  "FRC-CSO-PKG": "`rampscan exports` builds the certification package overview",
  "FRC-CSX-MOT": "the history meter walks the KSI's instants across the owed span (#159)",
  "FRC-CSX-VVK": "the method floor — the KSI register's automated-method numerator, and gaps G1/G2",
  // P2-1 earned this entry rather than declaring it: the rule obliges a
  // Security Decision Record carrying a row per applicable rule, and
  // `--sdr` now diffs exactly that. Note it does NOT excuse the rule's own
  // row — since §9.3 `computed` is axis B and excuses nothing.
  "SDR-CSO-FRR": "`rampscan submission --sdr` diffs the record's fedRampRequirements against the rules addressable at the class, which is the coverage this rule obliges",
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

/**
 * Reason 3's counts, on the two axes §9.3 keeps apart.
 *
 * Axis A is FedRAMP's question and the only one that yields a rejection: does
 * the submitted document answer this rule? Axis B is this appliance's — what
 * it can independently check — and it excuses nothing. The earlier
 * `computed | declared | outside | unaddressed` presented four values of one
 * variable, which is how `computed` came to excuse a row FedRAMP still wants.
 */
export interface ReasonThreeStates {
  /** axis A: applicable rules the document answers, whatever the status inside */
  answered: number;
  /** axis A: applicable rules with no row at all — the rejection */
  omitted: number;
  /** axis B: of `answered`, the ones this appliance can independently verify */
  verifiable: number;
  /** axis B: of `omitted`, the ones it computes anyway — evidence with no row to carry it */
  computedButOmitted: number;
}

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
   * what the exit code counts.
   *
   * For reason 3's rule half that means: the rule is applicable at this class
   * and the Security Decision Record has no row for it. It is read off the
   * artifact FedRAMP reads, so it needs no judgement about what a local
   * appliance can see (§9.2). A rule merely undeclared in the offering's
   * `ruleCoverage` is NOT a rejection — that fallback is rampscan-local, and a
   * provider may hold a complete SDR this run never saw.
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
  /** reason 3 only: the coverage counts; absent when the section is unmeasured */
  states?: Readonly<ReasonThreeStates>;
  /** a note the section owes its reader, printed under the heading */
  note?: string;
}

export interface RejectionRegisterView {
  offeringClass: OfferingClass;
  datasetVersion: string;
  /**
   * Rules addressable at the reporting class — the denominator nobody
   * publishes. A fact about the catalog, so it survives reason 3 being
   * unmeasured: whether a package answers them is a different question from
   * how many there are.
   */
  addressable: number;
  /**
   * Rules this appliance answers for itself — axis B (§9.3), and likewise
   * independent of any package. It is evidence to put in a row; since P2-1 it
   * excuses no row.
   */
  computed: number;
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
  /**
   * The Security Decision Record's coverage — reason 3's actual subject (§9).
   * Absent when none was supplied, which makes reason 3 unmeasured rather than
   * a queue of accusations against a checkout that never claimed to be a
   * package.
   */
  sdr?: SdrCoverage;
  /** the exports' own problems channel, read rather than recomputed (§5) */
  problems?: readonly string[];
  /** the directory the exports were written to; absent when none */
  outDir?: string;
  /**
   * A `rampscan probe` transcript (P4) — reason 1's only measurement. Absent
   * leaves the trust-center gate unmeasured, as it was before P4.
   */
  trustCenterProbe?: TrustCenterProbe;
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

/** a URL in one spelling, so a trailing slash does not decide whether a probe measured this trust center */
function sameUrl(a: string, b: string): boolean {
  try {
    const norm = (u: string) => new URL(u).toString().replace(/\/$/, "");
    return norm(a) === norm(b);
  } catch {
    return a === b;
  }
}

/**
 * Reason 1. The most important section in the register: FedRAMP's FIRST
 * listed reason, a property of a live URL that no package reveals. Before P4
 * it was unmeasured by construction; now a `rampscan probe` transcript can
 * measure it, and only in the directions the transcript PROVES (P4's rule — a
 * negative is proven positively): a gate needs positive evidence, and "open"
 * needs a certification document that came back anonymously and validated.
 * Everything between stays unmeasured, with the probe's own reasons.
 */
function trustCenterSection(
  declared: OfferingConfig["trustCenter"],
  probe: TrustCenterProbe | undefined,
): RejectionRegisterSection {
  const section: RejectionRegisterSection = {
    section: "trust-center-gate",
    reason: 1,
    quote:
      "Your Trust Center requires acknowledgement and/or acceptance of a privacy policy, terms of service or non-disclosure agreement",
    ruleIds: ["CDS-TRC-USH", "CDS-TRC-PAC", "CDS-TRC-HMR", "CDS-CSO-UTC"],
    rows: [],
  };
  if (declared === undefined) {
    section.unmeasured =
      "this command does not fetch, and no trust center is declared, so there is no URL to probe — the row below is the rejection that is certain";
    section.rows.push({
      subject: "CDS-CSO-UTC",
      detail:
        "no trust center declared in the offering — there is not even a URL to probe, which the exports' problems channel already reports",
      ruleId: "CDS-CSO-UTC",
      rejection: true,
    });
    return section;
  }
  const authGate = declared.authenticationRequired === true;
  section.rows.push({
    subject: declared.url,
    detail: `declared${authGate ? " — and declares that it requires authentication, which is the gate #167 names" : ""}`,
    ...(authGate ? { rejection: true as const } : {}),
  });

  if (probe === undefined) {
    section.unmeasured =
      `this command does not fetch — whether a gate stands in front of ${declared.url} is not a property of any file it reads. ` +
      `Run \`rampscan probe ${declared.url} --document <certification-document-url> --out probe.json\` and pass ` +
      `--trust-center-probe probe.json — until then this is the reason FedRAMP listed first and the one rampscan ` +
      `measures least, which is worth saying out loud rather than scoring`;
    return section;
  }
  if (!sameUrl(probe.trust_center, declared.url)) {
    section.unmeasured =
      `the probe transcript is of ${probe.trust_center}, but the offering declares ${declared.url} — a probe of a ` +
      `different URL measures a different trust center, so reason 1 stays unmeasured`;
    return section;
  }

  const when = `probed ${probe.probed_at}`;
  if (probe.outcome === "gated") {
    // Reason 1 is ACCEPTANCE. A click-through is the rejection itself; a
    // login is a rejection only when the offering declared there was none,
    // because then the package states something false about its own
    // repository. A declared login is permitted — and behind it this probe
    // cannot see whether a click-through waits, so the section stays
    // unmeasured rather than clean.
    let hiddenBehindLogin = false;
    for (const t of probe.targets.filter((t) => t.outcome === "gated")) {
      const clickThrough = t.gate === "click-through";
      const undeclaredLogin = t.gate === "authentication" && !authGate;
      if (!clickThrough && !undeclaredLogin) hiddenBehindLogin = true;
      section.rows.push({
        subject: t.url,
        detail:
          `${t.role}, ${t.gate}: ${t.reasons.join("; ")} (${when})` +
          (undeclaredLogin
            ? " — the offering declares authenticationRequired: false, and an anonymous reader was refused"
            : "") +
          (!clickThrough && !undeclaredLogin
            ? " — authentication is declared, which FedRAMP permits with access instructions"
            : ""),
        ...(clickThrough || undeclaredLogin ? { rejection: true as const } : {}),
      });
    }
    if (hiddenBehindLogin) {
      section.unmeasured =
        "a declared login stands in front of the data, and whether acceptance of terms or an NDA waits behind it " +
        "is not visible to an anonymous probe";
    }
    section.note = "gated on positive evidence — each row names what the anonymous fetch met";
    return section;
  }
  if (probe.outcome === "open") {
    const open = probe.targets.filter((t) => t.outcome === "open");
    for (const t of open) {
      section.rows.push({
        subject: t.url,
        detail: `reached anonymously and validates against ${t.schema} (sha256 ${t.sha256?.slice(0, 12)}…, ${when})`,
      });
    }
    section.note =
      `measured: ${open.length} named certification document(s) came back to an anonymous GET with no gate. ` +
      `That proves those documents, not every document the trust center holds — a gate in front of one it was ` +
      `not pointed at is not ruled out`;
    return section;
  }
  section.unmeasured =
    `the probe (${when}) found no gate and proved no document open: ` +
    probe.targets.map((t) => `${t.url} — ${t.reasons.join("; ")}`).join(" | ");
  return section;
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
  // The most important section in the register. It is FedRAMP's FIRST listed
  // reason and a property of a live URL that no package reveals, so this
  // command measures it only from a `rampscan probe` transcript (P4, #213) and
  // prints it as unmeasured otherwise — a register that omitted it would be a
  // vacuous pass on the most likely rejection.
  const declaredTrustCenter = input.offering?.trustCenter;
  sections.push(trustCenterSection(declaredTrustCenter, input.trustCenterProbe));

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

  // ---- reason 3, the rule half: a coverage diff over the SDR (§9) --------
  //
  // `SDR-CSO-FRR` requires a row per applicable rule, and its schema makes
  // `Not Implemented` a valid status. So the question is NOT "can this
  // appliance verify rule R" — that question is unanswerable for most of the
  // rule set and is what the cancelled `outside` set was trying to answer. The
  // question is "does the submitted document answer rule R", which is a diff.
  //
  // Two axes, kept apart (§9.3). Axis A is FedRAMP's: answered or omitted.
  // Axis B is this appliance's: what it can independently check. Conflating
  // them is what let `computed` excuse a row FedRAMP still wants.
  const source: "sdr" | "ruleCoverage" | null =
    input.sdr !== undefined ? "sdr" : coverage.size > 0 ? "ruleCoverage" : null;
  const answers: ReadonlySet<string> =
    input.sdr !== undefined ? input.sdr.ruleIds : new Set(coverage.keys());

  const states: ReasonThreeStates = {
    answered: 0,
    omitted: 0,
    verifiable: 0,
    computedButOmitted: 0,
  };
  const omitted: RejectionRow[] = [];
  // the fallback's own breakdown: #167 asks for "say so and tell us why", and
  // the two arms of `ruleCoverage` are which of those a provider used
  let declaredAddressed = 0;
  let declaredNotImplemented = 0;
  for (const declared of coverage.values()) {
    if (declared.status === "addressed") declaredAddressed += 1;
    else declaredNotImplemented += 1;
  }
  for (const rule of addressable) {
    const computes = COMPUTED_RULES[rule.id] !== undefined;
    if (answers.has(rule.id)) {
      states.answered += 1;
      if (computes) states.verifiable += 1;
      continue;
    }
    states.omitted += 1;
    // The §9.3 defect, now reported rather than excused: this appliance holds
    // evidence for the rule and the document has nowhere to put it.
    const detail = computes
      ? `${rule.name} — omitted, and this appliance computes it (${COMPUTED_RULES[rule.id]}), so the evidence exists and the row to carry it does not`
      : rule.name;
    if (computes) states.computedButOmitted += 1;
    const row = ruleRow(rule, cls, detail);
    // A rejection this appliance can stand behind: the rule is applicable at
    // this class and the submitted document has no row for it. That is reason
    // 3's own defect, read off the artifact FedRAMP reads.
    omitted.push(source === "sdr" ? { ...row, rejection: true as const } : row);
  }

  const ruleSection: RejectionRegisterSection = {
    section: "unaddressed-rules",
    reason: 3,
    quote:
      "Remember that ALL MUSTs and SHOULDs applicable to your class need to be addressed. If you don't have something implemented, say so and tell us why, don't just omit the KSI or rule altogether",
    ruleIds: ["SDR-CSO-FRR", "FRC-CSX-VVK", "FRC-CSX-MAS"],
    // The unresolvable declarations lead, ahead of the queue: the renderer
    // prints the first rows in full and groups the tail, and a typo'd rule id
    // buried under a hundred queue rows is a finding nobody reads.
    rows: [...unresolvableDeclarations],
  };

  if (source === null) {
    // Not a pass, and not an accusation either. A bare checkout is not a
    // submission: with no Security Decision Record and no declared coverage
    // there is no answer to diff against, and printing every applicable rule
    // as a rejection would be the false accusation at scale §4b warned about
    // — arrived at from the other direction, by measuring nothing and
    // reporting it as everything.
    ruleSection.unmeasured =
      `no Security Decision Record was read, so which of the ${addressable.length} rules addressable at class ${cls} the package answers is unknown — ` +
      "pass --sdr <security-decision-record.json>, the document SDR-CSO-FRR obliges and the one FedRAMP reads";
    ruleSection.note =
      `${addressable.length} rules are addressable at class ${cls}` +
      (register.applicabilityUnstated.length > 0
        ? `, including the rules of ${register.applicabilityUnstated.join(", ")}, whose subsets declare no applicability at all and which are therefore counted as owed`
        : "") +
      `. ${Object.keys(COMPUTED_RULES).length} this appliance computes for itself, which is evidence to put in a row and is not the row`;
  } else {
    ruleSection.states = states;
    ruleSection.rows.push(...omitted);
    ruleSection.note =
      `${addressable.length} rules are addressable at class ${cls}` +
      (register.applicabilityUnstated.length > 0
        ? `, including the rules of ${register.applicabilityUnstated.join(", ")}, whose subsets declare no applicability at all and which are therefore counted as owed`
        : "") +
      (source === "sdr"
        ? `. Read against the Security Decision Record at ${input.sdr?.path}: ${states.answered} answered, ${states.omitted} omitted. ` +
          `An omitted row is the rejection #167 reason 3 names — the schema's own status enum admits "Not Implemented", so declaring a rule unimplemented is compliance with SDR-CSO-FRR and saying nothing is not. ` +
          `This appliance does NOT check whether an answer is true: it checks that one exists. ` +
          `Of the answered, ${states.verifiable} are rules it can independently verify. ` +
          (states.computedButOmitted > 0
            ? `${states.computedButOmitted} omitted rule(s) are ones it computes anyway, so the evidence exists and the document has no row to carry it. `
            : "")
        : `. No Security Decision Record was read, so this is the offering's declared ruleCoverage standing in for it — a rampscan-local fallback, not the artifact submitted to FedRAMP: ${states.answered} declared, ${states.omitted} undeclared. ` +
          `${declaredAddressed} declared addressed by citation and ${declaredNotImplemented} declared not implemented with a reason — ` +
          `which #167 asks for explicitly and which this appliance does NOT verify: it checks that an answer exists, never that it is true. ` +
          `These rows are NOT counted as rejections, because a provider may hold a complete SDR this run never saw. Pass --sdr to measure the document itself. `) +
      (declaredOverComputed.length > 0
        ? `${declaredOverComputed.length} declaration(s) name a rule this appliance computes (${declaredOverComputed.sort().join(", ")}), which does not move the rule: a declaration is not a measurement, and a measurement is not a submitted row. `
        : "") +
      (declaredNotAddressable.length > 0
        ? `${declaredNotAddressable.length} declaration(s) name a rule class ${cls} does not oblige (${declaredNotAddressable.sort().join(", ")}), counted here against no denominator. `
        : "");
  }
  sections.push(ruleSection);
  // ---- reason 3, the KSI half ------------------------------------------
  const ksiSection: RejectionRegisterSection = {
    section: "unaddressed-ksis",
    reason: 3,
    quote: "don't just omit the KSI or rule altogether",
    ruleIds: ["FRC-CSX-VVK", "SDR-CSX-KSI"],
    rows: [],
  };
  // §9.6: the SDR carries BOTH halves of reason 3, and this half had the same
  // defect the rule half did. It reported "no validation method derives — the
  // KSI is omitted rather than declared unimplemented", which asserts an
  // omission from the PACKAGE on the strength of a fact about rampscan's own
  // method derivation. A provider whose SDR carries all 46
  // `keySecurityIndicators` rows would have been told 28 were omitted.
  //
  // So the omission is read off the document, exactly as the rule half is, and
  // the method count stays on axis B where it belongs — it is what this
  // appliance can independently verify, never what the provider owes.
  if (input.sdr !== undefined) {
    const obliged = (input.ksis?.rows ?? []).filter((r) => !r.optional);
    const claimed = input.sdr.ksiIds;
    for (const row of obliged) {
      if (claimed.has(row.ksi)) continue;
      ksiSection.rows.push({
        subject: row.ksi,
        detail:
          "no row in the record's keySecurityIndicators — the KSI is omitted rather than declared unimplemented, and the schema's status enum admits \"Not Implemented\"",
        rejection: true,
      });
    }
    const answered = obliged.length - ksiSection.rows.length;
    const noMethod = obliged.filter((r) => r.methods === 0 && claimed.has(r.ksi)).length;
    ksiSection.ruleIds = ["SDR-CSX-KSI", "FRC-CSX-VVK"];
    ksiSection.note =
      (input.ksis === undefined
        ? `the KSI register was not computed, so the catalog's obliged set is unknown and only the ${claimed.size} row(s) the record claims can be counted`
        : `${input.ksis.rows.length} KSI(s) in the catalog, ${obliged.length} obliged at class ${cls}: ${answered} answered by the record, ${ksiSection.rows.length} omitted`) +
      (noMethod > 0
        ? `. ${noMethod} of the answered have no automated validation method here, which is this appliance's gap to close and not an omission from the package`
        : "");
  } else if (input.ksis === undefined) {
    ksiSection.unmeasured =
      "the KSI register was not computed for this run — it needs a catalog and a frontier, and an empty list here would read as full coverage";
  } else {
    // No record to read. The method floor is still worth printing — it is the
    // number this appliance is best at — but it is axis B, so it is NOT a
    // rejection: a KSI with no method here may be fully declared in an SDR
    // this run never saw.
    //
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
        detail: "no automated validation method derives here — whether the package declares it is unknown without an SDR",
      });
    }
    const optionalBare = input.ksis.rows.filter((r) => r.optional && r.methods === 0).length;
    ksiSection.unmeasured =
      "no Security Decision Record was read, so whether the package omits these KSIs is unknown — pass --sdr; the rows below are this appliance's own method gap, not the provider's omission";
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
    addressable: addressable.length,
    computed: addressable.filter((r) => COMPUTED_RULES[r.id] !== undefined).length,
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
        `    ${section.states.answered} answered · ${red(String(section.states.omitted))} omitted` +
          (section.states.verifiable > 0
            ? ` · ${section.states.verifiable} independently verifiable`
            : "") +
          (section.states.computedButOmitted > 0
            ? ` · ${red(String(section.states.computedButOmitted))} computed but omitted`
            : ""),
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
        `An unmeasured section is not a pass` +
        (view.sections.some((sec) => sec.section === "trust-center-gate" && sec.unmeasured !== undefined)
          ? `: reason 1 is FedRAMP's first — measure it with \`rampscan probe\` and --trust-center-probe`
          : ""),
    ),
  );
  return lines.join("\n");
}
