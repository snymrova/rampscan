import { execFile } from "node:child_process";
import { mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { join, dirname } from "node:path";
import { promisify } from "node:util";
import { describe, expect, it } from "vitest";
import { addressableRules, loadRuleRegister, type RuleRegister } from "@rampscan/dataset";
import { OfferingConfig } from "@rampscan/schema";
import {
  buildOngoingCertificationReport,
  buildPackageOverview,
} from "../src/fedramp-exports.js";
import {
  COMPUTED_RULES,
  PROBLEM_RULE_IDS,
  buildRejectionRegister,
  renderRejectionRegister,
} from "../src/submission.js";
import { readSdrCoverage } from "../src/sdr.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "../../..");
const rulesFile = join(root, "docs/context/fedramp-rules/fedramp-consolidated-rules.json");
const cliSrc = join(root, "packages/cli/src");
const PIN = "2026.09.13.02";
const RULE_ID = /\b[A-Z]{3}-[A-Z]{3}-[A-Z]{3}\b/g;

let cached: RuleRegister | undefined;
const register = async (): Promise<RuleRegister> => {
  cached ??= await loadRuleRegister(rulesFile, PIN);
  return cached;
};

/** every rule-id-shaped string in a source file, less the KSI indicators */
async function citedIn(file: string): Promise<Set<string>> {
  const text = await readFile(file, "utf8");
  return new Set((text.match(RULE_ID) ?? []).filter((id) => !id.startsWith("KSI-")));
}

/** an offering declaring the bare minimum the schema accepts, plus whatever a test needs */
function declaredOffering(extra: Record<string, unknown> = {}) {
  return OfferingConfig.parse({
    providerName: "Example Cloud Inc.",
    serviceName: "Example Evidence Plane",
    serviceAcronym: "EEP",
    serviceDescription: "A CI/CD evidence plane for FedRAMP 20x key security indicators.",
    certificationType: "20x",
    fedRampPackageId: "Example Cloud Inc. (EEP)",
    website: "https://example.com/eep",
    logo: "https://example.com/logo.svg",
    serviceType: ["SaaS"],
    deploymentModel: "Public Cloud",
    contactInformation: [
      { contactType: "Security", contactName: "Security Team", contactEmail: "security@example.com" },
      { contactType: "Sales", contactName: "Sales Team", contactPhone: "202-555-0123" },
    ],
    ...extra,
  });
}

/** an SDR carrying a row for every rule addressable at `cls` except the ids handed in */
async function sdrOmitting(
  r: RuleRegister,
  cls: "a" | "b" | "c" | "d",
  omit: readonly string[],
  ksis: readonly string[] = [],
): Promise<string> {
  const omitted = new Set(omit);
  const rows = addressableRules(r, cls)
    .filter((rule) => !omitted.has(rule.id))
    .map((rule) => ({
      frrID: rule.id,
      frrImplementationStatus: "Implemented",
      frrImplementation: [{ statement: "Addressed by the evidence plane." }],
    }));
  const dir = await mkdtemp(join(tmpdir(), "rampscan-sdr-"));
  const path = join(dir, "security-decision-record.json");
  await writeFile(
    path,
    JSON.stringify({
      certificationPackageOverviewUri: "https://example.com/cpo.json",
      fedRampRequirements: rows,
      keySecurityIndicators: ksis.map((id) => ({
        ksiId: id,
        ksiImplementationStatus: "Implemented",
        ksiImplementation: [],
        ksiValidation: [],
        ksiAssessment: [],
        ksiTests: [],
        ksiEvidence: [],
      })),
    }),
  );
  return path;
}

// P2-3 (docs/RESEARCH-REJECTION-LINTER.md §4). The rejection register: one
// section per reason FedRAMP published in community#167, each carrying the
// reason's own words and the rules that make it binding.
describe("the rejection register", () => {
  it("prints a section for every reason #167 lists, and the KSI half", async () => {
    const view = await buildRejectionRegister({ register: await register(), offeringClass: "b" });
    expect(view.sections.map((s) => s.section)).toEqual([
      "trust-center-gate",
      "unaddressed-rules",
      "unaddressed-ksis",
      "missing-example",
      "schema-invalid",
      "assessment-content",
    ]);
    // every reason numbered, every section carrying FedRAMP's own words
    expect(view.sections.map((s) => s.reason)).toEqual([1, 3, 3, 2, 4, 5]);
    for (const section of view.sections) expect(section.quote.length).toBeGreaterThan(20);
    // and every rule a section cites is a rule that exists at this pin
    const ids = new Set((await register()).rules.map((r) => r.id));
    for (const section of view.sections) {
      for (const id of section.ruleIds) expect(ids.has(id), `${section.section} cites ${id}`).toBe(true);
    }
  });

  /**
   * The most important assertion in this file. Reason 1 is the one FedRAMP
   * listed FIRST and the only one a local appliance cannot answer: whether a
   * gate stands in front of a trust center is a property of a live URL, not
   * of any file. So the section prints as unmeasured **always** — including
   * when a trust center is declared and declares no authentication — because
   * a register that quietly omitted it, or scored it clean from the config,
   * would be a vacuous pass on the most likely rejection (ground rule 7).
   */
  it("holds the trust-center gate unmeasured even when a trust center is declared", async () => {
    const r = await register();
    const bare = await buildRejectionRegister({ register: r, offeringClass: "b" });
    const withTc = await buildRejectionRegister({
      register: r,
      offeringClass: "b",
      offering: {
        trustCenter: { url: "https://trust.example.gov", authenticationRequired: false },
      } as never,
    });
    for (const view of [bare, withTc]) {
      const section = view.sections.find((s) => s.section === "trust-center-gate");
      expect(section?.unmeasured).toBeDefined();
      expect(section?.unmeasured).toContain("does not fetch");
    }
    // the declared URL is printed, so a reader knows what P4 will probe
    expect(withTc.sections[0]?.rows[0]?.subject).toBe("https://trust.example.gov");
    // and an undeclared trust center is a rejection the appliance CAN stand behind
    expect(bare.sections[0]?.rows[0]?.rejection).toBe(true);
  });

  // §9.4 P2-1c. With no SDR and no declared coverage there is nothing to diff
  // against, and printing all 129 applicable rules as rejections would be the
  // false accusation at scale reached from the other direction — measuring
  // nothing and reporting it as everything. The register already owns a
  // channel for exactly this, and reason 3 now uses it.
  it("leaves reason 3 unmeasured when no SDR and no declared coverage were supplied", async () => {
    const r = await register();
    const view = await buildRejectionRegister({ register: r, offeringClass: "b" });
    const section = view.sections.find((s) => s.section === "unaddressed-rules");
    expect(section?.unmeasured).toBeDefined();
    expect(section?.unmeasured).toContain("--sdr");
    expect(section?.states).toBeUndefined();
    // no rows, and above all no rejections against a checkout that never
    // claimed to be a submission
    expect(section?.rows.filter((row) => row.rejection === true)).toEqual([]);
    expect(addressableRules(r, "b").length).toBe(129);
    // and the note still states the denominator nobody publishes
    expect(section?.note).toContain("129 rules are addressable at class b");
  });

  /**
   * The exit-code decision, pinned so it cannot regress into either failure
   * mode by accident (§9.2). Against a real Security Decision Record an
   * omitted rule IS a rejection: `SDR-CSO-FRR` obliges a row per applicable
   * rule and the schema's own status enum admits "Not Implemented", so
   * declaring a rule unimplemented satisfies the rule and saying nothing does
   * not. No judgement about what a local appliance can see is involved —
   * which is why the reviewed `outside` set was the wrong artifact.
   */
  it("calls an omitted rule a rejection when there is an SDR to read", async () => {
    const r = await register();
    const path = await sdrOmitting(r, "b", ["MAS-CSO-FLO", "SCG-CSO-RSC"]);
    const view = await buildRejectionRegister({
      register: r,
      offeringClass: "b",
      sdr: await readSdrCoverage(path),
    });
    const section = view.sections.find((s) => s.section === "unaddressed-rules");
    expect(section?.unmeasured).toBeUndefined();
    expect(section?.rows.map((row) => row.subject)).toEqual(["MAS-CSO-FLO", "SCG-CSO-RSC"]);
    expect(section?.rows.every((row) => row.rejection === true)).toBe(true);
    expect(section?.states?.answered).toBe(127);
    expect(section?.states?.omitted).toBe(2);
    // the denominator still closes, and the note names the document it read
    expect(section!.states!.answered + section!.states!.omitted).toBe(
      addressableRules(r, "b").length,
    );
    expect(section?.note).toContain("Security Decision Record at");
    expect(section?.note).toContain("Not Implemented");
    // the four undeclared-applicability subsets are named where the denominator is
    expect(section?.note).toContain("FRC/CSX");
  });

  /**
   * §5 again, and this one was a live bug rather than a hypothetical: the
   * first draft filtered the KSI rows on `methods === 0` alone and reported
   * 33 where the KSI register's own summary said 28. A class leaves some
   * indicators optional, every meter in that register counts the OBLIGED rows
   * only (§13.7), and an optional KSI with no method is not an omission the
   * class obliges. The two numbers printed three lines apart in the same
   * section, which is how it was caught.
   */
  it("counts only the KSIs the class obliges, and agrees with the KSI register's own number", async () => {
    const ksis = {
      rows: [
        { ksi: "KSI-CNA-OFA", methods: 0, optional: false },
        { ksi: "KSI-CNA-RNT", methods: 0, optional: false },
        { ksi: "KSI-IAM-APM", methods: 2, optional: false },
        { ksi: "KSI-PIY-IMP", methods: 0, optional: true },
      ],
      summary: { noMethod: 2 },
    } as never;
    const view = await buildRejectionRegister({
      register: await register(),
      offeringClass: "b",
      ksis,
    });
    const section = view.sections.find((s) => s.section === "unaddressed-ksis");
    expect(section?.rows.map((r) => r.subject)).toEqual(["KSI-CNA-OFA", "KSI-CNA-RNT"]);
    // the row count IS the register's own obliged count — the whole point
    expect(section?.rows).toHaveLength(2);
    expect(section?.note).toContain("2 obliged at class b with no method");
    // and the optional one is accounted for rather than dropped in silence
    expect(section?.note).toContain("a further 1 the class leaves optional");
  });

  it("says unmeasured rather than clean for every section whose input is absent", async () => {
    const view = await buildRejectionRegister({ register: await register(), offeringClass: "b" });
    const unmeasured = view.sections.filter((s) => s.unmeasured !== undefined).map((s) => s.section);
    expect(unmeasured).toEqual([
      "trust-center-gate",
      "unaddressed-rules",
      "unaddressed-ksis",
      "missing-example",
      "schema-invalid",
      "assessment-content",
    ]);
    expect(view.unmeasured).toBe(6);
  });

  /**
   * §5 — one fact computed twice is a bug. The exports' `problems` channel
   * already holds rejection-shaped findings; the register reprojects them
   * under the reason each belongs to rather than recomputing them, and
   * deduplicates by the rule cited so a fact computed here and reported there
   * does not print twice in two wordings.
   */
  it("reprojects the exports' problems under the reason each belongs to", async () => {
    const view = await buildRejectionRegister({
      register: await register(),
      offeringClass: "b",
      problems: [
        "no next Ongoing Certification Report date declared — CCM-OCR-NRD requires it published",
        "no trust center declared — CDS-CSO-UTC makes a FedRAMP-compatible trust center the definitive source",
        "the application is 41 days old — FRC-APP-FCP wants it within 7",
        "a problem citing no rule at all, which belongs to nobody",
      ],
    });
    const rowsOf = (name: string) =>
      view.sections.find((s) => s.section === name)?.rows.map((r) => r.subject) ?? [];
    expect(rowsOf("missing-example")).toEqual(["CCM-OCR-NRD", "FRC-APP-FCP"]);
    // CDS-CSO-UTC is already the trust-center section's own computed row, so
    // the reprojected problem is dropped rather than printed a second time
    expect(rowsOf("trust-center-gate")).toEqual(["CDS-CSO-UTC"]);
    expect(view.sections.flatMap((s) => s.rows).filter((r) => r.detail.includes("belongs to nobody"))).toEqual([]);
  });

  /**
   * Drift guard one. `COMPUTED_RULES` is the numerator of reason 3, declared
   * rather than grepped at runtime — so a test greps instead, and fails in
   * BOTH directions: a rule that gains a surface without an entry would be
   * counted unaddressed while the tool answers it, and an entry whose surface
   * was deleted would be counted computed while nothing computes it.
   */
  it("keeps COMPUTED_RULES equal to the rules the shipped sources actually cite", async () => {
    const files = (await readdir(cliSrc)).filter(
      (f) => f.endsWith(".ts") && f !== "submission.ts",
    );
    const cited = new Set<string>();
    for (const file of files) for (const id of await citedIn(join(cliSrc, file))) cited.add(id);
    const ids = new Set((await register()).rules.map((r) => r.id));
    // a rule-id-shaped string that is not a rule is rampscan's own typo
    for (const id of cited) expect(ids.has(id), `${id} is cited in packages/cli/src but is no rule at this pin`).toBe(true);
    expect([...cited].sort()).toEqual(Object.keys(COMPUTED_RULES).sort());
    // and every entry names the surface that answers it, for a reader who asks why
    for (const [id, why] of Object.entries(COMPUTED_RULES)) {
      expect(why.length, `${id} has no surface named`).toBeGreaterThan(20);
    }
  });

  /**
   * Drift guard two, and behavioural rather than textual: it asks the exports
   * for their problems and checks the rules those STRINGS cite, because
   * `fedramp-exports.ts` also names rules in comments and in the documents it
   * builds, and a source grep would fail on prose that emits nothing.
   *
   * A problem added upstream of `PROBLEM_RULE_SECTIONS` would be reprojected
   * nowhere — which is exactly the bug the first draft of this module had,
   * dropping every citation while appearing to carry them all.
   */
  it("gives every rule the exports' problems actually cite a section to land in", async () => {
    // an offering that declares the minimum, so every absence-driven problem
    // in the channel fires at once
    const offering = declaredOffering();
    const exportInput = {
      offering,
      offeringClass: "b" as const,
      projectedAt: "2026-09-18T00:00:00.000Z",
      datasetVersion: PIN,
      methodRegisters: [],
      vulnerabilities: [],
      drift: [],
    };
    const problems = [
      ...buildPackageOverview(exportInput).problems,
      ...(buildOngoingCertificationReport(exportInput).export?.problems ?? []),
    ];
    expect(problems.length).toBeGreaterThan(0);

    const ids = new Set((await register()).rules.map((r) => r.id));
    const cited = new Set(
      problems.flatMap((p) => (p.match(RULE_ID) ?? []).filter((id) => !id.startsWith("KSI-"))),
    );
    expect(cited.size).toBeGreaterThan(0);
    for (const id of cited) {
      // a rule named in a problem that is no rule at this pin is rampscan's
      // own typo, and the register must not print it beside FedRAMP's reasons
      expect(ids.has(id), `a problem cites ${id}, which is no rule at this pin`).toBe(true);
      expect(
        PROBLEM_RULE_IDS.includes(id),
        `the problems channel cites ${id} with no section in PROBLEM_RULE_SECTIONS — it would reproject nowhere`,
      ).toBe(true);
    }

    // and end to end: those problems land in the register rather than vanish
    const view = await buildRejectionRegister({
      register: await register(),
      offeringClass: "b",
      problems,
    });
    const landed = view.sections.flatMap((s) => s.rows).filter((r) => r.ruleId !== undefined);
    // every cited rule is accounted for — CDS-CSO-UTC through the
    // trust-center section's own computed row, the rest reprojected — and
    // each appears exactly once, which is what the dedupe by rule buys
    expect(new Set(landed.map((r) => r.ruleId))).toEqual(cited);
    expect(landed).toHaveLength(cited.size);
  });

  it("renders every section, its quote and its unmeasured reason", async () => {
    const view = await buildRejectionRegister({ register: await register(), offeringClass: "b" });
    const text = renderRejectionRegister(view, false);
    expect(text).toContain("rampscan submission — the rejection register");
    // reason 3 is unmeasured in this fixture, so the counts line is absent
    expect(text).toContain("no Security Decision Record was read");
    expect(text).toContain("unmeasured:");
    expect(text).toContain("FedRAMP/community#167");
    // the tail is grouped by document rather than truncated: a reader needs to
    // know where the remaining rules are. Reason 3 only has rows to group once
    // there is an SDR to diff, so the grouping is asserted on that path.
    const r = await register();
    const omitAll = addressableRules(r, "b").map((rule) => rule.id);
    const withSdr = renderRejectionRegister(
      await buildRejectionRegister({
        register: r,
        offeringClass: "b",
        sdr: await readSdrCoverage(await sdrOmitting(r, "b", omitAll)),
      }),
      false,
    );
    expect(withSdr).toMatch(/… \d+ more: /);
    // and the grouping names the families, not just a count
    expect(withSdr).toMatch(/[A-Z]{3}×\d+/);
    // no ANSI when colour is off
    expect(text).not.toContain("[");
    expect(renderRejectionRegister(view, true)).toContain("[");
  });

  /**
   * The tail grouping keys on the segment that discriminates. An FRR id's is
   * its document (`CDS-TRC-USH` → CDS); a KSI id's first segment is always
   * `KSI`, so grouping 21 of them printed "KSI×21", which tells a reader
   * nothing at all. Theirs is the theme.
   */
  it("groups a long KSI tail by theme rather than by the word KSI", async () => {
    const rows = [
      ...Array.from({ length: 8 }, (_, i) => ({ ksi: `KSI-CNA-${i}`, methods: 0, optional: false })),
      ...Array.from({ length: 5 }, (_, i) => ({ ksi: `KSI-MLA-${i}`, methods: 0, optional: false })),
    ];
    const view = await buildRejectionRegister({
      register: await register(),
      offeringClass: "b",
      ksis: { rows, summary: { noMethod: rows.length } } as never,
    });
    const text = renderRejectionRegister(view, false);
    expect(text).toContain("… 1 more: MLA×1");
    expect(text).not.toContain("KSI×");
  });
});

// P2-2 (docs/RESEARCH-REJECTION-LINTER.md §4b). The declaration surface:
// #167's third reason is the only one that names its own remedy — "if you
// don't have something implemented, say so and tell us why" — and before this
// there was nowhere in a rampscan config to say it. These tests pin the four
// things that must not blur: a declaration counts, a declaration does not
// overwrite a measurement, a declaration of a rule that does not exist is a
// finding rather than a no-op, and a declaration the class does not oblige
// does not inflate the numerator.
describe("reason 3's declaration surface", () => {
  /**
   * The guard on `frrRuleId`. The schema refuses a ruleId that is not three
   * uppercase triplets, which is only safe while every rule id at the pin IS
   * one. A rule set that numbered rules differently would make a legitimate
   * declaration unparseable — and that must fail here, where it is our bug,
   * rather than in a provider's config, where it looks like theirs.
   */
  it("accepts every rule id the pinned rule set carries", async () => {
    const ids = (await register()).rules.map((r) => r.id);
    expect(ids.length).toBe(246);
    const offering = declaredOffering({
      ruleCoverage: ids.map((ruleId) => ({ ruleId, status: "addressed", citation: "SSP §1" })),
    });
    expect(offering.ruleCoverage).toHaveLength(246);
  });

  it("moves a declared rule out of unaddressed, whether addressed or declined", async () => {
    const r = await register();
    const view = await buildRejectionRegister({
      register: r,
      offeringClass: "b",
      // §4b's own two examples: neither is visible to a local appliance, and
      // both are exactly what #167 asks a provider to speak to rather than omit
      offering: declaredOffering({
        ruleCoverage: [
          {
            ruleId: "FRC-APP-MLF",
            status: "not-implemented",
            reason: "the offering is not yet listed in the FedRAMP Marketplace; the listing request is filed",
          },
          { ruleId: "FRC-APP-AFC", status: "addressed", citation: "application submitted 2026-09-02, ref A-1187" },
        ],
      }),
    });
    const section = view.sections.find((s) => s.section === "unaddressed-rules");
    // the arithmetic still closes on the denominator — two rules answered,
    // none created. As a FALLBACK: ruleCoverage is rampscan-local, so these
    // are not rejections (§9.4 P2-1d).
    expect(section?.states?.answered).toBe(2);
    expect(section?.states?.omitted).toBe(127);
    expect(section!.states!.answered + section!.states!.omitted).toBe(
      addressableRules(r, "b").length,
    );
    expect(section?.note).toContain("rampscan-local fallback");
    expect(section?.rows.filter((row) => row.rejection === true)).toEqual([]);
    expect(section?.rows.map((row) => row.subject)).not.toContain("FRC-APP-MLF");
    // and a declaration is not a verification: the note says which one it is
    expect(section?.note).toContain("1 declared addressed by citation and 1 declared not implemented");
    expect(section?.note).toContain("does NOT verify");
  });

  /**
   * SPEC §12.4 rule 3, arriving from a new direction: a declared value has no
   * standing where a computed one exists. `FRC-CSX-VVK` is the method floor —
   * rampscan measures it — so a config declaring it addressed does not move it
   * into `declared`, and the overlap is reported rather than silently
   * resolved in favour of whichever answer was read last.
   */
  it("keeps a computed rule computed when the offering declares it too", async () => {
    const view = await buildRejectionRegister({
      register: await register(),
      offeringClass: "b",
      offering: declaredOffering({
        ruleCoverage: [
          { ruleId: "FRC-CSX-VVK", status: "addressed", citation: "every KSI has two automated methods" },
        ],
      }),
    });
    const section = view.sections.find((s) => s.section === "unaddressed-rules");
    expect(section?.note).toContain("FRC-CSX-VVK");
    expect(section?.note).toContain("a declaration is not a measurement");
  });

  /**
   * A mistyped rule id is the failure mode this surface introduces, so it is
   * the one it must catch: the config reads as answered while the rule the
   * provider meant is still unaddressed. It prints as a rejection, and it
   * prints FIRST — the renderer shows the leading rows in full and groups the
   * tail, and a finding buried under 116 queue rows is a finding nobody reads.
   */
  it("reports a declaration of a rule that does not exist, at the head of the queue", async () => {
    // the same offering, with and without the mistyped declaration, so the one
    // extra rejection is the declaration's and nothing else's
    const bare = await buildRejectionRegister({
      register: await register(),
      offeringClass: "b",
      offering: declaredOffering(),
    });
    const view = await buildRejectionRegister({
      register: await register(),
      offeringClass: "b",
      offering: declaredOffering({
        ruleCoverage: [{ ruleId: "FRC-APP-MFL", status: "addressed", citation: "listed in the marketplace" }],
      }),
    });
    const section = view.sections.find((s) => s.section === "unaddressed-rules");
    expect(section?.rows[0]?.subject).toBe("FRC-APP-MFL");
    expect(section?.rows[0]?.rejection).toBe(true);
    expect(section?.rows[0]?.detail).toContain("no rule with this id exists");
    expect(view.rejections).toBe(bare.rejections + 1);
    // the typo answered nothing, so nothing moved out of omitted either
    expect(section?.states?.answered).toBe(0);
    expect(renderRejectionRegister(view, false)).toContain("FRC-APP-MFL");
  });

  /**
   * Harmless over-declaration, counted and not punished. `CMU-CSO-UVM` is
   * addressable at class c and not at class b, so a provider declaring toward
   * c and scanning at b has said something true about a rule this class does
   * not oblige. It is named in the note and kept out of a denominator it is
   * not in — the same discipline as the KSI arm's optional indicators.
   */
  it("counts a declaration the class does not oblige without letting it into the numerator", async () => {
    const r = await register();
    expect(addressableRules(r, "b").some((x) => x.id === "CMU-CSO-UVM")).toBe(false);
    expect(addressableRules(r, "c").some((x) => x.id === "CMU-CSO-UVM")).toBe(true);
    const view = await buildRejectionRegister({
      register: r,
      offeringClass: "b",
      offering: declaredOffering({
        ruleCoverage: [{ ruleId: "CMU-CSO-UVM", status: "addressed", citation: "the class c uptime meter" }],
      }),
    });
    const section = view.sections.find((s) => s.section === "unaddressed-rules");
    expect(section?.states?.answered).toBe(0);
    expect(section?.rows.filter((row) => row.rejection === true)).toEqual([]);
    expect(section?.note).toContain("class b does not oblige (CMU-CSO-UVM)");
  });
});

/**
 * The one thing the unit suite above structurally cannot see: whether
 * `main.ts` hands the register anything to work with.
 *
 * This test exists because it did not. `buildRejectionRegister` reprojects the
 * exports' `problems` channel rather than recomputing it (§5), every arm of
 * that reprojection was tested, and the shipped command passed no `problems`
 * at all — so an undeclared next-OCR date reached nobody, and three sections
 * carried only what they could compute for themselves while looking complete.
 * A declared-but-unwired channel is invisible to a unit test by construction,
 * so the guard has to run the command.
 *
 * It runs against a fixture config in a temp directory rather than this
 * repository's own, so it is asserting the wiring and not the self-scan's
 * current state: an offering that gains a next-OCR date should not break it.
 */
describe("the shipped command", () => {
  it("hands the register the exports' problems, not just its own computations", async () => {
    const dir = await mkdtemp(join(tmpdir(), "rampscan-submission-"));
    await writeFile(
      join(dir, "rampscan.config.json"),
      // no `nextOngoingCertificationReportDate`, no assessor, no trust center:
      // three problems the exports' channel reports and this register must
      // carry under the reason each belongs to
      JSON.stringify({ offering: declaredOffering() }, null, 2),
    );
    let stdout: string;
    try {
      // exit 1 is expected — the register exits 1 on the rejections it can
      // stand behind, and this fixture earns several
      ({ stdout } = await promisify(execFile)(
        join(root, "node_modules/.bin/tsx"),
        [
          "packages/cli/src/main.ts",
          "submission",
          dir,
          "--json",
          "--ledger",
          join(tmpdir(), "no-ledger-here"),
        ],
        { cwd: root, env: { ...process.env, NO_COLOR: "1" }, maxBuffer: 16 * 1024 * 1024 },
      ));
    } catch (cause) {
      const out = (cause as { stdout?: string }).stdout;
      if (typeof out !== "string" || out.length === 0) throw cause;
      stdout = out;
    }
    const view = JSON.parse(stdout) as {
      sections: { section: string; rows: { subject: string; ruleId?: string }[] }[];
    };
    const rowsOf = (name: string) =>
      view.sections.find((s) => s.section === name)?.rows.map((r) => r.subject) ?? [];
    // reprojected, each under the reason it belongs to rather than all in one place
    expect(rowsOf("missing-example")).toContain("CCM-OCR-NRD");
    expect(rowsOf("assessment-content")).toContain("CDS-CSO-PUB");
    // and the trust-center section still prints ONE row for CDS-CSO-UTC: the
    // section computes it from the offering and the channel reports it too,
    // which is the dedupe by rule doing its job end to end
    expect(rowsOf("trust-center-gate")).toEqual(["CDS-CSO-UTC"]);
    await rm(dir, { recursive: true, force: true });
  }, 60_000);
});

// P2-1 (docs/RESEARCH-REJECTION-LINTER.md §9). Reason 3 is a coverage diff over
// the Security Decision Record, not a judgement about what a local appliance
// can verify. `SDR-CSO-FRR` requires a row per applicable rule and its schema
// makes "Not Implemented" a valid status, so the defect FedRAMP rejects on is
// a MISSING ROW.
describe("P2-1 — the SDR coverage diff", () => {
  // THE DEFECT §9.3 NAMES. `computed` is a fact about rampscan (axis B). It is
  // being used to excuse a row on axis A, which is FedRAMP's question. A
  // provider whose SDR omits FRC-CSX-VVK is reported clean today because this
  // appliance happens to compute that rule itself — but rampscan's computation
  // is evidence to put IN the row, it is not the row. Ground rule 7, arriving
  // from the direction §5 was not watching.
  it("reports a computed rule the SDR omits", async () => {
    const path = await sdrOmitting(await register(), "b", ["FRC-CSX-VVK"]);
    const view = await buildRejectionRegister({
      register: await register(),
      offeringClass: "b",
      sdr: await readSdrCoverage(path),
    });
    const section = view.sections.find((s) => s.section === "unaddressed-rules");
    expect(section?.rows.map((r) => r.subject)).toContain("FRC-CSX-VVK");
    // and the row says why it matters: the evidence exists, the row does not
    const row = section?.rows.find((r) => r.subject === "FRC-CSX-VVK");
    expect(row?.detail).toContain("this appliance computes it");
    expect(row?.rejection).toBe(true);
    expect(section?.states?.computedButOmitted).toBe(1);
  });

  /** write an SDR body verbatim, for the refusals that need a malformed document */
  async function sdrFile(body: unknown): Promise<string> {
    const dir = await mkdtemp(join(tmpdir(), "rampscan-sdr-raw-"));
    const path = join(dir, "sdr.json");
    await writeFile(path, JSON.stringify(body));
    return path;
  }

  // The P2-2 refusal arriving from the document side. A KSI indicator is the
  // same shape as a rule id, so counting one as a rule row would mark a rule
  // answered that is still omitted — a declaration talking its way past the
  // very thing this register measures.
  it("refuses a KSI claimed in the rule array, and does not let it answer a rule", async () => {
    const path = await sdrFile({
      certificationPackageOverviewUri: "https://example.com/cpo.json",
      fedRampRequirements: [
        { frrID: "KSI-CNA-OFA", frrImplementation: [] },
        { frrID: "MAS-CSO-FLO", frrImplementation: [] },
        { frrID: "MAS-CSO-FLO", frrImplementation: [] },
        { frrID: "FRC-APP-MFL", frrImplementation: [] },
      ],
    });
    const sdr = await readSdrCoverage(path);
    expect([...sdr.ruleIds]).toEqual(["MAS-CSO-FLO", "FRC-APP-MFL"]);
    const said = sdr.problems.map((p) => p.subject);
    expect(said).toEqual(["KSI-CNA-OFA", "MAS-CSO-FLO"]);
    expect(sdr.problems[0]?.detail).toContain("Key Security Indicator");
    // the duplicate is named, and counted once
    expect(sdr.problems[1]?.detail).toContain("more than once");
  });

  // Not an SDR at all. `fedRampRequirements` is required by the schema and IS
  // reason 3's rule half, so a document without it cannot be read for coverage
  // — and reading it as "covers nothing" would accuse a provider of omitting
  // all 129 rules on the strength of a wrong file path.
  it("refuses a document with no fedRampRequirements rather than reading it as empty", async () => {
    const path = await sdrFile({ certificationPackageOverviewUri: "https://example.com/cpo.json" });
    await expect(readSdrCoverage(path)).rejects.toThrow(/no fedRampRequirements array/);
  });

  // §9.6: the same document carries the KSI half, and it had the same defect —
  // it asserted an omission from the package on the strength of rampscan's own
  // method derivation.
  it("reads the KSI half off the record, not off the method floor", async () => {
    const r = await register();
    const ksis = {
      rows: [
        { ksi: "KSI-CNA-OFA", methods: 0, optional: false },
        { ksi: "KSI-CNA-RNT", methods: 0, optional: false },
        { ksi: "KSI-IAM-APM", methods: 2, optional: false },
      ],
      summary: { noMethod: 2 },
    } as never;
    // the record answers both method-less KSIs and omits the one rampscan can verify
    const path = await sdrOmitting(r, "b", [], ["KSI-CNA-OFA", "KSI-CNA-RNT"]);
    const view = await buildRejectionRegister({
      register: r,
      offeringClass: "b",
      ksis,
      sdr: await readSdrCoverage(path),
    });
    const section = view.sections.find((s) => s.section === "unaddressed-ksis");
    // KSI-IAM-APM is the omission: it has a method here and no row there
    expect(section?.rows.map((row) => row.subject)).toEqual(["KSI-IAM-APM"]);
    // and the two with no method are NOT accused — that is rampscan's gap
    expect(section?.note).toContain("this appliance's gap to close");
  });

  // Without a record the KSI half must not accuse either: a KSI with no method
  // here may be fully declared in an SDR this run never saw.
  it("stops calling a method-less KSI an omission when there is no record", async () => {
    const ksis = {
      rows: [{ ksi: "KSI-CNA-OFA", methods: 0, optional: false }],
      summary: { noMethod: 1 },
    } as never;
    const view = await buildRejectionRegister({
      register: await register(),
      offeringClass: "b",
      ksis,
    });
    const section = view.sections.find((s) => s.section === "unaddressed-ksis");
    expect(section?.rows.map((row) => row.subject)).toEqual(["KSI-CNA-OFA"]);
    expect(section?.rows.filter((row) => row.rejection === true)).toEqual([]);
    expect(section?.unmeasured).toContain("--sdr");
  });
});
