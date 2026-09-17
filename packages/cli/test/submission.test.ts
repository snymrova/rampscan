import { readFile, readdir } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { join, dirname } from "node:path";
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

  it("accounts for every addressable rule in exactly one of the four states", async () => {
    const r = await register();
    const view = await buildRejectionRegister({ register: r, offeringClass: "b" });
    const section = view.sections.find((s) => s.section === "unaddressed-rules");
    const states = section?.states;
    expect(states).toBeDefined();
    const total = states!.computed + states!.declared + states!.outside + states!.unaddressed;
    expect(total).toBe(addressableRules(r, "b").length);
    expect(total).toBe(129);
    // 13 rules have a surface; the other 116 have nowhere yet to be declared
    expect(states).toEqual({ computed: 13, declared: 0, outside: 0, unaddressed: 116 });
  });

  /**
   * The exit-code decision, pinned so it cannot regress into either failure
   * mode by accident. §4b: reporting 116 unaddressed rules as rejections is a
   * false accusation at scale — the appliance cannot tell "the provider is
   * silent" from "the provider said so somewhere this appliance does not
   * read" until P2-2 gives them a place to say it. Reporting them as fine is
   * the vacuous pass. So they are counted, named, printed loud, and are not
   * rejections; and the note says why in the register itself.
   */
  it("counts unaddressed rules loudly without calling them rejections", async () => {
    const view = await buildRejectionRegister({ register: await register(), offeringClass: "b" });
    const section = view.sections.find((s) => s.section === "unaddressed-rules");
    expect(section?.rows).toHaveLength(116);
    expect(section?.rows.filter((row) => row.rejection === true)).toEqual([]);
    expect(section?.note).toContain("UPPER BOUND");
    expect(section?.note).toContain("P2-1");
    expect(section?.note).toContain("P2-2");
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
      "unaddressed-ksis",
      "missing-example",
      "schema-invalid",
      "assessment-content",
    ]);
    expect(view.unmeasured).toBe(5);
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
    const offering = OfferingConfig.parse({
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
    });
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
    expect(text).toContain("13 computed · 0 declared · 0 outside · 116 unaddressed");
    expect(text).toContain("unmeasured:");
    expect(text).toContain("FedRAMP/community#167");
    // the tail is grouped by document rather than truncated: a reader needs to
    // know where the remaining rules are
    expect(text).toMatch(/… 104 more: /);
    expect(text).toContain("CDS×16");
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
