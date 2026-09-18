import { describe, expect, it } from "vitest";
import { DeclaredRuleCoverage, OfferingConfig } from "../src/index.js";

// P2-2 (docs/RESEARCH-REJECTION-LINTER.md §4b). `ruleCoverage` is where
// FedRAMP/community#167's third reason gets its answer: "ALL MUSTs and SHOULDs
// applicable to your class need to be addressed. If you don't have something
// implemented, say so and tell us why, don't just omit the KSI or rule
// altogether." So *declining* a rule with a reason is a pass, and omitting it
// is the rejection — which makes every refusal in this file load-bearing, and
// the refusal of an escape hatch the most load-bearing of all.

const addressed = {
  ruleId: "FRC-APP-AFC",
  status: "addressed",
  citation: "application submitted 2026-09-02, ref A-1187",
};
const declined = {
  ruleId: "FRC-APP-MLF",
  status: "not-implemented",
  reason: "the offering is not yet listed in the FedRAMP Marketplace; the listing request is filed",
};

describe("rule coverage — the two answers a provider may give", () => {
  it("baseline: both statuses parse as written", () => {
    expect(DeclaredRuleCoverage.parse(addressed)).toEqual(addressed);
    expect(DeclaredRuleCoverage.parse(declined)).toEqual(declined);
  });

  /**
   * THE REFUSAL THIS FILE EXISTS FOR. §4b: the `outside` state — a rule
   * structurally invisible to a local appliance — is rampscan's own reviewed
   * set (P2-1), written down with a reason per rule the way the AWS action
   * allowlist records a refused action. It is not a thing a provider declares
   * about themselves. A config key that let a rule drift into `outside`, or be
   * declared inapplicable, would be the one escape hatch capable of emptying
   * reason 3 entirely: 129 rules, all "not applicable", nothing accused.
   *
   * The type has no slot for one, so this is a structural refusal rather than
   * a validation rule someone can argue with — and these assertions are what
   * would catch a well-meaning future edit adding the slot back.
   */
  it("has no slot for declaring a rule inapplicable, outside, or waived", () => {
    for (const status of ["not-applicable", "outside", "waived", "n/a", "exempt"]) {
      expect(() => DeclaredRuleCoverage.parse({ ...addressed, status })).toThrow();
    }
    for (const key of ["outside", "notApplicable", "applicability", "waiver"]) {
      expect(() => DeclaredRuleCoverage.parse({ ...addressed, [key]: true })).toThrow();
    }
  });

  it("requires the answer that matches the status, and refuses the other one", () => {
    // "addressed" with a reason instead of a citation says nothing about where
    expect(() => DeclaredRuleCoverage.parse({ ruleId: "FRC-APP-AFC", status: "addressed", reason: "we did it" })).toThrow();
    // and "not-implemented" with a citation points at something that is not there
    expect(() =>
      DeclaredRuleCoverage.parse({ ruleId: "FRC-APP-MLF", status: "not-implemented", citation: "SSP §4" }),
    ).toThrow();
    // neither is not an answer at all
    expect(() => DeclaredRuleCoverage.parse({ ruleId: "FRC-APP-MLF", status: "not-implemented" })).toThrow();
  });

  /**
   * "Silence is neither" (§4b), applied to a string. #167 asks a provider to
   * say *why*, so a reason of "TBD" has not answered it and a citation of
   * "N/A" points at nothing. Refused at the declaration, where the person who
   * typed one is still looking at it — ground rule 7 in a config file.
   */
  it("refuses the null answers, which are the omission in one word", () => {
    for (const nothing of ["n/a", "N/A", "none", "TBD", "todo", "pending", "unknown", "-", "?", "  none  "]) {
      expect(() => DeclaredRuleCoverage.parse({ ...declined, reason: nothing }), nothing).toThrow();
      expect(() => DeclaredRuleCoverage.parse({ ...addressed, citation: nothing }), nothing).toThrow();
    }
    // a real reason that merely contains one of those words is fine
    expect(() =>
      DeclaredRuleCoverage.parse({ ...declined, reason: "none of our services touch this control plane yet" }),
    ).not.toThrow();
  });

  /**
   * The id is checked here so a typo fails at the config — but a typo that is
   * still well-shaped (`FRC-APP-MFL` for `FRC-APP-MLF`) cannot be caught by a
   * regex, so `rampscan submission` reports one that resolves to no rule as a
   * rejection. Both halves are needed: this one rejects nonsense, that one
   * rejects a plausible id that answers nothing.
   */
  it("refuses an id that is not shaped like an FRR rule id", () => {
    for (const ruleId of ["frc-app-afc", "FRC-APP", "FRC_APP_AFC", "FRC-APP-AFCX", ""]) {
      expect(() => DeclaredRuleCoverage.parse({ ...addressed, ruleId }), ruleId).toThrow();
    }
  });

  /**
   * A KSI indicator is the same shape as a rule id, so the regex above accepts
   * it and a separate refusal has to name it. This is the most likely mistake
   * anyone will make with this block, and the only one that would matter:
   * reason 3 has two halves, and the KSI half is the one rampscan MEASURES.
   * Accepting `KSI-CNA-OFA` here would let a provider declare their way past
   * the artifact plane and the method floor — the part of #167 this appliance
   * is actually good at.
   */
  it("refuses a KSI indicator, which is the same shape and the wrong surface", () => {
    expect(() => DeclaredRuleCoverage.parse({ ...addressed, ruleId: "KSI-CNA-OFA" })).toThrow(
      /KSI indicator, not an FRR rule/,
    );
  });
});

const offering = {
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
    { contactType: "Security", contactName: "Security Team" },
    { contactType: "Sales", contactName: "Sales Team" },
  ],
};

describe("rule coverage — the block on the offering", () => {
  it("baseline: the block is optional, and an offering without one parses", () => {
    expect(OfferingConfig.parse(offering).ruleCoverage).toBeUndefined();
    expect(OfferingConfig.parse({ ...offering, ruleCoverage: [addressed, declined] }).ruleCoverage).toHaveLength(2);
  });

  /**
   * Absent and empty are different facts, and this is the block where the
   * difference is the whole subject. Absent means no answer, which the
   * register already prints as an upper bound. An empty array declares
   * nothing while LOOKING like a declaration — the one reading that would let
   * a config appear to answer reason 3 without answering any of it.
   */
  it("refuses an empty block, which declares nothing while looking like a declaration", () => {
    expect(() => OfferingConfig.parse({ ...offering, ruleCoverage: [] })).toThrow(/declares nothing/);
  });

  /**
   * One rule, one answer — the same refusal the artifact plane makes of a
   * repeated slot. Two entries for a rule let a config both address it and
   * decline it, and the register would report whichever it read last.
   */
  it("refuses the same rule declared twice, and names it", () => {
    expect(() =>
      OfferingConfig.parse({
        ...offering,
        ruleCoverage: [addressed, { ...declined, ruleId: addressed.ruleId }],
      }),
    ).toThrow(/FRC-APP-AFC/);
  });
});

// R2.0 (docs/PLAN-SDR.md D4, D7): the two keys the SDR reads that nothing
// declared before.
describe("rule coverage — how far an addressed rule is addressed (SDR D4)", () => {
  it("accepts the two SDR statuses an addressed rule can carry, and absence", () => {
    for (const implementationStatus of ["Implemented", "Partially Implemented"]) {
      expect(DeclaredRuleCoverage.parse({ ...addressed, implementationStatus })).toMatchObject({
        implementationStatus,
      });
    }
    expect(DeclaredRuleCoverage.parse(addressed)).not.toHaveProperty("implementationStatus");
  });

  /**
   * "Not Implemented" is the other branch, and that branch requires a reason.
   * Letting an addressed rule call itself not implemented would give a decline
   * with no "why", which is the omission #167 rejects, one level down.
   */
  it("refuses Not Implemented on an addressed rule, and any status on a declined one", () => {
    expect(() => DeclaredRuleCoverage.parse({ ...addressed, implementationStatus: "Not Implemented" })).toThrow();
    expect(() => DeclaredRuleCoverage.parse({ ...addressed, implementationStatus: "implemented" })).toThrow();
    expect(() => DeclaredRuleCoverage.parse({ ...declined, implementationStatus: "Implemented" })).toThrow();
  });
});

describe("offering — where signed evidence is published (SDR D7)", () => {
  it("is optional, and accepts an http(s) base", () => {
    expect(OfferingConfig.parse(offering).evidenceBaseUri).toBeUndefined();
    const evidenceBaseUri = "https://evidence.example.com/eep";
    expect(OfferingConfig.parse({ ...offering, evidenceBaseUri }).evidenceBaseUri).toBe(evidenceBaseUri);
  });

  /** `/sha256/<hex>` is appended, so anything that would bend the joined address is refused. */
  it("refuses a base the digest path cannot be appended to cleanly", () => {
    for (const evidenceBaseUri of [
      "https://evidence.example.com/eep/",
      "https://evidence.example.com/eep?v=1",
      "https://evidence.example.com/eep#bundles",
      "ftp://evidence.example.com/eep",
      "evidence.example.com/eep",
    ]) {
      expect(() => OfferingConfig.parse({ ...offering, evidenceBaseUri }), evidenceBaseUri).toThrow();
    }
  });
});
