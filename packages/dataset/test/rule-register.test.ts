import { fileURLToPath } from "node:url";
import { join, dirname } from "node:path";
import { describe, expect, it } from "vitest";
import {
  addressableRules,
  effectiveForce,
  loadRuleRegister,
  type RuleRegister,
} from "../src/index.js";

const contextDir = join(dirname(fileURLToPath(import.meta.url)), "../../../docs/context");
const rulesFile = join(contextDir, "fedramp-rules/fedramp-consolidated-rules.json");
const obligationsFile = join(contextDir, "ramprules/derived/obligations.json");
const PIN = "2026.09.13.02";

let cached: RuleRegister | undefined;
const register = async (): Promise<RuleRegister> => {
  cached ??= await loadRuleRegister(rulesFile, PIN);
  return cached;
};

// P2-0 (docs/RESEARCH-REJECTION-LINTER.md §2a). Until now nothing in this
// repository enumerated the FRR rule set: roughly sixteen rule ids were
// hardcoded at the sites that needed them, and "is every MUST and SHOULD
// applicable to this class addressed?" — reason 3 in FedRAMP/community#167 —
// had no denominator to divide by.
describe("the FRR rule register", () => {
  it("enumerates every rule in the pinned file", async () => {
    const r = await register();
    expect(r.datasetVersion).toBe(PIN);
    // 246 rules across 17 documents. Literal, because a republication that
    // adds or drops rules has to arrive here as a failing test rather than as
    // a denominator that quietly moved (§13.7 rule 1, CONTRIBUTING rule 4).
    expect(r.rules).toHaveLength(246);
    expect(new Set(r.rules.map((x) => x.document)).size).toBe(17);
    // every rule declares who it affects; nothing falls through that read
    expect(r.rules.filter((x) => x.affects.length === 0)).toEqual([]);
  });

  /**
   * The trap this test exists to hold shut. `force` is a per-rule field
   * EXCEPT for 29 rules that carry `varies_by_class` instead, where the force
   * is per class — `FRC-CSX-VVK` reads MAY / SHOULD / MUST / MUST across a–d.
   * Reading the top-level `force` alone returns null for all 29 and makes
   * every class look identical, which is exactly the shape of the mistake the
   * first pass of this research made (it reported one denominator for all
   * four classes).
   */
  it("reads the force per class where the rule varies by class", async () => {
    const r = await register();
    expect(r.rules.filter((x) => x.forceByClass !== null)).toHaveLength(29);

    const vvk = r.rules.find((x) => x.id === "FRC-CSX-VVK");
    expect(vvk?.force).toBeNull();
    expect(
      ["a", "b", "c", "d"].map((c) => effectiveForce(vvk!, c as "a" | "b" | "c" | "d")),
    ).toEqual(["MAY", "SHOULD", "MUST", "MUST"]);
  });

  /**
   * Reason 3's denominator, and the number nobody in this field publishes.
   *
   * The filter, stated so a reader can re-derive it: the rule's scope is not
   * `rev5` (a 20x certification does not owe the Rev5-only rules); its
   * subset's applicability, WHEN DECLARED, names type `20x` and this class;
   * the rule's own `affects` names `Providers`; and its effective force at
   * this class is MUST or SHOULD.
   */
  it("computes the addressable rule count per class", async () => {
    const r = await register();
    const at = (cls: "b" | "c" | "d") => {
      const rules = addressableRules(r, cls);
      const must = rules.filter((x) => effectiveForce(x, cls) === "MUST").length;
      return { must, should: rules.length - must, total: rules.length };
    };
    expect(at("b")).toEqual({ must: 88, should: 41, total: 129 });
    expect(at("c")).toEqual({ must: 91, should: 40, total: 131 });
    expect(at("d")).toEqual({ must: 92, should: 40, total: 132 });
  });

  /**
   * §2b, and the reason this is a test rather than a comment.
   *
   * `FRR.SDR.info.subsets` declares one subset, `CSO`. The data carries two:
   * the `20x` slice holds a `CSX` subset whose rules have no declared
   * applicability at all. Four subsets are in that state and every one of
   * them is a `20x` subset — the gap falls precisely on the rules specific to
   * the programme this tool serves.
   *
   * A loader that read "no declared applicability" as "does not apply" would
   * silently drop the method floor, the history floor and the five owed
   * artifacts: the three rules this entire repository is built on. So
   * undeclared applicability counts as APPLICABLE and is declared as
   * undeclared (ground rule 7 — absence of evidence is not evidence of
   * absence), the twin of `KsiRegisterView.summary.applicabilityUnstated`.
   */
  it("counts a rule with no declared applicability as applicable, and says so", async () => {
    const r = await register();
    expect(r.applicabilityUnstated).toEqual(["CPO/CSX", "FRC/CSX", "IVV/CSX", "SDR/CSX"]);
    expect(r.applicabilityUnstatedReason).toContain("no declared applicability");

    const ids = new Set(addressableRules(r, "b").map((x) => x.id));
    expect(ids.has("FRC-CSX-VVK")).toBe(true); // the method floor
    expect(ids.has("FRC-CSX-MOT")).toBe(true); // the history floor
    expect(ids.has("SDR-CSX-KSI")).toBe(true); // the five owed artifacts

    for (const id of ["FRC-CSX-VVK", "FRC-CSX-MOT", "SDR-CSX-KSI"]) {
      expect(r.rules.find((x) => x.id === id)?.applicability).toBeNull();
    }
  });

  /**
   * The independent check that the enumeration and the class expansion are
   * right, rather than merely self-consistent: upstream publishes its own
   * force distribution in `obligations.json`, over both arms — once per
   * requirement, and once with the class variants expanded. This register
   * reproduces both exactly, from the other leg of §12.4.
   *
   * That file is NOT the feed for reason 3, which is the correction §3 of the
   * research note records: its `deadlines` array looks like the whole rule set
   * but holds 73 rows over 36 distinct ids — the timeframe rules only, out of
   * 246.
   */
  it("reproduces upstream's own published force distribution", async () => {
    const r = await register();
    const upstream = JSON.parse(await (await import("node:fs/promises")).readFile(obligationsFile, "utf8"));
    expect(r.forceDistribution.requirement).toEqual(upstream.data.forceDistribution.requirement);
    expect(r.forceDistribution.withClass).toEqual(upstream.data.forceDistribution.withClass);
    // and the shape, pinned, so a change upstream reads as a failure here
    expect(r.forceDistribution.requirement).toEqual({
      MUST: 136,
      "MUST NOT": 11,
      SHOULD: 45,
      "SHOULD NOT": 5,
      MAY: 20,
    });
  });

  /**
   * §2c, reason 2's second clause. 24 rules name a schema; at class b the
   * provider-addressable ones resolve to eight distinct schema files, of
   * which this checkout vendors two. NAMING a schema-bearing rule with no
   * supplied document is answerable for all eight; VALIDATING against one is
   * answerable for two, and the rest must print as unvalidatable rather than
   * as clean. The register carries the url so the linter can tell those two
   * questions apart.
   */
  it("carries the schema url each rule names", async () => {
    const r = await register();
    expect(r.rules.filter((x) => x.schemaUrl !== null)).toHaveLength(24);
    const atB = addressableRules(r, "b").filter((x) => x.schemaUrl !== null);
    expect(atB).toHaveLength(22);
    expect(new Set(atB.map((x) => x.schemaUrl)).size).toBe(8);
  });

  it("refuses a pin the file does not carry", async () => {
    await expect(loadRuleRegister(rulesFile, "2026.07.14.01")).rejects.toThrow(/2026\.09\.13\.02/);
  });
});
