import { createHash } from "node:crypto";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { addressableRules, optionalKsis, type OfferingClass } from "@rampscan/dataset";
import { checkConformance } from "../src/fedramp-conformance.js";
import { SDR_SCHEMA } from "../src/fedramp-schemas.js";
import { renderSdrMarkdown } from "../src/sdr-render.js";
import { checkSdrRules, rulesMet, type SdrRuleInput } from "../src/sdr-rules.js";
import { omittedRules } from "../src/sdr.js";
import { built, input, metricsFixture, root, sources } from "./sdr-fixture.js";

// R2.3 (#104, docs/PLAN-SDR.md §5). The rule verdict beside the schema verdict.
// What these pin:
//
//   1. The two verdicts never merge: a schema-valid record that fails the
//      rules is schema ✓, rules ✗ — divergence 1 is the sharpest case.
//   2. A lone JSON, or a pair that no longer agrees, is never a pass.
//   3. `met` is reachable. A gate no record can pass is a gate that gets
//      switched off, so one record here meets every rule.
//   4. The coverage diff is `submission --sdr`'s own, not a second copy.

const SCHEMA_REQUIRED = ["certificationPackageOverviewUri", "fedRampRequirements"];
const sha = (s: string) => createHash("sha256").update(s).digest("hex");

async function base(over: Partial<SdrRuleInput> = {}): Promise<SdrRuleInput> {
  const { catalog, register } = await sources();
  return {
    document: {},
    register,
    catalog,
    offeringClass: "b",
    schemaRequired: SCHEMA_REQUIRED,
    jsonSha256: sha("{}"),
    ...over,
  };
}

/** a record that answers every rule and KSI at the class, assessor included */
async function complete(cls: OfferingClass): Promise<Record<string, unknown>> {
  const { catalog, register } = await sources();
  const optional = new Set(optionalKsis(catalog, cls));
  return {
    certificationPackageOverviewUri: "https://trust.example.com/cpo.json",
    metadata: { version: "1", lastUpdated: "2026-09-18T12:00:00.000Z", updateSource: "the security team" },
    fedRampRequirements: addressableRules(register, cls).map((r) => ({
      frrID: r.id,
      frrImplementation: ["How it is followed."],
      frrAssessment: ["What the assessor found."],
    })),
    keySecurityIndicators: catalog.ksis
      .filter((k) => !optional.has(k.id))
      .map((k) => ({
        ksiId: k.id,
        ksiImplementation: ["The measures."],
        ksiValidation: ["The verification."],
        ksiAssessment: ["What the assessor found."],
        ksiTests: [],
        ksiEvidence: [],
      })),
  };
}

const verdictOf = (vs: ReturnType<typeof checkSdrRules>, ruleId: string, check: string) =>
  vs.find((v) => v.ruleId === ruleId && v.check === check);

describe("sdr rules — met is reachable", () => {
  it("meets every rule for a complete record with a matching companion, at class a", async () => {
    const document = await complete("a");
    const json = JSON.stringify(document);
    const verdicts = checkSdrRules(
      await base({
        document,
        offeringClass: "a",
        answeredRules: new Set((document["fedRampRequirements"] as { frrID: string }[]).map((r) => r.frrID)),
        jsonSha256: sha(json),
        companion: { path: "x.md", digest: sha(json) },
      }),
    );
    expect(verdicts.filter((v) => v.verdict !== "met")).toEqual([]);
    expect(rulesMet(verdicts)).toBe(true);
  });
});

describe("sdr rules — the coverage diff is submission's own", () => {
  it("reports exactly the rules omittedRules names", async () => {
    const { register } = await sources();
    const answered = new Set(["FRC-CSX-VVK", "FRC-APP-MLF"]);
    const v = verdictOf(checkSdrRules(await base({ answeredRules: answered })), "SDR-CSO-FRR", "a row per addressable rule")!;
    const omitted = omittedRules(register, "b", answered);
    expect(v.verdict).toBe("unmet");
    expect(v.detail).toMatch(new RegExp(`^${omitted.length} rule\\(s\\) addressable at class b have no row`));
  });

  it("flags a row whose explanation is an empty array, which the schema accepts", async () => {
    const vs = checkSdrRules(
      await base({ document: { fedRampRequirements: [{ frrID: "FRC-CSX-VVK", frrImplementation: [] }] }, answeredRules: new Set(["FRC-CSX-VVK"]) }),
    );
    expect(verdictOf(vs, "SDR-CSO-FRR", "each row explains")).toMatchObject({ verdict: "unmet" });
  });
});

describe("sdr rules — the KSI half, and divergence 1 by name", () => {
  /** the schema-valid record with no KSI rows at all: schema ✓, rules ✗ */
  it("names the pinned required array when keySecurityIndicators is absent", async () => {
    const v = verdictOf(
      checkSdrRules(await base({ document: { certificationPackageOverviewUri: "https://x.example/cpo", fedRampRequirements: [] } })),
      "SDR-CSX-KSI",
      "a row per obliged KSI",
    )!;
    expect(v.verdict).toBe("unmet");
    expect(v.detail).toContain("[certificationPackageOverviewUri, fedRampRequirements]");
    expect(v.detail).toContain("#105");
  });

  it("counts empty statements on obliged rows, and grades nothing", async () => {
    const doc = built(await input()).document;
    const vs = checkSdrRules(await base({ document: doc }));
    const v = verdictOf(vs, "SDR-CSX-KSI", "artifact statements present (counted, not judged)")!;
    // the fixture fills only KSI-SVC-SIN, so every other obliged row is empty
    expect(v.verdict).toBe("unmet");
    expect(v.detail).not.toContain("KSI-SVC-SIN,");
  });

  it("counts absent assessor content as awaited, never as met", async () => {
    const vs = checkSdrRules(await base({ document: built(await input()).document }));
    expect(verdictOf(vs, "SDR-CSO-FRR", "independent verification and validation")?.verdict).toBe("awaiting");
    expect(rulesMet(vs)).toBe(false);
  });
});

describe("sdr rules — KMT by class", () => {
  it("prints the in-schema impossibility where the class owes metrics, and nothing where it may", async () => {
    const doc = built(await input()).document;
    const atC = verdictOf(checkSdrRules(await base({ document: doc, offeringClass: "c" })), "SDR-CSX-KMT", "historical metrics");
    expect(atC?.verdict).toBe("unmet");
    expect(atC?.detail).toContain("FedRAMP/schemas#10");
    expect(verdictOf(checkSdrRules(await base({ document: doc, offeringClass: "a" })), "SDR-CSX-KMT", "historical metrics")).toBeUndefined();
  });

  it("stays unmet when carried, and says what is carried and what is missing (R3.3)", async () => {
    const { catalog } = await sources();
    const doc = built(
      await input({ offeringClass: "c", optionalKsis: optionalKsis(catalog, "c"), metrics: await metricsFixture("c") }),
    ).document;
    const full = verdictOf(checkSdrRules(await base({ document: doc, offeringClass: "c" })), "SDR-CSX-KMT", "historical metrics");
    expect(full?.verdict).toBe("unmet");
    expect(full?.detail).toMatch(/the daily data for (\d+) of \1/);
    expect(full?.detail).not.toContain("Missing for");
    const ksis = ((doc["x-rampscan"] as Record<string, unknown>)["metrics"] as Record<string, Record<string, Record<string, unknown>>>)["ksis"]!;
    delete ksis["KSI-SVC-SIN"]!["daily"];
    const short = verdictOf(checkSdrRules(await base({ document: doc, offeringClass: "c" })), "SDR-CSX-KMT", "historical metrics");
    expect(short?.detail).toContain("Missing for: KSI-SVC-SIN");
  });

  it("marks every per-class check unmeasured when no class is known", async () => {
    const { offeringClass: _unknown, ...noClass } = await base();
    const vs = checkSdrRules(noClass);
    expect(vs.filter((v) => v.verdict === "unmeasured").map((v) => v.ruleId).sort()).toEqual(
      ["SDR-CSO-FRR", "SDR-CSO-FRR", "SDR-CSX-KMT", "SDR-CSX-KSI"].sort(),
    );
  });
});

describe("sdr rules — through conformance, on files", () => {
  async function onDisk(markdown: "match" | "mismatch" | "none") {
    const dir = await mkdtemp(join(tmpdir(), "sdr-rules-"));
    const doc = built(await input()).document;
    const json = `${JSON.stringify(doc, null, 2)}\n`;
    await writeFile(join(dir, "fedramp-security-decision-record.json"), json);
    if (markdown !== "none") {
      const digest = markdown === "match" ? sha(json) : sha("something else");
      await writeFile(join(dir, "fedramp-security-decision-record.md"), renderSdrMarkdown(doc, digest));
    }
    const { catalog, register } = await sources();
    return checkConformance({ schemaRoot: root, target: dir, sdr: { register, catalog } });
  }
  const both = (r: Awaited<ReturnType<typeof onDisk>>) =>
    r.findings[0]!.rules!.verdicts.find((v) => v.check === "both formats")!;

  it("keeps the two verdicts apart: schema valid, rules not met", async () => {
    const r = await onDisk("match");
    expect(r.findings[0]!.schemaFile).toBe(SDR_SCHEMA);
    expect(r.conformant).toBe(true);
    expect(r.rulesMet).toBe(false);
    expect(both(r).verdict).toBe("met");
    // the class came from the record, and says so
    expect(r.findings[0]!.rules!.classSource).toMatch(/x-rampscan\.offeringClass/);
  });

  it("fails a companion rendered from other bytes", async () => {
    expect(both(await onDisk("mismatch")).verdict).toBe("unmet");
  });

  it("reads a lone JSON as unmeasured, never as a pass", async () => {
    expect(both(await onDisk("none")).verdict).toBe("unmeasured");
  });
});
