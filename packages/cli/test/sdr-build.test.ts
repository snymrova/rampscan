import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { allCollectors } from "@rampscan/collectors";
import type { MethodRegisterRow } from "@rampscan/core";
import { optionalKsis } from "@rampscan/dataset";
import { OfferingConfig } from "@rampscan/schema";
import { SDR_SCHEMA, loadPinnedSchema, validateAgainst } from "../src/fedramp-schemas.js";
import {
  COLLECTOR_EVIDENCE_TYPES,
  buildSecurityDecisionRecord,
  evidenceLocation,
  ksiStatus,
} from "../src/sdr-build.js";
import { readSdrCoverage } from "../src/sdr.js";
import { buildRejectionRegister } from "../src/submission.js";
import {
  AT,
  BODIES,
  artifacts,
  built,
  cell,
  hex,
  input,
  ksiRow,
  offering,
  offeringJson,
  root,
  row,
  ruleRow,
  sources,
} from "./sdr-fixture.js";

// R2.1 (#102, docs/PLAN-SDR.md §5). What these pin, most painful first:
//
//   1. No sentence nobody stood behind. An empty artifact slot renders as an
//      empty array, never as prose (D2).
//   2. The status field understates and never overstates (D6, the owner's call).
//   3. A rule nobody declared gets no row, so the record cannot read as
//      answering what the provider never answered (D4).
//   4. The document is schema-valid, deterministic, and agrees with
//      `submission --sdr` about what it omits.

describe("sdr — the schema", () => {
  it("validates against the pinned SDR schema, and the validator refuses a date-time where a date belongs", async () => {
    const doc = built(await input()).document;
    const schema = await loadPinnedSchema(root, SDR_SCHEMA);
    expect(validateAgainst(schema, doc)).toEqual([]);

    // §1.2: evidence.lastUpdated is a `date`. The register holds an instant,
    // and copying it as-is is the one mistake this field invites.
    const broken = structuredClone(doc);
    const ev = (ksiRow(broken, "KSI-SVC-SIN")!["ksiEvidence"] as Record<string, unknown>[])[0]!;
    ev["lastUpdated"] = "2026-09-17T08:00:00.000Z";
    expect(validateAgainst(schema, broken).map((v) => v.path)).toEqual([
      "/keySecurityIndicators/" +
        (doc["keySecurityIndicators"] as unknown[]).indexOf(ksiRow(doc, "KSI-SVC-SIN")) +
        "/ksiEvidence/0/lastUpdated",
    ]);
  });

  it("uses an evidenceLocation the pinned uri format accepts, in both forms", async () => {
    const schema = await loadPinnedSchema(root, SDR_SCHEMA);
    const ni = evidenceLocation(hex("a"));
    expect(ni).toMatch(/^ni:\/\/\/sha-256;[A-Za-z0-9_-]{43}$/);
    expect(evidenceLocation(hex("a"), "https://ev.example.com/eep")).toBe(`https://ev.example.com/eep/sha256/${hex("a")}`);
    const doc = built(await input({ offering: offering({ evidenceBaseUri: "https://ev.example.com/eep" }) })).document;
    expect(validateAgainst(schema, doc)).toEqual([]);
  });
});

describe("sdr — the KSI half (D2, D9, D10, D11)", () => {
  it("renders an authored artifact 1 into ksiImplementation, labelled with its source and digest", async () => {
    const k = ksiRow(built(await input()).document, "KSI-SVC-SIN")!;
    const impl = k["ksiImplementation"] as string[];
    expect(impl).toHaveLength(2);
    expect(impl[0]).toContain("**Artifact 1 — ");
    expect(impl[0]).toContain("authored; body sha256 111111111111…");
    expect(impl[0]).toContain("Body of artifact 1.");
    expect((k["ksiValidation"] as string[]).map((s) => s.match(/Artifact (\d)/)![1])).toEqual(["3", "4", "5"]);
  });

  /** D2 — the refusal the whole artifact plane is built around, at the last surface */
  it("leaves ksiImplementation empty when artifact 1 has no body, and says so in problems", async () => {
    const { catalog } = await sources();
    const optional = new Set(optionalKsis(catalog, "b"));
    const rows = catalog.ksis
      .filter((k) => !optional.has(k.id))
      .map((k) => (k.id === "KSI-SVC-SIN" ? row(k.id, { artifacts: artifacts([2, 3, 4, 5]) }) : row(k.id)));
    const out = built(await input({ methodRegisters: rows }));
    const impl = ksiRow(out.document, "KSI-SVC-SIN")!["ksiImplementation"] as string[];
    expect(impl.map((s) => s.match(/Artifact (\d)/)![1])).toEqual(["2"]);
    const missing = out.problems.filter((p) => p.startsWith("SDR-CSX-KSI artifact"));
    expect(missing).toHaveLength(1);
    expect(missing[0]).toMatch(/^SDR-CSX-KSI artifact 1 \(.*\) has no body on 1 obliged KSI row\(s\): KSI-SVC-SIN\./);
    expect(missing[0]).toMatch(/provider's own claim/);

    // and when it is every row, the line says so instead of listing forty ids
    const bare = built(await input({ methodRegisters: [] }));
    expect(bare.problems.find((p) => p.startsWith("SDR-CSX-KSI artifact 1"))).toMatch(
      new RegExp(`every one of the ${rows.length} obliged KSI rows`),
    );
  });

  it("does not render a body the bodies map does not hold", async () => {
    const out = built(await input({ bodies: new Map() }));
    expect(ksiRow(out.document, "KSI-SVC-SIN")!["ksiImplementation"]).toEqual([]);
  });

  it("gives every obliged KSI a row, and an optional one only when it holds evidence", async () => {
    const { catalog } = await sources();
    const optional = optionalKsis(catalog, "b");
    expect(optional.length).toBeGreaterThan(0);
    const doc = built(await input()).document;
    const ids = (doc["keySecurityIndicators"] as Record<string, unknown>[]).map((k) => k["ksiId"]);
    expect(ids).toHaveLength(catalog.ksis.length - optional.length);
    expect((doc["x-rampscan"] as Record<string, unknown>)["optionalKsis"]).toEqual(optional);

    const withEvidence = built(await input({ methodRegisters: [row(optional[0]!)] })).document;
    expect(ksiRow(withEvidence, optional[0]!)).toBeDefined();
  });

  it("lists every derived method in ksiTests, evidenced or not, and evidence only where it stands", async () => {
    const methods = [cell(), cell({ methodId: "pipeline:sbom", collector: "syft", bundleDigest: undefined, freshAsOf: undefined, state: "unevidenced", freshMet: false })];
    const k = ksiRow(built(await input({ methodRegisters: [row("KSI-SVC-SIN", { methods })] })).document, "KSI-SVC-SIN")!;
    expect(k["ksiTests"]).toEqual([
      "pipeline:secrets-scan — pipeline, automated, machine clock",
      "pipeline:sbom — pipeline, automated, machine clock",
    ]);
    expect(k["ksiEvidence"]).toEqual([
      {
        evidenceType: "Report",
        evidenceDescription: "pipeline:secrets-scan: evidenced, process-generated evidence",
        evidenceLocation: evidenceLocation(hex("a")),
        evidenceText: `signed bundle ${hex("a")}; check it offline with \`rampscan verify ${hex("a")}\``,
        lastUpdated: "2026-09-17",
      },
    ]);
  });

  it("maps every collector that exists to an evidence type (D8 drift guard)", () => {
    const names = allCollectors.map((c) => c.manifest.name).sort();
    expect(names.filter((n) => COLLECTOR_EVIDENCE_TYPES[n] === undefined)).toEqual([]);
    expect(Object.keys(COLLECTOR_EVIDENCE_TYPES).sort()).toEqual(names);
  });
});

describe("sdr — ksiImplementationStatus understates, never overstates (D6)", () => {
  it("is Implemented only when every condition holds", () => {
    expect(ksiStatus(row("KSI-SVC-SIN")).status).toBe("Implemented");
    expect(ksiStatus(row("KSI-SVC-SIN")).basis.short).toEqual([]);
  });

  it("is Not Implemented with no live evidence, and with no row at all", () => {
    const none = row("KSI-SVC-SIN", {
      methods: [cell({ bundleDigest: undefined, freshAsOf: undefined, state: "unevidenced", freshMet: false })],
    });
    expect(ksiStatus(none).status).toBe("Not Implemented");
    expect(ksiStatus(undefined).status).toBe("Not Implemented");
  });

  /** a failed check is evidence the KSI is not met — "partially" would be the overstatement */
  it("is Not Implemented when the only live evidence is a violation", () => {
    const { status, basis } = ksiStatus(row("KSI-SVC-SIN", { methods: [cell({ state: "violated" })] }));
    expect(status).toBe("Not Implemented");
    expect(basis.short).toEqual(["no validation method holds passing evidence; every live result is a violation"]);
  });

  const shortOf: [string, Partial<MethodRegisterRow>][] = [
    ["a violated method beside a passing one", { methods: [cell(), cell({ methodId: "m2", state: "violated" })] }],
    ["a stale method", { staleMethods: 1 }],
    ["the floor unmet", { floorMet: false }],
    ["history failed", { historyMet: false }],
    ["an absent artifact", { artifacts: artifacts([2, 3, 4, 5]) }],
    [
      "an in-scope method with no evidence, at a class with no window",
      { methods: [cell(), cell({ methodId: "m2", bundleDigest: undefined, freshAsOf: undefined, freshMet: null, window: null })] },
    ],
    [
      "no floor owed and no automated method evidenced",
      { floorMet: null, methodFloor: null, methods: [cell({ automated: false, source: "attestation", clock: "non-machine" })] },
    ],
  ];
  for (const [what, over] of shortOf) {
    it(`is Partially Implemented with ${what}, and names why`, () => {
      const { status, basis } = ksiStatus(row("KSI-SVC-SIN", over));
      expect(status).toBe("Partially Implemented");
      expect(basis.short.length).toBeGreaterThan(0);
    });
  }

  it("publishes the basis beside the row", async () => {
    const doc = built(await input()).document;
    const ext = (doc["x-rampscan"] as Record<string, Record<string, Record<string, unknown>>>)["ksis"]!;
    expect(ext["KSI-SVC-SIN"]!["statusBasis"]).toMatchObject({ methodsWithEvidence: 1, artifactsPresent: 5, short: [] });
  });
});

describe("sdr — the rule half (D4)", () => {
  const coverage = [
    { ruleId: "FRC-CSX-VVK", status: "addressed", citation: "docs/ksi-methods.md §2", implementationStatus: "Implemented" },
    { ruleId: "CCM-OCR-NRD", status: "addressed", citation: "trust center, next report dated" },
    { ruleId: "FRC-APP-MLF", status: "not-implemented", reason: "the Marketplace listing request is filed and pending" },
  ];

  it("writes a row per declared rule, with the declared words and nothing else", async () => {
    const doc = built(await input({ offering: offering({ ruleCoverage: coverage }) })).document;
    expect(ruleRow(doc, "FRC-APP-MLF")).toEqual({
      frrID: "FRC-APP-MLF",
      frrImplementationStatus: "Not Implemented",
      frrImplementation: ["Not implemented: the Marketplace listing request is filed and pending"],
    });
    // a computed rule the provider declared gets rampscan's validation line
    expect(ruleRow(doc, "FRC-CSX-VVK")).toMatchObject({
      frrImplementationStatus: "Implemented",
      frrImplementation: ["docs/ksi-methods.md §2"],
      frrValidation: [expect.stringMatching(/^Validated by rampscan, which computes this rule: /)],
    });
    // "addressed" alone does not say how far — the status is omitted, never guessed
    expect(ruleRow(doc, "CCM-OCR-NRD")).not.toHaveProperty("frrImplementationStatus");
  });

  it("gives an undeclared rule no row, computed or not, and names it in unaddressedRules", async () => {
    const out = built(await input({ offering: offering({ ruleCoverage: coverage }) }));
    const unaddressed = (out.document["x-rampscan"] as Record<string, unknown>)["unaddressedRules"] as {
      ruleId: string;
      computedBy?: string;
    }[];
    // FRC-CSX-MOT is computed by the history meter and undeclared here
    expect(ruleRow(out.document, "FRC-CSX-MOT")).toBeUndefined();
    expect(unaddressed.find((r) => r.ruleId === "FRC-CSX-MOT")?.computedBy).toMatch(/history meter/);
    expect(unaddressed.map((r) => r.ruleId)).not.toContain("FRC-CSX-VVK");
    expect(out.problems.some((p) => /have no row/.test(p))).toBe(true);
  });

  it("writes no row for a declared id that names no rule, and says so", async () => {
    const out = built(
      await input({
        offering: offering({ ruleCoverage: [{ ruleId: "FRC-APP-MFL", status: "addressed", citation: "somewhere real" }] }),
      }),
    );
    expect(ruleRow(out.document, "FRC-APP-MFL")).toBeUndefined();
    expect(out.problems.some((p) => p.includes("FRC-APP-MFL"))).toBe(true);
  });

  /**
   * One fact, two surfaces, one answer (the P2 note's §5, made executable).
   * `submission --sdr` over the generated file must report exactly the
   * omissions the file lists about itself.
   */
  it("agrees with submission --sdr about what it omits", async () => {
    const { register } = await sources();
    const i = await input({ offering: offering({ ruleCoverage: coverage }) });
    const doc = built(i).document;
    const dir = await mkdtemp(join(tmpdir(), "sdr-agree-"));
    const path = join(dir, "sdr.json");
    await writeFile(path, JSON.stringify(doc));
    const view = await buildRejectionRegister({
      register,
      offeringClass: "b",
      offering: i.offering,
      sdr: await readSdrCoverage(path),
    });
    const omitted = view.sections
      .find((s) => s.section === "unaddressed-rules")!
      .rows.filter((r) => r.rejection === true)
      .map((r) => r.subject)
      .sort();
    const listed = ((doc["x-rampscan"] as Record<string, unknown>)["unaddressedRules"] as { ruleId: string }[])
      .map((r) => r.ruleId)
      .sort();
    expect(omitted).toEqual(listed);
    expect(listed.length).toBeGreaterThan(100);
  });
});

describe("sdr — metadata, determinism, and the refusal (D5, D12)", () => {
  it("always emits metadata, with lastUpdated from the fold instant", async () => {
    const meta = built(await input()).document["metadata"] as Record<string, string>;
    expect(meta["lastUpdated"]).toBe(AT);
    expect(meta["version"]).toMatch(/^sha256:[0-9a-f]{12}$/);
    expect(meta["updateSource"]).toContain(`head ${hex("f")}`);
  });

  it("produces identical bytes for identical input", async () => {
    const i = await input();
    expect(JSON.stringify(built(i).document)).toBe(JSON.stringify(built(i).document));
  });

  it("moves the version when a body changes, and not when only the instant does", async () => {
    const base = built(await input()).document["metadata"] as Record<string, string>;
    const later = built(await input({ projectedAt: "2026-09-18T13:00:00.000Z" })).document["metadata"] as Record<string, string>;
    expect(later["version"]).toBe(base["version"]);
    expect(later["lastUpdated"]).not.toBe(base["lastUpdated"]);

    const revised = new Map(BODIES);
    revised.set("stmt-1", "Body of artifact 1, revised.");
    const moved = built(await input({ bodies: revised })).document["metadata"] as Record<string, string>;
    expect(moved["version"]).not.toBe(base["version"]);
  });

  it("writes nothing without a declared certification package overview address, and names the key", async () => {
    const { report: _report, ...rest } = offeringJson;
    const out = buildSecurityDecisionRecord(await input({ offering: OfferingConfig.parse(rest) }));
    expect(out.export).toBeUndefined();
    expect(out.skipped).toMatch(/offering\.report\.certificationPackageOverviewUri/);
  });

  it("states the KMT metrics it does not carry at a class that owes them", async () => {
    const out = built(await input());
    expect(out.problems.some((p) => p.startsWith("SDR-CSX-KMT (MUST at class b)") && p.includes("FedRAMP/schemas#10"))).toBe(true);
  });

  it("states an empty ledger rather than rendering it as a quiet record", async () => {
    const out = built(await input({ repo: undefined, methodRegisters: [] }));
    expect(out.problems[0]).toMatch(/holds no scan/);
    const summary = (out.document["x-rampscan"] as Record<string, Record<string, unknown>>)["summary"]!;
    expect((summary["ksiStatus"] as Record<string, number>)["Implemented"]).toBe(0);
  });
});
