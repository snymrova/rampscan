import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import type { DriftEvent, MethodRegisterRow, ValidationVulnerability } from "@rampscan/core";
import { OfferingConfig } from "@rampscan/schema";
import {
  buildOngoingCertificationReport,
  buildPackageOverview,
  certificationDataChanges,
  type FedrampExportInput,
} from "../src/fedramp-exports.js";
import {
  COMMON_SCHEMA,
  FEDRAMP_SCHEMA_PINS,
  OCR_SCHEMA,
  PACKAGE_OVERVIEW_SCHEMA,
  loadPinnedSchema,
  validateAgainst,
} from "../src/fedramp-schemas.js";
import { writeFedrampExports } from "../src/fedramp-run.js";
import { loadOffering } from "../src/offering.js";

// Q5.1 — the two FedRAMP schema-target exports. What these tests pin, in order
// of how much they would hurt to get wrong:
//
//   1. The VALIDATOR actually rejects. A conformance check that passes
//      everything is worse than none, so every keyword the pinned schemas use
//      is tested against an instance that violates it.
//   2. The DECLARED/COMPUTED line holds. A provider cannot type a validation
//      history into a config file; an appliance cannot attest about incidents.
//   3. Both documents are schema-valid for a complete declaration — the phase
//      exit gate, asserted against the pinned bytes rather than a copy.

const REPO_ROOT = join(import.meta.dirname, "../../..");

const offeringJson = {
  providerName: "Example Cloud Inc.",
  serviceName: "Example Pipeline Evidence Plane",
  serviceAcronym: "EPEP",
  serviceDescription: "A CI/CD evidence plane for FedRAMP 20x key security indicators.",
  certificationType: "20x" as const,
  fedRampPackageId: "Example Cloud Inc. (EPEP)",
  website: "https://example.com/epep",
  logo: "https://example.com/logo.svg",
  serviceType: ["SaaS" as const],
  deploymentModel: "Public Cloud" as const,
  businessCategory: ["Development Tools"],
  trustCenter: {
    repositoryType: ["Trust Center"],
    url: "https://trust.example.com",
    repositoryDescription: "Certification data and assessment reports.",
    authenticationRequired: false,
  },
  nextOngoingCertificationReportDate: "2026-12-15",
  contactInformation: [
    { contactType: "Security", contactName: "Security Team", contactEmail: "security@example.com" },
    { contactType: "Sales", contactName: "Sales Team", contactPhone: "202-555-0123" },
  ],
  assessor: { name: "Example Assessment Services", assessorID: "123456" },
};

const reportJson = {
  certificationPackageOverviewUri: "https://trust.example.com/certification-package.json",
  previousReportThrough: "2026-06-12",
  plannedCertificationDataChanges: {
    planningHorizonThrough: "2026-12-31",
    changes: ["Add a second region."],
  },
  acceptedVulnerabilities: "Two low-severity findings carried with compensating controls.",
  transformativeChanges: [],
  updatedRecommendations: [],
  activeAgencies: ["Department of Example"],
  reportableIncidents: { incidents: [] },
};

function offering(overrides: Record<string, unknown> = {}) {
  return OfferingConfig.parse({ ...offeringJson, ...overrides });
}

const methodRegisters: MethodRegisterRow[] = [
  {
    repo: "/repo/app",
    ksi: "KSI-SCR-MIT",
    methods: [
      {
        methodId: "pipeline:sbom#KSI-SCR-MIT",
        source: "pipeline",
        automated: true,
        clock: "machine",
        standing: "full",
        state: "evidenced",
        recipeId: "sbom",
        bundleDigest: "aaa",
        freshAsOf: "2026-09-10T00:00:00.000Z",
        window: { num: 7, unit: "days" },
        freshMet: true,
      },
    ],
    automatedMethods: 1,
    methodFloor: 1,
    floorMet: true,
    freshAsOf: "2026-09-10T00:00:00.000Z",
    historySince: "2026-03-01T00:00:00.000Z",
    historyFloorMonths: null,
    historyMet: null,
    staleMethods: 0,
    artifacts: [
      { artifact: 1, basis: "computed", present: true },
      { artifact: 2, basis: "computed", present: false },
      { artifact: 3, basis: "judged", present: false },
      { artifact: 4, basis: "judged", present: false },
      { artifact: 5, basis: "judged", present: false },
    ],
    artifactsPresent: 1,
    pointInTimeMethods: 0,
  },
  {
    repo: "/repo/app",
    ksi: "KSI-CMT-CHG",
    methods: [],
    automatedMethods: 0,
    methodFloor: 1,
    floorMet: false,
    historyFloorMonths: null,
    historyMet: null,
    staleMethods: 0,
    artifacts: [
      { artifact: 1, basis: "computed", present: false },
      { artifact: 2, basis: "computed", present: false },
      { artifact: 3, basis: "judged", present: false },
      { artifact: 4, basis: "judged", present: false },
      { artifact: 5, basis: "judged", present: false },
    ],
    artifactsPresent: 0,
    pointInTimeMethods: 0,
    gap: "G1",
  },
];

const vulnerabilities: ValidationVulnerability[] = [
  {
    repo: "/repo/app",
    recipeId: "secrets",
    ksiIds: ["KSI-SCR-MIT"],
    detectedAt: "2026-08-02T00:00:00.000Z",
    commit: "deadbeef",
    bundleDigest: "vuln-1",
    status: "open",
  },
];

const drift: DriftEvent[] = [
  { at: "2026-07-01T00:00:00.000Z", repo: "/repo/app", recipeId: "sbom", kind: "born", bundleDigest: "aaa" },
  {
    at: "2026-08-02T00:00:00.000Z",
    repo: "/repo/app",
    recipeId: "secrets",
    kind: "verdict-flipped",
    from: "evidenced",
    to: "violated",
    bundleDigest: "vuln-1",
  },
  {
    at: "2026-02-01T00:00:00.000Z", // BEFORE the declared period — must not appear
    repo: "/repo/app",
    recipeId: "ancient",
    kind: "born",
    bundleDigest: "old",
  },
];

function input(overrides: Partial<FedrampExportInput> = {}): FedrampExportInput {
  return {
    offering: offering(),
    offeringClass: "b",
    repo: "/repo/app",
    projectedAt: "2026-09-12T12:00:00.000Z",
    datasetVersion: "2026.07.14.01",
    methodRegisters,
    vulnerabilities,
    drift,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// the pins
// ---------------------------------------------------------------------------

describe("the pinned schemas", () => {
  it("loads all three at their pinned bytes and versions", async () => {
    const loaded = await loadPinnedSchema(REPO_ROOT, PACKAGE_OVERVIEW_SCHEMA);
    expect(loaded.registry.size).toBe(2); // the target plus common definitions
    expect(loaded.schema["$schemaVersion"]).toBe(
      FEDRAMP_SCHEMA_PINS[PACKAGE_OVERVIEW_SCHEMA]!.schemaVersion,
    );
  });

  it("pins each schema separately, because FedRAMP semvers them separately", () => {
    const versions = new Set(Object.values(FEDRAMP_SCHEMA_PINS).map((p) => p.schemaVersion));
    // three files, three different versions off one date stamp — a single
    // global pin would have been wrong the day it was written
    expect(versions.size).toBe(3);
  });

  it("refuses a schema whose bytes drifted from the pin", async () => {
    const dir = await mkdtemp(join(tmpdir(), "rampscan-schemas-"));
    const nested = join(dir, "docs", "context", "fedramp-schemas");
    await writeFile(join(dir, "marker"), "");
    const { mkdir } = await import("node:fs/promises");
    await mkdir(nested, { recursive: true });
    for (const name of [PACKAGE_OVERVIEW_SCHEMA, COMMON_SCHEMA]) {
      const bytes = await readFile(join(REPO_ROOT, "docs/context/fedramp-schemas", name), "utf8");
      // one byte of description text — semantically nothing, and refused anyway
      await writeFile(join(nested, name), bytes.replace("Cloud Service Offering", "cloud service offering"));
    }
    await expect(loadPinnedSchema(dir, PACKAGE_OVERVIEW_SCHEMA)).rejects.toThrow(
      /does not match its pinned bytes/,
    );
  });
});

// ---------------------------------------------------------------------------
// the validator — it must actually reject
// ---------------------------------------------------------------------------

describe("the conformance validator", () => {
  it("reports a missing required field by JSON Pointer", async () => {
    const loaded = await loadPinnedSchema(REPO_ROOT, PACKAGE_OVERVIEW_SCHEMA);
    const violations = validateAgainst(loaded, {});
    expect(violations.map((v) => v.path).sort()).toEqual([
      "/contactInformation",
      "/serviceIdentification",
      "/serviceProperties",
    ]);
  });

  it("reports every violation, not only the first", async () => {
    const loaded = await loadPinnedSchema(REPO_ROOT, OCR_SCHEMA);
    const violations = validateAgainst(loaded, { reportPeriod: { from: "nope" } });
    // eight required fields, one absent nested field, one bad date
    expect(violations.length).toBeGreaterThan(5);
    expect(violations.some((v) => v.path === "/reportPeriod/from")).toBe(true);
    expect(violations.some((v) => v.path === "/reportPeriod/to")).toBe(true);
  });

  it("rejects a bad enum, type, pattern and format", async () => {
    const loaded = await loadPinnedSchema(REPO_ROOT, PACKAGE_OVERVIEW_SCHEMA);
    const document = buildPackageOverview(input()).document;
    expect(validateAgainst(loaded, document)).toEqual([]);

    const broken = structuredClone(document);
    (broken["serviceIdentification"] as Record<string, unknown>)["certificationType"] = "20y";
    (broken["serviceProperties"] as Record<string, unknown>)["serviceType"] = "SaaS"; // string, not array
    (broken["contactInformation"] as Array<Record<string, unknown>>)[1]!["contactPhone"] = "5550123";
    (broken["serviceIdentification"] as Record<string, unknown>)["website"] = "not-a-url";
    const violations = validateAgainst(loaded, broken);
    const messages = violations.map((v) => `${v.path}: ${v.message}`);
    expect(messages).toContain('/serviceIdentification/certificationType: "20y" is not one of "20x", "Rev5"');
    expect(messages).toContain("/serviceProperties/serviceType: expected array, got string");
    expect(messages.some((m) => m.startsWith("/contactInformation/1/contactPhone: does not match pattern"))).toBe(true);
    expect(messages).toContain("/serviceIdentification/website: is not a valid uri");
  });

  it("resolves a local $ref against its DOCUMENT, not the node that carried it", async () => {
    // `contactInformation.items` is `$ref: #/$defs/contactInfo`. Resolving that
    // against the items node — which has no $defs — is the bug this pins.
    const loaded = await loadPinnedSchema(REPO_ROOT, PACKAGE_OVERVIEW_SCHEMA);
    const document = buildPackageOverview(input()).document as Record<string, unknown>;
    const broken = structuredClone(document) as Record<string, Array<Record<string, unknown>>>;
    delete broken["contactInformation"]![0]!["contactType"];
    // the `required` inside the $ref'd contactInfo fires, AND the schema's own
    // allOf/contains loses its Security contact — both are the point
    expect(validateAgainst(loaded, broken)).toEqual([
      { path: "/contactInformation/0/contactType", message: "required field is absent" },
      {
        path: "/contactInformation",
        message: 'no item satisfies the required "contains" shape (contactType="Security")',
      },
    ]);
  });

  it("resolves a CROSS-DOCUMENT $ref into the common definitions schema", async () => {
    // `logo` refs common's `logoUri`, whose pattern lives in the other file
    const loaded = await loadPinnedSchema(REPO_ROOT, PACKAGE_OVERVIEW_SCHEMA);
    const document = buildPackageOverview(input()).document;
    const broken = structuredClone(document);
    (broken["serviceIdentification"] as Record<string, unknown>)["logo"] = "https://example.com/logo.pdf";
    const violations = validateAgainst(loaded, broken);
    expect(violations.map((v) => v.path)).toEqual(["/serviceIdentification/logo"]);
  });

  it("enforces the schema's own allOf/contains: a Security and a Sales contact", async () => {
    const loaded = await loadPinnedSchema(REPO_ROOT, PACKAGE_OVERVIEW_SCHEMA);
    const document = buildPackageOverview(input()).document as Record<string, unknown>;
    const broken = structuredClone(document) as Record<string, unknown>;
    broken["contactInformation"] = [{ contactType: "Primary" }];
    const violations = validateAgainst(loaded, broken);
    expect(violations).toHaveLength(2);
    expect(violations[0]!.message).toContain('contactType="Security"');
    expect(violations[1]!.message).toContain('contactType="Sales"');
  });

  it("enforces the repository if/then: a gated repository owes access instructions", async () => {
    const loaded = await loadPinnedSchema(REPO_ROOT, PACKAGE_OVERVIEW_SCHEMA);
    // built by hand: the declaration's own refine blocks this shape earlier,
    // which is the point — but the schema must catch it too
    const document = {
      ...(buildPackageOverview(input()).document as Record<string, unknown>),
    } as Record<string, Record<string, unknown>>;
    document["serviceProperties"] = {
      ...document["serviceProperties"],
      trustCenter: {
        repositoryType: ["Trust Center"],
        url: "https://trust.example.com",
        repositoryDescription: "gated",
        authenticationRequired: true,
      },
    };
    const violations = validateAgainst(loaded, document);
    expect(violations).toEqual([
      {
        path: "/serviceProperties/trustCenter/accessRequestInstructions",
        message: "required field is absent",
      },
    ]);
  });

  it("rejects a shaped-but-impossible date rather than pattern-matching it", async () => {
    const loaded = await loadPinnedSchema(REPO_ROOT, OCR_SCHEMA);
    const built = buildOngoingCertificationReport(
      input({ offering: offering({ report: reportJson }) }),
    ).export!;
    const broken = structuredClone(built.document) as Record<string, Record<string, unknown>>;
    broken["reportPeriod"]!["from"] = "2026-02-30";
    expect(validateAgainst(loaded, broken)).toEqual([
      { path: "/reportPeriod/from", message: "is not a valid date" },
    ]);
  });
});

// ---------------------------------------------------------------------------
// the declared/computed line
// ---------------------------------------------------------------------------

describe("the declared/computed line", () => {
  it("has no slot for a computed field — a provider cannot type a report period", () => {
    expect(() =>
      OfferingConfig.parse({
        ...offeringJson,
        report: { ...reportJson, reportPeriod: { from: "2020-01-01", to: "2020-04-01" } },
      }),
    ).toThrow();
  });

  it("has no slot for certificationDataChanges — only for changes ADDED to it", () => {
    expect(() =>
      OfferingConfig.parse({
        ...offeringJson,
        report: { ...reportJson, certificationDataChanges: ["we rewrote history"] },
      }),
    ).toThrow();
    const ok = OfferingConfig.parse({
      ...offeringJson,
      report: { ...reportJson, additionalCertificationDataChanges: ["Added a region."] },
    });
    expect(ok.report?.additionalCertificationDataChanges).toEqual(["Added a region."]);
  });

  it("appends declared changes after computed ones, never in place of them", () => {
    const built = buildOngoingCertificationReport(
      input({
        offering: offering({
          report: { ...reportJson, additionalCertificationDataChanges: ["Added a second region."] },
        }),
      }),
    ).export!;
    const changes = built.document["certificationDataChanges"] as string[];
    expect(changes.at(-1)).toBe("Added a second region.");
    expect(changes.length).toBeGreaterThan(1);
    expect(changes.some((c) => c.includes("newly evidenced"))).toBe(true);
  });

  it("labels every top-level field declared, computed or mixed, in the document", () => {
    const built = buildOngoingCertificationReport(input({ offering: offering({ report: reportJson }) })).export!;
    const extension = built.document["x-rampscan"] as Record<string, unknown>;
    expect(extension["fieldSources"]).toMatchObject({
      reportPeriod: "computed",
      certificationDataChanges: "mixed",
      reportableIncidents: "declared",
      acceptedVulnerabilities: "declared",
    });
  });

  it("keeps the G13 feed OUT of acceptedVulnerabilities and says why", () => {
    const built = buildOngoingCertificationReport(input({ offering: offering({ report: reportJson }) })).export!;
    expect(built.document["acceptedVulnerabilities"]).toBe(reportJson.acceptedVulnerabilities);
    const extension = built.document["x-rampscan"] as Record<string, Record<string, unknown>>;
    const feed = extension["validationVulnerabilities"]!;
    expect(feed["open"]).toBe(1);
    expect(String(feed["note"])).toContain("acceptance is a provider risk determination");
    // and the open record is surfaced as a stated problem, not buried
    expect(built.problems.some((p) => p.includes("stand open"))).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// the attestation refusal
// ---------------------------------------------------------------------------

describe("the incident attestation", () => {
  it("generates no OCR when no report is declared, and says why", () => {
    const outcome = buildOngoingCertificationReport(input());
    expect(outcome.export).toBeUndefined();
    expect(outcome.skipped).toContain("does not make attestations on a provider's behalf");
  });

  it("refuses a report declaration with no reportableIncidents key", () => {
    const { reportableIncidents: _omitted, ...withoutIncidents } = reportJson;
    expect(() => OfferingConfig.parse({ ...offeringJson, report: withoutIncidents })).toThrow();
  });

  it("states plainly that an empty incidents array IS the attestation", () => {
    const built = buildOngoingCertificationReport(
      input({ offering: offering({ report: reportJson }) }),
    ).export!;
    expect(built.problems.some((p) => p.includes("ATTESTS that no FedRAMP Reportable Incidents"))).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// the computed half
// ---------------------------------------------------------------------------

describe("the computed half", () => {
  it("summarises drift by kind rather than pasting every event", () => {
    const lines = certificationDataChanges(drift);
    expect(lines).toHaveLength(2); // born, verdict-flipped — one line each
    expect(lines[0]).toContain("2 validations newly evidenced");
    expect(lines[1]).toContain("into `violated`");
  });

  it("says what it can see rather than that nothing happened", () => {
    const lines = certificationDataChanges([]);
    expect(lines).toHaveLength(1);
    expect(lines[0]).toContain("no changes recorded in the evidence ledger");
    expect(lines[0]).toContain("not an assertion about FedRAMP Certification Data the ledger does not cover");
  });

  it("reads only drift inside the report period", () => {
    const built = buildOngoingCertificationReport(
      input({ offering: offering({ report: reportJson }) }),
    ).export!;
    const extension = built.document["x-rampscan"] as Record<string, Record<string, unknown>>;
    // the 2026-02 event predates the declared 2026-06-12 period opening
    expect(extension["certificationDataChangesBasis"]!["driftEventsInPeriod"]).toBe(2);
  });

  it("opens the period three calendar months back for a first report, and flags it", () => {
    const { previousReportThrough: _none, ...firstReport } = reportJson;
    const built = buildOngoingCertificationReport(
      input({ offering: offering({ report: firstReport }) }),
    ).export!;
    expect(built.document["reportPeriod"]).toEqual({ from: "2026-06-12", to: "2026-09-12" });
    expect(built.problems.some((p) => p.includes("correct for a FIRST report"))).toBe(true);
  });

  it("carries a validation summary computed from the register, not typed", () => {
    const built = buildPackageOverview(input());
    const extension = built.document["x-rampscan"] as Record<string, Record<string, unknown>>;
    expect(extension["validation"]).toMatchObject({
      offeringClass: "b",
      ksisTracked: 2,
      automatedMethods: 1,
      methodFloor: 1,
      ksisMeetingFloor: 1,
      staleMethods: 0,
      freshestEvidence: "2026-09-10T00:00:00.000Z",
      historySince: "2026-03-01T00:00:00.000Z",
      gapsByClass: { G1: 1 },
    });
  });

  it("states the package overview is declared end to end", () => {
    const extension = buildPackageOverview(input()).document["x-rampscan"] as Record<string, unknown>;
    expect(String(extension["note"])).toContain("Every schema field in this document is DECLARED");
  });
});

// ---------------------------------------------------------------------------
// the exit gate
// ---------------------------------------------------------------------------

describe("Q5 exit gate", () => {
  it("writes both documents schema-valid, each carrying its own conformance verdict", async () => {
    const exportsDir = join(await mkdtemp(join(tmpdir(), "rampscan-exports-")), "exports");
    const result = await writeFedrampExports({
      ...input({ offering: offering({ report: reportJson }) }),
      schemaRoot: REPO_ROOT,
      exportsDir,
    });

    expect(result.conformant).toBe(true);
    expect(result.written.map((w) => w.filename)).toEqual([
      "fedramp-certification-package-overview.json",
      "fedramp-ongoing-certification-report.json",
    ]);

    for (const written of result.written) {
      const document = JSON.parse(await readFile(written.path, "utf8")) as Record<string, Record<string, unknown>>;
      const conformance = document["x-rampscan"]!["conformance"] as Record<string, unknown>;
      expect(conformance["valid"]).toBe(true);
      expect(conformance["ruleId"]).toBe("FRC-CSO-JSN");
      expect(conformance["schemaSha256"]).toBe(FEDRAMP_SCHEMA_PINS[written.schemaFile]!.sha256);
      // the stated shortfalls travel with the file, not only to a terminal
      expect(document["x-rampscan"]!["problems"]).toEqual(written.problems);
      // and the written bytes are still valid AFTER the stamp
      const loaded = await loadPinnedSchema(REPO_ROOT, written.schemaFile);
      expect(validateAgainst(loaded, document)).toEqual([]);
    }
  });

  it("writes a nonconforming document too, stamped with its violations", async () => {
    const exportsDir = join(await mkdtemp(join(tmpdir(), "rampscan-exports-")), "exports");
    // a logo that the schema's pattern rejects but the declaration allowed:
    // reached by bypassing the config parse, the way a schema bump would
    const loose = { ...offering(), logo: "https://example.com/logo" } as ReturnType<typeof offering>;
    const result = await writeFedrampExports({
      ...input({ offering: loose }),
      schemaRoot: REPO_ROOT,
      exportsDir,
    });
    expect(result.conformant).toBe(false);
    const document = JSON.parse(
      await readFile(result.written[0]!.path, "utf8"),
    ) as Record<string, Record<string, unknown>>;
    const conformance = document["x-rampscan"]!["conformance"] as Record<string, unknown>;
    expect(conformance["valid"]).toBe(false);
    expect(conformance["violations"]).toHaveLength(1);
  });

  it("reads the self-scan's own declared offering", async () => {
    const declared = await loadOffering(REPO_ROOT);
    expect(declared).toBeDefined();
    expect(declared!.certificationType).toBe("20x");
  });

  it("refuses a malformed offering block rather than silently waiving it", async () => {
    const dir = await mkdtemp(join(tmpdir(), "rampscan-offering-"));
    await writeFile(
      join(dir, "rampscan.config.json"),
      JSON.stringify({ offering: { ...offeringJson, contacts: offeringJson.contactInformation } }),
    );
    await expect(loadOffering(dir)).rejects.toThrow(/failed validation \(exit refused\)/);
  });

  it("returns undefined when no offering is declared — a claim never made", async () => {
    const dir = await mkdtemp(join(tmpdir(), "rampscan-offering-"));
    await writeFile(join(dir, "rampscan.config.json"), JSON.stringify({ graph: {} }));
    expect(await loadOffering(dir)).toBeUndefined();
  });
});
