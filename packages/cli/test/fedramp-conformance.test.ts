import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  checkConformance,
  renderConformance,
  resolveSchema,
} from "../src/fedramp-conformance.js";
import { OCR_ARTIFACT, PACKAGE_OVERVIEW_ARTIFACT } from "../src/fedramp-exports.js";
import { OCR_SCHEMA, PACKAGE_OVERVIEW_SCHEMA } from "../src/fedramp-schemas.js";
import { buildPackageOverview } from "../src/fedramp-exports.js";
import { loadOffering } from "../src/offering.js";
import { OfferingConfig } from "@rampscan/schema";

// Q5.2 — the package conformance check (G10, `FRC-CSO-JSN`).
//
// What these tests pin, in order of how much it would hurt to get wrong:
//
//   1. IT FAILS CLOSED. A document whose schema cannot be resolved, a
//      directory with nothing in it, a stamp naming a schema we do not pin —
//      every one is an exit. A conformance checker that skips is worse than
//      none, because it reports on files it never opened.
//   2. THE STAMP IS CHECKED AGAINST A FRESH VALIDATION. This is the only thing
//      the command does that regenerating could not, so it is the thing most
//      worth a test.
//   3. Clean documents read clean, and every document is named either way.

const REPO_ROOT = join(import.meta.dirname, "../../..");

/** A minimal package overview that actually validates against the pinned schema. */
function overviewDocument(): Record<string, unknown> {
  return {
    serviceIdentification: {
      fedRampPackageId: "Example Cloud Inc. (EPEP)",
      providerName: "Example Cloud Inc.",
      serviceName: "Example Pipeline Evidence Plane",
      serviceAcronym: "EPEP",
      serviceDescription: "A CI/CD evidence plane for FedRAMP 20x key security indicators.",
      certificationType: "20x",
      website: "https://example.com/epep",
      logo: "https://example.com/logo.svg",
    },
    serviceProperties: { serviceType: ["SaaS"], deploymentModel: "Public Cloud" },
    contactInformation: [
      { contactType: "Security", contactName: "Security Team", contactEmail: "security@example.com" },
      { contactType: "Sales", contactName: "Sales Team", contactPhone: "202-555-0123" },
    ],
  };
}

function stamp(valid: boolean, overrides: Record<string, unknown> = {}) {
  return {
    conformance: {
      ruleId: "FRC-CSO-JSN",
      schema: PACKAGE_OVERVIEW_SCHEMA,
      schemaVersion: "0.1.4",
      valid,
      violations: [],
      ...overrides,
    },
  };
}

async function dir(files: Record<string, unknown>): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "rampscan-conformance-"));
  for (const [name, body] of Object.entries(files)) {
    await writeFile(join(root, name), JSON.stringify(body, null, 2) + "\n");
  }
  return root;
}

describe("resolving which schema gates a document", () => {
  it("prefers an explicit --schema over everything else", () => {
    const resolved = resolveSchema("/x/anything.json", {}, OCR_SCHEMA);
    expect(resolved).toEqual({ schemaFile: OCR_SCHEMA, schemaSource: "--schema" });
  });

  it("reads the document's own stamp when there is no override", () => {
    const resolved = resolveSchema("/x/renamed.json", { "x-rampscan": stamp(true) });
    expect(resolved.schemaFile).toBe(PACKAGE_OVERVIEW_SCHEMA);
    expect(resolved.schemaSource).toBe("x-rampscan stamp");
  });

  it("falls back to the filename rampscan itself writes", () => {
    expect(resolveSchema(`/x/${OCR_ARTIFACT}`, {}).schemaSource).toBe("filename");
    expect(resolveSchema(`/x/${OCR_ARTIFACT}`, {}).schemaFile).toBe(OCR_SCHEMA);
  });

  it("REFUSES an unrecognised document rather than skipping it", () => {
    expect(() => resolveSchema("/x/somebody-elses.json", { serviceIdentification: {} })).toThrow(
      /cannot tell which FedRAMP schema/,
    );
  });

  it("refuses a stamp naming a schema this checkout does not pin", () => {
    const doc = { "x-rampscan": stamp(true, { schema: "fedramp-something-2027.json" }) };
    expect(() => resolveSchema("/x/old.json", doc)).toThrow(/does not pin/);
  });

  it("refuses an unpinned --schema", () => {
    expect(() => resolveSchema("/x/a.json", {}, "not-a-schema.json")).toThrow(/not a pinned/);
  });

  it("never infers a schema from the document's SHAPE", () => {
    // shaped exactly like a package overview, named nothing, stamped nothing:
    // guessing here would pick the schema a malformed document resembles
    expect(() => resolveSchema("/x/untitled.json", overviewDocument())).toThrow(
      /cannot tell which FedRAMP schema/,
    );
  });
});

describe("the check", () => {
  it("reads a clean document as conformant and names it", async () => {
    const root = await dir({
      [PACKAGE_OVERVIEW_ARTIFACT]: { ...overviewDocument(), "x-rampscan": stamp(true) },
    });
    const result = await checkConformance({ schemaRoot: REPO_ROOT, target: root });
    expect(result.conformant).toBe(true);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]?.violations).toEqual([]);
    expect(result.findings[0]?.stampDisagreement).toBeUndefined();
    expect(renderConformance(result)).toContain("1 document(s) conform");
  });

  it("reports a violation by JSON Pointer", async () => {
    const doc = overviewDocument();
    delete doc["contactInformation"];
    const root = await dir({ [PACKAGE_OVERVIEW_ARTIFACT]: doc });
    const result = await checkConformance({ schemaRoot: REPO_ROOT, target: root });
    expect(result.conformant).toBe(false);
    expect(result.findings[0]?.violations.map((v) => v.path)).toContain("/contactInformation");
  });

  it("catches a document that stamps itself conformant and is NOT", async () => {
    const doc = overviewDocument();
    delete doc["contactInformation"];
    const root = await dir({
      [PACKAGE_OVERVIEW_ARTIFACT]: { ...doc, "x-rampscan": stamp(true) },
    });
    const result = await checkConformance({ schemaRoot: REPO_ROOT, target: root });
    expect(result.conformant).toBe(false);
    expect(result.findings[0]?.stampDisagreement).toMatch(/stamps itself conformant and it is not/);
  });

  it("catches a document that stamps itself NONconformant and validates clean", async () => {
    // the honest version of this: a fix landed, the stamp predates it
    const root = await dir({
      [PACKAGE_OVERVIEW_ARTIFACT]: {
        ...overviewDocument(),
        "x-rampscan": stamp(false, { violations: [{ path: "/x", message: "gone now" }] }),
      },
    });
    const result = await checkConformance({ schemaRoot: REPO_ROOT, target: root });
    expect(result.conformant).toBe(false);
    expect(result.findings[0]?.stampDisagreement).toMatch(/validates clean/);
  });

  it("catches a document judged against a schema VERSION we no longer pin", async () => {
    const root = await dir({
      [PACKAGE_OVERVIEW_ARTIFACT]: {
        ...overviewDocument(),
        "x-rampscan": stamp(true, { schemaVersion: "0.1.3" }),
      },
    });
    const result = await checkConformance({ schemaRoot: REPO_ROOT, target: root });
    expect(result.conformant).toBe(false);
    expect(result.findings[0]?.stampDisagreement).toMatch(/0\.1\.3.*pins @ 0\.1\.4/);
  });

  it("does not call an UNSTAMPED document a liar", async () => {
    const root = await dir({ [PACKAGE_OVERVIEW_ARTIFACT]: overviewDocument() });
    const result = await checkConformance({ schemaRoot: REPO_ROOT, target: root });
    expect(result.conformant).toBe(true);
    expect(result.findings[0]?.stampDisagreement).toBeUndefined();
    expect(result.findings[0]?.schemaSource).toBe("filename");
  });

  it("takes a single file as well as a directory", async () => {
    const root = await dir({ [PACKAGE_OVERVIEW_ARTIFACT]: overviewDocument() });
    const result = await checkConformance({
      schemaRoot: REPO_ROOT,
      target: join(root, PACKAGE_OVERVIEW_ARTIFACT),
    });
    expect(result.findings).toHaveLength(1);
    expect(result.conformant).toBe(true);
  });

  it("refuses an EMPTY directory — nothing checked is not a pass", async () => {
    const root = await dir({});
    await expect(checkConformance({ schemaRoot: REPO_ROOT, target: root })).rejects.toThrow(
      /no JSON document to check/,
    );
  });

  it("checks every document in the directory, not only the first", async () => {
    const broken = overviewDocument();
    delete broken["serviceProperties"];
    const root = await dir({
      [PACKAGE_OVERVIEW_ARTIFACT]: overviewDocument(),
      "second-overview.json": { ...broken, "x-rampscan": stamp(true) },
    });
    const result = await checkConformance({ schemaRoot: REPO_ROOT, target: root });
    expect(result.findings).toHaveLength(2);
    expect(result.conformant).toBe(false);
    // both named, so a reader can tell "clean" from "never ran"
    const rendered = renderConformance(result);
    expect(rendered).toContain(PACKAGE_OVERVIEW_ARTIFACT);
    expect(rendered).toContain("second-overview.json");
  });
});

// ---------------------------------------------------------------------------
// ground rule 7, applied to our own gate
// ---------------------------------------------------------------------------

describe("the CI gate is able to fail", () => {
  // A gate that cannot fail is not a gate, and this one is closer to that than
  // it looks: `OfferingConfig` deliberately MIRRORS the FedRAMP schema's own
  // constraints — the Sales contact, the phone pattern, the six-digit
  // assessorID, the gated-repository if/then — so that a typo fails one layer
  // closer to the person who can fix it. A config that parses is therefore
  // already most of the way to a conforming document.
  //
  // What the conformance check still catches is the DIVERGENCE between that
  // hand-written mirror and the pinned schema it mirrors. The mirror is
  // maintained by hand against a draft and the pin will bump, so the divergence
  // is not hypothetical — it exists today, and this test names it. If a future
  // pin closes this particular gap, this test fails and the next divergence
  // must be found and named rather than the gate being assumed alive.
  it("catches a declaration zod accepts and the FedRAMP schema does not", async () => {
    const declared = await loadOffering(REPO_ROOT);
    // `businessCategory` is z.array(z.string().min(1)) in the mirror and a
    // closed 36-value enum in the schema
    const diverged = OfferingConfig.parse({ ...declared, businessCategory: ["Widgets"] });
    expect(diverged.businessCategory).toEqual(["Widgets"]);

    const built = buildPackageOverview({
      offering: diverged,
      offeringClass: "b",
      projectedAt: "2026-09-12T12:00:00.000Z",
      datasetVersion: "2026.07.14.01",
      methodRegisters: [],
      vulnerabilities: [],
      drift: [],
    });

    const root = await dir({ [PACKAGE_OVERVIEW_ARTIFACT]: built.document });
    const result = await checkConformance({ schemaRoot: REPO_ROOT, target: root });
    expect(result.conformant).toBe(false);
    expect(result.findings[0]?.violations.map((v) => v.path)).toContain(
      "/serviceProperties/businessCategory/0",
    );
  });

  it("and passes this repository's real declaration unchanged", async () => {
    const declared = await loadOffering(REPO_ROOT);
    const built = buildPackageOverview({
      offering: declared!,
      offeringClass: "b",
      projectedAt: "2026-09-12T12:00:00.000Z",
      datasetVersion: "2026.07.14.01",
      methodRegisters: [],
      vulnerabilities: [],
      drift: [],
    });
    const root = await dir({ [PACKAGE_OVERVIEW_ARTIFACT]: built.document });
    const result = await checkConformance({ schemaRoot: REPO_ROOT, target: root });
    expect(result.conformant).toBe(true);
  });
});
