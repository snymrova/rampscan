import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { loadRuleRegister, DEFAULT_DATASET_PIN } from "@rampscan/dataset";
import { OfferingConfig } from "@rampscan/schema";
import { buildRejectionRegister } from "../src/submission.js";
import {
  classifyTarget,
  clickThroughMarkers,
  loadTrustCenterProbe,
  pinnedDocumentValidator,
  probeTrustCenter,
  type DocumentValidator,
  type TrustCenterProbe,
} from "../src/trust-center-probe.js";

// P4 (#213; docs/RESEARCH-TRUST-CENTER-PROBE.md): the trust-center probe.
//
// The rule every test here leans on: a negative is proven positively. A page
// that loads is UNDETERMINED; OPEN takes a certification document validating
// against a pinned schema; GATED takes positive evidence, and says which kind
// — because FedRAMP permits a declared login, and rejects acceptance.

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const DOC = join(REPO_ROOT, "fixtures/trust-center-probe/certification-package-overview.json");
const RULES = join(REPO_ROOT, "docs/context/fedramp-rules/fedramp-consolidated-rules.json");

const never: DocumentValidator = () => undefined;
const always: DocumentValidator = () => "fedramp-certification-package-overview-schema-2026-06-24.json";
const ok = (body: string, contentType = "text/html") => ({
  hops: [{ url: "https://tc.example.com/", status: 200 }],
  contentType,
  body: Buffer.from(body),
});

describe("the classifier (pure)", () => {
  it("reads a clean 200 on a landing page as UNDETERMINED, never open", () => {
    const t = classifyTarget("https://tc.example.com/", "trust-center", ok("<h1>Trust</h1>"), always);
    expect(t.outcome).toBe("undetermined");
    expect(t.reasons[0]).toContain("proves a page loaded");
  });

  it("does not gate on a bare privacy-policy footer link", () => {
    expect(clickThroughMarkers('<footer><a href="/p">Privacy Policy</a></footer>')).toEqual([]);
  });

  it("gates on terms language beside an acceptance control — a click-through, reason 1", () => {
    const t = classifyTarget(
      "https://tc.example.com/",
      "trust-center",
      ok("<p>Review our Terms of Service.</p><button>I agree</button>"),
      always,
    );
    expect(t.outcome).toBe("gated");
    expect(t.gate).toBe("click-through");
    expect(t.reasons[0]).toContain("terms of service");
  });

  it("gates on an NDA alone, as a click-through", () => {
    const t = classifyTarget("https://tc.example.com/", "trust-center", ok("Please sign the NDA to view."), always);
    expect(t.gate).toBe("click-through");
  });

  it("reads 401/403 and a login redirect as an AUTHENTICATION gate, not a click-through", () => {
    const forbidden = classifyTarget(
      "https://tc.example.com/doc.json",
      "document",
      { hops: [{ url: "https://tc.example.com/doc.json", status: 403 }], body: Buffer.alloc(0) },
      always,
    );
    expect(forbidden.gate).toBe("authentication");
    const sso = classifyTarget(
      "https://tc.example.com/",
      "trust-center",
      {
        hops: [
          { url: "https://tc.example.com/", status: 302, location: "https://acme.okta.com/app/x" },
          { url: "https://acme.okta.com/app/x", status: 200 },
        ],
        body: Buffer.from("<html></html>"),
      },
      always,
    );
    expect(sso.outcome).toBe("gated");
    expect(sso.gate).toBe("authentication");
    expect(sso.reasons[0]).toContain("okta.com");
  });

  it("opens a document ONLY when its bytes validate against a pinned schema", () => {
    const json = ok('{"a":1}', "application/json");
    const doc = classifyTarget("https://tc.example.com/d.json", "document", json, always);
    expect(doc.outcome).toBe("open");
    expect(doc.schema).toContain("package-overview");
    expect(doc.sha256).toMatch(/^[0-9a-f]{64}$/);
    // an error body served 200 is not certification data
    expect(classifyTarget("https://tc.example.com/d.json", "document", json, never).outcome).toBe(
      "undetermined",
    );
    // and a landing page can never be open, even if its body would validate
    expect(classifyTarget("https://tc.example.com/", "trust-center", json, always).outcome).toBe(
      "undetermined",
    );
  });

  it("reads a 404 and a network failure as undetermined, saying why", () => {
    const missing = classifyTarget(
      "https://tc.example.com/d.json",
      "document",
      { hops: [{ url: "https://tc.example.com/d.json", status: 404 }] },
      always,
    );
    expect(missing.outcome).toBe("undetermined");
    expect(missing.reasons[0]).toContain("missing document, not a gate");
    const down = classifyTarget("https://tc.example.com/", "trust-center", { hops: [], error: "ECONNREFUSED" }, always);
    expect(down.outcome).toBe("undetermined");
  });
});

describe("the probe against a live server", () => {
  let base = "";
  const server = createServer((req, res) => {
    if (req.url === "/tc") {
      res.writeHead(200, { "content-type": "text/html" }).end("<h1>Example Trust Center</h1>");
    } else if (req.url === "/doc.json") {
      void readFile(DOC).then((b) => res.writeHead(200, { "content-type": "application/json" }).end(b));
    } else if (req.url === "/gated") {
      res.writeHead(302, { location: "/login?next=/gated" }).end();
    } else if (req.url === "/nda") {
      res
        .writeHead(200, { "content-type": "text/html" })
        .end("<p>You must accept the Non-Disclosure Agreement.</p><button>Accept and continue</button>");
    } else {
      res.writeHead(404).end();
    }
  });
  beforeAll(async () => {
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });
  afterAll(() => new Promise<void>((r) => server.close(() => r())));

  it("proves open with a real pinned-schema document, and records every target", async () => {
    const probe = await probeTrustCenter({
      trustCenter: `${base}/tc`,
      documents: [`${base}/doc.json`],
      validate: await pinnedDocumentValidator(REPO_ROOT),
      fetch: { userAgent: "rampscan-test" },
    });
    expect(probe.targets.map((t) => t.outcome)).toEqual(["undetermined", "open"]);
    expect(probe.outcome).toBe("open");
    expect(probe.targets[1]!.schema).toContain("certification-package-overview");
  });

  it("follows a redirect by hand and gates on the login it lands in", async () => {
    const probe = await probeTrustCenter({
      trustCenter: `${base}/tc`,
      documents: [`${base}/gated`],
      validate: always,
      fetch: { userAgent: "rampscan-test" },
    });
    const gated = probe.targets[1]!;
    expect(gated.hops[0]).toMatchObject({ status: 302, location: "/login?next=/gated" });
    expect(gated.gate).toBe("authentication");
    expect(probe.outcome).toBe("gated");
  });

  it("with no document named, nothing can read open", async () => {
    const probe = await probeTrustCenter({
      trustCenter: `${base}/tc`,
      documents: [],
      validate: always,
      fetch: { userAgent: "rampscan-test" },
    });
    expect(probe.outcome).toBe("undetermined");
  });

  it("round-trips through the transcript, and refuses one whose summary disagrees with its targets", async () => {
    const probe = await probeTrustCenter({
      trustCenter: `${base}/nda`,
      documents: [],
      validate: always,
      fetch: { userAgent: "rampscan-test" },
    });
    expect(probe.outcome).toBe("gated");
    const dir = await mkdtemp(join(tmpdir(), "rampscan-p4-"));
    const path = join(dir, "probe.json");
    await writeFile(path, JSON.stringify(probe));
    expect((await loadTrustCenterProbe(path)).outcome).toBe("gated");
    await writeFile(path, JSON.stringify({ ...probe, outcome: "open" }));
    await expect(loadTrustCenterProbe(path)).rejects.toThrow(/disagrees with its evidence/);
  });
});

describe("reason 1 in the rejection register (P4)", () => {
  const TC = "https://trust.example.gov/";
  const offering = (authenticationRequired: boolean) =>
    OfferingConfig.parse({
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
      trustCenter: {
        repositoryType: ["Trust Center"],
        url: TC,
        repositoryDescription: "the trust center",
        authenticationRequired,
        ...(authenticationRequired ? { accessRequestInstructions: "request via the portal" } : {}),
      },
    });
  const probeOf = (targets: TrustCenterProbe["targets"], outcome: TrustCenterProbe["outcome"]): TrustCenterProbe => ({
    _type: "https://rampscan.dev/trust-center-probe/v1",
    trust_center: TC,
    probed_at: "2026-09-18T12:00:00.000Z",
    user_agent: "rampscan-test",
    targets,
    outcome,
  });
  const landing = { url: TC, role: "trust-center" as const, hops: [{ url: TC, status: 200 }], outcome: "undetermined" as const, reasons: ["a page loaded"] };
  const section = async (auth: boolean, probe?: TrustCenterProbe) => {
    const view = await buildRejectionRegister({
      register: await loadRuleRegister(RULES, DEFAULT_DATASET_PIN),
      offeringClass: "b",
      offering: offering(auth),
      ...(probe !== undefined ? { trustCenterProbe: probe } : {}),
    });
    return view.sections.find((s) => s.section === "trust-center-gate")!;
  };

  it("without a probe, stays unmeasured and says how to measure it", async () => {
    const s = await section(false);
    expect(s.unmeasured).toContain("rampscan probe");
    expect(s.rows.some((r) => r.rejection === true)).toBe(false);
  });

  it("a declared login is not a rejection on its own — with no probe, nothing in the section rejects", async () => {
    const s = await section(true);
    expect(s.rows.some((r) => r.rejection === true)).toBe(false);
    expect(s.rows[0]?.detail).toContain("FedRAMP permits");
    expect(s.unmeasured).toContain("rampscan probe");
  });

  it("a click-through is the rejection itself", async () => {
    const s = await section(
      false,
      probeOf([{ ...landing, outcome: "gated", gate: "click-through", reasons: ["the page asks for a non-disclosure agreement"] }], "gated"),
    );
    expect(s.rows.filter((r) => r.rejection === true).map((r) => r.subject)).toEqual([TC]);
    expect(s.unmeasured).toBeUndefined();
  });

  it("a login the offering DECLARED is permitted — not a rejection, and what waits behind it stays unmeasured", async () => {
    const s = await section(
      true,
      probeOf([{ ...landing, outcome: "gated", gate: "authentication", reasons: ["HTTP 401"] }], "gated"),
    );
    // neither the declaration row nor the probe row is a rejection
    expect(s.rows.some((r) => r.rejection === true)).toBe(false);
    expect(s.unmeasured).toContain("behind it");
  });

  it("a login the offering said was NOT there is a rejection — the package states something false", async () => {
    const s = await section(
      false,
      probeOf([{ ...landing, outcome: "gated", gate: "authentication", reasons: ["HTTP 403"] }], "gated"),
    );
    expect(s.rows.find((r) => r.detail.includes("authenticationRequired: false"))?.rejection).toBe(true);
  });

  it("open is measured, and says it proves only the documents it was pointed at", async () => {
    const doc = {
      url: `${TC}package.json`,
      role: "document" as const,
      hops: [{ url: `${TC}package.json`, status: 200 }],
      sha256: "b".repeat(64),
      schema: "fedramp-certification-package-overview-schema-2026-06-24.json",
      outcome: "open" as const,
      reasons: ["validates"],
    };
    const s = await section(false, probeOf([landing, doc], "open"));
    expect(s.unmeasured).toBeUndefined();
    expect(s.rows.some((r) => r.rejection === true)).toBe(false);
    expect(s.note).toContain("not every document");
  });

  it("a probe of a different URL measures a different trust center", async () => {
    const s = await section(false, { ...probeOf([landing], "undetermined"), trust_center: "https://other.example.com/" });
    expect(s.unmeasured).toContain("measures a different trust center");
  });
});
