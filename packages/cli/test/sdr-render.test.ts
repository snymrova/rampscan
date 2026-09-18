import { describe, expect, it } from "vitest";
import { optionalKsis } from "@rampscan/dataset";
import { SDR_DIGEST_LINE, renderSdrMarkdown } from "../src/sdr-render.js";
import { artifacts, built, hex, input, offering, row, sources } from "./sdr-fixture.js";

// R2.2 (#103, docs/PLAN-SDR.md D3). The human-readable half is a function of
// the JSON object alone, so these tests hand it a document, not a projection.
// What they pin:
//
//   1. It says nothing the JSON does not. Every KSI and rule row in the JSON
//      appears in the Markdown, and no row appears that the JSON lacks. The
//      check walks the structure rather than comparing a snapshot, so a
//      reformatting cannot hide a dropped row.
//   2. An empty slot reads as missing and is never filled.
//   3. The digest it carries is the one it was handed. The run test in
//      sdr.e2e.test.ts checks that this is the digest of the file beside it.

const DIGEST = hex("d");

const coverage = [
  { ruleId: "FRC-CSX-VVK", status: "addressed", citation: "docs/ksi-methods.md §2 | the floor", implementationStatus: "Implemented" },
  { ruleId: "FRC-APP-MLF", status: "not-implemented", reason: "the Marketplace listing request is filed and pending" },
];

/** a document as `emit` writes it: the builder's output plus the stamp and problems */
async function written(over: Parameters<typeof input>[0] = {}) {
  const out = built(await input(over));
  const x = out.document["x-rampscan"] as Record<string, unknown>;
  x["conformance"] = {
    ruleId: "FRC-CSO-JSN",
    schema: "fedramp-security-decision-record-schema-2026-06-24.json",
    schemaVersion: "1.1.1",
    valid: true,
    violations: [],
  };
  x["problems"] = out.problems;
  return out.document;
}

async function obligedRows(except?: { ksi: string; present: number[] }) {
  const { catalog } = await sources();
  const optional = new Set(optionalKsis(catalog, "b"));
  return catalog.ksis
    .filter((k) => !optional.has(k.id))
    .map((k) => (k.id === except?.ksi ? row(k.id, { artifacts: artifacts(except.present) }) : row(k.id)));
}

describe("sdr markdown — says nothing the JSON does not", () => {
  it("has a KSI section for exactly the JSON's KSI rows, and a table row for exactly its rules", async () => {
    const doc = await written({
      offering: offering({ ruleCoverage: coverage }),
      methodRegisters: await obligedRows(),
    });
    const md = renderSdrMarkdown(doc, DIGEST);

    const jsonKsis = (doc["keySecurityIndicators"] as { ksiId: string }[]).map((k) => k.ksiId).sort();
    const mdKsis = [...md.matchAll(/^### (KSI-[A-Z]{3}-[A-Z]{3})\b/gm)].map((m) => m[1]).sort();
    expect(mdKsis).toEqual(jsonKsis);

    const x = doc["x-rampscan"] as { unaddressedRules: { ruleId: string }[] };
    const jsonRules = [
      ...(doc["fedRampRequirements"] as { frrID: string }[]).map((r) => r.frrID),
      ...x.unaddressedRules.map((r) => r.ruleId),
    ].sort();
    const mdRules = [...md.matchAll(/^\| ([A-Z]{3}-[A-Z]{3}-[A-Z]{3}) \|/gm)].map((m) => m[1]).sort();
    expect(mdRules).toEqual(jsonRules);
  });

  it("quotes every problem in full", async () => {
    const doc = await written();
    const md = renderSdrMarkdown(doc, DIGEST);
    const problems = (doc["x-rampscan"] as { problems: string[] }).problems;
    expect(problems.length).toBeGreaterThan(0);
    for (const p of problems) expect(md).toContain(`- ${p}`);
  });

  it("carries the digest it was handed on the line R2.3 reads back", async () => {
    const md = renderSdrMarkdown(await written(), DIGEST);
    expect(SDR_DIGEST_LINE.exec(md)?.[1]).toBe(DIGEST);
  });

  it("is the same text for the same document", async () => {
    const doc = await written();
    expect(renderSdrMarkdown(doc, DIGEST)).toBe(renderSdrMarkdown(structuredClone(doc), DIGEST));
  });
});

describe("sdr markdown — an empty slot stays empty", () => {
  it("prints artifact 1 as missing and never shows text for it", async () => {
    const doc = await written({ methodRegisters: await obligedRows({ ksi: "KSI-SVC-SIN", present: [2, 3, 4, 5] }) });
    const md = renderSdrMarkdown(doc, DIGEST);
    const section = md.slice(md.indexOf("### KSI-SVC-SIN"), md.indexOf("#### Assessment", md.indexOf("### KSI-SVC-SIN")));
    expect(section).toMatch(/^1\. \*\*Artifact 1 — .*\*\* — \*missing: no body in this record\.\*/m);
    expect(section).not.toContain("Body of artifact 1.");
    expect(section).toContain("> Body of artifact 2.");
  });

  it("keeps a body's own headings inside its quote, so they cannot restructure the record", async () => {
    const bodies = new Map([
      ["stmt-1", "# Not a section\n\n## Nor this\n\nprose"],
      ...[2, 3, 4, 5].map((s) => [`stmt-${s}`, `Body of artifact ${s}.`] as [string, string]),
    ]);
    const md = renderSdrMarkdown(await written({ bodies }), DIGEST);
    expect(md).toContain("> # Not a section");
    expect(md.split("\n").filter((l) => /^# /.test(l))).toHaveLength(1);
  });

  it("escapes a pipe inside a declared citation instead of splitting the table", async () => {
    const md = renderSdrMarkdown(await written({ offering: offering({ ruleCoverage: coverage }) }), DIGEST);
    const line = md.split("\n").find((l) => l.startsWith("| FRC-CSX-VVK |"))!;
    expect(line).toContain("§2 \\| the floor");
    expect(line.split(/(?<!\\)\|/).length - 2).toBe(5);
  });
});

describe("sdr markdown — the golden reading", () => {
  it("matches the reviewed rendering of the fixture", async () => {
    const doc = await written({
      offering: offering({ ruleCoverage: coverage }),
      methodRegisters: await obligedRows({ ksi: "KSI-SVC-SIN", present: [2, 3, 4, 5] }),
    });
    await expect(renderSdrMarkdown(doc, DIGEST)).toMatchFileSnapshot("./golden/sdr.md");
  });
});
