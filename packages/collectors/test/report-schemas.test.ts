import { describe, expect, it } from "vitest";
import { CheckovOutput } from "../src/checkov.js";
import { GitleaksReport } from "../src/gitleaks.js";
import { GrypeReport } from "../src/grype.js";
import { RawSemgrepOutput } from "../src/semgrep.js";
import { SpectralOutput } from "../src/spectral.js";
import { CycloneDx } from "../src/syft.js";

// The other half of the #31 pins. The six report schemas parse loosely on
// purpose: unknown vendor fields must SURVIVE the parse and reach the signed
// artifact, because tool output evolves faster than these shapes and a
// dropped field is a silently thinner piece of evidence. Nothing asserted
// that retention before this file — a zod major degrading loose parsing to
// stripping would have passed every existing test while quietly discarding
// vendor data.

describe("collector report schemas retain unknown vendor fields (#31)", () => {
  it("grype — at the report, match, vulnerability and artifact levels", () => {
    const parsed = GrypeReport.parse({
      descriptor: { name: "grype" },
      matches: [
        {
          vulnerability: { id: "CVE-2026-0001", fix: { state: "fixed", versions: ["1.2.3"] }, cvss: [] },
          artifact: { name: "openssl", purl: "pkg:apk/openssl@3" },
          matchDetails: [{ type: "exact-direct-match" }],
        },
      ],
    });
    expect(parsed["descriptor"]).toEqual({ name: "grype" });
    const match = parsed.matches[0]!;
    expect(match["matchDetails"]).toEqual([{ type: "exact-direct-match" }]);
    expect(match.vulnerability["cvss"]).toEqual([]);
    expect(match.vulnerability.fix!["versions"]).toEqual(["1.2.3"]);
    expect(match.artifact["purl"]).toBe("pkg:apk/openssl@3");
  });

  it("semgrep — at the output, result and extra levels", () => {
    const parsed = RawSemgrepOutput.parse({
      version: "1.0.0",
      results: [
        {
          check_id: "rules.no-eval",
          path: "src/x.ts",
          start: { line: 3, col: 1 },
          end: { line: 3, col: 9 },
          extra: { severity: "ERROR", message: "no eval", fingerprint: "abc" },
        },
      ],
      errors: [{ code: 2, level: "warn" }],
      paths: { scanned: ["src"] },
    });
    expect(parsed["paths"]).toEqual({ scanned: ["src"] });
    expect(parsed.results[0]!.start["col"]).toBe(1);
    expect(parsed.results[0]!.extra["fingerprint"]).toBe("abc");
    expect(parsed.errors[0]!["level"]).toBe("warn");
  });

  it("syft — at the document, metadata and component levels", () => {
    const parsed = CycloneDx.parse({
      specVersion: "1.5",
      serialNumber: "urn:uuid:0",
      metadata: { timestamp: "2026-09-11T00:00:00Z", tools: [] },
      components: [{ name: "zod", version: "4.4.3" }],
    });
    expect(parsed["serialNumber"]).toBe("urn:uuid:0");
    expect(parsed.metadata!["tools"]).toEqual([]);
    expect(parsed.components![0]!["name"]).toBe("zod");
  });

  it("checkov — both output forms, at the report, results and check levels", () => {
    const report = {
      check_type: "dockerfile",
      results: {
        failed_checks: [{ check_id: "CKV_DOCKER_2", file_path: "Dockerfile", severity: null }],
        parsing_errors: [],
      },
      summary: { failed: 1 },
    };
    const single = CheckovOutput.parse(report);
    if (Array.isArray(single)) throw new Error("single report parsed as array");
    expect(single["summary"]).toEqual({ failed: 1 });
    expect(single.results["parsing_errors"]).toEqual([]);
    expect(single.results.failed_checks![0]!["severity"]).toBeNull();
    expect(CheckovOutput.parse([report])).toEqual([single]);
  });

  it("spectral — at the result, range and position levels", () => {
    const parsed = SpectralOutput.parse([
      {
        code: "oas3-schema",
        message: "invalid",
        severity: 0,
        range: { start: { line: 4, character: 2 }, end: { line: 4, character: 9 } },
        fingerprint: "xyz",
      },
    ]);
    expect(parsed[0]!["fingerprint"]).toBe("xyz");
    expect(parsed[0]!.range["end"]).toEqual({ line: 4, character: 9 });
    expect(parsed[0]!.range.start["character"]).toBe(2);
  });

  it("gitleaks — at the leak level", () => {
    const parsed = GitleaksReport.parse([
      {
        RuleID: "aws-access-key",
        Description: "AWS key",
        File: ".env",
        StartLine: 1,
        Commit: "deadbeef",
        Entropy: 3.7,
      },
    ]);
    expect(parsed[0]!["Entropy"]).toBe(3.7);
  });
});
