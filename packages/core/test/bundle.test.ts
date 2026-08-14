import { describe, expect, it } from "vitest";
import type { EvidenceBundle } from "@rampscan/schema";
import { sameEvidence } from "../src/bundle.js";

// Evidence identity vs the I2c additions: offenders/offender_count/reproduce
// restate what `detail` already witnesses, so they are deliberately EXCLUDED
// from `sameEvidence` — a pre-I2c bundle and its pointer-carrying re-scan are
// the same evidence, and nothing re-keys just because pointers arrived.

function bundle(extra: {
  offenders?: Array<{ file?: string; line?: number }>;
  offender_count?: number;
  reproduce?: string;
}): EvidenceBundle {
  return {
    _type: "https://in-toto.io/Statement/v1",
    subject: [{ name: "x", digest: { sha256: "e".repeat(64) } }],
    predicateType: "https://rampscan.dev/evidence/v1",
    predicate: {
      recipe_id: "r",
      ksi_ids: ["KSI-SCR-MIT"],
      control_ids: ["si-7.1"],
      verdict: "violated",
      repo: "fixtures/app",
      commit: "1".repeat(40),
      anchor_paths: [{ path: "f", contentHash: "a".repeat(64) }],
      dataset_version: "2026.07.14.01",
      tool_versions: { "repo-facts": "0.1.0" },
      assertions: [
        {
          description: "check",
          passed: false,
          detail: "1 of 1 row(s) fail x eq",
          ...(extra.offenders !== undefined ? { offenders: extra.offenders } : {}),
          ...(extra.offender_count !== undefined ? { offender_count: extra.offender_count } : {}),
        },
      ],
      ...(extra.reproduce !== undefined ? { reproduce: extra.reproduce } : {}),
      cadence: "continuous",
      run_id: "run-1",
      timestamp: "2026-08-01T00:00:00.000Z",
    },
  };
}

describe("sameEvidence × the I2c additions", () => {
  it("a pre-I2c bundle and its offender-carrying re-scan are the same evidence", () => {
    const before = bundle({});
    const after = bundle({
      offenders: [{ file: "bad.ts", line: 2 }],
      offender_count: 1,
      reproduce: "gitleaks git --redact <repo>",
    });
    expect(sameEvidence(before, after)).toBe(true);
    expect(sameEvidence(after, before)).toBe(true);
  });

  it("a changed detail still re-keys — identity itself is untouched", () => {
    const a = bundle({});
    const b = bundle({});
    b.predicate.assertions[0]!.detail = "2 of 2 row(s) fail x eq";
    expect(sameEvidence(a, b)).toBe(false);
  });
});
