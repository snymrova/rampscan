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
  collector?: string;
  basis?: EvidenceBundle["predicate"]["basis"];
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
      ...(extra.collector !== undefined ? { collector: extra.collector } : {}),
      ...(extra.basis !== undefined ? { basis: extra.basis } : {}),
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

// The J5/I3f additions go the OTHER way from I2c's: `collector` and `basis`
// are claims about what the evidence RESTS ON, not restatements of what it
// says, so they are keyed. The hole this closes is concrete: sast-reachability
// anchors the flagged files and rampscan.config.json — not package.json — so
// with the basis outside identity, an edit to package.json that moves
// entry-point inference leaves every "not affected" bundle alive, still
// claiming unreachability from a set that no longer exists.

const basis = (over: Record<string, unknown> = {}) =>
  ({
    approximation: "over" as const,
    statement: "unknowns count against us",
    entrypoints: ["src/index.js"],
    entrypoint_source: "package.json",
    ...over,
  }) as EvidenceBundle["predicate"]["basis"];

describe("sameEvidence × the J5/I3f additions", () => {
  it("a different producing collector is different evidence", () => {
    expect(
      sameEvidence(bundle({ collector: "sast-reachability" }), bundle({ collector: "semgrep" })),
    ).toBe(false);
  });

  it("a moved entry-point set re-keys even when every row and verdict is identical", () => {
    const before = bundle({ collector: "c", basis: basis() });
    const after = bundle({
      collector: "c",
      basis: basis({ entrypoints: ["src/index.js", "src/cli.js"] }),
    });
    expect(sameEvidence(before, after)).toBe(false);
  });

  it("the SOURCE of an unchanged entry-point set re-keys too", () => {
    // same files, but "declared in config" and "guessed from filenames" are
    // different ground under the same claim
    const declared = bundle({ collector: "c", basis: basis({ entrypoint_source: "config" }) });
    const guessed = bundle({ collector: "c", basis: basis({ entrypoint_source: "fallback" }) });
    expect(sameEvidence(declared, guessed)).toBe(false);
  });

  it("an identical basis is the same evidence — nothing re-keys for restating the ground", () => {
    expect(sameEvidence(bundle({ collector: "c", basis: basis() }), bundle({ collector: "c", basis: basis() }))).toBe(
      true,
    );
  });

  it("a pre-J5 bundle does NOT match its re-scan, deliberately and once", () => {
    // no back-compat exemption: "absent means whatever is there now" is how an
    // identity rule stops being one. Every live bundle supersedes once, in the
    // open, on the first scan after this change.
    expect(sameEvidence(bundle({}), bundle({ collector: "repo-facts" }))).toBe(false);
  });
});
