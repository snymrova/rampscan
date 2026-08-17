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
  population?: number;
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
          ...(extra.population !== undefined ? { population: extra.population } : {}),
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

  it("a pre-N0 bundle and its population-carrying re-scan are the same evidence", () => {
    // N0-T1 rides the same slot for the same reason: the population restates
    // the SIZE of what `detail` already witnesses, so keying on it would
    // supersede every live bundle for zero informational change. The exit test
    // for N0 says no digest in the ledger may move because the field arrived,
    // and this is where that promise is kept.
    expect(sameEvidence(bundle({}), bundle({ population: 412 }))).toBe(true);
    expect(sameEvidence(bundle({ population: 412 }), bundle({}))).toBe(true);
    // and — the case the field exists for — an exhaustive pass and an
    // empty-domain pass are the same EVIDENCE while being very different
    // facts. Identity is about what re-signs, not about what a reader should
    // be told: the board and the evidence page draw them apart (N0-T1's
    // surfaces), the ledger does not re-key over it.
    expect(sameEvidence(bundle({ population: 0 }), bundle({ population: 412 }))).toBe(true);
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

// L1's contract rules ride the same slot for the same reason, and this is the
// hole they close: the contract gate anchors rampscan.config.json, so an edit
// to the FILE already drifts the anchor — but an anchor is a content hash of
// the whole file, and the two contract recipes share it. Without the rules in
// the basis, editing a boundary rule would re-key BOTH recipes' evidence (the
// config's hash moved) while telling neither which rules it was actually
// checked against. Keyed per kind, each recipe's evidence states its own rules.

const contractBasis = (rules: string[]) =>
  ({
    approximation: "over" as const,
    statement: "unknowns count against the repo",
    entrypoints: ["src/index.js"],
    entrypoint_source: "package.json",
    contract_rules: rules,
  }) as EvidenceBundle["predicate"]["basis"];

describe("sameEvidence × L1's contract rules", () => {
  it("an edited rule re-keys, even when the verdict and every row hold still", () => {
    // widening an allow-list is exactly the case: the same code, the same
    // "evidenced" verdict — against a DIFFERENT rule. The old bundle claiming
    // the new rule holds is the stale claim this kills.
    const strict = bundle({
      collector: "contract",
      basis: contractBasis(['{"allowedImporters":["src/server.js"],"id":"billing-isolated"}']),
    });
    const widened = bundle({
      collector: "contract",
      basis: contractBasis([
        '{"allowedImporters":["src/server.js","src/render.js"],"id":"billing-isolated"}',
      ]),
    });
    expect(sameEvidence(strict, widened)).toBe(false);
  });

  it("an added rule re-keys the evidence of its own kind", () => {
    const one = bundle({ collector: "contract", basis: contractBasis(['{"id":"a"}']) });
    const two = bundle({ collector: "contract", basis: contractBasis(['{"id":"a"}', '{"id":"b"}']) });
    expect(sameEvidence(one, two)).toBe(false);
  });

  it("an unchanged contract is the same evidence — a re-scan of a still-true claim survives", () => {
    const rules = ['{"id":"billing-isolated","module":"src/billing"}'];
    expect(
      sameEvidence(
        bundle({ collector: "contract", basis: contractBasis(rules) }),
        bundle({ collector: "contract", basis: contractBasis([...rules]) }),
      ),
    ).toBe(true);
  });
});
