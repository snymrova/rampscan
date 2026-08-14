import { describe, expect, it } from "vitest";
import type { RecipeAssertion } from "@rampscan/schema";
import { MAX_OFFENDER_POINTERS, evaluateAssertion, offenderPointer } from "../src/assert.js";

// Fix pointers (I2c): the offender extraction is PINNED to the row shapes the
// real observation producers emit — each block below copies a producer's
// actual field names (see the collector named in the comment). Renaming a
// field in a collector breaks a test here instead of that collector's
// violations silently losing their pointers.

const NOW = new Date("2026-08-14T00:00:00.000Z");

describe("offenderPointer: pinned to the real producers' row shapes", () => {
  it("sast-gate rows: path + line + check_id + call_path (sast-gate.ts)", () => {
    expect(
      offenderPointer({
        check_id: "detect-child-process",
        path: "src/exec.ts",
        line: 42,
        severity: "ERROR",
        message: "…",
        reachable: "true",
        not_affected: false,
        call_path: "src/index.ts » src/router.ts » src/exec.ts",
      }),
    ).toEqual({
      file: "src/exec.ts",
      line: 42,
      check: "detect-child-process",
      call_path: "src/index.ts » src/router.ts » src/exec.ts",
    });
  });

  it("semgrep result rows: path + start_line + check_id (semgrep.ts normalized results)", () => {
    expect(
      offenderPointer({
        check_id: "dangerous-exec",
        path: "src/run.ts",
        start_line: 7,
        end_line: 9,
        severity: "ERROR",
        message: "…",
      }),
    ).toEqual({ file: "src/run.ts", line: 7, check: "dangerous-exec" });
  });

  it("reachability rows: `path` IS the call path (» separator), advisory is the check (reachability.ts)", () => {
    expect(
      offenderPointer({
        advisory: "GHSA-xxxx-yyyy",
        severity: "CRITICAL",
        package: "leftpad",
        version: "1.0.0",
        ecosystem: "npm",
        reachable: "true",
        not_affected: false,
        path: "src/index.ts » node_modules/leftpad",
        aliases: [],
      }),
    ).toEqual({ check: "GHSA-xxxx-yyyy", call_path: "src/index.ts » node_modules/leftpad" });
  });

  it("gitleaks rows: file + line + rule_id (gitleaks.ts)", () => {
    expect(
      offenderPointer({
        rule_id: "aws-access-token",
        description: "…",
        file: "config/creds.env",
        line: 3,
        commit: "abc123",
      }),
    ).toEqual({ file: "config/creds.env", line: 3, check: "aws-access-token" });
  });

  it("checkov rows: file + check_id, no line (checkov.ts)", () => {
    expect(
      offenderPointer({
        check_id: "CKV_DOCKER_2",
        check_name: "Ensure HEALTHCHECK",
        framework: "dockerfile",
        file: "Dockerfile",
        resource: "/Dockerfile.",
      }),
    ).toEqual({ file: "Dockerfile", check: "CKV_DOCKER_2" });
  });

  it("spectral rows: file + line + code (spectral.ts)", () => {
    expect(
      offenderPointer({
        code: "oas3-schema",
        file: "openapi.yaml",
        line: 12,
        severity: "error",
        message: "…",
        json_path: "paths./x.get",
      }),
    ).toEqual({ file: "openapi.yaml", line: 12, check: "oas3-schema" });
  });

  it("repo-facts ci-actions-pinned rows: workflow + action (repo-facts.ts usesRows)", () => {
    expect(
      offenderPointer({
        workflow: ".github/workflows/ci.yml",
        action: "actions/checkout@v4",
        pinned_to_sha: false,
      }),
    ).toEqual({ file: ".github/workflows/ci.yml", check: "actions/checkout@v4" });
  });

  it("graph route-auth rows: file, no check (graph.ts)", () => {
    expect(
      offenderPointer({ route: "GET /admin", file: "src/routes/admin.ts", auth_guarded: false }),
    ).toEqual({ file: "src/routes/admin.ts" });
  });

  it("a summary row with no pointer fields yields no pointer, not `{}`", () => {
    expect(offenderPointer({ workflow_count: 3, provenance_step_count: 0 })).toBeUndefined();
  });
});

describe("evaluateAssertion: offenders ride the result", () => {
  const rowWise: RecipeAssertion = {
    description: "every hit unreachable",
    field: "not_affected",
    op: "eq",
    value: true,
  };
  const countZero: RecipeAssertion = {
    description: "zero leaks",
    field: "rule_id",
    op: "count_eq",
    value: 0,
  };

  it("a failing row-wise assertion carries the failing rows' pointers and the total", () => {
    const result = evaluateAssertion(
      rowWise,
      [
        { check_id: "a", path: "ok.ts", line: 1, not_affected: true },
        { check_id: "b", path: "bad.ts", line: 2, not_affected: false },
        { check_id: "c", path: "worse.ts", line: 3, not_affected: false },
      ],
      NOW,
    );
    expect(result.passed).toBe(false);
    expect(result.offenders).toEqual([
      { file: "bad.ts", line: 2, check: "b" },
      { file: "worse.ts", line: 3, check: "c" },
    ]);
    expect(result.offender_count).toBe(2);
  });

  it("a failing count assertion's offenders are the counted rows themselves", () => {
    const result = evaluateAssertion(
      countZero,
      [{ rule_id: "aws-access-token", file: "x.env", line: 1 }],
      NOW,
    );
    expect(result.passed).toBe(false);
    expect(result.offenders).toEqual([{ file: "x.env", line: 1, check: "aws-access-token" }]);
    expect(result.offender_count).toBe(1);
  });

  it("offenders are bounded; offender_count still says how many actually failed", () => {
    const rows = Array.from({ length: 9 }, (_, i) => ({
      rule_id: `r${i}`,
      file: `f${i}.ts`,
      line: i,
    }));
    const result = evaluateAssertion(countZero, rows, NOW);
    expect(result.offenders).toHaveLength(MAX_OFFENDER_POINTERS);
    expect(result.offender_count).toBe(9);
  });

  it("a passing assertion carries no offenders", () => {
    const result = evaluateAssertion(countZero, [], NOW);
    expect(result.passed).toBe(true);
    expect(result.offenders).toBeUndefined();
    expect(result.offender_count).toBeUndefined();
  });

  it("pointer-less failing rows keep the count but attach no pointers", () => {
    const result = evaluateAssertion(
      { description: "provenance step exists", field: "provenance_step_count", op: "gte", value: 1 },
      [{ workflow_count: 2, provenance_step_count: 0 }],
      NOW,
    );
    expect(result.passed).toBe(false);
    expect(result.offenders).toBeUndefined();
    expect(result.offender_count).toBe(1);
  });

  it("detail stays byte-identical to the pre-I2c wording — it participates in evidence identity", () => {
    const failing = evaluateAssertion(
      rowWise,
      [{ check_id: "b", path: "bad.ts", line: 2, not_affected: false }],
      NOW,
    );
    expect(failing.detail).toBe(
      '1 of 1 row(s) fail not_affected eq; e.g. {"check_id":"b","path":"bad.ts","line":2,"not_affected":false}',
    );
    const counted = evaluateAssertion(
      countZero,
      [{ rule_id: "r", file: "x.env", line: 1 }],
      NOW,
    );
    expect(counted.detail).toBe(
      'expected count == 0, got 1; e.g. {"rule_id":"r","file":"x.env","line":1}',
    );
  });
});
