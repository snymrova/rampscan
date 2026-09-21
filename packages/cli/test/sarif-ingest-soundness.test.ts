import { readFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import type { SarifCrosswalk } from "@rampscan/schema";
import { SarifCrosswalk as CrosswalkSchema, submissionVerdict } from "@rampscan/schema";
import { SARIF_NO_ERROR_LEVEL_RESULTS, sarifSubmissions } from "../src/sarif-ingest.js";
import type { SarifRunDeclaration } from "../src/sarif-ingest.js";
import { looksLikeSarif, parseSarif } from "../src/sarif.js";
import type { SarifDocument } from "../src/sarif.js";

// The SARIF adapter's refusals (docs/PLAN-REACH.md N2-2), each the vacuous
// pass in a different coat, written as the tests the adapter had to pass.
// The fixtures are real logs: semgrep over fixtures/vulnerable-app with the
// ruleset rampscan's own collector runs, and zizmor over this repository's
// workflows — so the round trip below is against bytes a tool wrote, not a
// shape a test imagined.

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const FIXTURES = join(REPO_ROOT, "fixtures/ingest-sarif");
const CROSSWALKS = join(REPO_ROOT, "recipes/crosswalks");
const T = "2026-09-21T12:00:00.000Z";

let semgrepRaw: unknown;
let zizmorRaw: unknown;
let semgrepCw: SarifCrosswalk;
let zizmorCw: SarifCrosswalk;

const run = (over: Partial<SarifRunDeclaration> = {}): SarifRunDeclaration & { timestamp: string } => ({
  exit_code: 0,
  signer_identity: "runner:ci",
  cadence: "daily",
  artifact: { name: "log.sarif", sha256: "a".repeat(64) },
  timestamp: T,
  ...over,
});

beforeAll(async () => {
  semgrepRaw = JSON.parse(await readFile(join(FIXTURES, "semgrep.sarif"), "utf8"));
  zizmorRaw = JSON.parse(await readFile(join(FIXTURES, "zizmor.sarif"), "utf8"));
  semgrepCw = CrosswalkSchema.parse(JSON.parse(await readFile(join(CROSSWALKS, "sarif-semgrep-oss-1.173.0.json"), "utf8")));
  zizmorCw = CrosswalkSchema.parse(JSON.parse(await readFile(join(CROSSWALKS, "sarif-zizmor-1.30.1.json"), "utf8")));
});

/** a document edited in memory — the fixture as the tool wrote it, with one fact changed */
function doc(raw: unknown, edit: (d: SarifDocument) => void = () => {}): SarifDocument {
  const d = parseSarif(structuredClone(raw), "test.sarif");
  edit(d);
  return d;
}

describe("the reader", () => {
  it("sniffs a SARIF log on content, and not a native submission or a Prowler array", () => {
    expect(looksLikeSarif(semgrepRaw)).toBe(true);
    expect(looksLikeSarif(zizmorRaw)).toBe(true);
    expect(looksLikeSarif([])).toBe(false);
    expect(looksLikeSarif({ _type: "https://rampscan.dev/ingest-submission/v1" })).toBe(false);
    expect(looksLikeSarif({ runs: [] })).toBe(false); // runs alone, with no SARIF schema or version
  });

  it("reads the tool, its version, the declared rules and the invocation off a real semgrep log", () => {
    const d = doc(semgrepRaw);
    expect(d.tool).toEqual({ name: "Semgrep OSS", version: "1.173.0" });
    expect(d.declaredRules).toEqual(["child-process-non-literal", "dangerous-eval", "weak-hash-algorithm"]);
    expect(d.executionSuccessful).toBe(true);
    expect(d.results.map((r) => [r.ruleId, r.level, r.kind, r.suppressed])).toEqual([
      ["dangerous-eval", "error", "fail", false],
      ["dangerous-eval", "error", "fail", false],
      ["weak-hash-algorithm", "warning", "fail", false],
    ]);
  });

  it("resolves a result's missing level from its rule's defaultConfiguration, and defaults to warning past that", () => {
    // semgrep writes no level on results: an ERROR rule must still read error
    const d = doc(semgrepRaw);
    expect(d.results[0]!.level).toBe("error");
    const stripped = structuredClone(semgrepRaw) as { runs: Array<{ tool: { driver: { rules?: unknown } } }> };
    delete stripped.runs[0]!.tool.driver.rules;
    expect(parseSarif(stripped, "t").results[0]!.level).toBe("warning");
  });

  it("refuses a log that is not 2.1.0, one with runs from two tools, and a result that names no rule", () => {
    expect(() => parseSarif({ ...(semgrepRaw as object), version: "2.0.0" }, "t")).toThrow(/SARIF 2\.0\.0/);
    const two = structuredClone(semgrepRaw) as { runs: unknown[] };
    two.runs.push(structuredClone((zizmorRaw as { runs: unknown[] }).runs[0]));
    expect(() => parseSarif(two, "t")).toThrow(/2 different tools/);
    const nameless = structuredClone(semgrepRaw) as { runs: Array<{ results: Array<Record<string, unknown>> }> };
    delete nameless.runs[0]!.results[0]!["ruleId"];
    expect(() => parseSarif(nameless, "t")).toThrow(/names no rule/);
  });
});

describe("the adapter's refusals — the vacuous pass in five coats", () => {
  it("1. the assertion is rampscan's: error-level rows fail it, warning-level rows count and pass", () => {
    const { submissions } = sarifSubmissions(doc(semgrepRaw), run(), semgrepCw);
    const byId = new Map(submissions.map((s) => [s.recipe_id, s]));
    expect(submissionVerdict(byId.get("semgrep-oss/dangerous-eval")!)).toBe("violated");
    expect(byId.get("semgrep-oss/dangerous-eval")!.assertions[0]!.population).toBe(2);
    expect(submissionVerdict(byId.get("semgrep-oss/weak-hash-algorithm")!)).toBe("evidenced");
    expect(byId.get("semgrep-oss/weak-hash-algorithm")!.assertions[0]!.population).toBe(1);
    expect(SARIF_NO_ERROR_LEVEL_RESULTS.where).toEqual([{ field: "level", op: "eq", value: "error" }]);
  });

  it("2. a suppressed result is counted, never waived: the error still fails, and the count is named", () => {
    const d = doc(semgrepRaw, (x) => {
      for (const r of x.results) r.suppressed = true;
    });
    const { submissions } = sarifSubmissions(d, run(), semgrepCw);
    const evalSub = submissions.find((s) => s.recipe_id === "semgrep-oss/dangerous-eval")!;
    expect(submissionVerdict(evalSub)).toBe("violated");
    expect(evalSub.assertions[0]!.detail).toContain("2 suppressed and counted");
  });

  it("3a. a declared non-zero exit skips every rule, named — nothing minted", () => {
    const { submissions, skipped } = sarifSubmissions(doc(semgrepRaw), run({ exit_code: 2 }), semgrepCw);
    expect(submissions).toEqual([]);
    expect(skipped.map((s) => s.script).sort()).toEqual([
      "semgrep-oss/child-process-non-literal",
      "semgrep-oss/dangerous-eval",
      "semgrep-oss/weak-hash-algorithm",
    ]);
    for (const s of skipped) expect(s.reason).toMatch(/exit 2 is a failed run/);
  });

  it("3b. the log's own executionSuccessful: false skips everything even at exit 0", () => {
    const d = doc(semgrepRaw, (x) => {
      x.executionSuccessful = false;
    });
    const { submissions, skipped } = sarifSubmissions(d, run(), semgrepCw);
    expect(submissions).toEqual([]);
    expect(skipped[0]!.reason).toMatch(/executionSuccessful: false/);
  });

  it("4a. a rule with no results that the driver DECLARED ran, on a successful invocation, is clean — population is the tool's word", () => {
    // child-process-non-literal: declared in tool.driver.rules, zero results
    const { submissions, skipped } = sarifSubmissions(doc(semgrepRaw), run(), semgrepCw);
    const clean = submissions.find((s) => s.recipe_id === "semgrep-oss/child-process-non-literal")!;
    expect(submissionVerdict(clean)).toBe("evidenced");
    expect(clean.assertions[0]!.population).toBe(0);
    expect(clean.assertions[0]!.detail).toContain("population is the tool's word");
    expect(skipped).toEqual([]);
  });

  it("4b. a rule with no results that the driver did NOT declare is skipped and named — silence is not clean", () => {
    const d = doc(semgrepRaw, (x) => {
      x.declaredRules = x.declaredRules.filter((r) => r !== "child-process-non-literal");
    });
    const { submissions, skipped } = sarifSubmissions(d, run(), semgrepCw);
    expect(submissions.map((s) => s.recipe_id)).not.toContain("semgrep-oss/child-process-non-literal");
    expect(skipped).toHaveLength(1);
    expect(skipped[0]!.reason).toMatch(/does not declare it ran/);
  });

  it("4c. a rule with no results, declared, but with NO recorded invocation is skipped — a clean result needs the tool's word that it ran", () => {
    const d = doc(semgrepRaw, (x) => {
      x.executionSuccessful = null;
    });
    const { skipped } = sarifSubmissions(d, run(), semgrepCw);
    expect(skipped.map((s) => s.script)).toEqual(["semgrep-oss/child-process-non-literal"]);
    expect(skipped[0]!.reason).toMatch(/no successful invocation/);
  });

  it("5. a rule id the crosswalk does not carry refuses the whole batch, and names it", () => {
    const d = doc(semgrepRaw, (x) => {
      x.results.push({ ...x.results[0]!, ruleId: "made-up-rule" });
    });
    expect(() => sarifSubmissions(d, run(), semgrepCw)).toThrow(/does not file: made-up-rule/);
  });

  it("refuses a log from another tool, or another version, than the crosswalk is pinned to", () => {
    expect(() => sarifSubmissions(doc(zizmorRaw), run(), semgrepCw)).toThrow(/written by "zizmor"/);
    const d = doc(semgrepRaw, (x) => {
      x.tool.version = "1.174.0";
    });
    expect(() => sarifSubmissions(d, run(), semgrepCw)).toThrow(/pinned to 1\.173\.0/);
  });

  it("every submission states reachability unknown and the commit plane, and is automated because rampscan evaluated it", () => {
    const { submissions, notes } = sarifSubmissions(doc(zizmorRaw), run(), zizmorCw);
    expect(submissions.length).toBeGreaterThan(0);
    for (const s of submissions) {
      expect(s.plane).toBe("commit");
      expect(s.automated).toBe(true);
      expect(s.evidence_class).toBe("process-generated");
      expect(s.assertions[0]!.detail).toContain("reachability unknown");
      expect(s.tool_versions).toEqual({ zizmor: "1.30.1" });
    }
    expect(notes.some((n) => /reachability unknown/.test(n))).toBe(true);
    expect(notes.some((n) => /plane commit/.test(n))).toBe(true);
  });

  it("zizmor over this repository: the error-level audit is violated, the warning and note audits pass, each under its KSI", () => {
    const { submissions } = sarifSubmissions(doc(zizmorRaw), run(), zizmorCw);
    const verdicts = Object.fromEntries(
      submissions.filter((s) => s.assertions[0]!.population! > 0).map((s) => [s.recipe_id, [s.ksi, submissionVerdict(s)]]),
    );
    expect(verdicts).toEqual({
      "zizmor/artipacked": ["KSI-SVC-ASM", "evidenced"],
      "zizmor/dependabot-cooldown": ["KSI-SCR-MON", "evidenced"],
      "zizmor/excessive-permissions": ["KSI-CNA-MAT", "violated"],
      "zizmor/self-repository": ["KSI-SVC-ACM", "evidenced"],
      "zizmor/template-injection": ["KSI-CNA-MAT", "evidenced"],
    });
  });
});
