import { describe, expect, it } from "vitest";
import { allCollectors } from "@rampscan/collectors";
import { assessSelfScan, renderSelfScanAssessment } from "../src/self-scan-assert.js";

// N1-1's test-first obligation: the scheduled self-scan's coverage check
// must pass when every collector ran or was named, and FAIL when one tool is
// deliberately absent — a coverage unit the clock quietly stopped serving.

const names = allCollectors.map((c) => c.manifest.name);
const allRan = Object.fromEntries(names.map((n) => [n, "1.0.0"]));

describe("assessSelfScan", () => {
  it("passes when every registered collector ran", () => {
    const a = assessSelfScan({ tool_versions: allRan, skipped_collectors: [] }, allCollectors, { requireTools: true });
    expect(a.ok).toBe(true);
    expect(a.missing).toEqual([]);
    expect(a.blocked).toEqual([]);
    expect(a.units.every((u) => u.state === "ran")).toBe(true);
  });

  it("fails, naming the unit, when one tool is deliberately absent and tools are required", () => {
    const { checkov: _drop, ...rest } = allRan;
    const a = assessSelfScan(
      {
        tool_versions: { ...rest, checkov: "absent" },
        skipped_collectors: [
          { collector: "checkov", reason: "checkov is not on PATH and tools.json pins no image for it" },
        ],
      },
      allCollectors,
      { requireTools: true },
    );
    expect(a.ok).toBe(false);
    expect(a.blocked).toEqual(["checkov"]);
    expect(a.units.find((u) => u.collector === "checkov")!.recipes).toContain("iac-baseline-clean");
    expect(renderSelfScanAssessment(a, true)).toMatch(/blocked by an absent tool: checkov.*pin did not hold/s);
    // the same run outside the workflow's mode is printed, not failed
    expect(assessSelfScan({ tool_versions: { ...rest, checkov: "absent" }, skipped_collectors: [{ collector: "checkov", reason: "checkov is not on PATH and tools.json pins no image for it" }] }, allCollectors, { requireTools: false }).ok).toBe(true);
  });

  it("an honest skip for a reason that is not an absent tool is named and passes", () => {
    const a = assessSelfScan(
      {
        tool_versions: { ...allRan, checkov: "n/a" },
        skipped_collectors: [{ collector: "checkov", reason: "no IaC in the committed tree — nothing config-shaped to scan" }],
      },
      allCollectors,
      { requireTools: true },
    );
    expect(a.ok).toBe(true);
    expect(a.units.find((u) => u.collector === "checkov")!.state).toBe("skipped");
  });

  it("a collector neither run nor named is the silent skip, and fails in every mode", () => {
    const { gitleaks: _drop, ...rest } = allRan;
    const a = assessSelfScan({ tool_versions: rest, skipped_collectors: [] }, allCollectors, { requireTools: false });
    expect(a.ok).toBe(false);
    expect(a.missing).toEqual(["gitleaks"]);
    expect(renderSelfScanAssessment(a, false)).toContain("neither ran nor named as skipped: gitleaks");
  });
});
