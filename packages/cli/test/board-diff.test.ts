import { describe, expect, it } from "vitest";
import type { RegisterDiff } from "@rampscan/core";
import { renderBoardDiff } from "../src/board.js";
import type { BoardDiffOutcome } from "../src/board-diff.js";

// I2d: the diff must be readable before it is clickable — these pin the text
// surface `rampscan board --since` leads with. The computation itself is
// pinned in packages/projector/test/diff.test.ts; this is the rendering.

const T1 = "2026-08-01T00:00:00.000Z";

function outcome(diff: Partial<RegisterDiff>): BoardDiffOutcome {
  return {
    scans: [T1, "2026-08-08T00:00:00.000Z"],
    baseline: T1,
    baselineIsScan: true,
    diff: {
      baseline: T1,
      changes: [],
      counts: {
        "newly-violated": 0,
        "evidence-lapsed": 0,
        unscoped: 0,
        removed: 0,
        appeared: 0,
        scoped: 0,
        "newly-evidenced": 0,
        resolved: 0,
      },
      unchanged: 0,
      ...diff,
    },
  };
}

describe("renderBoardDiff", () => {
  it("says out loud when nothing moved — with the held-cell count", () => {
    const text = renderBoardDiff(outcome({ unchanged: 7 }), false);
    expect(text).toContain(`SINCE ${T1}`);
    expect(text).toContain("a prior scan's board");
    expect(text).toContain("no register moved since the baseline (7 cell(s) held their state)");
  });

  it("groups by kind, bad news first, with from → to and fix pointers", () => {
    const text = renderBoardDiff(
      outcome({
        changes: [
          {
            repo: "fixtures/app",
            recipeId: "no-secrets",
            kind: "newly-violated",
            from: "evidenced",
            to: "violated",
            pointers: [{ file: "src/x.ts", line: 12, check: "aws-access-token" }],
            introducedAt: "2026-08-08T00:00:00.000Z",
            introducingCommit: "2".repeat(40),
          },
          {
            repo: "fixtures/app",
            recipeId: "sbom-present",
            kind: "resolved",
            from: "violated",
            to: "evidenced",
          },
          {
            repo: "fixtures/other",
            recipeId: "pinned-actions",
            kind: "appeared",
            to: "unevidenced",
          },
        ],
        unchanged: 3,
      }),
      false,
    );
    expect(text.indexOf("NEWLY VIOLATED (1)")).toBeGreaterThanOrEqual(0);
    expect(text.indexOf("NEWLY VIOLATED (1)")).toBeLessThan(text.indexOf("ROWS APPEARED (1)"));
    expect(text.indexOf("ROWS APPEARED (1)")).toBeLessThan(text.indexOf("RESOLVED (1)"));
    expect(text).toContain("evidenced → violated");
    expect(text).toContain("src/x.ts:12");
    expect(text).toContain("violating since 2026-08-08T00:00:00.000Z at 222222222222");
    expect(text).toContain("new row → unevidenced");
    expect(text).toContain("unchanged: 3 cell(s) held their state");
  });

  it("labels an explicit non-scan baseline as an as-of fold, not a scan", () => {
    const text = renderBoardDiff({ ...outcome({}), baselineIsScan: false }, false);
    expect(text).toContain("an as-of fold at that instant");
  });
});
