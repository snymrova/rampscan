import { describe, expect, it } from "vitest";
import { COMMENT_MARKER, movementOf, renderCheckComment } from "../src/check-comment.js";
import { DRY_RUN_NOT_EVIDENCE, type DryRunOutcome, type DryRunRow } from "../src/check.js";

// N2a's exit test, at the rendering layer: a breach names the file, the import
// chain and the AUTHORED fix sentence; a clean tree produces no comment at all;
// and a row the board already holds as violated is described as inherited
// rather than caused. The end-to-end half (exit codes, a real worktree, the
// ledger's bytes) lives in check.e2e.test.ts — this pins the words.

const PLAIN = {
  checks: "Walks every import edge crossing a declared module boundary.",
  violation: "A module reaches into another's internals, so the boundary is a comment, not a rule.",
  fix: "Route the call through the owning module's public entry point, or declare the edge.",
};

function row(over: Partial<DryRunRow> = {}): DryRunRow {
  return {
    recipeId: "no-cross-boundary-imports",
    collector: "contract",
    wouldBe: "violated",
    plain: PLAIN,
    assertions: [
      {
        description: "Zero import edges cross a declared boundary.",
        passed: false,
        offenders: [
          {
            file: "packages/cli/src/serve.ts",
            line: 41,
            call_path: "serve.ts → projector/internal/sqlite.ts",
          },
        ],
        offender_count: 1,
      },
    ],
    ...over,
  } as DryRunRow;
}

function outcome(over: Partial<DryRunOutcome> = {}): DryRunOutcome {
  return {
    dryRun: true,
    notEvidence: DRY_RUN_NOT_EVIDENCE,
    repo: "snymrova/rampscan",
    headCommit: "a".repeat(40),
    tree: { modified: [], untracked: [], deleted: [], differsFromHead: false },
    gatesRun: ["repo-facts", "graph", "contract"],
    gatesRefused: [],
    rows: [row()],
    summary: { evidenced: 0, violated: 1, unevidenced: 0 },
    wouldViolate: true,
    datasetVersion: "2026.08.1",
    ...over,
  };
}

describe("renderCheckComment", () => {
  it("names the file, the import chain and the recipe's own fix sentence", () => {
    const body = renderCheckComment(outcome({ rows: [row({ boardState: "evidenced" })] }));
    expect(body).toBeDefined();
    expect(body).toContain("packages/cli/src/serve.ts:41");
    expect(body).toContain("serve.ts → projector/internal/sqlite.ts");
    // the authored sentence, quoted rather than paraphrased
    expect(body).toContain(PLAIN.fix);
    expect(body).toContain(PLAIN.violation);
    expect(body).toContain(COMMENT_MARKER);
  });

  it("returns nothing at all when no row would be violated", () => {
    const clean = outcome({
      rows: [row({ wouldBe: "evidenced", assertions: [] })],
      summary: { evidenced: 1, violated: 0, unevidenced: 0 },
      wouldViolate: false,
    });
    // undefined, not an empty string and not a green tick: a clean run gets no
    // comment, so the one comment a reader ever sees is a real one
    expect(renderCheckComment(clean)).toBeUndefined();
  });

  it("describes an already-violated row as inherited, naming the streak's commit", () => {
    const body = renderCheckComment(
      outcome({
        rows: [
          row({
            boardState: "violated",
            introducedAt: "2026-07-02T09:00:00.000Z",
            introducingCommit: "b".repeat(40),
          }),
        ],
      }),
    );
    expect(body).toContain("Inherited, not introduced here");
    expect(body).toContain("violated since `bbbbbbbbbbbb`");
    expect(body).toContain("2026-07-02");
    expect(body).toContain("This pull request did not cause it");
    // and the headline must not read as an accusation
    expect(body).toContain("None of these is introduced by this tree");
    expect(body).not.toContain("newly-violated");
  });

  it("speaks the diff's vocabulary when the tree would move the row", () => {
    const body = renderCheckComment(outcome({ rows: [row({ boardState: "evidenced" })] }));
    expect(body).toContain("`evidenced` → `violated` (newly-violated)");
    expect(body).toContain("1 would be introduced or moved by this tree");
  });

  it("says plainly when there is no baseline to compare against", () => {
    const body = renderCheckComment(outcome({ rows: [row({ boardState: "absent" })] }));
    expect(body).toContain("No baseline to compare against");
    expect(body).not.toContain("Inherited");
  });

  it("counts a breach against the BASE TREE as introduced, with no ledger anywhere", () => {
    // The regression test for #19. A CI job reads no ledger — `rampscan-ledger/`
    // is gitignored — so every row arrived here with no `boardState` at all,
    // landed in `unknown`, and the gate that fails on `introduced` could never
    // fire. The base tree is the baseline a CI job can actually obtain.
    const body = renderCheckComment(
      outcome({
        baseline: { ref: "main", commit: "b".repeat(40) },
        rows: [row({ baselineWouldBe: "evidenced" })],
      }),
    );
    expect(body).toContain("introduced=1 inherited=0 unknown=0");
    expect(body).toContain("1 would be introduced or moved by this tree");
    // and it says which baseline answered, because a dry run is not evidence
    // and the board sentence would claim it was
    expect(body).toContain("the base tree at `bbbbbbbbbbbb`");
    expect(body).not.toContain("The board already holds");
    expect(body).toContain("baseline `main` at `bbbbbbbbbbbb`");
  });

  it("calls a row the base tree already violates inherited, not caused", () => {
    const body = renderCheckComment(
      outcome({
        baseline: { ref: "main", commit: "b".repeat(40) },
        rows: [row({ baselineWouldBe: "violated" })],
      }),
    );
    expect(body).toContain("introduced=0 inherited=1 unknown=0");
    expect(body).toContain("Inherited, not introduced here.");
    expect(body).toContain("reaches `violated` too");
    // the board's streak sentence must not appear over a base-tree answer
    expect(body).not.toContain("violated since");
  });

  it("counts a missing baseline as unknown, never as introduced", () => {
    // the gate reads these three numbers off the marker, and folding
    // `no-baseline` into `introduced` would fail every pull request in any job
    // that has no ledger to read — calling old debt a regression
    // the key ABSENT is the no-ledger case — `check` omits `boardState`
    // entirely when it could not read a ledger, rather than setting it undefined
    const noLedger = renderCheckComment(outcome({ rows: [row()] }));
    expect(noLedger).toContain("introduced=0 inherited=0 unknown=1");
    expect(noLedger).toContain("none of these can be called new");

    const real = renderCheckComment(outcome({ rows: [row({ boardState: "evidenced" })] }));
    expect(real).toContain("introduced=1 inherited=0 unknown=0");

    const old = renderCheckComment(outcome({ rows: [row({ boardState: "violated" })] }));
    expect(old).toContain("introduced=0 inherited=1 unknown=0");
  });

  it("carries the not-evidence sentence in the body, not in a footnote", () => {
    const body = renderCheckComment(outcome({ rows: [row({ boardState: "evidenced" })] }));
    expect(body).toContain(DRY_RUN_NOT_EVIDENCE);
    expect(body).toContain("worktree on top of `aaaaaaaaaaaa`");
    expect(body).toContain("dataset `2026.08.1`");
  });

  it("lists what the dry run refused to answer — silence is not a pass", () => {
    const body = renderCheckComment(
      outcome({
        rows: [row({ boardState: "evidenced" })],
        gatesRefused: [
          { collector: "gitleaks", recipes: ["no-secrets-in-history"], reason: "spawns gitleaks" },
        ],
      }),
    );
    expect(body).toContain("What this run did not check (1 recipe(s))");
    expect(body).toContain("no-secrets-in-history");
    expect(body).toContain("silence about them is not a pass");
  });

  it("bounds the offender list and states the true total behind it", () => {
    const many = row({
      boardState: "evidenced",
      assertions: [
        {
          description: "Zero import edges cross a declared boundary.",
          passed: false,
          offenders: Array.from({ length: 9 }, (_, i) => ({ file: `src/f${i}.ts`, line: i })),
          offender_count: 40,
        },
      ],
    });
    const body = renderCheckComment(outcome({ rows: [many] }), { offenderLimit: 5 });
    expect(body).toContain("src/f4.ts:4");
    expect(body).not.toContain("src/f5.ts");
    expect(body).toContain("… and 35 more failing row(s)");
  });

  it("promises no withheld pointer when the failing rows carry none", () => {
    const empty = row({
      boardState: "evidenced",
      assertions: [
        {
          description: "CODEOWNERS names an owner for every path.",
          passed: false,
          offenders: [],
          offender_count: 2,
        },
      ],
    });
    const body = renderCheckComment(outcome({ rows: [empty] }));
    expect(body).toContain("2 failing row(s), none carrying a file or check to point at");
    expect(body).not.toContain("… and");
  });
});

describe("movementOf", () => {
  it("never calls an equal pair a change", () => {
    expect(movementOf(row({ boardState: "violated" }))).toEqual({
      kind: "inherited",
      source: "board",
    });
  });

  it("treats a missing ledger and a missing cell the same way — no baseline", () => {
    expect(movementOf(row())).toEqual({ kind: "no-baseline" });
    expect(movementOf(row({ boardState: "absent" }))).toEqual({ kind: "no-baseline" });
  });

  it("classifies a real movement with the projector's own classifier", () => {
    expect(movementOf(row({ boardState: "unevidenced" }))).toEqual({
      kind: "changed",
      source: "board",
      change: "newly-violated",
      from: "unevidenced",
    });
  });

  it("prefers the base tree over the board, and says which one answered", () => {
    // like-for-like beats better-provenance: the board describes whatever
    // commit was last scanned, which is not this pull request's base
    expect(movementOf(row({ boardState: "violated", baselineWouldBe: "evidenced" }))).toEqual({
      kind: "changed",
      source: "base-tree",
      change: "newly-violated",
      from: "evidenced",
    });
    expect(movementOf(row({ boardState: "evidenced", baselineWouldBe: "violated" }))).toEqual({
      kind: "inherited",
      source: "base-tree",
    });
  });

  it("falls back to the board for a recipe the base tree has no row for", () => {
    expect(movementOf(row({ boardState: "evidenced", baselineWouldBe: "absent" }))).toEqual({
      kind: "changed",
      source: "board",
      change: "newly-violated",
      from: "evidenced",
    });
    expect(movementOf(row({ baselineWouldBe: "absent" }))).toEqual({ kind: "no-baseline" });
  });
});
