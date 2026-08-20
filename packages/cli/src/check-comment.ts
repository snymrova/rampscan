import { classifyChange } from "@rampscan/projector";
import type { RegisterChangeKind, RegisterState } from "@rampscan/core";
import { DRY_RUN_NOT_EVIDENCE, type DryRunOutcome, type DryRunRow } from "./check.js";

// N2a — the pull-request comment. Four things this repository already had and
// had never rendered together: the board comparison a `RegisterDiff` speaks in,
// the `OffenderPointer`s an assertion carries, the `introducedAt` streak the
// projector walks, and each recipe's AUTHORED `plain.fix` sentence.
//
// The comment is a rendering and nothing more. It computes no verdict, reaches
// no state, and adds no fact to the dry run it was handed — every sentence
// below either quotes the outcome or quotes the catalog. That matters because
// this is the surface a stranger reads first, and a PR comment that editorialised
// beyond its input would be the most persuasive wrong thing in the system.
//
// Two properties it inherits from `check` rather than implementing:
//   - it is not evidence, and says so in its own body rather than in a footnote
//     a reader can miss (the dry run's own sentence, verbatim);
//   - it appends nothing. Rendering a comment reads the ledger and writes
//     markdown; the ledger is byte-identical across the run because no code
//     path here can open it for writing.

/**
 * The prefix of the HTML marker every rendered comment opens with — how the
 * action finds the comment it left last time, so a pull request carries one
 * rampscan comment and not one per push.
 *
 * The full marker carries the three counts (`introduced=1 inherited=3
 * unknown=0`), and they are there for a caller, not a reader: a CI job has to
 * decide whether to fail, and the honest input to that decision is how many
 * rows this tree MADE WORSE — not how many are violated, which includes debt
 * the pull request never touched.
 *
 * `unknown` is separated from `introduced` for a reason a gate would otherwise
 * learn the hard way: a job with no ledger to read has no board for ANY row, so
 * folding "no baseline" into "introduced" would fail every pull request on
 * every pre-existing violation and call them all regressions. A tree cannot be
 * blamed against a baseline that was never there.
 *
 * They ride in the marker rather than in a second invocation of the command
 * because the alternative is running the whole dry run twice to ask it three
 * numbers.
 */
export const COMMENT_MARKER = "<!-- rampscan-check";

/**
 * How the board's state for a cell relates to what the worktree would reach.
 *
 * `inherited` is the case this whole field exists for: the recipe is violated
 * in the comment AND violated on the board, so the pull request found the
 * breach rather than caused it. It is a separate kind rather than a
 * `classifyChange` result because the diff's classifier is never handed two
 * equal states — "unchanged" is not a change — and calling an inherited
 * violation `newly-violated` would blame the wrong commit in the one sentence
 * an author reads most carefully.
 *
 * `no-baseline` is honest about the third possibility: no readable ledger, or
 * a recipe with no cell for this repo yet. There is nothing to compare, and
 * "this PR introduced it" is a claim the data does not support.
 */
/**
 * WHICH baseline answered. The two are not interchangeable and the prose must
 * not pretend they are: the board is a fold of signed evidence about a commit
 * rampscan scanned, while the base tree is a second dry run — not evidence,
 * nothing signed, and the comment says so about itself already.
 *
 * Naming the source is the difference between "the board already holds this
 * row as violated" and "the base tree reaches the same result". The first is a
 * claim about recorded evidence. Saying it when a dry run produced the answer
 * would be the most persuasive wrong sentence in the system.
 */
export type BaselineSource = "board" | "base-tree";

export type Movement =
  | { kind: "no-baseline" }
  | { kind: "inherited"; source: BaselineSource }
  | {
    kind: "changed";
    source: BaselineSource;
    change: RegisterChangeKind;
    from: RegisterState;
  };

/**
 * The base tree wins over the board when both are present, and the reason is
 * the question being asked. A gate asks what THIS pull request made worse,
 * which is a comparison against its own base; the board answers about whatever
 * commit was last scanned, which may be far behind the base, far ahead of it,
 * or on another branch entirely. Like-for-like beats better-provenance here,
 * and the comment names which one it used either way.
 */
export function movementOf(row: DryRunRow): Movement {
  const base = row.baselineWouldBe;
  if (base !== undefined && base !== "absent") {
    if (base === row.wouldBe) return { kind: "inherited", source: "base-tree" };
    return {
      kind: "changed",
      source: "base-tree",
      change: classifyChange(base, row.wouldBe),
      from: base,
    };
  }
  const board = row.boardState;
  if (board === undefined || board === "absent") return { kind: "no-baseline" };
  if (board === row.wouldBe) return { kind: "inherited", source: "board" };
  // the projector's own classifier, over a worktree instead of a second fold:
  // the states are the same alphabet, so the vocabulary a reader learned on the
  // board's `--since` diff is the vocabulary they meet here
  return { kind: "changed", source: "board", change: classifyChange(board, row.wouldBe), from: board };
}

/** short commit, the way every other surface in this repository writes one */
const short = (commit: string) => commit.slice(0, 12);

function sentenceFor(
  row: DryRunRow,
  movement: Movement,
  baseline: { ref: string; commit: string } | undefined,
): string {
  const baseTree =
    baseline !== undefined
      ? `the base tree at \`${short(baseline.commit)}\``
      : "the base tree";
  switch (movement.kind) {
    case "inherited": {
      if (movement.source === "base-tree") {
        return (
          `**Inherited, not introduced here.** The same dry run over ${baseTree} reaches ` +
          "`violated` too, so this pull request found the breach rather than caused it. Fixing it " +
          "is not this pull request's debt — but nothing in the tree resolves it either."
        );
      }
      const since =
        row.introducingCommit !== undefined
          ? ` — violated since \`${short(row.introducingCommit)}\`${
              row.introducedAt !== undefined ? ` (${row.introducedAt.slice(0, 10)})` : ""
            }`
          : "";
      return (
        `**Inherited, not introduced here.** The board already holds this row as violated${since}. ` +
        "This pull request did not cause it, and fixing it is not this pull request's debt — " +
        "but nothing in the tree resolves it either."
      );
    }
    case "changed":
      if (movement.source === "base-tree") {
        return (
          `**This tree would move the row: \`${movement.from}\` → \`violated\` (${movement.change}).** ` +
          `The same command over ${baseTree} reaches \`${movement.from}\`, so the tree in front of ` +
          "you is the only difference between the two answers. Neither side is evidence; both are " +
          "dry runs, which is what makes them comparable."
        );
      }
      return (
        `**This tree would move the row: \`${movement.from}\` → \`violated\` (${movement.change}).** ` +
        "The board's state comes from signed evidence about a commit; the right-hand side is a dry " +
        "run over the working tree. Both are stated because they are different kinds of claim."
      );
    case "no-baseline":
      return (
        "**No baseline to compare against**, so whether this is new cannot be said from here — " +
        "no base tree was named and the ledger holds no cell for this recipe on this repository yet."
      );
  }
}

/** the offenders of every failing assertion, as markdown list items */
function offenderLines(row: DryRunRow, limit: number): string[] {
  const lines: string[] = [];
  for (const assertion of row.assertions.filter((a) => !a.passed)) {
    lines.push(`- \`assert\` ${assertion.description}`);
    for (const offender of (assertion.offenders ?? []).slice(0, limit)) {
      const where = [offender.file, offender.line].filter((x) => x !== undefined).join(":");
      // `call_path` IS the import chain — the reason a reachability finding is
      // actionable rather than a file name with a shrug attached
      const what = offender.call_path ?? offender.check;
      lines.push(`  - \`${where || "(no file)"}\`${what !== undefined ? ` — ${what}` : ""}`);
    }
    const total = assertion.offender_count ?? (assertion.offenders ?? []).length;
    const shown = Math.min((assertion.offenders ?? []).length, limit);
    // the same two-case honesty `renderCheck` spends: a bounded list has more
    // behind it, an empty one has nothing to point at, and they are not the
    // same fact
    if (shown > 0 && total > shown) lines.push(`  - … and ${total - shown} more failing row(s)`);
    else if (shown === 0 && total > 0) {
      lines.push(`  - ${total} failing row(s), none carrying a file or check to point at`);
    }
  }
  return lines;
}

export interface CommentOptions {
  /** offenders listed per failing assertion before the list is bounded */
  offenderLimit?: number;
  /** e.g. `https://github.com/o/r/actions/runs/123` — linked as where this ran */
  runUrl?: string;
}

/**
 * The comment body, or `undefined` when there is nothing to say.
 *
 * Undefined is the load-bearing half: a pull request that breaches no declared
 * boundary gets NO comment. A green tick on every push is noise that teaches a
 * reader to scroll past the one that matters, and the exit code already carries
 * the pass. The action deletes any stale comment when this returns undefined,
 * so a fixed violation leaves no red text behind.
 */
export function renderCheckComment(
  outcome: DryRunOutcome,
  options: CommentOptions = {},
): string | undefined {
  const violated = outcome.rows.filter((r) => r.wouldBe === "violated");
  if (violated.length === 0) return undefined;

  const limit = options.offenderLimit ?? 5;
  const kinds = violated.map((r) => movementOf(r).kind);
  const introduced = kinds.filter((k) => k === "changed").length;
  const inherited = kinds.filter((k) => k === "inherited").length;
  const unknown = kinds.filter((k) => k === "no-baseline").length;

  // Where the inherited half came from. With a base tree in play the sources
  // can be mixed — a row the base tree has no answer for falls back to the
  // board — so the summary says "the baseline" rather than naming a source it
  // would sometimes get wrong. The per-row sentences below name theirs exactly.
  const at = outcome.baseline !== undefined ? "at the baseline" : "on the board";
  const noRow =
    outcome.baseline !== undefined ? "with no baseline row" : "with no board row";

  // the headline counts the kinds separately, because "3 violations" over a
  // branch that introduced none is a number that reads as an accusation
  const headline =
    introduced > 0
      ? `${introduced} would be introduced or moved by this tree` +
        (inherited > 0 ? ` · ${inherited} already violated ${at}` : "") +
        (unknown > 0 ? ` · ${unknown} ${noRow} to compare against` : "")
      : inherited > 0 && unknown === 0
        ? `None of these is introduced by this tree — all ${inherited} are already violated ${at}`
        : unknown > 0 && inherited === 0
          ? `No baseline was readable, so none of these can be called new: ${unknown} row(s) are reported as found, not as caused`
          : `None of these is introduced by this tree — ${inherited} already violated ${at}, ` +
            `${unknown} ${noRow} to compare against`;

  const lines: string[] = [
    `${COMMENT_MARKER} introduced=${introduced} inherited=${inherited} unknown=${unknown} -->`,
    `### rampscan check — ${violated.length} recipe(s) would be violated`,
    "",
    headline,
    "",
  ];

  for (const row of violated) {
    const movement = movementOf(row);
    lines.push(`#### \`${row.recipeId}\``, "");
    if (row.plain !== undefined) {
      lines.push(`*${row.plain.checks}*`, "");
      lines.push(`**What a violation means.** ${row.plain.violation}`, "");
    }
    lines.push(sentenceFor(row, movement, outcome.baseline), "");
    const offenders = offenderLines(row, limit);
    if (offenders.length > 0) lines.push(...offenders, "");
    if (row.plain !== undefined) {
      // the authored sentence, last, because it is the thing to act on — and
      // quoted rather than paraphrased: this repository's whole claim about
      // plain language is that a human wrote it
      lines.push(`**Fix.** ${row.plain.fix}`, "");
    }
  }

  if (outcome.gatesRefused.length > 0) {
    const unanswered = outcome.gatesRefused.flatMap((g) => g.recipes);
    lines.push(
      "<details><summary>" +
        `What this run did not check (${unanswered.length} recipe(s))</summary>`,
      "",
      "A dry run runs no external tool and reads no artifact another scan produced, so these " +
        "recipes were not answered here — silence about them is not a pass:",
      "",
    );
    for (const gate of outcome.gatesRefused) {
      lines.push(`- **${gate.collector}** — ${gate.reason}`);
      if (gate.recipes.length > 0) lines.push(`  - unanswered: ${gate.recipes.join(", ")}`);
    }
    lines.push("", "</details>", "");
  }

  lines.push(
    "---",
    "",
    `> ${DRY_RUN_NOT_EVIDENCE}`,
    "",
    `<sub>worktree on top of \`${short(outcome.headCommit)}\` · dataset \`${outcome.datasetVersion}\`` +
      `${
        outcome.baseline !== undefined
          ? ` · baseline \`${outcome.baseline.ref}\` at \`${short(outcome.baseline.commit)}\``
          : ""
      }` +
      ` · gates: ${outcome.gatesRun.join(", ")}` +
      `${options.runUrl !== undefined ? ` · [run](${options.runUrl})` : ""}</sub>`,
  );

  return lines.join("\n");
}
