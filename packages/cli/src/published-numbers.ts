// The numbers gate (plan S2-1) — ground rule 4's missing *Enforced by* line.
//
// "Computed, never typed" had no test behind it, and §3 of the soundness plan
// is what happens to a rule with no gate: on 2026-09-13 the README asserted 46
// KSI rows where `frontier` printed 41, a floor met on 13 of 46 where the
// command said 13 of 41, and a test count a month and a hundred tests stale.
// The 46 → 41 drift is the sharpest, because 41 is the number the code moved
// to when it fixed the denominator — the tool got more truthful and the
// document did not follow. Nobody typed a lie; somebody copied a figure that
// was true last month, which is exactly the way rule 4 says it breaks.
//
// This module is deliberately narrow. It does not parse prose, because a gate
// that parses prose is deleted within a month: it looks for a handful of
// sentence shapes the README commits to carrying, extracts the figures, and
// compares each with the command that produces it —
//
//   the register's own summary lines   `rampscan frontier`, run by the test
//   the self-scan verdict line         `rampscan report`'s generated document
//   the suite's test and file counts   the suite's own reporter, at run end
//
// A README sentence that stops matching is a failure too, named as such: the
// gate would rather fail on a rephrasing than silently stop reading a number.

export class PublishedNumbersError extends Error {
  override name = "PublishedNumbersError";
}

/** the figures README.md commits to carrying, in the shapes this gate reads */
export interface ReadmeFigures {
  /** "**N of M KSIs meet the class-b method floor, and K have no pipeline method at all.**" */
  floor: { met: number; total: number; noMethod: number };
  /** every "N tests across M files" in the document — they must all agree */
  suite: Array<{ tests: number; files: number }>;
  /** the fenced `$ pnpm rampscan frontier` block, line by line, fence excluded */
  frontierBlock: string[];
  /** "`rampscan scan .` on this repository, at `<sha>`:" and the fenced line under it */
  selfScan: { commit: string; line: string };
  /**
   * "**N rules are addressable at class b — M MUST and K SHOULD — and rampscan
   * itself answers J.**" The rejection register's denominator (P2-3). Gated
   * for the reason the others are, and with one of its own: this figure moves
   * on every re-pin AND on every commit that teaches the appliance a new rule,
   * so it is the README number most likely to go quietly stale.
   */
  submission: { addressable: number; must: number; should: number; computed: number };
}

const FLOOR_SENTENCE =
  /\*\*(\d+) of (\d+) KSIs meet the class-b method floor, and (\d+) have no pipeline method at all\.\*\*/;
const SUITE_SENTENCE = /\b([\d,]+) tests across (\d+) files\b/g;
const FRONTIER_BLOCK = /```\n\$ pnpm rampscan frontier\n([\s\S]*?)```/;
const SELF_SCAN = /`rampscan scan \.` on this repository, at `([0-9a-f]{7,40})`:\n\n```\n([^\n]+)\n```/;
const SUBMISSION_SENTENCE =
  /\*\*(\d+) rules are addressable at class b — (\d+) MUST and (\d+) SHOULD — and rampscan itself answers (\d+)\.\*\*/;

function missing(what: string, shape: string): PublishedNumbersError {
  return new PublishedNumbersError(
    `README.md no longer carries ${what} in the shape the numbers gate reads (${shape}) — ` +
      "the sentence was rephrased or removed; put the figure back in that shape, or change " +
      "packages/cli/src/published-numbers.ts in the same commit so the number stays gated",
  );
}

export function readmeFigures(readme: string): ReadmeFigures {
  const floor = FLOOR_SENTENCE.exec(readme);
  if (floor === null) {
    throw missing(
      "the method-floor sentence",
      "**N of M KSIs meet the class-b method floor, and K have no pipeline method at all.**",
    );
  }
  const suite = [...readme.matchAll(SUITE_SENTENCE)].map((m) => ({
    tests: Number(m[1]!.replaceAll(",", "")),
    files: Number(m[2]),
  }));
  if (suite.length === 0) throw missing("the suite figures", "N tests across M files");
  const block = FRONTIER_BLOCK.exec(readme);
  if (block === null) throw missing("the frontier sample block", "```\\n$ pnpm rampscan frontier\\n…```");
  const self = SELF_SCAN.exec(readme);
  if (self === null) {
    throw missing(
      "the self-scan line",
      "`rampscan scan .` on this repository, at `<sha>`: followed by a fenced verdict line",
    );
  }
  const submission = SUBMISSION_SENTENCE.exec(readme);
  if (submission === null) {
    throw missing(
      "the rejection register's denominator",
      "**N rules are addressable at class b — M MUST and K SHOULD — and rampscan itself answers J.**",
    );
  }
  return {
    floor: { met: Number(floor[1]), total: Number(floor[2]), noMethod: Number(floor[3]) },
    submission: {
      addressable: Number(submission[1]),
      must: Number(submission[2]),
      should: Number(submission[3]),
      computed: Number(submission[4]),
    },
    suite,
    frontierBlock: block[1]!.replace(/\n$/, "").split("\n"),
    selfScan: { commit: self[1]!, line: self[2]! },
  };
}

/**
 * The lines of `rampscan frontier`'s output the README's block must carry
 * verbatim: the ones every number in the block's prose is read from, and none
 * of the ones that depend on which ledger the command was pointed at. The
 * clock, artifact and evidence-class meters are counted over a ledger, so a
 * README pasted from a self-scan and a gate run over an empty ledger would
 * disagree on them honestly; the floor line, the denominator, the queue and
 * the legacy footer are derived from the catalog, the recipes and the pinned
 * dataset alone, and those are the ones a reader quotes.
 */
const GATED_FRONTIER_LINES = /^ {2}(floor met on |covering all |adjudication queue \(G8\): |legacy view: --by-controls)/;

export function gatedFrontierLines(frontierOutput: string): string[] {
  const lines = frontierOutput.split("\n").filter((l) => GATED_FRONTIER_LINES.test(l));
  if (lines.length !== 4) {
    throw new PublishedNumbersError(
      `expected \`rampscan frontier\` to print four gated summary lines (floor met, covering all, ` +
        `adjudication queue, legacy view) and found ${lines.length} — the renderer moved; move this gate with it`,
    );
  }
  return lines;
}

/** the floor line's three figures, read back from the command's own output */
export function floorFromFrontier(frontierOutput: string): ReadmeFigures["floor"] {
  const m = /^ {2}floor met on (\d+) of (\d+) KSIs · at least one automated method on \d+ · no method on (\d+)$/m.exec(
    frontierOutput,
  );
  if (m === null) {
    throw new PublishedNumbersError(
      "`rampscan frontier` did not print its floor line in the shape the gate reads — the renderer moved; move this gate with it",
    );
  }
  return { met: Number(m[1]), total: Number(m[2]), noMethod: Number(m[3]) };
}

/**
 * The self-scan as `rampscan report` wrote it into docs/FRONTIER-PIPELINE.md:
 * the commit the run was anchored to and the verdict line `scan` printed for
 * it, recomposed from the report's own figures. The README may quote the line
 * only at the commit the generated document names — a README that cites a
 * newer commit than the report has been edited by hand.
 */
export function reportSelfScan(report: string): { commit: string; line: string } {
  const commit = /^- \*\*commit:\*\* `([0-9a-f]{40})`$/m.exec(report);
  const verdicts =
    /\*\*(\d+) evidenced\*\*, \*\*(\d+) violated\*\*, \*\*(\d+) unevidenced\*\*/.exec(report);
  const findings = /^Findings this run: (\d+)\./m.exec(report);
  if (commit === null || verdicts === null || findings === null) {
    throw new PublishedNumbersError(
      "docs/FRONTIER-PIPELINE.md does not carry the commit, the three verdict counts and the findings " +
        "count in the shape `rampscan report` writes them — regenerate it with `pnpm rampscan report`, " +
        "or move this gate with the report renderer",
    );
  }
  return {
    commit: commit[1]!,
    line: `${verdicts[1]} evidenced · ${verdicts[2]} violated · ${verdicts[3]} unevidenced · ${findings[1]} findings`,
  };
}

/** README's frontier block and floor sentence against a live `rampscan frontier` */
export function frontierDrift(readme: string, frontierOutput: string): string[] {
  const figures = readmeFigures(readme);
  const drift: string[] = [];
  for (const line of gatedFrontierLines(frontierOutput)) {
    if (!figures.frontierBlock.includes(line)) {
      const stale = figures.frontierBlock.find((l) => l.slice(0, 14) === line.slice(0, 14));
      drift.push(
        `README's frontier block does not carry the line \`rampscan frontier\` prints today:\n` +
          `    now:    ${line.trim()}\n` +
          `    README: ${stale === undefined ? "(no such line)" : stale.trim()}`,
      );
    }
  }
  const live = floorFromFrontier(frontierOutput);
  const said = figures.floor;
  if (said.met !== live.met || said.total !== live.total || said.noMethod !== live.noMethod) {
    drift.push(
      `README's floor sentence says ${said.met} of ${said.total} meet the floor and ${said.noMethod} have no method; ` +
        `\`rampscan frontier\` says ${live.met} of ${live.total} and ${live.noMethod}`,
    );
  }
  return drift;
}

/**
 * README's rejection-register denominator against what `rampscan submission`
 * prints today. Read from the command's own `--json`, not recomputed here:
 * a gate that derived the figure a second way would be testing its own
 * arithmetic rather than the README's claim.
 */
export function submissionDrift(readme: string, submissionJson: string): string[] {
  const said = readmeFigures(readme).submission;
  const view = JSON.parse(submissionJson) as {
    sections: Array<{
      section: string;
      rows: Array<{ force?: string }>;
      states?: { computed: number; declared: number; outside: number; unaddressed: number };
    }>;
  };
  const section = view.sections.find((x) => x.section === "unaddressed-rules");
  if (section?.states === undefined) {
    throw new PublishedNumbersError(
      "`rampscan submission --json` did not carry an `unaddressed-rules` section with its four state " +
        "counts — the register moved; move this gate with it",
    );
  }
  const states = section.states;
  const addressable = states.computed + states.declared + states.outside + states.unaddressed;
  const drift: string[] = [];
  if (said.addressable !== addressable || said.computed !== states.computed) {
    drift.push(
      `README says ${said.addressable} rules are addressable at class b and rampscan answers ${said.computed}; ` +
        `\`rampscan submission\` says ${addressable} and ${states.computed}`,
    );
  }
  // The MUST/SHOULD split is the register's, over the rules it prints — the
  // unaddressed rows carry their force, and the computed ones are counted by
  // difference rather than asserted, so this arm cannot drift on its own.
  if (said.must + said.should !== said.addressable) {
    drift.push(
      `README's split does not add up: ${said.must} MUST + ${said.should} SHOULD is ${said.must + said.should}, ` +
        `and it says ${said.addressable} rules are addressable`,
    );
  }
  return drift;
}

/** README's "It scans itself" line against the generated report */
export function selfScanDrift(readme: string, report: string): string[] {
  const said = readmeFigures(readme).selfScan;
  const generated = reportSelfScan(report);
  const drift: string[] = [];
  if (!generated.commit.startsWith(said.commit)) {
    drift.push(
      `README quotes the self-scan at \`${said.commit}\`, but docs/FRONTIER-PIPELINE.md was generated ` +
        `from a run at \`${generated.commit.slice(0, 7)}\` — the README cites a run the report does not carry`,
    );
  }
  if (said.line !== generated.line) {
    drift.push(
      `README's self-scan line reads "${said.line}"; the report generated from that run reads "${generated.line}"`,
    );
  }
  return drift;
}

/** README's suite figures against what the suite's reporter counted at run end */
export function suiteDrift(readme: string, counted: { tests: number; files: number }): string[] {
  // one line per distinct stale figure — the README carries the sentence in
  // more than one place, and two copies of one wrong number is one drift
  const drift = new Set<string>();
  for (const said of readmeFigures(readme).suite) {
    if (said.tests !== counted.tests || said.files !== counted.files) {
      drift.add(
        `README says "${said.tests.toLocaleString("en-US")} tests across ${said.files} files"; ` +
          `this run collected ${counted.tests.toLocaleString("en-US")} tests across ${counted.files} files`,
      );
    }
  }
  return [...drift];
}
