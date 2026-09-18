import { execFile } from "node:child_process";
import { readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { beforeAll, describe, expect, it } from "vitest";
import {
  PublishedNumbersError,
  frontierDrift,
  readmeFigures,
  reportSelfScan,
  selfScanDrift,
  submissionDrift,
  suiteDrift,
} from "../src/published-numbers.js";

// The numbers gate (plan S2-1): ground rule 4's *Enforced by* line. Every
// figure the README asserts about this repository is compared here with the
// command that produces it, and the README fails CI when it drifts — the
// failure that, unenforced, had the README asserting 46 KSI rows a month
// after `frontier` moved to 41 (docs/PLAN-SOUNDNESS.md §3).
//
// Three arms. The register's figures are read from a live `rampscan frontier`,
// spawned exactly as the README says to run it; the self-scan verdict line is
// read from the document `rampscan report` generated for that run, because a
// real self-scan needs every scan tool and CI installs none; the suite's own
// count is read by the suite's own reporter at the end of the run
// (`published-numbers-reporter.ts`), the one place it is known. Each arm is
// also shown here to fail on a hand-edited figure — a gate that has only ever
// read a true README proves nothing about the day somebody copies last
// month's number.

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const README = join(REPO_ROOT, "README.md");
const REPORT = join(REPO_ROOT, "docs/FRONTIER-PIPELINE.md");

const run = promisify(execFile);

/** `pnpm rampscan frontier`, as the README's block is captioned, over no ledger */
async function frontier(): Promise<string> {
  const { stdout } = await run(
    join(REPO_ROOT, "node_modules/.bin/tsx"),
    ["packages/cli/src/main.ts", "frontier", "--ledger", join(tmpdir(), "no-ledger-here")],
    { cwd: REPO_ROOT, env: { ...process.env, NO_COLOR: "1" }, maxBuffer: 16 * 1024 * 1024 },
  );
  return stdout;
}

/**
 * `pnpm rampscan submission --json`, over no ledger, for the same reason the
 * frontier arm runs over none: the denominator is derived from the catalog,
 * the recipes and the pinned dataset alone, so it is the same in CI as on a
 * developer's machine. Exit 1 is EXPECTED — the register exits 1 on the
 * rejections it can stand behind, and this repository's own offering declares
 * no assessor — so the stdout is read off the rejection rather than treated as
 * a failure to run.
 */
async function submission(): Promise<string> {
  try {
    const { stdout } = await run(
      join(REPO_ROOT, "node_modules/.bin/tsx"),
      [
        "packages/cli/src/main.ts",
        "submission",
        "--json",
        "--ledger",
        join(tmpdir(), "no-ledger-here"),
      ],
      { cwd: REPO_ROOT, env: { ...process.env, NO_COLOR: "1" }, maxBuffer: 16 * 1024 * 1024 },
    );
    return stdout;
  } catch (cause) {
    const stdout = (cause as { stdout?: string }).stdout;
    if (typeof stdout === "string" && stdout.length > 0) return stdout;
    throw cause;
  }
}

let readme: string;
let report: string;
let live: string;
let liveSubmission: string;

beforeAll(async () => {
  [readme, report, live, liveSubmission] = await Promise.all([
    readFile(README, "utf8"),
    readFile(REPORT, "utf8"),
    frontier(),
    submission(),
  ]);
});

describe("published numbers — the README against the commands that produce its figures (S2-1)", () => {
  it("carries every figure in a shape the gate can read", () => {
    const figures = readmeFigures(readme);
    expect(figures.floor.total).toBeGreaterThan(0);
    expect(figures.suite.length).toBeGreaterThanOrEqual(1);
    expect(figures.frontierBlock.length).toBeGreaterThan(4);
    expect(figures.selfScan.commit).toMatch(/^[0-9a-f]{7,40}$/);
  });

  it("the frontier block and the floor sentence are what `rampscan frontier` prints today", () => {
    expect(frontierDrift(readme, live)).toEqual([]);
  });

  it("the rejection register's denominator is what `rampscan submission` prints today", () => {
    expect(submissionDrift(readme, liveSubmission)).toEqual([]);
  });

  it("the self-scan line is the generated report's, at the commit the report names", () => {
    expect(selfScanDrift(readme, report)).toEqual([]);
  });

  it("every suite figure in the README agrees with every other — the reporter checks them against the run", () => {
    // the count itself is only known at the end of the run, so the reporter
    // holds that comparison; what a test can hold is that the README does not
    // carry two different counts, which is the drift a partial edit leaves
    const [first, ...rest] = readmeFigures(readme).suite;
    for (const figure of rest) expect(figure).toEqual(first);
    // and that the reporter's comparison would pass on the README's own
    // figure, so a green run means the two agree rather than that nobody read
    expect(suiteDrift(readme, first!)).toEqual([]);
  });
});

describe("the gate fails on a hand-edited figure (ground rule 7)", () => {
  it("names a KSI denominator that the register no longer prints", () => {
    const stale = readme
      .replace(/covering all (\d+)/, "covering all 46")
      .replace(/of (\d+) KSIs meet the class-b method floor/, "of 46 KSIs meet the class-b method floor");
    const drift = frontierDrift(stale, live);
    expect(drift.length).toBe(2);
    expect(drift[0]).toMatch(/README: covering all 46/);
    expect(drift[1]).toMatch(/of 46 meet the floor/);
  });

  it("names a floor count the register no longer prints", () => {
    const figures = readmeFigures(readme);
    const stale = readme.replace(
      /floor met on (\d+) of/,
      `floor met on ${figures.floor.met + 1} of`,
    );
    expect(frontierDrift(stale, live)).toEqual([
      expect.stringContaining(`README: floor met on ${figures.floor.met + 1} of`),
    ]);
  });

  it("names a rule denominator the register no longer prints", () => {
    const figures = readmeFigures(readme).submission;
    const stale = readme.replace(
      `**${figures.addressable} rules are addressable at class b`,
      `**${figures.addressable + 8} rules are addressable at class b`,
    );
    const drift = submissionDrift(stale, liveSubmission);
    expect(drift).toHaveLength(2);
    expect(drift[0]).toContain(`says ${figures.addressable + 8} rules are addressable`);
    // and the internal-consistency arm fires too: the MUST/SHOULD split no
    // longer adds up to the total, which is the shape of a partial hand-edit
    expect(drift[1]).toContain("does not add up");
  });

  it("names a self-scan line quoted at a commit the report was not generated from", () => {
    const stale = readme.replace(
      /(`rampscan scan \.` on this repository, at `)[0-9a-f]+`/,
      "$1deadbee`",
    );
    expect(selfScanDrift(stale, report)).toEqual([expect.stringContaining("`deadbee`")]);
  });

  it("names a self-scan line whose verdicts moved", () => {
    const generated = reportSelfScan(report);
    const stale = readme.replace(generated.line, generated.line.replace(/^\d+/, "99"));
    expect(selfScanDrift(stale, report)).toEqual([expect.stringMatching(/reads "99 evidenced/)]);
  });

  it("names a test count the run did not collect", () => {
    const [said] = readmeFigures(readme).suite;
    expect(suiteDrift(readme, { tests: said!.tests + 1, files: said!.files })).toEqual([
      expect.stringContaining(`this run collected ${(said!.tests + 1).toLocaleString("en-US")} tests`),
    ]);
    expect(suiteDrift(readme, { tests: said!.tests, files: said!.files - 1 })).toHaveLength(1);
    // a partial edit — one copy of the sentence moved, the other did not —
    // is two distinct stale figures, and both are named
    const partial = readme.replace(
      `${said!.tests.toLocaleString("en-US")} tests across ${said!.files} files`,
      `${(said!.tests + 7).toLocaleString("en-US")} tests across ${said!.files} files`,
    );
    expect(readmeFigures(partial).suite.length).toBeGreaterThan(1);
    expect(suiteDrift(partial, { tests: said!.tests + 1, files: said!.files })).toHaveLength(2);
  });

  it("fails, rather than stops reading, when a gated sentence is rephrased away", () => {
    const rephrased = readme.replace(/tests across (\d+) files/g, "tests in $1 files");
    expect(() => readmeFigures(rephrased)).toThrow(PublishedNumbersError);
    expect(() => readmeFigures(rephrased)).toThrow(/the suite figures/);
    expect(() => readmeFigures(readme.replace("$ pnpm rampscan frontier", "$ frontier"))).toThrow(
      /the frontier sample block/,
    );
    expect(() => reportSelfScan(report.replace(/^- \*\*commit:\*\*.*$/m, ""))).toThrow(
      /docs\/FRONTIER-PIPELINE\.md/,
    );
  });
});
