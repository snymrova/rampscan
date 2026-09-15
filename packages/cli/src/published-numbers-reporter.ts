import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { Reporter, TestModule, TestRunEndReason, Vitest } from "vitest/node";
import { suiteDrift } from "./published-numbers.js";

// The suite arm of the numbers gate (plan S2-1), and the reason it is a
// reporter rather than a test: the only process that knows how many tests the
// suite holds is the run itself, at its end. A test asking the question from
// inside the run has two ways to answer it and both are wrong — `vitest list`
// re-collects every file (62 s, measured, about the length of the run it is
// inside) and re-executes the global setup that rebuilds the fixture
// repositories underneath the tests still reading them; a static count of
// `it(` calls is a second, worse test runner. So the count is read where the
// suite's own reporter reads it, and compared with the README there.
//
// It gates only a WHOLE run. `pnpm test some-filter` collects a subset, and a
// subset disagreeing with the README is not drift; the reporter says so in one
// dim line and stands down. And it fails the run the only way a reporter can,
// by setting the exit code — a hand-edited test count in the README turns
// `pnpm test` red at the end, with the two figures printed side by side.
//
// `packages/cli/test/published-numbers.test.ts` is where the comparison is
// proven able to fail (ground rule 7); this file is only where it is wired.

export default class PublishedNumbersReporter implements Reporter {
  private vitest!: Vitest;

  onInit(vitest: Vitest): void {
    this.vitest = vitest;
  }

  async onTestRunEnd(
    testModules: ReadonlyArray<TestModule>,
    _errors: ReadonlyArray<unknown>,
    reason: TestRunEndReason,
  ): Promise<void> {
    // an interrupted run has counted nothing yet, and a failed one has
    // already said what is wrong — the gate adds its line only over a run
    // that finished
    if (reason !== "passed") return;
    const whole = await this.vitest.globTestSpecifications();
    if (testModules.length !== whole.length) {
      this.vitest.logger.log(
        `published numbers: ${testModules.length} of ${whole.length} test files ran — a filtered run, so ` +
          "the README's suite figures are not gated here",
      );
      return;
    }
    const tests = testModules.reduce((n, m) => n + [...m.children.allTests()].length, 0);
    const files = testModules.length;
    const readme = await readFile(join(this.vitest.config.root, "README.md"), "utf8");
    const drift = suiteDrift(readme, { tests, files });
    if (drift.length === 0) {
      this.vitest.logger.log(
        `published numbers: README's suite figures match this run — ${tests.toLocaleString("en-US")} tests across ${files} files`,
      );
      return;
    }
    this.vitest.logger.error(
      "\npublished numbers: README.md drifted from the suite (ground rule 4 — computed, never typed):\n" +
        drift.map((d) => `  - ${d}`).join("\n") +
        "\n  regenerate the figure from `pnpm test` in the same change that moved it",
    );
    process.exitCode = 1;
  }
}
