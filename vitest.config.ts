import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["packages/*/test/**/*.test.ts"],
    globalSetup: ["./scripts/vitest-global-setup.mjs"],

    // Vitest's defaults are 5s per test and 10s per hook, which are sized for
    // unit tests. Most of this suite is not one: the e2e files build fixture
    // repositories, walk a code graph, run a dry scan and fold a ledger, and
    // they do it inside the test body rather than behind a mock, on purpose.
    //
    // Measured on a warm local machine, the slowest test is 5115ms — already
    // OVER the 5s default — and the second is 4608ms. Both pass here only
    // because the machine is fast and the caches are warm. A GitHub runner is
    // slower on CPU and colder on disk, so this suite would have failed its
    // first CI run on the clock rather than on a claim, and the failure would
    // have looked like a flake instead of like a default that never fit.
    //
    // 30s is roughly six times the slowest observed test: enough headroom for a
    // cold, contended runner, and still short enough that a genuine hang fails
    // the job in seconds rather than sitting until the 15-minute job timeout.
    // The hooks get more because `beforeAll` is where the fixture repositories
    // are built and the seeding scan is run.
    testTimeout: 30_000,
    hookTimeout: 60_000,
  },
});
