import { defineConfig } from "@playwright/test";

// The first console smoke (plan I2e, ground rule 5): a REAL fixture scan
// behind a real `rampscan serve` — nothing canned, nothing mocked. The
// webServer command below (e2e/smoke-server.mjs) builds the fixture, scans
// it into e2e/.smoke, and only then starts the same `rampscan serve` an
// operator runs, pointed at that scratch ledger (and a scratch --pb-data, so
// a smoke run can never touch the dev console's users or pending proposals).
// The prepare steps live INSIDE the server command, not in a globalSetup:
// Playwright starts the webServer before global setup runs.

export const WEB_PORT = 3098;
export const PB_PORT = 8098;

export default defineConfig({
  testDir: "./e2e",
  // one serve, one PocketBase: keep the first smoke serial and deterministic
  workers: 1,
  timeout: 60_000,
  // next dev compiles each page on first hit — generous expect timeout
  expect: { timeout: 15_000 },
  reporter: [["list"]],
  use: {
    baseURL: `http://127.0.0.1:${WEB_PORT}`,
    trace: "retain-on-failure",
  },
  webServer: {
    command: "node e2e/smoke-server.mjs",
    url: `http://127.0.0.1:${WEB_PORT}/login`,
    // The smoke ports are pinned, so anything on 3098 is a smoke server that
    // already ran the prepare steps — reusing it locally makes spec iteration
    // fast. CI always starts fresh.
    reuseExistingServer: !process.env.CI,
    // the timeout covers fixture build + full scan (cold tool DBs) + next dev
    timeout: 600_000,
    stdout: "pipe",
    stderr: "pipe",
    // own compile cache: NEXT_PUBLIC_* is inlined at build time and .next's
    // webpack cache does not invalidate on env change — sharing .next with a
    // dev serve hands the smoke stale chunks pointing at the wrong PocketBase
    env: {
      NEXT_DIST_DIR: ".next-smoke",
      SMOKE_PB_PORT: String(PB_PORT),
      SMOKE_WEB_PORT: String(WEB_PORT),
    },
  },
});
