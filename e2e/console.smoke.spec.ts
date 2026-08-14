import { expect, test, type Page } from "@playwright/test";

// The first console smoke (plan I2e, ground rule 5): serve → login → board
// renders rows from a real fixture scan → evidence detail shows assertions +
// call path → action queue renders ranked. Every assertion pins a KNOWN
// fixture truth (the planted lodash advisory, its call path, the violated
// verdict) — "something rendered" is not evidence.

const VIEWER = "viewer@rampscan.local";
const PASSWORD = "rampscan-demo";
/** flagship recipe (M4): reachable lodash CRITICAL with path src/index.js » lodash/merge */
const FLAGSHIP = "no-critical-reachable-advisories";

async function signIn(page: Page): Promise<void> {
  await page.goto("/");
  // signed out, every register page bounces to the login card
  await expect(page).toHaveURL(/\/login/);
  await page.locator("#email").fill(VIEWER);
  await page.locator("#password").fill(PASSWORD);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("heading", { name: "Coverage board" })).toBeVisible();
}

test("login: signed out bounces to /login; a demo identity lands on the board", async ({ page }) => {
  await signIn(page);
  // the subtitle proves a projection is loaded, not an empty shell
  await expect(page.locator("p.subtitle")).toContainText("dataset");
});

test("board: fixture scan rows render, flagship violated, no-daemon strip says so", async ({ page }) => {
  await signIn(page);

  // the flagship row is violated — a real verdict from the real scan
  const flagshipRow = page.getByRole("row").filter({ hasText: FLAGSHIP }).first();
  await expect(flagshipRow).toBeVisible();
  await expect(flagshipRow.locator(".pill.violated")).toBeVisible();

  // no daemon runs in this smoke — the I2b strip must say so, loudly,
  // not reassure (the I2 exit test: "with the daemon stopped, the console
  // visibly says so")
  await expect(page.locator(".strip.nodaemon")).toBeVisible();
  await expect(page.locator(".strip.nodaemon")).toContainText("no daemon");

  // fix pointers (I2c) ride the violated row on the board itself
  await expect(page.locator("td.pointer-row").first()).toBeVisible();
});

test("evidence detail: assertions render with the flagship call path", async ({ page }) => {
  await signIn(page);
  // click the recipe cell, not the row: the row's trailing actions cell
  // swallows clicks (stopPropagation), and a row-center click can land there
  await page.getByRole("cell", { name: FLAGSHIP, exact: true }).click();
  await expect(page).toHaveURL(/\/evidence\/[0-9a-f]{64}/);

  // at least one failing assertion, with the reachability call path —
  // the » separator is the call-path grammar (src/index.js » lodash/merge)
  await expect(page.locator(".assertion-fail").first()).toBeVisible();
  await expect(page.locator("body")).toContainText("lodash");
  await expect(page.locator("body")).toContainText("»");
});

test("action queue: renders ranked, with the scan's new violations", async ({ page }) => {
  await signIn(page);
  await page.goto("/queue");
  await expect(page.getByRole("heading", { name: "Action queue" })).toBeVisible();

  // the scan's born-violated drift events must surface as queue items
  const pills = page.locator("table.reg tbody td:first-child .pill");
  await expect(pills.first()).toBeVisible();
  const labels = await pills.allTextContents();
  expect(labels).toContain("violation");

  // ranked means ranked: divergence > expiring > new violation > actionable
  // unevidenced — the rendered order must be non-decreasing in that ranking
  const rank: Record<string, number> = {
    divergence: 0,
    expiring: 1,
    violation: 2,
    unevidenced: 3,
  };
  for (const label of labels) expect(rank[label]).toBeDefined();
  for (let i = 1; i < labels.length; i++) {
    expect(rank[labels[i]!]!).toBeGreaterThanOrEqual(rank[labels[i - 1]!]!);
  }
});
