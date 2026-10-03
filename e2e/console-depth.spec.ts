import { resolve } from "node:path";
import { expect, test, type Page } from "@playwright/test";

// Plan U (docs/PLAN-CONSOLE-DEPTH.md): the console read from the top down.
// These run against the same smoke world as console.smoke.spec.ts — both
// fixture repos scanned, one `rampscan serve` — and pin the rules the
// phases deliver. U0 lands U-R1's scope and U-R2's walk; the rabbit-hole
// gate (§6) is written now and expected to fail until U4 unwraps it.

const VIEWER = "viewer@rampscan.local";
const PASSWORD = "rampscan-demo";
const FIXTURE_REPO = resolve("fixtures/vulnerable-app");
const BARE_REPO = resolve("fixtures/bare-app");
const FLAGSHIP = "no-critical-reachable-advisories";

async function signIn(page: Page): Promise<void> {
  await page.goto("/login");
  await page.locator("#email").fill(VIEWER);
  await page.locator("#password").fill(PASSWORD);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("heading", { name: "KSI board" })).toBeVisible({ timeout: 45_000 });
}

const scopeSelect = (page: Page) => page.getByLabel("repo scope");

/**
 * U-R2's walk: every text node on the page that names an entity must sit
 * inside a link or an element marked `data-entity` (a mention that was
 * considered and has nowhere to go, like a commit no scan names). Code,
 * form controls and the page's own command lines are text to copy, not
 * mentions. Returns the offending snippets.
 */
async function bareIds(page: Page): Promise<string[]> {
  return page.evaluate(() => {
    const PATTERNS = [
      /\bKSI-[A-Z]{3}-[A-Z]{3}\b/, // a KSI
      /\b[0-9a-f]{64}\b/, // a full digest
      /\b[0-9a-f]{12,16}…/, // a shortened digest
      /\b[0-9a-f]{12}\b/, // a short commit sha
      /\brun-\d{4}-\d{2}-\d{2}T[\w-]+/, // a scan run id
    ];
    const SKIP = "a, [data-entity], code, pre, input, select, option, textarea, script, style, .verify-cmd";
    const found: string[] = [];
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    for (let node = walker.nextNode(); node; node = walker.nextNode()) {
      const text = node.textContent ?? "";
      const parent = node.parentElement;
      if (!parent || parent.closest(SKIP)) continue;
      if (parent.closest("[hidden], [aria-hidden='true']")) continue;
      for (const re of PATTERNS) {
        const m = text.match(re);
        if (m) found.push(`${m[0]} in "${text.trim().slice(0, 90)}"`);
      }
    }
    return found;
  });
}

test("U-R2: no page names an entity without a way to it", async ({ page }) => {
  await signIn(page);
  const pages = [
    `/?repo=${encodeURIComponent(FIXTURE_REPO)}&ksi=KSI-CMT-VTD`,
    "/recipes?repo=all",
    `/queue?repo=${encodeURIComponent(FIXTURE_REPO)}`,
    "/controls?repo=all",
    "/scoping",
    "/clock?repo=all",
    "/drift?repo=all",
    "/runs?repo=all",
    "/approvals",
  ];
  const offenders: string[] = [];
  for (const path of pages) {
    await page.goto(path);
    // every page settles on a heading once its collections have loaded
    await expect(page.locator("h1").first()).toBeVisible({ timeout: 45_000 });
    await page.waitForLoadState("networkidle");
    for (const o of await bareIds(page)) offenders.push(`${path}: ${o}`);
  }

  // one level down: the flagship's evidence page, reached the way a reader would
  await page.goto(`/recipes?repo=${encodeURIComponent(FIXTURE_REPO)}`);
  await page.getByRole("cell", { name: FLAGSHIP, exact: true }).click();
  await expect(page).toHaveURL(/\/evidence\/[0-9a-f]{64}/, { timeout: 45_000 });
  await expect(page.locator("dl.kv").first()).toBeVisible();
  await page.waitForLoadState("networkidle");
  for (const o of await bareIds(page)) offenders.push(`evidence: ${o}`);

  expect(offenders).toEqual([]);
});

test("U-R5: the repo scope defaults to the newest scan and survives navigation", async ({ page }) => {
  await signIn(page);
  // the smoke scans vulnerable-app, then bare-app: the newest scan is bare-app
  await expect(scopeSelect(page)).toHaveValue(BARE_REPO);
  await expect(scopeSelect(page).locator("option:checked")).toContainText("newest scan");

  await scopeSelect(page).selectOption(FIXTURE_REPO);
  await expect(page).toHaveURL(new RegExp(`repo=${encodeURIComponent(FIXTURE_REPO).replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`));

  // every nav hop keeps it, and every register reads it
  for (const label of ["Recipes", "Queue", "Clock", "Runs", "Board"]) {
    await page.getByRole("navigation").getByRole("link", { name: label, exact: true }).click();
    await expect(scopeSelect(page)).toHaveValue(FIXTURE_REPO, { timeout: 45_000 });
  }
  // under one repo, no row wastes a column saying which
  await page.goto(`/recipes?repo=${encodeURIComponent(FIXTURE_REPO)}`);
  await expect(page.getByRole("columnheader", { name: "Repo", exact: true })).toHaveCount(0);
  await scopeSelect(page).selectOption("all");
  await expect(page.getByRole("columnheader", { name: "Repo", exact: true })).toBeVisible();
  // and then it is a basename, with the path one hover away
  const cell = page.locator("td .repo-name").first();
  await expect(cell).toHaveAttribute("title", /\/fixtures\//);
  expect(await cell.textContent()).not.toContain("/");

  // a link inside a page carries the scope too: a KSI mention opens the board there
  await page.goto(`/clock?repo=${encodeURIComponent(FIXTURE_REPO)}`);
  await page.locator("a[data-entity='ksi']").first().click();
  await expect(page).toHaveURL(/[?&]ksi=KSI-/, { timeout: 45_000 });
  await expect(scopeSelect(page)).toHaveValue(FIXTURE_REPO);
  await expect(page.locator("tr.linked")).toHaveAttribute("aria-expanded", "true");
});

test("U0: a signed-out deep link survives the sign-in", async ({ page }) => {
  const target = `/recipes?repo=${encodeURIComponent(FIXTURE_REPO)}&recipe=${FLAGSHIP}`;
  await page.goto(target);
  await expect(page).toHaveURL(/\/login\?next=/, { timeout: 45_000 });
  await page.locator("#email").fill(VIEWER);
  await page.locator("#password").fill(PASSWORD);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page).toHaveURL(new RegExp(`recipe=${FLAGSHIP}`), { timeout: 45_000 });
  // the named cell arrives marked, in view, and explained
  const row = page.locator(`tr#recipe-${FLAGSHIP}`);
  await expect(row).toHaveClass(/linked/);
  await expect(row).toBeInViewport();
  await expect(page.getByRole("button", { name: "▾ plain English" })).toBeVisible();
});

// §6, the exit gate for the whole plan: the flagship violation's verify
// command in four clicks from the posture block, and back up by breadcrumbs
// alone. The posture block (U2), the KSI page (U1), the check page (U3) and
// the breadcrumbs (U4) do not exist yet, so this fails today by design —
// each phase makes more of it true, and U4 removes the marker.
test.fail("rabbit-hole: posture → theme → KSI → check → verify in four clicks, and back up", async ({ page }) => {
  await signIn(page);
  await scopeSelect(page).selectOption(FIXTURE_REPO);
  const posture = page.locator("[data-level='posture']");
  await expect(posture).toBeVisible({ timeout: 10_000 });

  await posture.getByRole("link", { name: /SCR/ }).first().click(); // 1: theme
  await page.getByRole("link", { name: "KSI-SCR-MON" }).click(); // 2: KSI
  await page.getByRole("link", { name: FLAGSHIP }).first().click(); // 3: check
  await page.getByRole("link", { name: /current bundle/ }).click(); // 4: bundle
  await expect(page.locator(".verify-cmd")).toBeInViewport();

  for (const crumb of [FLAGSHIP, "KSI-SCR-MON", "SCR", "posture"]) {
    await page.getByRole("navigation", { name: "breadcrumb" }).getByRole("link", { name: crumb }).click();
  }
  await expect(posture).toBeVisible();
  await expect(scopeSelect(page)).toHaveValue(FIXTURE_REPO);
});
