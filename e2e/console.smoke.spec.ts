import { execFileSync } from "node:child_process";
import { createHash, createPublicKey, verify as cryptoVerify } from "node:crypto";
import { readFileSync } from "node:fs";
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
  // first client-side hit of /evidence/[digest]: next dev compiles the route
  // on demand, and under load that can outlast the default expect timeout
  await expect(page).toHaveURL(/\/evidence\/[0-9a-f]{64}/, { timeout: 45_000 });

  // at least one failing assertion, with the reachability call path —
  // the » separator is the call-path grammar (src/index.js » lodash/merge)
  await expect(page.locator(".assertion-fail").first()).toBeVisible();
  await expect(page.locator("body")).toContainText("lodash");
  await expect(page.locator("body")).toContainText("»");
});

test("verify yourself: the downloads verify with standard crypto alone (I3b)", async ({ page }) => {
  await signIn(page);
  await page.getByRole("cell", { name: FLAGSHIP, exact: true }).click();
  await expect(page).toHaveURL(/\/evidence\/[0-9a-f]{64}/, { timeout: 45_000 });
  const digest = /[0-9a-f]{64}/.exec(page.url())![0];

  // the header surfaces what the bundle already carries
  await expect(page.locator("body")).toContainText("scanned commit");
  await expect(page.locator("body")).toContainText("dataset pin");

  // download the raw DSSE envelope and the public key
  const [bundleDownload] = await Promise.all([
    page.waitForEvent("download"),
    page.getByRole("button", { name: "download DSSE bundle" }).click(),
  ]);
  const [keyDownload] = await Promise.all([
    page.waitForEvent("download"),
    page.getByRole("button", { name: "download public key" }).click(),
  ]);
  const envelope = JSON.parse(readFileSync((await bundleDownload.path())!, "utf8")) as {
    payload: string;
    payloadType: string;
    signatures: Array<{ sig: string }>;
  };
  const publicKeyPem = readFileSync((await keyDownload.path())!, "utf8");

  // independent verification — node:crypto ONLY, no rampscan code:
  // 1. content: the signed payload hashes to the bundle's address
  const payload = Buffer.from(envelope.payload, "base64");
  expect(createHash("sha256").update(payload).digest("hex")).toBe(digest);
  // 2. the payload is the flagship's statement, not something else signed
  expect(payload.toString("utf8")).toContain(FLAGSHIP);
  // 3. signature: ECDSA P-256/SHA-256 over the DSSE PAE, against the key alone
  const pae = Buffer.concat([
    Buffer.from(`DSSEv1 ${envelope.payloadType.length} ${envelope.payloadType} ${payload.length} `),
    payload,
  ]);
  const publicKey = createPublicKey(publicKeyPem);
  expect(
    envelope.signatures.some((s) => cryptoVerify("sha256", pae, publicKey, Buffer.from(s.sig, "base64"))),
  ).toBe(true);

  // and the page's own copy-paste invocation passes, run verbatim (modulo the
  // `pnpm rampscan` prefix → the package script's real entry point)
  const command = (await page.locator("code.copycmd").first().textContent()) ?? "";
  expect(command).toContain(`rampscan verify ${digest} --ledger`);
  const args = command.trim().split(/\s+/).slice(2); // drop "pnpm rampscan"
  const report = execFileSync("node_modules/.bin/tsx", ["packages/cli/src/main.ts", ...args], {
    encoding: "utf8",
  });
  expect(report).toContain("signature ok");
  expect(report).toContain("payload  ok");
});

test("control register: rollup → recipe → evidence, and the evidence links back (I3a)", async ({ page }) => {
  await signIn(page);
  await page.goto("/controls");
  await expect(page.getByRole("heading", { name: "Control register" })).toBeVisible();

  // ra-5 maps the flagship recipe — the fixture scan left the rollup violated,
  // because violated beats every other mapped verdict in the rollup precedence
  const row = page
    .locator("tr")
    .filter({ has: page.getByRole("cell", { name: "ra-5", exact: true }) });
  await expect(row.locator(".pill.violated").first()).toBeVisible();

  // control → mapped recipes: expanding lists the flagship with its own verdict
  await row.click();
  const sub = page.locator("tr").filter({ hasText: FLAGSHIP });
  await expect(sub.first()).toBeVisible();

  // recipe → evidence bundle (45s: dev-compile-on-first-hit, as above)
  await sub.first().click();
  await expect(page).toHaveURL(/\/evidence\/[0-9a-f]{64}/, { timeout: 45_000 });

  // and back (the other direction of the hop): the bundle's control ids link
  // into the register, deep-linking the rollup row expanded and highlighted
  await page.getByRole("link", { name: "ra-5", exact: true }).click();
  await expect(page).toHaveURL(/\/controls\?reg=controls&id=ra-5/);
  await expect(page.locator("tr.hl .pill.violated").first()).toBeVisible();
  await expect(page.locator("tr").filter({ hasText: FLAGSHIP }).first()).toBeVisible();
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
