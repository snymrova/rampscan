import { execFileSync } from "node:child_process";
import { createHash, createPublicKey, verify as cryptoVerify } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { expect, test, type Page } from "@playwright/test";
import { PB_PORT } from "../playwright.config";

// The first console smoke (plan I2e, ground rule 5): serve → login → board
// renders rows from a real fixture scan → evidence detail shows assertions +
// call path → action queue renders ranked. Every assertion pins a KNOWN
// fixture truth (the planted lodash advisory, its call path, the violated
// verdict) — "something rendered" is not evidence.

const VIEWER = "viewer@rampscan.local";
const APPROVER = "approver@rampscan.local";
const PASSWORD = "rampscan-demo";
/** flagship recipe (M4): reachable lodash CRITICAL with path src/index.js » lodash/merge */
const FLAGSHIP = "no-critical-reachable-advisories";

async function signIn(page: Page, email: string = VIEWER): Promise<void> {
  await page.goto("/");
  // signed out, every register page bounces to the login card
  await expect(page).toHaveURL(/\/login/);
  await page.locator("#email").fill(email);
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

test("scoping register: the two-key flow lands on the record, approved verified and rejected kept (I3c)", async ({ page }) => {
  const approveRecipe = "container-runs-nonroot";
  const rejectRecipe = "codeowners-defined";
  const approveJustification = "the fixture ships no production container image — smoke scope-out";
  const rejectJustification = "declined by the smoke — this recipe stays in scope";

  await signIn(page, APPROVER);

  // first key: file both proposals — the exact write the board's propose form
  // performs (a `proposals` create with the console identity's token). The
  // form's button only renders on unevidenced rows, and a fully-tooled scan
  // of the fixture leaves none — the register under test starts at the
  // proposal ROW, not at the form.
  const pbUrl = `http://127.0.0.1:${PB_PORT}`;
  const auth = (await (
    await fetch(`${pbUrl}/api/collections/users/auth-with-password`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ identity: APPROVER, password: PASSWORD }),
    })
  ).json()) as { token: string; record: { id: string } };
  const repo = resolve("fixtures/vulnerable-app"); // the scan recorded the absolute path
  for (const [recipe, justification] of [
    [approveRecipe, approveJustification],
    [rejectRecipe, rejectJustification],
  ] as const) {
    const created = await fetch(`${pbUrl}/api/collections/proposals/records`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: auth.token },
      body: JSON.stringify({
        repo,
        recipe_id: recipe,
        justification,
        status: "pending",
        proposed_by: `${APPROVER} (pb:${auth.record.id})`,
      }),
    });
    expect(created.ok, `filing the ${recipe} proposal failed: ${created.status}`).toBe(true);
  }

  // second key: the approver decides — one approval (a REAL signed scoping
  // event appended to the scratch ledger) and one rejection (which never
  // touches the ledger; the register must list it all the same)
  await page.goto("/approvals");
  const entry = (recipe: string) => page.locator(".panel > div").filter({ hasText: recipe });
  await entry(approveRecipe).getByRole("button", { name: "approve & sign" }).click();
  // first hit compiles the decide route, then signs + appends — be generous
  await expect(
    entry(approveRecipe).filter({ hasText: "approved" }).first(),
  ).toBeVisible({ timeout: 45_000 });
  await entry(rejectRecipe).getByRole("button", { name: "reject", exact: true }).click();
  await expect(entry(rejectRecipe).filter({ hasText: "rejected" }).first()).toBeVisible();

  // the register: the approved decision reads from the LEDGER's signed event,
  // its signature re-verified server-side on this very load
  await page.goto("/scoping");
  await expect(page.getByRole("heading", { name: "Scoping register" })).toBeVisible({
    timeout: 45_000,
  });
  const approved = page.locator(".panel > div").filter({ hasText: approveRecipe }).first();
  await expect(approved).toContainText("scoped out");
  await expect(approved).toContainText("signature verified");
  await expect(approved).toContainText(approveJustification);
  await expect(approved).toContainText(APPROVER); // the identity the predicate carries
  await expect(approved).toContainText("removed from scope:");

  // the rejected decision is on the record too — with its justification and
  // the honest framing that nothing left scope
  const rejected = page
    .locator(".panel > div")
    .filter({ hasText: rejectRecipe })
    .filter({ hasText: "rejected" })
    .first();
  await expect(rejected).toContainText(rejectJustification);
  await expect(rejected).toContainText("kept in scope:");

  // and the hop: the approved row's digest opens the scoping bundle itself
  await approved.locator("a[href^='/evidence/']").click();
  await expect(page).toHaveURL(/\/evidence\/[0-9a-f]{64}/, { timeout: 45_000 });
  await expect(page.locator("body")).toContainText(approveJustification);
});

test("as-of selector: the past refolds honestly on board and control register; the clock shows the lapse record (I3d)", async ({ page }) => {
  await signIn(page);

  // turn the as-of view on — it defaults to now, so the refold must agree
  // with the live board: the flagship stays violated
  await page.getByRole("button", { name: "as of", exact: true }).click();
  await expect(page.locator(".asof-strip")).toBeVisible();
  // first hit compiles the asof route (dev compile-on-first-hit, as elsewhere)
  const flagshipRow = page.getByRole("row").filter({ hasText: FLAGSHIP }).first();
  await expect(flagshipRow.locator(".pill.violated")).toBeVisible({ timeout: 45_000 });
  await expect(page.locator(".asof-strip")).toContainText("read-only");
  // a historical fold offers no actions to take today
  await expect(page.getByRole("button", { name: "propose N/A" })).toHaveCount(0);

  // rewind to before the scan: the board empties honestly — an answer, not
  // an error ("what did the world look like?" — nothing was recorded yet)
  await page.locator("input[type='datetime-local']").fill("2000-01-01T00:00");
  await expect(page.locator("td.empty")).toContainText(
    "no ledger statement at or before it",
    { timeout: 15_000 },
  );

  // jump to the scan instant via the quick-pick: the scan's board returns,
  // and the strip says the instant IS a scan
  await page.locator("select:has(option[value=''])").selectOption({ index: 1 });
  await expect(page.locator(".asof-strip")).toContainText("(a scan instant)");
  await expect(flagshipRow.locator(".pill.violated")).toBeVisible();

  // the control register rides the SAME fold: as-of now shows ra-5 violated,
  // as-of before the scan shows an honestly empty register
  await page.goto("/controls");
  await expect(page.getByRole("heading", { name: "Control register" })).toBeVisible();
  await page.getByRole("button", { name: "as of", exact: true }).click();
  const ra5 = page
    .locator("tr")
    .filter({ has: page.getByRole("cell", { name: "ra-5", exact: true }) });
  await expect(ra5.locator(".pill.violated").first()).toBeVisible({ timeout: 15_000 });
  await page.locator("input[type='datetime-local']").fill("2000-01-01T00:00");
  await expect(page.locator("td.empty")).toContainText("no ledger statement at or before it");

  // the cadence-gap timeline (I1d's projection, rendered): the fixture was
  // scanned minutes ago, so the honest record is that nothing has lapsed —
  // the section must say that, not render an invented gap
  await page.goto("/clock");
  await expect(page.getByRole("heading", { name: "Cadence lapses" })).toBeVisible();
  await expect(page.locator(".panel .empty").last()).toContainText("no cadence lapse on record");
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

test("export: the auditor takes the record away — package verifies offline, CSV matches the screen, print keeps the facts (I3e)", async ({
  page,
}) => {
  await signIn(page);
  await page.goto("/controls");
  await expect(page.getByRole("heading", { name: "Control register" })).toBeVisible();

  // ---- the per-control evidence package -----------------------------------
  // ra-5 is the flagship's control: pick it on the register, take it away
  const row = page
    .locator("tr")
    .filter({ has: page.getByRole("cell", { name: "ra-5", exact: true }) });
  const [download] = await Promise.all([
    page.waitForEvent("download"),
    row.getByRole("button", { name: "evidence package" }).click(),
  ]);
  expect(download.suggestedFilename()).toMatch(/^rampscan-evidence-control-ra-5-\d{4}-\d{2}-\d{2}\.tar$/);
  const files = untar(readFileSync((await download.path())!));

  // the manifest speaks for every mapped recipe, gaps included
  const manifest = JSON.parse(files.get("MANIFEST.json")!.toString("utf8")) as {
    id: string;
    state: string;
    counts: { total: number };
    verifyCommand: string;
    rows: Array<{ recipeId: string; state: string; digest?: string; envelopePath?: string }>;
  };
  expect(manifest.id).toBe("ra-5");
  expect(manifest.rows.length).toBe(manifest.counts.total);
  expect(manifest.rows.map((r) => r.recipeId)).toContain(FLAGSHIP);
  expect(files.has("VERIFY.md")).toBe(true);

  // verification with node:crypto ONLY, against the package's own bytes —
  // no rampscan code, and nothing read from this machine but the tar
  const flagship = manifest.rows.find((r) => r.recipeId === FLAGSHIP)!;
  expect(flagship.envelopePath).toBeTruthy();
  const envelope = JSON.parse(files.get(flagship.envelopePath!)!.toString("utf8")) as {
    payload: string;
    payloadType: string;
    signatures: Array<{ sig: string }>;
  };
  const payload = Buffer.from(envelope.payload, "base64");
  expect(createHash("sha256").update(payload).digest("hex")).toBe(flagship.digest);
  expect(payload.toString("utf8")).toContain(FLAGSHIP);
  const pae = Buffer.concat([
    Buffer.from(`DSSEv1 ${envelope.payloadType.length} ${envelope.payloadType} ${payload.length} `),
    payload,
  ]);
  const publicKey = createPublicKey(files.get("rampscan.pub")!.toString("utf8"));
  expect(
    envelope.signatures.some((s) =>
      cryptoVerify("sha256", pae, publicKey, Buffer.from(s.sig, "base64")),
    ),
  ).toBe(true);

  // every artifact the package ships hashes to the digest its statement attests
  for (const [name, bytes] of files) {
    if (!name.startsWith("artifacts/")) continue;
    expect(createHash("sha256").update(bytes).digest("hex")).toBe(name.split("/")[1]);
  }

  // and the package's own instructions work: run its verifyCommand verbatim
  const args = manifest.verifyCommand
    .replace("<digest>", flagship.digest!)
    .trim()
    .split(/\s+/)
    .slice(2); // drop "pnpm rampscan"
  const report = execFileSync("node_modules/.bin/tsx", ["packages/cli/src/main.ts", ...args], {
    encoding: "utf8",
  });
  expect(report).toContain("signature ok");
  expect(report).toContain("payload  ok");

  // ---- CSV: the row count equals the screen -------------------------------
  // compared against the count the PAGE renders, which is what "equals the
  // on-screen register" means to the person holding both
  const csvRows = async (name: string): Promise<string> => {
    const [download] = await Promise.all([
      page.waitForEvent("download"),
      page.getByRole("button", { name: "export CSV" }).click(),
    ]);
    expect(download.suggestedFilename()).toMatch(new RegExp(`^rampscan-${name}-`));
    return readFileSync((await download.path())!, "utf8");
  };
  const dataLines = (csv: string): number => csv.trimEnd().split("\r\n").length - 1;

  const controlCount = Number(await page.locator(".tabs button", { hasText: "Controls" }).locator(".count").innerText());
  expect(dataLines(await csvRows("controls"))).toBe(controlCount);

  // the coverage board, and the filtered case — a CSV that ignored the
  // filters would still "match" an unfiltered screen, so filter first
  await page.goto("/");
  await expect(page.getByRole("row").filter({ hasText: FLAGSHIP }).first()).toBeVisible();
  const allCount = Number(await page.locator(".tabs button", { hasText: "All" }).locator(".count").innerText());
  const boardCsv = await csvRows("board");
  expect(dataLines(boardCsv)).toBe(allCount);
  expect(boardCsv).toContain(FLAGSHIP);

  await page.locator(".tabs button", { hasText: "Violated" }).click();
  const violatedCount = Number(await page.locator(".tabs button", { hasText: "Violated" }).locator(".count").innerText());
  expect(violatedCount).toBeGreaterThan(0);
  expect(violatedCount).toBeLessThan(allCount);
  const violatedCsv = await csvRows("board");
  expect(dataLines(violatedCsv)).toBe(violatedCount);
  await page.locator(".tabs button", { hasText: "All" }).click();

  // ---- print: the facts that make the claim checkable survive on paper ----
  await page.getByRole("cell", { name: FLAGSHIP, exact: true }).click();
  await expect(page).toHaveURL(/\/evidence\/[0-9a-f]{64}/, { timeout: 45_000 });
  const digest = /[0-9a-f]{64}/.exec(page.url())![0];
  await page.emulateMedia({ media: "print" });
  const printed = page.locator("body");
  await expect(printed).toContainText(digest.slice(0, 16));
  await expect(printed).toContainText("scanned commit");
  await expect(printed).toContainText("dataset pin");
  await expect(printed).toContainText("tool versions");
  // screen-only chrome is gone; the record is not
  await expect(page.locator(".nav")).toBeHidden();
  await page.emulateMedia({ media: "screen" });
});

/** the reference tar reader — the package must be readable without our writer */
function untar(bytes: Buffer): Map<string, Buffer> {
  const out = new Map<string, Buffer>();
  for (let offset = 0; offset + 512 <= bytes.length; ) {
    const header = bytes.subarray(offset, offset + 512);
    const name = header.subarray(0, 100).toString("ascii").replace(/\0.*$/, "");
    if (name === "") break;
    const size = parseInt(header.subarray(124, 135).toString("ascii").trim(), 8);
    const start = offset + 512;
    out.set(name, bytes.subarray(start, start + size));
    offset = start + Math.ceil(size / 512) * 512;
  }
  return out;
}
