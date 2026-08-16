import { execFileSync } from "node:child_process";
import { createHash, createPublicKey, verify as cryptoVerify } from "node:crypto";
import { existsSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
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

/**
 * The smoke's world holds TWO scanned repositories since K1, and the second
 * one is the point: `vulnerable-app` is fully tooled, so every one of its rows
 * comes back evidenced or violated and the board has no empty cell anywhere —
 * which left J3's "why is this empty?" hop and K1's guided empty states with
 * nothing real to render. `bare-app` has no Dockerfile, no CI, no IaC and no
 * API description, so its collectors skip honestly and say why.
 *
 * Every test that reads a board, a register or the run timeline therefore
 * names the repo it means, through the page's own filter — the way an operator
 * would, and the reason those filters have finally been exercised at all.
 * The scan records the absolute path, so both are resolved rather than typed.
 */
const FIXTURE_REPO = resolve("fixtures/vulnerable-app");
const BARE_REPO = resolve("fixtures/bare-app");

async function pickRepo(page: Page, repo: string = FIXTURE_REPO): Promise<void> {
  await page.locator("select").first().selectOption(repo);
}

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
  await pickRepo(page);

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
  await pickRepo(page);
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
  await pickRepo(page);
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
  await pickRepo(page);

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
  const repo = FIXTURE_REPO; // the scan recorded the absolute path
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
  await pickRepo(page);

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
  await pickRepo(page);
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
  await pickRepo(page);

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
  await pickRepo(page);
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

test("runs: the machinery behind the board — the timeline's counts are a recount of its own table (J2)", async ({
  page,
}) => {
  await signIn(page);
  await page.goto("/runs");
  await expect(page.getByRole("heading", { name: "Runs" })).toBeVisible();
  await pickRepo(page);

  // the fixture scan appended exactly one run record, and the timeline shows
  // it: the smoke's scan is manual, so the trigger is a known fixture truth
  const row = page.locator("tr.rowlink");
  await expect(row).toHaveCount(1);
  await expect(row).toContainText("manual");
  // a fully-tooled scan skips nothing, and the page says the zero out loud
  // rather than leaving the reader to infer it from silence
  await expect(row).toContainText("0 skipped");

  // the summary is a RECOUNT, not a stored number: parse what the row claims,
  // expand, and count the collector rows the expansion renders. This is the
  // property the page exists to keep — a reader recounting the table must
  // reproduce the timeline row exactly.
  const summary = await row.locator("td").nth(5).innerText();
  const claimed = {
    dispatched: Number(/(\d+) collector/.exec(summary)![1]),
    ran: Number(/(\d+) ran/.exec(summary)![1]),
    cacheHit: Number(/(\d+) cache-hit/.exec(summary)?.[1] ?? 0),
    skipped: Number(/(\d+) (?:skipped|SKIPPED)/.exec(summary)![1]),
  };
  expect(claimed.ran + claimed.cacheHit + claimed.skipped).toBe(claimed.dispatched);

  await row.click();
  const collectorRows = page.locator("table.subtable tbody tr");
  await expect(collectorRows.first()).toBeVisible();
  expect(await collectorRows.count()).toBe(claimed.dispatched);
  expect(await page.locator("table.subtable .pill.runtime-skipped").count()).toBe(claimed.skipped);
  expect(await page.locator("table.subtable .pill.runtime-cache-hit").count()).toBe(
    claimed.cacheHit,
  );

  // every collector carries the facts an auditor asked the run record for.
  // repo-facts spawns nothing — it says so as a fact about the collector,
  // never as a missing tool
  const facts = page
    .locator("table.subtable tr")
    .filter({ has: page.getByRole("cell", { name: "repo-facts", exact: true }) });
  await expect(facts.locator(".pill.runtime-pure")).toBeVisible();
  await expect(facts).toContainText("repo-facts.json");
  await expect(facts).toContainText("no external tool");

  // syft resolved a real tool: version, runtime and artifact digest are the
  // record's own claims, and the artifact it produced is named beside them
  const sbom = page
    .locator("table.subtable tr")
    .filter({ has: page.getByRole("cell", { name: "syft", exact: true }) });
  await expect(sbom.locator(".pill.runtime-binary, .pill.runtime-docker")).toBeVisible();
  await expect(sbom).toContainText("sbom.cdx.json");
  await expect(sbom).toContainText("invocation");

  // deep link (the address J3's board hop will use): arrives expanded, with
  // the named collector highlighted and its argv already open — the command
  // line that produced the evidence, redaction markers included
  const runId = (await page.locator("table.subtable").first().getAttribute("data-run"))!;
  expect(runId).toBeTruthy();
  await page.goto(`/runs?scan=${encodeURIComponent(runId)}&collector=syft`);
  await expect(page.locator("tr.hl")).toContainText("syft");
  await expect(page.locator(".run-argv").first()).toContainText("syft");

  // and the record itself is a signed statement like any other: the hop lands
  // on its evidence page, which says what it is and carries no verdict
  await page.locator("tr.rowlink td a").first().click();
  await expect(page).toHaveURL(/\/evidence\/[0-9a-f]{64}/, { timeout: 45_000 });
  await expect(page.locator("h1 .pill").first()).toContainText("scan run");
  await expect(page.locator("body")).toContainText("dispatched");
});

test("board hop: every row answers “how was this produced?”, and an empty row answers why not (J3)", async ({
  page,
}) => {
  await signIn(page);
  await pickRepo(page);

  // ── an evidenced/violated row hops to THE run that produced it ──────────
  // The flagship is violated by a real verdict from the real scan, so its hop
  // is the exact case: this scan, this collector.
  const flagshipRow = page.getByRole("row").filter({ hasText: FLAGSHIP }).first();
  const hop = flagshipRow.getByRole("link", { name: "how was this produced?" });
  await expect(hop).toBeVisible();

  // the href is resolved from the row's own projected fields — read it before
  // clicking so the landing can be checked against what the board claimed
  const href = (await hop.getAttribute("href"))!;
  const hopParams = new URLSearchParams(href.split("?")[1]);
  const hopScan = hopParams.get("scan")!;
  const hopCollector = hopParams.get("collector")!;
  expect(hopScan).toBeTruthy();
  // the flagship's verdict rests on reachability — the catalog's collector for
  // it, not a tool name, and not a guess
  expect(hopCollector).toBe("reachability");

  await hop.click();
  await expect(page).toHaveURL(/\/runs\?/, { timeout: 45_000 });
  // it landed on the run the board named, expanded, with that collector
  // highlighted — the page is not merely showing "a" run
  const table = page.locator("table.subtable").first();
  await expect(table).toBeVisible();
  expect(await table.getAttribute("data-run")).toBe(hopScan);
  await expect(page.locator("tr.hl")).toContainText(hopCollector);
  // …and the run this hop reached is one this page actually holds: the
  // "not in the projection" notice must NOT be showing
  await expect(page.locator(".notice")).toHaveCount(0);

  // ── the hop does not swallow the row's own click (I3a's stopPropagation) ──
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Coverage board" })).toBeVisible();
  await pickRepo(page);
  await page.getByRole("cell", { name: FLAGSHIP, exact: true }).click();
  await expect(page).toHaveURL(/\/evidence\/[0-9a-f]{64}/, { timeout: 45_000 });

  // ── no row is left without an answer ────────────────────────────────────
  // Every evidenced/violated cell must carry the hop, not just the flagship:
  // a board where some rows explain themselves and others do not is the
  // failure mode this link exists to remove.
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Coverage board" })).toBeVisible();
  await pickRepo(page);
  const producedRows = page
    .locator("table.reg tbody tr")
    .filter({ has: page.locator("td .pill.evidenced, td .pill.violated") });
  const producedCount = await producedRows.count();
  expect(producedCount).toBeGreaterThan(1);
  expect(await producedRows.locator("a.runhop").count()).toBe(producedCount);

  // ── the unevidenced arrival ─────────────────────────────────────────────
  // This fixture is fully tooled, so its board has no unevidenced row to click
  // — the shape is pinned in the runHop twin test instead. What is pinned HERE
  // is the landing that shape produces against the real run record: no scan
  // named, so /runs substitutes the newest recorded scan of the repo and says
  // out loud that it did.
  const repo = (await producedRows.first().locator("td").nth(2).innerText()).trim();
  expect(repo).toBeTruthy();
  await page.goto(`/runs?repo=${encodeURIComponent(repo)}&collector=${hopCollector}`);
  const notice = page.locator(".notice");
  await expect(notice).toBeVisible();
  await expect(notice).toContainText("no run produced that board cell");
  await expect(notice).toContainText("newest recorded scan");
  // the substitution still highlights the collector the caller asked about
  await expect(page.locator("tr.hl")).toContainText(hopCollector);

  // …and when the named collector was never dispatched at all, the page says
  // THAT instead of promising a highlight it will not draw — a different fact
  // from "it ran and skipped", and the one an operator needs
  await page.goto(`/runs?repo=${encodeURIComponent(repo)}&collector=not-a-collector`);
  await expect(notice).toBeVisible();
  await expect(notice).toContainText("never dispatched");
  await expect(page.locator("tr.hl")).toHaveCount(0);

  // ── a scoped-out row gets no hop: its provenance is the scoping event ────
  // (the two-key flow earlier in this file left one behind)
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Coverage board" })).toBeVisible();
  await pickRepo(page);
  const naRow = page.getByRole("row").filter({ has: page.locator(".pill.notApplicable") }).first();
  if ((await naRow.count()) > 0) {
    await expect(naRow.locator("a.runhop")).toHaveCount(0);
    // the row still explains itself — with the signed scoping, not a run
    await expect(naRow.locator(".faint")).toContainText("approved by");
  }

  // ── the same hop rides the control register's recipe sub-rows ────────────
  await page.goto("/controls");
  await expect(page.getByRole("heading", { name: /register/i })).toBeVisible();
  await page
    .getByRole("row")
    .filter({ hasText: /recipe/ })
    .first()
    .click();
  await expect(page.locator("a.runhop").first()).toBeVisible();
});

test("artifact viewers: the tool's own output, verified in the browser, and a tampered file refused (J4)", async ({
  page,
}) => {
  await signIn(page);
  await pickRepo(page);
  await page.getByRole("cell", { name: FLAGSHIP, exact: true }).click();
  await expect(page).toHaveURL(/\/evidence\/[0-9a-f]{64}/, { timeout: 45_000 });

  // the advisory the verdict rests on, read off the assertion the page already
  // renders — this is what the artifact table has to agree with
  const assertionText = (await page.locator(".assertion-fail").first().locator("..").innerText()) ?? "";
  const advisory = /(?:GHSA-[0-9a-z-]+|CVE-\d{4}-\d+)/.exec(assertionText)?.[0];
  expect(advisory, "the flagship assertion names an advisory").toBeTruthy();

  // ── the artifact renders, and the BROWSER verified the bytes first ───────
  const vexRow = page.getByRole("row").filter({ hasText: "openvex.json" }).first();
  await expect(vexRow).toBeVisible();
  const attestedDigest = (await vexRow.locator("td").nth(2).innerText()).trim();
  expect(attestedDigest).toMatch(/^[0-9a-f]{64}$/);

  await vexRow.getByRole("button", { name: "view", exact: true }).click();
  const verified = vexRow.locator(".artifact-verified");
  await expect(verified).toBeVisible({ timeout: 30_000 });
  await expect(verified).toContainText("sha256 verified in this browser");

  const vexTable = vexRow.locator(".artifact-scroll table");
  await expect(vexTable).toBeVisible();
  await expect(vexTable.locator("th")).toContainText(["vulnerability", "product", "status"]);
  // the tool's own record names the very advisory the verdict cites: the
  // page's conclusion and the artifact behind it agree, which is the whole
  // reason this table exists beside the pill
  await expect(vexTable).toContainText(advisory!);
  // the claim's own limit travels with the claim
  await expect(vexRow.locator(".artifact-view")).toContainText("unknowns count against us");

  // ── the raw download is byte-exact: it hashes to the attested digest ─────
  const [raw] = await Promise.all([
    page.waitForEvent("download"),
    vexRow.getByRole("button", { name: "raw", exact: true }).click(),
  ]);
  const rawBytes = readFileSync((await raw.path())!);
  expect(createHash("sha256").update(rawBytes).digest("hex")).toBe(attestedDigest);
  // and it is the artifact itself, not a re-serialization of the projection
  expect(JSON.parse(rawBytes.toString("utf8"))["@context"]).toContain("openvex.dev");

  // ── an anchor is never served: `git show` is the answer, not a button ────
  const anchorRow = page
    .getByRole("row")
    .filter({ hasText: "anchor — drift here kills this evidence" })
    .first();
  await expect(anchorRow).toBeVisible();
  await expect(anchorRow).toContainText("git show");
  await expect(anchorRow.getByRole("button", { name: "view", exact: true })).toHaveCount(0);

  // ── the load-bearing refusal: a file on disk that no longer matches ──────
  // Serving an artifact by path without re-hashing would let a modified file
  // render under a signed bundle's digest. Prove it cannot, against the real
  // scan output the serve is pointed at.
  // the same scan output dir the serve is pointed at (smoke-server.mjs)
  const artifactsRoot = resolve("e2e/.smoke/out/artifacts");
  const vexPath = readdirSync(artifactsRoot)
    .map((collector) => resolve(artifactsRoot, collector, "openvex.json"))
    .find((candidate) => existsSync(candidate));
  expect(vexPath, "the smoke scan wrote an openvex.json").toBeTruthy();
  const original = readFileSync(vexPath!);
  try {
    writeFileSync(vexPath!, JSON.stringify({ "@context": "tampered", statements: [] }));
    await page.reload();
    const tamperedRow = page.getByRole("row").filter({ hasText: "openvex.json" }).first();
    await tamperedRow.getByRole("button", { name: "view", exact: true }).click();
    const view = tamperedRow.locator(".artifact-view");
    await expect(view).toContainText("no bytes:", { timeout: 30_000 });
    // the two facts stay separate: the digest is still attested, the BYTES are
    // the problem, and the reason names which
    await expect(view).toContainText("from a later run");
    await expect(view).toContainText("does not match the attested digest");
    // and nothing was rendered from them
    await expect(tamperedRow.locator(".artifact-scroll")).toHaveCount(0);
    await expect(tamperedRow.locator(".artifact-verified")).toHaveCount(0);
  } finally {
    writeFileSync(vexPath!, original);
  }

  // the refusal was about the bytes: with them back, the table returns
  await page.reload();
  const restored = page.getByRole("row").filter({ hasText: "openvex.json" }).first();
  await restored.getByRole("button", { name: "view", exact: true }).click();
  await expect(restored.locator(".artifact-verified")).toBeVisible({ timeout: 30_000 });

  // ── a secret is never rendered ──────────────────────────────────────────
  // The fixture plants a well-formed AWS key in commit history (fault 1). The
  // gitleaks table names the rule, the file:line and the commit — and never
  // the value, which is the one column this viewer must not have.
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Coverage board" })).toBeVisible();
  await pickRepo(page);
  await page.getByRole("cell", { name: "no-secrets-in-history", exact: true }).click();
  await expect(page).toHaveURL(/\/evidence\/[0-9a-f]{64}/, { timeout: 45_000 });
  const leakRow = page.getByRole("row").filter({ hasText: "gitleaks-report.json" }).first();
  await leakRow.getByRole("button", { name: "view", exact: true }).click();
  const leakTable = leakRow.locator(".artifact-scroll table");
  await expect(leakTable).toBeVisible({ timeout: 30_000 });
  await expect(leakTable.locator("th")).toContainText(["rule", "file:line", "commit"]);
  await expect(leakTable).toContainText("aws-access");
  await expect(leakRow.locator(".artifact-view")).toContainText("deliberately not rendered");
  // the planted value, absent from the entire page — not masked, not truncated
  await expect(page.locator("body")).not.toContainText("<aws-key-shape-assembled-at-build-time>");
});

test("provenance chain: the whole causal line, both directions, and the walk a not-affected claim rests on (J5 + I3f)", async ({
  page,
}) => {
  await signIn(page);

  // ── the chain, forwards ─────────────────────────────────────────────────
  // The SAST recipe is the case the chain exists for: `sast-reachability`
  // spawns no tool at all, so a chain built from the collector's own tools
  // would print "no external tool" over a verdict semgrep's output produced.
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Coverage board" })).toBeVisible();
  await pickRepo(page);
  await page.getByRole("cell", { name: "no-reachable-dangerous-code", exact: true }).click();
  await expect(page).toHaveURL(/\/evidence\/[0-9a-f]{64}/, { timeout: 45_000 });
  const evidenceUrl = page.url();

  const chain = page.locator("ol.chain .chain-hop");
  await expect(chain.first()).toBeVisible({ timeout: 30_000 });
  // every hop drawn, none silently dropped
  await expect(chain.filter({ hasText: "no-reachable-dangerous-code" })).toBeVisible();
  await expect(chain.filter({ hasText: "sast-reachability" })).toBeVisible();
  // the tool hop reached THROUGH the artifact the gate ate — this is the link
  // that makes the line causal rather than decorative
  const toolHop = chain.filter({ hasText: "semgrep@" });
  await expect(toolHop).toBeVisible();
  await expect(toolHop).toContainText("semgrep-results.json");
  await expect(toolHop).toContainText("produced by semgrep in this run");
  // no gap: this bundle came out of the smoke's own scan, so every hop resolves
  expect(await page.locator("ol.chain .chain-missing").count()).toBe(0);

  // ── the hop lands where it says it lands ────────────────────────────────
  await toolHop.getByRole("link").first().click();
  await expect(page).toHaveURL(/\/runs\?scan=/, { timeout: 45_000 });
  await expect(page.locator("tr.hl")).toContainText("semgrep");

  // ── the chain, backwards ────────────────────────────────────────────────
  // From the run, the collector row names the statements it produced — recipe
  // and digest only. A verdict here would make /runs a second source of truth
  // about the board, which is the one thing this page may never be.
  const gateRow = page
    .locator("table.subtable tr")
    .filter({ has: page.getByRole("cell", { name: "sast-reachability", exact: true }) });
  await expect(gateRow).toContainText("no-reachable-dangerous-code");
  await expect(gateRow).toContainText("consumes");
  await expect(gateRow).toContainText("semgrep-results.json");
  await expect(gateRow.locator(".pill")).not.toContainText(["violated", "evidenced"]);
  await gateRow.getByRole("link", { name: "no-reachable-dangerous-code" }).click();
  await expect(page).toHaveURL(evidenceUrl, { timeout: 45_000 });

  // ── tooling health: history, and it says it is history ──────────────────
  await page.goto("/runs");
  const tooling = page.locator(".tooling");
  await expect(tooling).toBeVisible({ timeout: 30_000 });
  // the fixture scan really ran semgrep, so its card carries a real runtime
  const semgrepCard = tooling.locator(".tool-card").filter({ hasText: "semgrep" });
  await expect(semgrepCard).toContainText(/docker|binary/);
  await expect(semgrepCard).toContainText("asked for by semgrep");
  // and the page refuses to pass historical resolution off as a live probe
  await expect(page.locator("body")).toContainText("pnpm doctor");

  // ── I3f: the not-affected claim shows its work ──────────────────────────
  await page.goto(evidenceUrl);
  const basis = page.locator(".panel.basis").first();
  await expect(basis).toBeVisible({ timeout: 30_000 });
  // the fixture's entry point is inferred from package.json — the set AND
  // where it came from, because "not affected" means "unreachable from THESE"
  await expect(basis).toContainText("src/index.js");
  await expect(basis).toContainText("inferred from package.json");
  // the direction of the error, stated where the claim is read
  await expect(basis).toContainText("over-approximate");
  await expect(basis).toContainText("Unknowns count against us");
  // the graph it walked, counted — including how many edges are only names
  await expect(basis).toContainText(/\d+ nodes · \d+ edges \(\d+ inferred by name\)/);

  // ── every displayed edge marked ─────────────────────────────────────────
  // The fixture's reachable eval sits one exact hop from the entry point.
  const callPath = page.locator(".callpath").first();
  await expect(callPath).toBeVisible();
  await expect(callPath).toContainText("src/index.js");
  await expect(callPath).toContainText("src/render.js");
  await expect(callPath).toContainText("exactly resolved");
  expect(await callPath.locator(".hop-unmarked").count()).toBe(0);

  // ── and the flagship advisory's claim rests on the same stated ground ───
  await page.goto("/");
  await pickRepo(page);
  await page.getByRole("cell", { name: FLAGSHIP, exact: true }).click();
  await expect(page).toHaveURL(/\/evidence\/[0-9a-f]{64}/, { timeout: 45_000 });
  const advisoryBasis = page.locator(".panel.basis").first();
  await expect(advisoryBasis).toContainText("src/index.js");
  await expect(advisoryBasis).toContainText("declared route");
});

test("plain language: the check explained, the jargon defined, and the empty row says why it is empty (K1)", async ({
  page,
}) => {
  await signIn(page);
  await pickRepo(page);

  // ── the board: collapsed by default, authored prose one click away ──────
  const flagshipRow = page.getByRole("row").filter({ hasText: FLAGSHIP }).first();
  await expect(flagshipRow).toBeVisible();
  // collapsed means COLLAPSED: fifteen paragraphs at once would bury the row
  // an operator came for, so nothing of the prose is on screen until asked
  await expect(page.locator(".plain-row")).toHaveCount(0);
  await flagshipRow.getByRole("button", { name: /plain English/ }).click();

  const plain = page.locator(".plain-row .plain").first();
  await expect(plain).toBeVisible();
  // the three questions, each answered — the authored text from the recipe
  // JSON itself, not a paraphrase assembled in the console
  await expect(plain).toContainText("Cross-references the repository's component inventory");
  await expect(plain).toContainText("known critical or high-severity advisory");
  await expect(plain).toContainText("Upgrade the named package to the fixed version");
  // and it says whose voice it is: prose about the CHECK, not about this repo
  await expect(plain).toContainText("it explains the check, and states nothing about this repository");
  await flagshipRow.getByRole("button", { name: /plain English/ }).click();
  await expect(page.locator(".plain-row")).toHaveCount(0);

  // ── the glossary: hover a term, get a definition; unknown words stay bare ──
  const stateTerm = flagshipRow.locator(".pill.violated .term");
  await expect(stateTerm).toBeVisible();
  await stateTerm.click();
  const tip = page.locator(".termtip").first();
  await expect(tip).toBeVisible();
  await expect(tip).toContainText("at least one assertion failed");
  // asking what a word means is not asking to navigate: the row underneath is
  // a link to the evidence page, and the board is still on screen
  await expect(page.getByRole("heading", { name: "Coverage board" })).toBeVisible();
  // the repo cell is not jargon and has no entry — no dotted underline, no
  // popover that opens onto nothing
  await expect(
    page.getByRole("cell", { name: FIXTURE_REPO }).first().locator(".term"),
  ).toHaveCount(0);
  // Escape closes it — the definition is dismissed without touching the row
  await stateTerm.press("Escape");
  await expect(page.locator(".termtip")).toHaveCount(0);

  // ── the guided empty state, on a REAL empty row ─────────────────────────
  // bare-app is the fixture with honest gaps: no Dockerfile, no CI, no IaC,
  // no API description. Its skipped collectors wrote the reasons this section
  // reads — every sentence below came out of a signed run record.
  // the scan records the repo by absolute path, so the option is resolved
  // here the same way test 4 resolves it rather than typed as a literal
  await pickRepo(page, BARE_REPO);
  await page.locator(".tabs button", { hasText: "Unevidenced" }).click();

  const emptyRows = page.locator("tr.why-row");
  const emptyCount = await emptyRows.count();
  expect(emptyCount).toBeGreaterThan(0);
  // EVERY empty row explains itself: a board where some empty cells have a
  // reason and others are silent is the state K1 exists to end
  const unevidencedPills = await page.locator("tbody .pill.unevidenced").count();
  expect(emptyCount).toBe(unevidencedPills);

  // the honest skip, quoted from the collector that wrote it
  const iacRow = page
    .getByRole("row")
    .filter({ hasText: "iac-baseline-clean" })
    .first();
  await expect(iacRow).toBeVisible();
  const iacWhy = page.locator("tr.why-row").filter({ hasText: "checkov" }).first();
  await expect(iacWhy).toContainText("no IaC in the committed tree");
  await expect(iacWhy).toContainText("read from the run record of run-");
  // an honest skip is explained, and explicitly NOT dressed up as a task
  await expect(iacWhy).toContainText("not a task");

  // the other real shape this fixture produces, which the plan never named: a
  // collector that RAN and still left the cell empty. It is not a skip, so the
  // record has no reason to quote — and the page says that rather than
  // inventing one.
  const ranEmpty = page.locator("tr.why-row").filter({ hasText: "repo-facts" }).first();
  await expect(ranEmpty).toContainText("ran in the newest recorded scan");
  await expect(ranEmpty).toContainText("came out with nothing to state");

  // no empty row claims a verdict — the sentence explains the cell, it never
  // moves it (J1's standing rule, restated for K1)
  for (const word of ["evidenced", "violated", "notApplicable"]) {
    expect(
      await page.locator("tr.why-row").filter({ hasText: new RegExp(`\\b${word}\\b`) }).count(),
      word,
    ).toBe(0);
  }

  // ── the queue reaches the same conclusion through the same hand ─────────
  // no daemon has ever run in this smoke, so before K1 this tier was empty
  // while a real toolchain answer sat in the run record.
  await page.goto("/queue");
  await expect(page.getByRole("heading", { name: "Action queue" })).toBeVisible({ timeout: 45_000 });
  const queueRows = page.getByRole("row").filter({ hasText: "unevidenced" });
  // honest skips are still not tasks here either — the tier is empty of them
  await expect(queueRows.filter({ hasText: "no IaC in the committed tree" })).toHaveCount(0);

  // ── the evidence page: expanded, and a run record gets none ─────────────
  await page.goto("/");
  await pickRepo(page);
  await page.getByRole("cell", { name: FLAGSHIP, exact: true }).click();
  await expect(page).toHaveURL(/\/evidence\/[0-9a-f]{64}/, { timeout: 45_000 });
  await expect(page.getByText("In plain English")).toBeVisible();
  const evidencePlain = page.locator(".plain").first();
  await expect(evidencePlain).toContainText("Cross-references the repository's component inventory");
  await expect(evidencePlain).toContainText("Upgrade the named package");
  // the glossary rides the auditor's page too, on the words only it uses
  const dsse = page.locator(".term").filter({ hasText: "DSSE" }).first();
  await expect(dsse).toBeVisible();
  await dsse.click();
  await expect(page.locator(".termtip").first()).toContainText("Dead Simple Signing Envelope");

  // a run record answers no recipe, so there is no check to explain and the
  // section is absent rather than empty
  await page.goto("/runs");
  const runDigest = page.locator('table.reg td.mono a[href^="/evidence/"]').first();
  await expect(runDigest).toBeVisible({ timeout: 45_000 });
  await runDigest.click();
  await expect(page.locator(".pill").filter({ hasText: "scan run" }).first()).toBeVisible({
    timeout: 45_000,
  });
  await expect(page.getByText("In plain English")).toHaveCount(0);
});

test("architecture contract: the repo's own declaration, checked against its code and signed (L1)", async ({
  page,
}) => {
  const BOUNDARY = "arch-boundaries-hold";
  await signIn(page);
  await pickRepo(page);

  // ── the board: the repo broke a rule it wrote about itself ───────────────
  // The fixture's rampscan.config.json says only src/server.js may import
  // src/billing; src/render.js does. Nothing external was consulted to decide
  // this — the declaration and the code are both in the repository.
  const boundaryRow = page.getByRole("row").filter({ hasText: BOUNDARY }).first();
  await expect(boundaryRow).toBeVisible();
  await expect(boundaryRow.locator(".pill.violated")).toBeVisible();

  // the fix pointer rides the board row (I2c's slot, unchanged): the rule that
  // broke and the file that broke it. The full import chain is the evidence
  // page's job — the board names the offender, it does not draw the graph.
  const boardPointer = page.locator("td.pointer-row").filter({ hasText: "billing-isolated" }).first();
  await expect(boardPointer).toBeVisible();
  await expect(boardPointer).toContainText("src/render.js");
  // and the allowed importer is NOT an offender: src/server.js imports the same
  // module and the declared allow-list permits exactly that
  await expect(boardPointer).not.toContainText("src/server.js");

  // ── the evidence page: the offending import chain and the rule text ──────
  await page.getByRole("cell", { name: BOUNDARY, exact: true }).click();
  await expect(page).toHaveURL(/\/evidence\/[0-9a-f]{64}/, { timeout: 45_000 });

  const failing = page.locator(".assertion-fail").first();
  await expect(failing).toBeVisible();
  // the import is drawn as a path, with its single hop marked like every other
  // displayed edge (I3f's rule, inherited rather than re-invented)
  const callPath = page.locator(".callpath").first();
  await expect(callPath).toBeVisible();
  await expect(callPath).toContainText("src/render.js");
  await expect(callPath).toContainText("src/billing.js");
  expect(await callPath.locator(".hop-unmarked").count()).toBe(0);

  // the basis names the RULE ITSELF — not a paraphrase of it. This is what
  // lets a reader decide whether the verdict matches the declaration.
  const basis = page.locator(".panel.basis").first();
  await expect(basis).toBeVisible({ timeout: 30_000 });
  await expect(basis).toContainText("billing-isolated");
  await expect(basis).toContainText("src/server.js"); // the declared allow-list
  await expect(basis).toContainText("over-approximate"); // holding a boundary is a claim of absence
  await expect(basis).toContainText("editing a rule re-keys this evidence");

  // the contract file is an anchor: this evidence is about a commit AND a
  // declaration, and drift in either kills it
  await expect(page.locator("body")).toContainText("rampscan.config.json");

  // ── the route half, whose walk errs the other way ────────────────────────
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Coverage board" })).toBeVisible();
  await pickRepo(page);
  await page.getByRole("cell", { name: "arch-route-auth-declared", exact: true }).click();
  await expect(page).toHaveURL(/\/evidence\/[0-9a-f]{64}/, { timeout: 45_000 });
  const routeBasis = page.locator(".panel.basis").first();
  await expect(routeBasis).toBeVisible({ timeout: 30_000 });
  // two contract claims from one scan, and they must NOT read alike: reaching
  // auth is a positive claim (under), holding a boundary is one of absence (over)
  await expect(routeBasis).toContainText("under-approximate");
  await expect(routeBasis).toContainText("all-routes-authed");
  // the failing assertion's own row: the unauthenticated route is named, and
  // the authed one is not among the offenders (`.assertion-fail` is the FAIL
  // cell — the detail sits beside it, the way J4 reads it)
  const routeFail = page.locator(".assertion-fail").first().locator("..");
  await expect(routeFail).toContainText("/health");
  await expect(routeFail).not.toContainText("/settings");

  // ── the contract-less repo: an honest skip, in the collector's own words ──
  // bare-app declares nothing, so the gate has nothing of its kind to check —
  // which must read as an explained empty cell, never as a pass.
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Coverage board" })).toBeVisible();
  await pickRepo(page, BARE_REPO);
  await page.locator(".tabs button", { hasText: "Unevidenced" }).click();

  const why = page.locator("tr.why-row").filter({ hasText: "contract" }).first();
  await expect(why).toBeVisible();
  await expect(why).toContainText("no architecture contract declared");
  // an honest skip is explained and explicitly not dressed up as work
  await expect(why).toContainText("not a task");
  // and the empty cell is an empty cell: no verdict was invented for it
  await expect(
    page.getByRole("row").filter({ hasText: BOUNDARY }).first().locator(".pill.unevidenced"),
  ).toBeVisible();
});

test("repo model: the scan's own derivation, attested by its run record and readable in the browser (L2)", async ({
  page,
}) => {
  const BOUNDARY = "arch-boundaries-hold";
  await signIn(page);

  // the model is a subject of the RUN RECORD, not of any evidence bundle —
  // the first artifact in this system attested by a run alone — so the hop to
  // it is the one J2 built: the run timeline's own statement.
  await page.goto("/runs");
  await pickRepo(page);
  await expect(page.locator("tr.rowlink")).toHaveCount(1);
  await page.locator("tr.rowlink td a").first().click();
  await expect(page).toHaveURL(/\/evidence\/[0-9a-f]{64}/, { timeout: 45_000 });
  await expect(page.locator("h1 .pill").first()).toContainText("scan run");

  const modelRow = page
    .getByRole("row")
    .filter({ has: page.getByRole("cell", { name: "repo-model.json", exact: true }) });
  await expect(modelRow).toHaveCount(1);
  // it is an ARTIFACT, not an anchor and not a justification: the row offers
  // bytes rather than a `git show` line
  await expect(modelRow).toContainText("artifact");
  await modelRow.getByRole("button", { name: "view", exact: true }).click();

  // the browser re-hashed the bytes against the digest the run record signed
  // before a single row was drawn — J4's rule, on J4's hand
  await expect(modelRow.locator(".artifact-verified")).toBeVisible({ timeout: 30_000 });
  const table = modelRow.locator(".artifact-scroll table");
  await expect(table).toBeVisible();

  // Rows are located by their ID CELL, exactly — never by substring. A node's
  // links column names other nodes, so the repo row contains the text
  // "…:billing-isolated" and a hasText filter would hand back the repo row
  // when asked for the rule (which is exactly what it did the first time).
  const nodeRow = (id: string) =>
    table.locator("tr").filter({ has: page.getByRole("cell", { name: id, exact: true }) });

  // the fixture's own world, read off the model: the repo, its contract, its
  // graph. Each of these is a known fixture truth, not "something rendered".
  const repoRow = nodeRow(`repo:${FIXTURE_REPO}`);
  await expect(repoRow).toHaveCount(1);
  // the board's verdicts ride the links, so a reader can see WHICH cell is bad
  await expect(repoRow).toContainText(`state:violated→recipe:${FLAGSHIP}`);
  await expect(repoRow).toContainText(`declares→rule:${FIXTURE_REPO}:billing-isolated`);
  await expect(repoRow).toContainText(`walked→graph:${FIXTURE_REPO}`);

  // the contract rule is the DECLARATION the gate signed, not a paraphrase —
  // the same posture L1 gave the basis panel, for the same reader
  const ruleRow = nodeRow(`rule:${FIXTURE_REPO}:billing-isolated`);
  await expect(ruleRow).toHaveCount(1);
  await expect(ruleRow).toContainText("boundary");
  await expect(ruleRow).toContainText('"module":"src/billing"');
  await expect(ruleRow).toContainText(`checked-by→recipe:${BOUNDARY}`);

  // the walk the gated verdicts rest on, with I3f's marking carried through
  const graphRow = nodeRow(`graph:${FIXTURE_REPO}`);
  await expect(graphRow).toContainText("name-inferred");
  await expect(graphRow).toContainText("roots:");

  // and the provenance half: a pure gate still reaches its tool through the
  // artifact it eats (J5's transitive truth, as a link)
  await expect(nodeRow("collector:reachability")).toContainText(
    "consumes:graph.db→collector:graph",
  );

  // what the table refuses to do: compute a second coverage number. The board
  // owns the counts, and a percentage here would be a second answer that
  // merely looks like the same one.
  const rendered = (await table.innerText()) + ((await modelRow.locator(".muted").allInnerTexts()).join(" "));
  expect(rendered).not.toMatch(/\d+\s*%/);
  expect(rendered).not.toMatch(/\d+ of \d+/);

  // ── the command, standalone from the ledger ──────────────────────────────
  // `rampscan model` needs no scan: it derives from the ledger as it stands
  // NOW, which is two scans deep by this point. That the artifact above shows
  // one repo and the command below shows two is the honest reading of both:
  // the artifact is a point-in-time derivation, attested and dated by the run
  // that emitted it; the command is the live one.
  const text = execFileSync(
    "node_modules/.bin/tsx",
    ["packages/cli/src/main.ts", "model", "--ledger", "e2e/.smoke/ledger", "--no-color"],
    { encoding: "utf8" },
  );
  expect(text).toContain(FIXTURE_REPO);
  expect(text).toContain(BARE_REPO);
  expect(text).toContain("billing-isolated (boundary)");
  // the bare repo declares no contract, and the model says that rather than
  // rendering an empty line (K1's rule, in a terminal)
  expect(text).toMatch(/contract {2}none declared in any live claim's basis/);
  // the whole registry is registered, so nothing in this world is unlinkable
  expect(text).not.toContain("PROBLEMS");

  // the JSON is the artifact's own serialization: canonical, newline-ended,
  // and carrying no instant anywhere — which is what makes it reproducible
  const json = execFileSync(
    "node_modules/.bin/tsx",
    ["packages/cli/src/main.ts", "model", "--ledger", "e2e/.smoke/ledger", "--json"],
    { encoding: "utf8" },
  );
  expect(json.endsWith("\n")).toBe(true);
  expect(json).not.toMatch(/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/);
  const model = JSON.parse(json) as { nodes: unknown[]; links: unknown[]; problems: string[] };
  expect(model.problems).toEqual([]);
  expect(model.nodes.length).toBeGreaterThan(0);
  // and it really is stable: a second run of the same command, same bytes
  expect(
    execFileSync(
      "node_modules/.bin/tsx",
      ["packages/cli/src/main.ts", "model", "--ledger", "e2e/.smoke/ledger", "--json"],
      { encoding: "utf8" },
    ),
  ).toBe(json);
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
