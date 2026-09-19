# U — the console, read from the top down

**Status:** proposed 2026-09-19. Milestone *U — the console, read from the top down*, issues #235 (U0) – #241 (U6). The owner asked for it: "there is too much data, which is good, but we need a methodological way to show it and lead the user down the rabbit hole if they want to go." Nothing here is adopted until the owner takes the decisions in §5.
**Reads against:** `console/web/PRODUCT.md` (users, principles), `console/web/DESIGN.md` ("The Ledger Room", its named rules), and the console as it runs on the smoke fixtures at `main` = `0e9c8a8` (screenshots taken 2026-09-19, both fixture repos scanned).

---

## 1. What is wrong, measured

The data is right and the receipts are all there. What is wrong is that every page shows everything at the same weight, and the pages do not lead into each other.

**No top.** The nav has nine tabs of equal rank: Board, Recipes, Queue, Controls, Scoping, Clock, Drift, Runs and Approvals. Four of them are registers of the same facts, cut differently. Nothing says which one to open first, or which one answers "how are we doing".

**No order within a page.**
- The board opens on 41 obliged rows at one weight. On `bare-app`, 28 of them are the same amber `G1 coverage` row. The 13 rows with something to say are scattered alphabetically among them.
- The only summary is three pills in a filter row.
- The board's repo select defaults to the first repo alphabetically, not the one the reader last scanned. On the fixtures it opens on `bare-app`.
- The repo is an absolute path, printed in full on every row of Recipes, Queue and Clock, and it takes the widest column.
- The Queue repeats the same two sentences ("first seen at commit … open the evidence — the assertions and artifacts name exactly what failed") on every row.
- On the Clock, all 41 rows read `6d 23h · 7d · machine`. The page has one fact to tell and prints it 41 times.
- The evidence page has twelve sections, one after another at the same weight, and the verify command is the tenth.

**No way down, and no way back up.** From a read of every page file and its links:
- **A KSI has no URL.** Nothing can link to a KSI's row on the board. Every KSI id elsewhere (`/evidence`, `/recipes`, `/scoping`) goes instead to `/controls?reg=ksis`, a second KSI model with different columns and different state semantics. The board and that register never link to each other.
- **A recipe cell has no URL.** `/recipes` accepts no parameters, so the row with the actions (propose N/A, why is this empty, plain English) is reachable only from the nav.
- **`/approvals` has no outgoing link at all.** Ledger digests, recipes, KSIs and repos are all plain text.
- **Plain-text entity ids with no link:** KSI and recipe on `/clock`, CloudRuns, and the drift vulnerability feed; the commit and the "run" field on `/evidence`. `CollectEvidence` says "Watch it on the Runs page" without a link.
- **`/evidence`'s "← board"** returns to the top of `/` with the row collapsed and the repo reset.
- **The same fact is rendered in many places:** the dataset/projected subtitle on four pages, state pills on five, freshness on six, skip reasons on four. Each page renders it separately, so nothing holds the copies together.

So the reader has to already know where a fact lives. An operator who does not know the vocabulary cannot find their way, and an assessor who does has to cross-check four registers by hand.

## 2. The model: six levels of zoom

Every fact in the console belongs to one level. Each level:
- answers one question;
- shows the level below as **counts and the worst few**, never the whole list unless asked;
- links each of those down one level;
- carries a breadcrumb back up.

| Level | Question it answers | Where it lives | What it shows of the level below |
|---|---|---|---|
| **L0 Posture** | How are we doing, and where is the worst of it? | `/` (top) | Per theme: counts by worst gap, and the next three actions |
| **L1 Theme** | Which indicators in this area need me? | `/` grouped by theme, `/?theme=` | Per KSI: one row, its worst gap and its next step |
| **L2 KSI** | Why is this indicator in this state, what is owed, and what do I do? | **new** `/ksi/[id]` | Methods, owed artifacts, clocks, controls, collect evidence |
| **L3 Check** | What does this one check say over time, and why? | **new** `/check/[recipe]?repo=` | Current bundle, previous bundles, run, lapses, drift events |
| **L4 Evidence** | What exactly was claimed, and on what basis? | `/evidence/[digest]`, re-layered | Claim, basis, assertions, subjects |
| **L5 Bytes** | Show me the signed thing itself. | `/artifacts/[digest]`, raw statement, verify | — |

Four views are **lenses across the levels**, not levels themselves. They stay, but are grouped under the ladder instead of beside it:
- **Work:** Queue, Approvals.
- **Time:** Clock, Drift, and as-of.
- **Provenance:** Runs.
- **Auditor:** Controls, Scoping, and the export package.

A lens row always links into the ladder at the level it names.

The rabbit hole is then one path, the same from anywhere:

posture → theme → KSI → check → bundle → bytes → `verify` on your own machine.

The assessor's guarantee (PRODUCT.md principle 2, every claim carries its receipt) is kept by moving things down a level, never by removing them. Anything visible today is still reachable, in at most the clicks named in the exit gate (§6).

## 3. Rules the build follows

- **U-R1 — one canonical URL per entity.** KSI → `/ksi/[id]`, check → `/check/[recipe]?repo=`, bundle → `/evidence/[digest]`, artifact → `/artifacts/[digest]`, run → `/runs?scan=`, control → `/controls?reg=controls&id=`. They are built by a single `lib/links.ts`, and a test fails the build if a page hand-writes one of these paths.
- **U-R2 — every entity mention is a link.** A KSI id, recipe id, digest, run id, commit or control id is rendered through one `EntityLink` component. A test walks the rendered smoke pages and fails on a bare id (the `/approvals` class of defect).
- **U-R3 — the answer comes first, in a sentence, computed.**
  - Each level opens with one line generated from the fold, for example "13 of 41 obliged indicators meet the floor; 3 have a violated check; 28 have no method at all".
  - It uses the same counts as the pills. Nothing in it is typed except the sentence template, which is authored and tested like `lib/glossary.ts` (PRODUCT.md principle 4).
- **U-R4 — severity order, not alphabet.** The default sort at every level is worst first: violated > stale > artifact missing > no method > met. The order is a pure function shared by board, theme and KSI, so the four registers can never disagree on it.
- **U-R5 — the repo is a scope, not a column.**
  - One repo selector in the nav, carried in the URL as `?repo=` and kept across navigation. Its default is the repo with the newest scan.
  - Rows show the repo only when the scope is "all repos", and then as its basename, with the full path in `title` and in print.
- **U-R6 — say a repeated fact once.** When every row in a table would carry the same sentence or value, it moves to the table's header line, and the rows carry only what differs. This applies to the Queue's boilerplate and the Clock's identical windows.
- **U-R7 — breadcrumbs on L1–L5.** They are built from the entity, not from browser history, so a deep link arrives with its context. "← board" goes away.
- **U-R8 — depth is `<details>` or its own page, never a modal.** DESIGN.md's rule stands: no modal, no drawer, no split view. Long L4/L5 sections (the raw statement, subjects, signature) open closed as `<details>`, and the print stylesheet opens them all (the Paper-Is-Not-A-Screen rule).
- **U-R9 — no fact is lost.** Before a page is re-layered, its current facts are listed in the PR description, and each one is checked off against where it now lives.

## 4. The phases

Each phase is a stacked PR, tested red first where it adds behaviour, with the Playwright smoke extended in the same PR.

### U0 — groundwork: URLs, links, scope

- `lib/links.ts` and `EntityLink`, with the U-R1 test.
- Deep-link parameters:
  - `/?ksi=` scrolls to and opens a row, until U1 replaces it.
  - `/recipes?repo=&recipe=` highlights and opens a row.
  - `/login?next=` returns the reader where they were.
- The global repo scope (U-R5), with the default being the repo with the newest scan. *Corrected while building U0:* on the smoke fixtures this still opens on `bare-app`, because the smoke scans it second, so it is the newest. The rule is right; the claim that it changes the fixture board was not.
- Every existing bare id is turned into an `EntityLink`: `/approvals` entirely, the `/clock` KSI and method columns, CloudRuns, the drift feed, the `/evidence` run field and commit, and the "Runs page" text in `CollectEvidence`.
- Shorter repo display: the basename, with the full path in `title` and in print.

**Exit:** the U-R2 walk passes on every smoke page; a test proves the scope survives navigation.

### U1 — the KSI page (L2)

- `/ksi/[id]` holds today's board expansion, re-laid as sections under the U-R3 sentence:
  - methods (worst first, each linking to its check);
  - owed artifacts 1–5;
  - clocks for this KSI's methods;
  - `FRC-CSX-MOT` history;
  - collect evidence;
  - the controls crosswalk.
- A board row click goes to the page. The in-row expansion is kept as a two-line preview, so a scan-reader need not leave the board.
- `/controls?reg=ksis&id=` redirects to `/ksi/[id]`. This retires the second KSI model as a destination. The KSI rollup stays available as the Controls page's KSI tab for the auditor's CSV, and each of its rows links to `/ksi/[id]`.

**Exit:** the board expansion's facts are ticked off under U-R9; the smoke's assessor-interrogation tests pass against the new page.

### U2 — posture and themes (L0, L1)

- The top of `/` becomes the posture block:
  - the U-R3 sentence;
  - a **theme matrix**: one row per KSI theme (10), with a segmented bar of its KSIs by worst gap, drawn only in the four verdict hues, each segment labelled with its count so the colour is never alone;
  - **the next three actions**, from `deriveActionQueue`, each linking into the ladder.
- The register below is grouped by theme under collapsible theme headers, worst theme first (U-R4).
- Within a theme, rows whose only gap is G1 fold into one "N indicators with no method — show" line. This is the 28-row wall on `bare-app`.
- `?theme=` opens one theme as an L1 view.

**Exit:** on `bare-app` the first screen shows every violated and stale KSI without scrolling; the counts in the sentence, the matrix and the pills are one computation (test).

### U3 — the check page (L3)

- `/check/[recipe]?repo=` merges what is today split across four pages:
  - the recipes row's state, pointers, plain English, "why is this empty?" and propose N/A;
  - the clock and its cadence lapses for this cell;
  - the drift events for this cell;
  - the bundle history (current, superseded, dead, with the killing commit);
  - the run hop.
- `/recipes` rows, Queue items, Clock rows, Drift events and the KSI page's methods all link here.
- `/recipes` stays as the flat register and CSV.

**Exit:** a smoke test walks from a violated Queue item to its check page and on to the bundle.

### U4 — the evidence page, layered (L4, L5)

`/evidence/[digest]` becomes four bands. Nothing is removed (U-R9).
1. **The claim.** Verdict, recipe, repo, commit, alive or dead, signed when, plus the plain-English panel, in one block.
2. **Why.** The provenance chain, the basis panel and the assertions with call paths.
3. **The proof.** Subjects and artifacts, and the signature, as `<details>` closed by default.
4. **Check it yourself.** The verify command, the reproduce command, the downloads and the raw statement.

Also:
- An in-page contents line under the title links the four bands.
- The breadcrumb reads theme → KSI → check → bundle.
- Previous and next bundles for the same cell are linked. This closes the supersede dead end.

**Exit:** the smoke's zero-rampscan-code verify step passes, now reached from the band-4 anchor; print shows every `<details>` open.

### U5 — the lenses

- **Queue:** grouped by tier with counts. The shared sentence goes in the group header (U-R6). Each item links to its check page, and skip items link to their run.
- **Clock:** rows grouped by remaining-time bucket (expired · <24h · <window/2 · fresh), collapsed when every row in a bucket is identical in all but the method. The cadence-lapse table moves to the check page and is linked from here.
- **Drift:** repo, kind and date-range filters, and resolved vulnerabilities become listable.
- **Approvals:** every card links (U0 did the ids). Decided items link to their signed statement.
- **Scoping:** linked from Approvals.
- **Nav:** the grouping from D1.

**Exit:** the U-R2 walk and the full smoke pass.

### U6 — visual finish

This phase fits inside DESIGN.md unless D2 is taken.
- Close the two AA contrast gaps DESIGN.md records as known: Label Grey 3.23 and Scoped Violet 4.11. Define a visible focus ring.
- Resolve the two one-off radii.
- Settle vertical rhythm between the new bands.
- Refresh `docs/images/` screenshots, and the README images that come from them.
- Update DESIGN.md with the zoom-level component vocabulary (posture block, theme matrix, breadcrumb, band, `EntityLink`), and PRODUCT.md's "Surfaces today".
- Run a design review pass against the running console before and after, with screenshots in the PR.

**Exit:** a contrast test over the tokens (computed, not typed, as DESIGN.md's figures are); screenshots in the PR.

## 5. Decisions for the owner

Each has a recommendation. U0 and U1 need none of them, so building can start on U0 while these are open.

- **D1 — nav grouping.** Recommend four groups plus the scope:
  - **Posture** (Board, with Controls under it);
  - **Work** (Queue, Approvals, with a count badge each);
  - **Time** (Clock, Drift);
  - **Record** (Runs, Scoping, Recipes).

  Alternative: keep nine flat tabs and only reorder them.
- **D2 — one larger number on the posture block.** DESIGN.md's Compressed Scale Rule caps everything but the page title at 14px. The theme matrix and sentence work inside that rule. A single numeral step (the "13 of 41") at the title's 19px would read better. **Recommend: stay inside the rule** and let weight and colour carry it. Reopen it only if the U2 screenshots read flat.
- **D3 — retire `/controls?reg=ksis` as a destination** in favour of `/ksi/[id]`, keeping its CSV. Recommend yes. Two KSI models that never link to each other leave the reader to reconcile them.
- **D4 — fold the G1 rows by default.** Recommend yes, with the count always visible and one click to open. PRODUCT.md principle 1 says a design that makes the board look better than the ledger is a defect. So the fold line states the count in amber, and the posture sentence counts those indicators first.
- **D5 — is motion still banned?** DESIGN.md bans it entirely. The plan needs none. Recommend keeping the ban.

## 6. The exit gate for the whole plan

A Playwright test named `rabbit-hole`, run on the smoke fixtures:
1. Sign in and land on the posture block.
2. Reach the flagship violation's verify command in **four clicks**: theme → KSI → check → bundle band 4. Today the path is: board row click, scan the expansion for the method, digest link, then scroll past nine sections.
3. Climb back to the posture block by breadcrumbs alone, with the repo scope unchanged.
4. On every page visited, the U-R2 walk finds no bare entity id.

It is written first and marked `it.fails` in U0, the way P3-2 stated the adapter's obligations. Each phase unwraps what it delivers.

## 7. What this plan does not do

- No new data. Every number on every new surface is a fold or query that already exists. Where one does not (bundle history per cell), it is computed from `bundles` in the console's lib, with a test, not added to the projector.
- No change to what is signed, to the ledger, or to the projector's collections.
- No mobile layout. Desktop-only remains a PRODUCT.md decision.
- No React Flow graph canvas (deferred in PRODUCT.md, still deferred).
- No change to the four verdict hues.
