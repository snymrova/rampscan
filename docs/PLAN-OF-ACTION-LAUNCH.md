# rampscan — plan of action: public launch (Phases P0–P6)

**Status:** proposed plan of record for one deliverable — *this repository, public on GitHub, as `v0.1.0-beta`*. It does not touch product scope. `docs/PLAN-OF-ACTION-DEPTH.md` (N0–N3) stays the plan of record for the engine and keeps running underneath; the only intersection is P6, which is N2a brought forward on purpose and decided at a gate rather than assumed here.
**Date:** 2026-08-18
**Phase letter:** **P**. A–H, I, J, K and L are taken, M0–M5 are the original milestones, N is depth. O reads as a zero in a checkbox list, so it is skipped for the same reason N was chosen over a third collision.
**Reads against:** the repository as it stands (tests, CI, git history, tracked tree), not against the plans — the plans describe what was built, and a launch is judged on what a stranger receives.

**Thesis in one line:** the engine is not what is blocking a launch. 695 tests pass, `tsc --build` is clean, and eleven CLI commands work; what is missing is a licence, a history that can be published, a CI that gates what it claims to, and a first five minutes that a stranger can actually complete.

---

## 0. Ground rules, active from P0

The six from `PLAN-OF-ACTION.md` §0 and ground rules 7–10 from the depth plan stay active unchanged. Five are specific to publishing, and each exists because publishing is the one operation in this repository that is not append-only.

1. **Nothing is pushed until the history is final.** A rewrite before the first push costs an hour. After the first push it costs a forced push, every clone, and GitHub's object cache, which keeps the old commits reachable by SHA whether or not the branch moves. P1 therefore lands before a remote exists — not before the first release, before the first *remote*.
2. **Every number in a published document comes from a command.** This is ground rule 4 and the depth plan's ground rule 9, applied to the README, the release notes and any launch post. `rampscan frontier` owns coverage; `pnpm test` owns the test count. A number typed into the README is a number that will be wrong by the second release.
3. **No claim the fixture cannot demonstrate.** The README may describe only what `fixtures/vulnerable-app` or the self-scan actually produces on a clean machine. This is ground rule 7 — no vacuous passes — pointed at marketing copy, which is where it is easiest to break and most expensive to break.
4. **Fresh-clone honesty.** Every instruction in the README is verified by executing it in a clone made into a temporary directory, with this working tree's `node_modules`, caches, ledger, keys and PocketBase binary all absent. An instruction verified here and nowhere else is a guess.
5. **The published tree carries one authoring identity.** Author and committer fields across all history resolve to the repository's authoring identity. Verified by a command, not by memory.

---

## 1. What the repository already has

Stated so the plan is not re-litigating settled work, and so the launch copy has something true to quote.

| | |
|---|---|
| Unit tests | **695 passing across 59 files** (`vitest run`) |
| Typecheck | `tsc --build` clean, root and console |
| CLI | 11 commands — `scan · check · verify · board · rebuild · daemon · report · tools · model · frontier · serve` |
| Engine | M0–M5 · Phase H (semgrep/checkov/spectral) · I/J/K/L · N1a triage closed, N1b wave 1 landed |
| Coverage | `rampscan frontier`: 23 of 209 controls covered · 38 reachable (18.2%) · 68 of 112 frontier controls unreviewed |
| CI | one workflow, `smoke.yml` — Playwright console smoke only |
| Tool pins | 7 tools pinned by version and image in `packages/collectors/tools.json` |
| History | 56 commits, ~12 MB `.git` |

Two of those rows are launch problems rather than achievements: CI runs the smoke and **gates none of the 695 tests**, and the history is not publishable as it stands. Both are P1/P3.

---

## 2. Sequencing

```
P0  →  P1  →  P2  →  P3  →  P4  →  P5  →  [P6]
 ·      ·      ·      ·      ·      ·       ·
decisions history  files    CI    README   push   the gate
```

**Why history is first among the doing phases.** It is the only irreversible one. Every other item on this plan can be fixed in a follow-up commit after launch at no cost; a history rewrite cannot be, and its window closes the instant a remote exists. P1 also has to precede P3, because CI cannot be observed before there is a remote to run it on, and a remote must not exist before P1 is done.

**Why the README is late.** It quotes numbers from commands (ground rule 2) and instructions verified against a clone (ground rule 4). Both are cheaper once the tree is final.

Estimates, focused-work days: P0 0.5 · P1 0.5 · P2 0.5 · P3 1 · P4 1 · P5 0.5. **Total ≈ 4 days.** With P6: **+2**, per the depth plan's own N2a estimate.

---

## 3. Phase P0 — decisions locked before anything is written

No code. Two of these need the owner and cannot be defaulted.

- [x] **P0-1. The licence.** *Owner's decision.* Recommendation: **Apache-2.0** — the patent grant is the reason security tooling standardises on it over MIT, and a tool whose whole output is a signed attestation is a tool people will want patent clarity on before adopting. The alternative worth weighing is a source-available licence (BSL/Elastic) if rampscan is intended to become commercial, which converts every later relicensing conversation into a contributor-consent problem. Decide once; the choice propagates into P2's headers and the `NOTICE`.
- [x] **P0-2. What of `docs/context/` ships.** *Owner's decision.* `docs/context/ramprules/` is a 3.0 MB snapshot of the sibling project's published dataset, and publishing this repository redistributes it. Three options: ship with attribution and the upstream licence recorded in `NOTICE`; trim to only the slices `packages/dataset` pins against; or gitignore it and have `docs/context/README.md` state how to fetch it. Note the constraint before choosing — the loader's dev mode reads `derived/`, so option three changes what a fresh clone can do without a sibling checkout, which is a P4 problem.

  > **Decided 2026-08-18: ship whole, with `NOTICE`.** Two of the three options
  > died on contact with the code. **Gitignoring it is not available:**
  > `docs/context/ramprules/derived` is the CLI's default `--dataset` dir
  > (`main.ts`) and is read by **17 test files**, so removing it breaks
  > `pnpm test` and the default command on a fresh clone — ground rule 4 forbids
  > exactly that. **Trimming is not worth its seam:** 8 of the 15 files have zero
  > references (688K of 3.0M), and the largest single file, `evidence-plan.json`
  > at 1.6M, became load-bearing at N1b′ when the link check started reading
  > upstream's evidence plan. A trim saves 23% and buys a re-pin maintenance
  > obligation.
  >
  > **What this decision uncovered, and P2-2 must not paper over:** the sibling
  > is *our own* repository, already public, and it **carries no `LICENSE`**. So
  > there is no third-party redistribution risk in substance — and nothing for
  > `NOTICE` to cite. An adopter of rampscan inherits an unlicensed data
  > dependency they cannot legally reuse. **P2-2 is therefore blocked on a
  > one-file change in the sibling repo**, not on anything in this one.
- [x] **P0-3. What of the internal plans ships.** ~3,500 lines across 14 documents, including session logs of unusual length. Default: **ship all of it.** The build log is the credibility argument for a compliance-evidence tool — it is the artifact that shows the reasoning was done rather than asserted, which is exactly what the product claims about evidence. Record the decision either way so it is not re-opened per-file during P4.

  > **Decided 2026-08-18, against the default: the internal plans do not ship.**
  > Ten documents removed at HEAD — four `PLAN-OF-ACTION`, four
  > `IMPLEMENTATION-PLAN`, two `BRAINSTORM`, plus `PRODUCT-READ.md`. What stays
  > is what a stranger needs and what the code depends on: `ARCHITECTURE.md`,
  > `SPEC.md`, `COMPLIANCE-SCAN-HARNESS.md` (SPEC assumes its argument, and
  > §11–§13 is the only written record of several scope decisions),
  > `FRONTIER-PIPELINE.md` (generated — it is `rampscan report`'s default output
  > path and `report.test.ts` asserts on it) and `docs/context/` (read by 17
  > test files). `docs/` goes 3,770 lines → 1,065.
  >
  > **At HEAD only, and the reason is the same one that made the default
  > attractive.** The build-log argument was never really about the plan files:
  > the reasoning in this repository lives in its commit messages, which are
  > long-form by design and stay exactly where they are. Rewriting the documents
  > out of history while keeping those messages would remove an index and none
  > of the substance — and rewriting the messages too would destroy the evidence
  > the plans were being kept for. So the files remain reachable in the 63
  > commits to anyone who looks, and nothing in the published tree points at
  > them.
  >
  > **This document is the exception and goes last**, immediately before P5-1.
  > It is the plan of record and is still being executed; deleting it here would
  > mean finishing the launch out of git history.
- [x] **P0-4. Version and tag scheme.** `v0.1.0-beta` for this launch; workspace packages stay `private: true` and unpublished (no npm), so the tag is the only version surface. Record that the CLI is run from a clone, by decision, until an external user asks for a bin.
- [x] **P0-5. Support posture.** What `SECURITY.md` promises and to what address; whether issues are open; what "beta" commits you to. A security tool with no vulnerability-report path is the first thing a security reader looks for and does not find.

  > **Decided 2026-08-18: GitHub private vulnerability reporting, issues open
  > with the three templates, and a promise sized to one maintainer** — 7 days to
  > acknowledge, 14 to a first assessment, fix or public statement best-effort,
  > `main` only, credit unless declined. The private-reporting channel is chosen
  > over a published address because there is no domain to host one and an
  > unmonitored `security@` is worse than no address; it also costs a repository
  > setting at P5 rather than a mailbox forever. What the policy adds beyond the
  > template is a scope sentence this product needs and a generic one would not
  > have: **a recipe reporting `evidenced` without the evidence being there is a
  > security report, not a bug report** — a compliance tool that passes a control
  > it cannot prove is issuing a false attestation, and someone will hand it to an
  > assessor.
- [~] **P0-6. Repository name, description, topics, visibility.** Public from the first push — a repository created private and flipped later carries its whole private history into public visibility at the moment of the flip, which is a worse version of the P1 problem.

  > **Decided 2026-08-18: the name is `rampscan`, so the slug is `snymrova/rampscan`.** Description and topics stay open and are P5-5, which is after the push and cheap to change. Visibility stands at the item's own reasoning: public from the first push.

**Exit:** six decisions recorded in this document's session log with their reasoning. No files written.

---

## 4. Phase P1 — the history, made publishable (irreversible; before any remote)

- [x] **P1-1. Remove the shaped credential from history.** `fixtures/build-vulnerable-app.mjs` carries an AWS-key-shaped literal (deliberately, to make the fixture's planted fault real). `gitleaks detect` finds **4 hits across 56 commits**. Change the builder to synthesize the string at build time so no shaped literal exists in any blob, then rewrite so no reachable commit contains one. The fixture's behaviour must not change: the generated repo still carries the planted secret, and the fixture's SHAs are deterministic by design, so the M0/B4 determinism test is the check that the rewrite did not alter what is generated.

  > **Corrected 2026-08-18, during execution: this item was one file short.**
  > It was written from the fixture's description; the scanner's output names
  > **three** files. `packages/collectors/test/journal.test.ts` plants a stripe
  > key to prove the redaction vocabulary refuses it, and
  > `e2e/console.smoke.spec.ts` asserts the planted AWS value is absent from a
  > rendered page — which it can only do by naming the value. Both are
  > load-bearing; neither was deletable. All three took the same remedy
  > (assembly at run time, not an allowlist), and the fixture's SHAs
  > `c37ed34 · d2e8583 · b9d879b` are unchanged, verified by rebuild.
  > The general lesson is the one this project keeps relearning: **a plan item
  > written from a description under-scopes a plan item written from output.**
- [x] **P1-2. Scrub the non-authoring identity.** 2 of 56 commits carry a second author/committer email. Rewrite both to the authoring identity. Display names are already clean.
- [x] **P1-3. One rewrite, not two.** P1-1 and P1-2 ride the same `git filter-repo` pass. It is not installed on this machine (`git-filter-repo not found`) — install it first; `filter-branch` is the wrong tool and its own manual says so.
- [x] **P1-4. Pin the local identity** so nothing new lands wrong: `git config user.email` set in this repository, not relied on globally.
- [x] **P1-5. Full re-verification after the rewrite.** `pnpm test`, `tsc --build`, and a fixture rebuild — a history rewrite touches every blob's parentage and this repository's tests are unusually coupled to commit identity (anchor drift, `git show` lines, the self-scan).

**Exit test:** `gitleaks detect` over the rewritten history reports zero findings; `git log --format='%ae %ce' | sort -u` returns exactly one address; `pnpm test` is 695/695 green and `tsc --build` clean on the rewritten tree; the fixture builder still produces its documented SHAs. **No remote has been added at any point during this phase.**

---

## 5. Phase P2 — the files a public repository owes

- [x] **P2-1. `LICENSE`** per P0-1, plus a copyright line with a real holder.
- [x] **P2-2. `NOTICE`** — attribution for `docs/context/` per P0-2, and for the pinned third-party tools the collectors invoke. Not required by every licence; required by honesty for a repository that vendors a snapshot of someone else's published data.
- [x] **P2-3. `SECURITY.md`** per P0-5 — reporting path, expected response, and the one sentence a reader of *this* product wants: what rampscan does and does not send anywhere (collectors take no network, execution is local, signing is `node:crypto` — the sentence the adjudication records already make repeatedly, which makes it quotable rather than new).
- [x] **P2-4. `CONTRIBUTING.md`** — the ground rules that actually gate a merge, not a generic template: ports-and-adapters (§0.1), append-only tested by a cheat (§0.3), computed-never-typed (§0.4), no vacuous passes (depth §0.7), and the three authored `plain` paragraphs every recipe owes. A contributor who reads this and writes a recipe correctly on the first try is what the file is for.
- [~] **P2-5. `.github/` furniture** — issue templates (bug · recipe proposal · adjudication disagreement), a PR template pointing at the ground rules, and `CODEOWNERS`.
- [x] **P2-6. `.gitleaksignore`** for the fixture's remaining intentional plants, so the self-scan and any contributor's scan stay honest rather than noisy.

  > **Corrected 2026-08-18: the file has no content to hold, and shipping one
  > would be a detection hole rather than an allowlist.** The item was written
  > before P1 ran and assumed plants would survive it; none did. `gitleaks git
  > --redact .` — the exact command `packages/collectors/src/gitleaks.ts` runs —
  > reports **no leaks across 59 commits**, and no tracked file contains one.
  > A *working-tree* scan does find 40, and that is the number the item was
  > reaching for, but every one is untracked local state: the signing key under
  > `rampscan-keys/`, the PocketBase superuser record, and pattern hits inside
  > `console/web/.next/` build output. The collector scans history, so none of it
  > ever reaches the self-scan. Allowlisting them would quiet a scan nobody runs
  > here while blinding the scan everybody does — and it would blind it over
  > exactly the paths where an accidental commit is most damaging, which is risk
  > 3's "quiet weakening of the fixture" wearing different clothes. Shipped as
  > **no file plus a recorded reason** in `CONTRIBUTING.md`, so the next person to
  > notice the 40 finds the argument instead of re-deriving it.

**Exit test:** a reader landing cold can answer, without opening a source file: what may I do with this, where do I report a vulnerability, what is expected of a change, and what does this send off my machine.

---

## 6. Phase P3 — CI that gates what the README claims

Today `smoke.yml` runs the Playwright console smoke and **nothing else**. The 695 unit tests and both typechecks are ungated on every pull request, which means the repository's central quality claim is currently unenforced in the one place a stranger can see.

- [x] **P3-1. A `test` job** — `pnpm install --frozen-lockfile`, `pnpm test`, `pnpm typecheck`, plus the console typecheck. No tool binaries needed; minutes, not tens of minutes.
- [x] **P3-2. Keep the smoke as its own job**, unchanged in scope. It installs four binaries, resolves three more through Docker and runs Playwright on a 30-minute timeout (~6 min cold locally). Leave the engine-track collector-family CI deferred — that decision is the owner's and is not reopened here (depth plan §2).
- [ ] **P3-3. Status badges** in the README, added only after both jobs have gone green on the remote at least once. A badge added before the first run is a claim with no evidence behind it.
- [ ] **P3-4. Budget the first real run.** This workflow has **never executed** — there is no remote. Expect one to two iterations on tool installs, Docker availability in Actions, and Playwright deps. This is a scheduled cost, not a surprise.

**Exit test:** a pull request that breaks a unit test fails CI; a pull request that breaks the console fails CI; both jobs are green on `main`; the badges reflect runs that happened.

---

## 7. Phase P4 — the stranger's first five minutes

- [x] **P4-1. Rewrite the README status.** It currently says *"Local prototype, M4 complete"* and is stale by Phase H, I, J, K, L and all of N. It also says *"Next: M5"*, which shipped.
- [x] **P4-2. Quote coverage from the command.** Ground rule 2: the README states 23 of 209 covered and 18.2% reachable **only** as `rampscan frontier`'s output, shown as a transcript, with the ceiling stated beside it. The small number is the credibility, not the weakness — a launch that hides it forfeits the one property that distinguishes this tool from the category.
- [x] **P4-3. A quickstart that has been walked from a clean clone** (ground rule 4), in a temp directory: `pnpm install` → `pnpm test` → `pnpm doctor` → `rampscan scan <path>` → `rampscan board`, and separately `pnpm fetch-pocketbase` → `rampscan serve`. Each step's real output, including what `doctor` prints on a machine with no scan tools and no Docker — the graceful-skip path is a feature and the README should show it working rather than assert it.

  > **Corrected 2026-08-18, during execution: the walk found two defects, and
  > neither was visible from this tree.** (1) **`pnpm install` exits 1 on a clean
  > clone.** pnpm 10+ refuses an undeclared build script, and `esbuild` and
  > `sharp` ship one; this tree passed only because its `node_modules` predates
  > the gate, and CI passed only because it pinned pnpm 9.6.0 — so the very first
  > README instruction failed for every stranger on a current pnpm while looking
  > green in both places we could see. Fixed at the root: `packageManager` now
  > pins pnpm, so the maintainer, CI and a stranger all get one version, and
  > `allowBuilds` denies both scripts explicitly — the posture the README already
  > claims, since a tool that installs nothing on the host should not run a third
  > party's postinstall to test itself. Install goes 12s → ~3s and no build script
  > runs. (2) **`pnpm doctor` was never rampscan's doctor.** pnpm has a built-in
  > `doctor` that shadows the script, and it prints *"All checks passed"* about
  > the package manager's own environment — a **reassuring** message about the
  > wrong subject, which is ground rule 7's vacuous pass arriving through the
  > README rather than through a recipe. It was `pnpm doctor` in twelve places
  > including four test assertions and the console's empty-state hint; all now
  > say `pnpm run doctor`.
  >
  > The general lesson is P1-1's, from the other direction: **a plan item written
  > from this tree under-scopes a plan item written from a clone.** Both defects
  > were invisible to `pnpm test` here and to CI, and both were the first thing a
  > stranger would have hit.
- [x] **P4-4. Say plainly how it is run.** Every package is `private: true` with no `bin`; the entry point is `pnpm rampscan …` from a clone via tsx. State it, with the reason (no external user has asked for a bin), rather than letting a reader discover it after `npm i -g` fails.
- [ ] **P4-5. Console screenshots** — the coverage board, an evidence detail page, the drift view. The visual loop is a large share of what was built and is currently invisible to anyone who does not clone and run it.
- [x] **P4-6. Prune or label the docs index** per P0-3, so a reader can tell the plan of record from the spent plans without opening seven files. *Done ahead of the rest of P4, because P4-1's README rewrite has to describe the index that survives rather than the one being deleted.* The five dangling references the removal created are fixed in the same commit; `docs/PLAN-OF-ACTION-LAUNCH.md` itself is held for P5-0(d).

**Exit test:** a clone into an empty directory on a machine with neither scan tools nor Docker reaches a rendered board by following only the README, with no step failing and no step undocumented; every number on the page is reproducible by a command printed beside it.

---

## 8. Phase P5 — the push

- [ ] **P5-0. The three placeholders that must be closed before the push, not after.** Each is a file that is already correct except for a fact P0-6 has not decided, and each fails silently rather than loudly. (a) `NOTICE` states that `docs/context/ramprules/` is CC BY 4.0 — **decided 2026-08-18, and not yet applied in the sibling repository.** Until a `LICENSE` lands there, `NOTICE` cites a licence that does not exist, which is worse than the missing-licence problem it was written to fix. (b) ~~`.github/ISSUE_TEMPLATE/config.yml` carries `OWNER/REPO` in two absolute URLs~~ **Closed 2026-08-18: `snymrova/rampscan`.** The hard-coding is inherent — GitHub's issue-form schema takes no relative link — so the comment now says which two lines break on a rename rather than which two are unfinished. (d) **This document.** `docs/PLAN-OF-ACTION-LAUNCH.md` is the last of the ten-plus-one removed under P0-3, and it goes when the phases above it are all ticked — not before, because it is what is being executed. (c) ~~`CODEOWNERS` is unwritten because it needs a GitHub handle.~~ **Closed 2026-08-18** — the handle is `@snymrova`, read off the sibling ramprules remote rather than guessed, and it is the same person who authors every commit here. It is one line to change if rampscan lands under an organisation instead.
- [ ] **P5-1. Create the remote** (public, per P0-6) and push `main`.
- [ ] **P5-2. Watch the first CI run** and fix forward per P3-4.
- [ ] **P5-3. Handle secret-scanning.** Push protection may still flag the fixture's remaining intentional plants even after P1. If it blocks, the resolution is the allowlist and a dismissal with a reason — never a quiet weakening of the fixture, which is load-bearing for the product's own tests.
- [ ] **P5-4. Tag `v0.1.0-beta`** with release notes assembled from what the phases actually did, and the coverage figures quoted from the command.
- [ ] **P5-5. Repository settings** — description, topics, branch protection requiring both CI jobs, and the security policy linked.

**Exit test:** a machine that has never seen this project clones the public URL, follows the README, and reaches a board; both CI jobs are green on `main`; the tag exists and its notes state no number a command did not produce.

---

## 9. Phase P6 — the gate, decided at the P5 exit (recommended)

N2a from the depth plan, brought forward: a GitHub Action wrapping `rampscan check`, and a PR comment assembled from `RegisterDiff`, `OffenderPointer`, the `introducedAt` walk and each recipe's authored `plain.fix` sentence — four pieces that already exist and that nothing has ever rendered.

The launch argument for jumping is narrow and strong: it is the only remaining item that changes what a *visitor* can do. Without it the beta is a CLI plus a local console — real, but something a reader has to take on faith or spend twenty minutes proving. With it, the repository demonstrates itself on its own pull requests, in the recipe's own words, where a stranger can watch. The depth plan already flags this fork and recommends taking the jump if N1b landed clean, which it did.

**Decide at the P5 exit, not now.** If P3's first runs were rough, ship the beta and make P6 the first post-launch release.

**Exit test:** unchanged from the depth plan's N2a — a PR that breaches a declared boundary gets a comment naming the file, the import chain and the authored fix sentence, and exits 1; a PR that breaches nothing gets no comment and exits 0; a PR touching an already-violated row is described as inheriting it, not causing it; the ledger is byte-identical across the run.

---

## 10. Risks worth naming

1. **The rewrite window closes silently.** Nothing in git warns that adding a remote made P1 expensive. The mitigation is ordering, which is why ground rule 1 is a ground rule and not a task.
2. **The first CI run is genuinely untested.** Zero executions of a workflow that installs four binaries, pulls three images and runs a browser. Treat a red first run as expected, not as a signal that something is wrong with the repository.
3. **Push protection blocks the fixture.** The planted fault is the point of the fixture; the resolution is an allowlist and a stated dismissal, never a weakened fixture. Named here so it is not improvised at the worst moment.
4. **The coverage number disappoints before it reassures** — depth plan risk 6, arriving in public for the first time. 23 of 209 read cold looks like an unfinished tool. The mitigation is the ceiling published beside it: the honest statement of what a repository *cannot* answer is what makes the 23 believable, and it is the most rampscan-shaped thing in the launch.
5. **Redistribution of the sibling snapshot** (P0-2). A 3 MB copy of another project's published dataset becomes a public redistribution the moment the push lands, and unlike everything else here that cannot be undone by deleting the file later.
6. **Launch scope creeping into N.** Every item on this plan is hygiene or delivery. The one product item is P6, and it is gated. Any other engine work that appears during this plan belongs to the depth plan and waits.

---

## 11. What "launched" looks like

- A public repository under a stated licence, whose history carries one identity and no shaped credential.
- Two green CI jobs, one of which gates the 695 tests the README quotes.
- A README whose every number came from a command, whose quickstart was walked from a clean clone, and which states the ceiling beside the coverage.
- A `v0.1.0-beta` tag, a security-reporting path, and contribution rules that are this project's actual merge gates.
- Optionally, a pull request on that repository being told — in the recipe's own authored words — that it broke a control.

---

## Session log

Update as work lands — newest first. "Phase" refers to this document's phases.

| Date | Phase | What landed |
|---|---|---|
| 2026-08-18 | P4 · ground rule 4 | **The README is rewritten against commands, and walking it from a clone found two defects that were invisible here.** P4-1 (status: `v0.1.0-beta`, eleven commands, twenty recipes, 692 passed · 3 skipped across 59 files — the stale *"M4 complete / Next: M5"* is gone), P4-2 (`rampscan frontier` quoted as a transcript, 23 of 209 with the 38-ceiling beside it and the 68 unreviewed printed as a question), P4-3 and P4-4 (run from a clone, `pnpm rampscan …`, with the reason). **`pnpm install` exited 1 on a clean clone** and **`pnpm doctor` was pnpm's doctor, not ours** — both fixed, both recorded at P4-3. Every line of the quickstart re-walked afterwards on a fresh `git clone`: install 3.1s · 692 passed \| 3 skipped · doctor · `scan .` **12 evidenced · 2 violated · 6 unevidenced** · board · both typechecks, all exit 0. P4-5 (screenshots) is the one item of the phase still open. |
| 2026-08-18 | P0-3 · P4-6 | **The internal plans do not ship — decided against this item's own default.** Ten documents removed at HEAD, `docs/` 3,770 → 1,065 lines; see the decision recorded at P0-3 for the split and for why the removal stops at HEAD. The removal created exactly five dangling references and all five are fixed in the same commit — `CONTRIBUTING.md` now states the ground rules' provenance instead of linking to it, `ARCHITECTURE.md` drops one entry from *reads against*, `smoke.yml` names the deferral instead of the document that deferred it, `frontier.ts` loses a filename from a comment, and `README.md` loses two index bullets it was about to lose anyway. P4-6 is therefore done ahead of the rest of P4, which is the right order: P4-1 has to describe the index that survives. |
| 2026-08-18 | P3 · P5-0 | **The 695 tests are gated, and the one row left violated is left violated on purpose.** `test.yml` runs `pnpm typecheck`, the console's own `tsc --noEmit` (root `tsc --build` walks the ten packages and does **not** reach `console/web`) and `pnpm test` — no tool binaries, no images, minutes not tens of minutes (P3-1). `smoke.yml` is unchanged (P3-2); badges wait for a green run on a remote that does not exist (P3-3). Two launch-hygiene rows from the last self-scan closed with them: `CODEOWNERS` (which also closes P5-0(c)) and `.github/dependabot.yml`, added because a security tool letting its own dependencies rot argues against itself — and because SHA-pinned actions are exactly the kind of pin that goes stale silently. **Self-scan: 10 · 4 · 6 → `12 evidenced · 2 violated · 6 unevidenced`.** |
| 2026-08-18 | P3 note | **`ci-provenance-present` stays violated, and that is the decision rather than the backlog.** The row flips by adding an `attest-build-provenance` step, and this repository **publishes no build artifact** — every package is `private: true` with no `bin`, and the CLI runs from a clone (P0-4). A provenance step here would attest nothing and the recipe would pass on it, which is **ground rule 7's vacuous pass with the tool pointed at its own repository** — the exact failure P2-3 just defined as a security report. It flips honestly when there is something to attest, and not before. The second violation, `iac-baseline-clean`, is checkov flagging `fixtures/vulnerable-app/.github/workflows/ci.yml` — the **generated fixture's planted workflow**, gitignored and deliberately faulty — which raises a scan-scope question the engine track owns and this plan does not touch (risk 6): whether a checkout scan should read paths the repository ignores. |
| 2026-08-18 | P2 exit | **The self-scan is the exit test, and it moved.** `rampscan scan .` after P2: **10 evidenced · 4 violated · 6 unevidenced**. `security-disclosure-published` flipped to **evidenced** — the recipe that reads for a security policy, answered by the security policy P2-3 wrote, which is the first time this repository has satisfied one of its own controls by doing the thing rather than by writing the check. The board also prices the held items in the project's own vocabulary: **`codeowners-defined` is violated** because P2-5's `CODEOWNERS` is waiting on a GitHub handle, so the P5-0(c) placeholder is not a note in a plan but a red row on the board. Two further violations are launch-adjacent and belong to P3 rather than here — **`ci-provenance-present`** (no workflow step attests a build) and **`dependency-update-automation`** (no dependabot or renovate config) — both real for a repository about to become public, both out of P2's scope, and both now named so they are chosen rather than forgotten. |
| 2026-08-18 | P2 · P0-5 | **P2 closes; the last two files landed on answers.** `SECURITY.md` per the P0-5 decision recorded at that item, carrying the no-network/local-execution/`node:crypto` sentence the adjudication records make repeatedly and a scope clause that counts a vacuous pass as a security report. `NOTICE` attributes the ramprules snapshot as CC BY 4.0 per the sibling-licence decision, attributes the harnessarch snapshot, and states plainly that **no scan tool is redistributed** — each resolves at run time from its own publisher — which is a shorter and truer NOTICE than one asserting seven licences it cannot verify offline. The sibling's `LICENSE` is decided but not yet written, so **`NOTICE` is correct only after that lands**; tracked as P5-0(a) alongside the `OWNER/REPO` placeholder and the unwritten `CODEOWNERS`, because all three are files that are already right except for a fact P0-6 has not decided. |
| 2026-08-18 | P2 | **Four of six landed; two are held on answers, and one of the four was a plan item that dissolved on inspection.** `LICENSE` is the canonical Apache-2.0 text per P0-1 (P2-1). `CONTRIBUTING.md` states the ten ground rules as merge gates and names the test that enforces each — `self-contract.test.ts`, `ledger.test.ts`'s cheating tests, `plain.test.ts`, `catalog.test.ts` and `catalog-bare.e2e.test.ts`, `frontier.test.ts` — plus the recipe and adjudication checklists (P2-4). `.github/` carries three issue forms (bug · recipe proposal · adjudication disagreement, the last two written as the CONTRIBUTING checklists asked as questions) and a PR template (P2-5, less `CODEOWNERS`, which needs a GitHub handle). **P2-6 shipped as no file** — see the correction at the item. **P2-2 stays blocked on the sibling's missing licence; P2-3 stays blocked on P0-5.** |
| 2026-08-18 | P1 | **The history is publishable, and no remote has ever existed.** One `git filter-repo` pass (P1-3), `--replace-text` + `--mailmap` together. `gitleaks detect` over the rewritten 57 commits: **no leaks found**, from 4. `git log --format='%ae %ce' \| sort -u`: **one address**. 695/695 tests green, `tsc --build` clean root and console, fixture rebuilds to its documented SHAs. A verified `git bundle` of the pre-rewrite history is held outside the repo. |
| 2026-08-18 | P1-1 | The three shaped credentials assembled rather than written (see the correction at P1-1 — the item named one file, gitleaks named three). |
| 2026-08-18 | P0 | **P0-1 decided: Apache-2.0** — the patent grant is why security tooling standardises on it over MIT, and a tool whose entire output is a signed attestation is one adopters want patent clarity on. **P0-2 decided: ship `docs/context/` whole with `NOTICE`** — see the correction at P0-2, including the sibling's missing licence, which now blocks P2-2. **P0-4 stands at its stated default** (`v0.1.0-beta`, no npm, run from a clone). **P0-3, P0-5 and P0-6 remain open and are the owner's.** |
