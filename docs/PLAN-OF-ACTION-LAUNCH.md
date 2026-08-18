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

- [ ] **P0-1. The licence.** *Owner's decision.* Recommendation: **Apache-2.0** — the patent grant is the reason security tooling standardises on it over MIT, and a tool whose whole output is a signed attestation is a tool people will want patent clarity on before adopting. The alternative worth weighing is a source-available licence (BSL/Elastic) if rampscan is intended to become commercial, which converts every later relicensing conversation into a contributor-consent problem. Decide once; the choice propagates into P2's headers and the `NOTICE`.
- [ ] **P0-2. What of `docs/context/` ships.** *Owner's decision.* `docs/context/ramprules/` is a 3.0 MB snapshot of the sibling project's published dataset, and publishing this repository redistributes it. Three options: ship with attribution and the upstream licence recorded in `NOTICE`; trim to only the slices `packages/dataset` pins against; or gitignore it and have `docs/context/README.md` state how to fetch it. Note the constraint before choosing — the loader's dev mode reads `derived/`, so option three changes what a fresh clone can do without a sibling checkout, which is a P4 problem.

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
- [ ] **P0-3. What of the internal plans ships.** ~3,500 lines across 14 documents, including session logs of unusual length. Default: **ship all of it.** The build log is the credibility argument for a compliance-evidence tool — it is the artifact that shows the reasoning was done rather than asserted, which is exactly what the product claims about evidence. Record the decision either way so it is not re-opened per-file during P4.
- [ ] **P0-4. Version and tag scheme.** `v0.1.0-beta` for this launch; workspace packages stay `private: true` and unpublished (no npm), so the tag is the only version surface. Record that the CLI is run from a clone, by decision, until an external user asks for a bin.
- [ ] **P0-5. Support posture.** What `SECURITY.md` promises and to what address; whether issues are open; what "beta" commits you to. A security tool with no vulnerability-report path is the first thing a security reader looks for and does not find.
- [ ] **P0-6. Repository name, description, topics, visibility.** Public from the first push — a repository created private and flipped later carries its whole private history into public visibility at the moment of the flip, which is a worse version of the P1 problem.

**Exit:** six decisions recorded in this document's session log with their reasoning. No files written.

---

## 4. Phase P1 — the history, made publishable (irreversible; before any remote)

- [ ] **P1-1. Remove the shaped credential from history.** `fixtures/build-vulnerable-app.mjs` carries an AWS-key-shaped literal (deliberately, to make the fixture's planted fault real). `gitleaks detect` finds **4 hits across 56 commits**. Change the builder to synthesize the string at build time so no shaped literal exists in any blob, then rewrite so no reachable commit contains one. The fixture's behaviour must not change: the generated repo still carries the planted secret, and the fixture's SHAs are deterministic by design, so the M0/B4 determinism test is the check that the rewrite did not alter what is generated.

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
- [ ] **P1-2. Scrub the non-authoring identity.** 2 of 56 commits carry a second author/committer email. Rewrite both to the authoring identity. Display names are already clean.
- [ ] **P1-3. One rewrite, not two.** P1-1 and P1-2 ride the same `git filter-repo` pass. It is not installed on this machine (`git-filter-repo not found`) — install it first; `filter-branch` is the wrong tool and its own manual says so.
- [ ] **P1-4. Pin the local identity** so nothing new lands wrong: `git config user.email` set in this repository, not relied on globally.
- [ ] **P1-5. Full re-verification after the rewrite.** `pnpm test`, `tsc --build`, and a fixture rebuild — a history rewrite touches every blob's parentage and this repository's tests are unusually coupled to commit identity (anchor drift, `git show` lines, the self-scan).

**Exit test:** `gitleaks detect` over the rewritten history reports zero findings; `git log --format='%ae %ce' | sort -u` returns exactly one address; `pnpm test` is 695/695 green and `tsc --build` clean on the rewritten tree; the fixture builder still produces its documented SHAs. **No remote has been added at any point during this phase.**

---

## 5. Phase P2 — the files a public repository owes

- [ ] **P2-1. `LICENSE`** per P0-1, plus a copyright line with a real holder.
- [ ] **P2-2. `NOTICE`** — attribution for `docs/context/` per P0-2, and for the pinned third-party tools the collectors invoke. Not required by every licence; required by honesty for a repository that vendors a snapshot of someone else's published data.
- [ ] **P2-3. `SECURITY.md`** per P0-5 — reporting path, expected response, and the one sentence a reader of *this* product wants: what rampscan does and does not send anywhere (collectors take no network, execution is local, signing is `node:crypto` — the sentence the adjudication records already make repeatedly, which makes it quotable rather than new).
- [ ] **P2-4. `CONTRIBUTING.md`** — the ground rules that actually gate a merge, not a generic template: ports-and-adapters (§0.1), append-only tested by a cheat (§0.3), computed-never-typed (§0.4), no vacuous passes (depth §0.7), and the three authored `plain` paragraphs every recipe owes. A contributor who reads this and writes a recipe correctly on the first try is what the file is for.
- [ ] **P2-5. `.github/` furniture** — issue templates (bug · recipe proposal · adjudication disagreement), a PR template pointing at the ground rules, and `CODEOWNERS`.
- [ ] **P2-6. `.gitleaksignore`** for the fixture's remaining intentional plants, so the self-scan and any contributor's scan stay honest rather than noisy.

**Exit test:** a reader landing cold can answer, without opening a source file: what may I do with this, where do I report a vulnerability, what is expected of a change, and what does this send off my machine.

---

## 6. Phase P3 — CI that gates what the README claims

Today `smoke.yml` runs the Playwright console smoke and **nothing else**. The 695 unit tests and both typechecks are ungated on every pull request, which means the repository's central quality claim is currently unenforced in the one place a stranger can see.

- [ ] **P3-1. A `test` job** — `pnpm install --frozen-lockfile`, `pnpm test`, `pnpm typecheck`, plus the console typecheck. No tool binaries needed; minutes, not tens of minutes.
- [ ] **P3-2. Keep the smoke as its own job**, unchanged in scope. It installs four binaries, resolves three more through Docker and runs Playwright on a 30-minute timeout (~6 min cold locally). Leave the engine-track collector-family CI deferred — that decision is the owner's and is not reopened here (depth plan §2).
- [ ] **P3-3. Status badges** in the README, added only after both jobs have gone green on the remote at least once. A badge added before the first run is a claim with no evidence behind it.
- [ ] **P3-4. Budget the first real run.** This workflow has **never executed** — there is no remote. Expect one to two iterations on tool installs, Docker availability in Actions, and Playwright deps. This is a scheduled cost, not a surprise.

**Exit test:** a pull request that breaks a unit test fails CI; a pull request that breaks the console fails CI; both jobs are green on `main`; the badges reflect runs that happened.

---

## 7. Phase P4 — the stranger's first five minutes

- [ ] **P4-1. Rewrite the README status.** It currently says *"Local prototype, M4 complete"* and is stale by Phase H, I, J, K, L and all of N. It also says *"Next: M5"*, which shipped.
- [ ] **P4-2. Quote coverage from the command.** Ground rule 2: the README states 23 of 209 covered and 18.2% reachable **only** as `rampscan frontier`'s output, shown as a transcript, with the ceiling stated beside it. The small number is the credibility, not the weakness — a launch that hides it forfeits the one property that distinguishes this tool from the category.
- [ ] **P4-3. A quickstart that has been walked from a clean clone** (ground rule 4), in a temp directory: `pnpm install` → `pnpm test` → `pnpm doctor` → `rampscan scan <path>` → `rampscan board`, and separately `pnpm fetch-pocketbase` → `rampscan serve`. Each step's real output, including what `doctor` prints on a machine with no scan tools and no Docker — the graceful-skip path is a feature and the README should show it working rather than assert it.
- [ ] **P4-4. Say plainly how it is run.** Every package is `private: true` with no `bin`; the entry point is `pnpm rampscan …` from a clone via tsx. State it, with the reason (no external user has asked for a bin), rather than letting a reader discover it after `npm i -g` fails.
- [ ] **P4-5. Console screenshots** — the coverage board, an evidence detail page, the drift view. The visual loop is a large share of what was built and is currently invisible to anyone who does not clone and run it.
- [ ] **P4-6. Prune or label the docs index** per P0-3, so a reader can tell the plan of record from the spent plans without opening seven files.

**Exit test:** a clone into an empty directory on a machine with neither scan tools nor Docker reaches a rendered board by following only the README, with no step failing and no step undocumented; every number on the page is reproducible by a command printed beside it.

---

## 8. Phase P5 — the push

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
| 2026-08-18 | P1 | **The history is publishable, and no remote has ever existed.** One `git filter-repo` pass (P1-3), `--replace-text` + `--mailmap` together. `gitleaks detect` over the rewritten 57 commits: **no leaks found**, from 4. `git log --format='%ae %ce' \| sort -u`: **one address**. 695/695 tests green, `tsc --build` clean root and console, fixture rebuilds to its documented SHAs. A verified `git bundle` of the pre-rewrite history is held outside the repo. |
| 2026-08-18 | P1-1 | The three shaped credentials assembled rather than written (see the correction at P1-1 — the item named one file, gitleaks named three). |
| 2026-08-18 | P0 | **P0-1 decided: Apache-2.0** — the patent grant is why security tooling standardises on it over MIT, and a tool whose entire output is a signed attestation is one adopters want patent clarity on. **P0-2 decided: ship `docs/context/` whole with `NOTICE`** — see the correction at P0-2, including the sibling's missing licence, which now blocks P2-2. **P0-4 stands at its stated default** (`v0.1.0-beta`, no npm, run from a clone). **P0-3, P0-5 and P0-6 remain open and are the owner's.** |
