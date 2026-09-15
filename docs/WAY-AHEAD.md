# rampscan — way ahead, for a new working session

**Purpose:** the first document to read at the start of a coding session. It says where the project is, what is decided, what is next, and how work is done here. It points at the plans rather than repeating them. Written 2026-09-14 at `main` = `c0a4d0a`; the session log at the bottom is where later sessions move the pointer.

---

## 1. What rampscan is, in three sentences

rampscan turns a git checkout into signed, commit-anchored compliance evidence for FedRAMP 20x, one row per Key Security Indicator, and computes the gap between what the catalog owes and what has been proven. Evidence comes from three sources: pipeline recipes the tool runs over the checkout, client-run AWS results the tool ingests but never executes, and human attestations signed with two keys. The value proposition is that every claim is *computed, signed and anchored*, and unknowns count against you rather than being waved through.

The appliance holds no AWS credential and makes no AWS call. That boundary is deliberate (`SECURITY.md`) and every plan below preserves it.

## 2. Where it is

| | |
|---|---|
| Version | `v0.1.0-beta`, public on GitHub since 2026-08-18. 0 stars, 0 forks, 2 views in the first fourteen days. Nobody outside this machine has read it yet. |
| Suite | 1,138 tests across 91 files, 0 expected failures (at PR #151; 1,127 at PR #150; 1,121 at `c0a4d0a`). `pnpm typecheck` clean. CI: `check`, `test`, `console-smoke`. |
| Plan of record | **`docs/PLAN-SOUNDNESS.md`, phases S0–S4.** Adopted 2026-09-13 (#123). Milestones S0–S4 on GitHub. |
| Paused | R2–R5 (`docs/PLAN-ARTIFACT-PLANE.md`, #102–#115). They resume at the S3 exit. Do not work them. |
| Drafted, not adopted | `docs/PLAN-CLOUD-RUNNER.md`, phases T0–T5 (PR #146). Builds after S1 closes. |

**Why the roadmap was reordered.** On 2026-09-13 the reachability gate was found to sign `not_affected` OpenVEX statements for any advisory in a package the code did not import directly, because "no node in the graph" was treated as proof of unreachability. That is the `SECURITY.md` class (a check that reports `evidenced` without the evidence). It is recorded in `docs/FINDING-VACUOUS-NOT-AFFECTED.md` and published as **GHSA-7jff-6v53-r56x**. Feature work stopped until soundness is restored and one stranger has looked.

### Phase status

| Phase | State | Notes |
|---|---|---|
| S0 record the finding | ✅ #144 | Advisory public, no embargo (S0-1). Supersede, never delete (S0-2). |
| S1 reachability soundness | ✅ closed 2026-09-15 | S1-1 (#145), S1-2 (#150), S1-3 (#152), barrel edge (#153), S1-4 (#154), S1-5 (#155) merged. Self-scan at `c0d1c73` reads `11 evidenced · 3 violated` — `next` ×2 exact, `postcss` ×2 via `sbom`, `sharp` ×2 unknown. One earned `not_affected` (`vitest`, a September advisory) the exit gate's letter forbids — recorded in the plan as met in intent, missed in letter. |
| S2 the numbers gate | ✅ closed 2026-09-15 | #133–#136 in one PR. `published-numbers.test.ts` (frontier + report arms) and `published-numbers-reporter.ts` (suite arm, at run end) gate the README; both shown red on the stale figures first. README regenerated (46 → 41, 33 → 28, `1,168 tests across 93 files`). ARCHITECTURE marked built/design per row; §7 says the human/machine signature line is one key with a recorded field. CONTRIBUTING rules 4 and 9 name their gates. |
| S3 the first stranger | S3-0 (#147) and S3-1 (#137) done; S3-2 next | S3-0 landed 2026-09-15 ahead of S2: the ingest adapter no longer reads exit 0 as a pass. S3-1 landed 2026-09-15: the package adapter, the Phase One → 2026 crosswalk, and `docs/RESEARCH-PARAMIFY-REGISTER.md` — the first gap register over a real authorized package (116 human-read methods on 38 KSIs, 0 automated, 3 obliged KSIs unreached, 8 of 51 validations retired to FRR). #138, #105, and **#72 due 2026-10-09**. Exit gate is a reply from someone outside the project. |
| S4 the surface S1 leans on | not started | #139–#141. |
| T cloud runner | drafted | Starts at the S1 exit. Three owner decisions pending (T0-1..T0-3). |

### Open items outside any phase

- **The history meter reads the earliest instant.** Surfaced by S3-1: one 2025 snapshot satisfies class c's 6-month `FRC-CSX-MOT` floor on 38 rows. A single stale capture is not persistent validation; the fold's G4 arm should want more than one instant, or cadence adherence. Filed as #159.
- #11 branch protection (owner-only), #13 retire the launch plan, #29 TypeScript 7, #30 Next 16, #142 fold cost (measured, not a problem), #143 register below the CLI (waits on S3).

## 3. What is next, in order

1. **S3** with #72 by 2026-10-09 — S3-0 (#147) and S3-1 (#137) are done; **S3-2 (#138)** sends `docs/RESEARCH-PARAMIFY-REGISTER.md` to Paramify, Coalfire and the 20x community channel with the one question; then S3-3 (#72) and S3-4 (#105). Then **S4**.
2. **T0** decisions, then T1–T4, without displacing S3. T0-2 (what a collected-only run counts for) now has a concrete starting state: such a bundle is `unevidenced` in the ledger, and the judgment path is what would move it.
3. **Owner call, not blocking:** whether #147 gets a published advisory like GHSA-7jff-6v53-r56x. Same class, but the path had only ever run on the fixture; S0-1's argument for filing (the advisory is an asset) applies, and so does the counter-argument that an advisory for a never-shipped path is noise.

## 4. The decisions already made — do not re-open

| Decision | Recorded |
|---|---|
| Disclosure: public advisory, no embargo, fix in the open | PLAN-SOUNDNESS §5 S0-1 |
| False `openvex.json`: supersede, never delete | S0-2 |
| Unreachability is proven positively or not claimed; SBOM edges prove presence only | PLAN-SOUNDNESS §0 rule 2, §7.3 |
| No phase is exited by its author; S3's gate is an outsider's reply | §0 rule 4 |
| Cloud evidence: one-click via a **client-deployed runner**, not guided upload, not appliance execution | PLAN-CLOUD-RUNNER, owner 2026-09-14 |
| Cloud runner builds **after S1**, never ahead of #72 | same |
| Exit 0 from a client script proves collection, not compliance | RESEARCH-PARAMIFY-PILOT §8.1, #147 |
| Nothing from the Paramify repository is vendored (no license); shapes only | RESEARCH-PARAMIFY-PILOT header, §7 |

## 5. How work is done here

**Per item.** One squash PR per numbered item. Subject suffixed `(#NN)`, body carries `Closes #NN`. CI green (`check`, `test`, `console-smoke`) before merge. Update the phase checkbox and the session log in the plan document in the same PR. Failing test first for any soundness change, wrapped in `it.fails` until the fix unwraps it.

**Verify.**
```
export PATH="$HOME/.nvm/versions/node/v22.22.2/bin:$HOME/.local/bin:$PATH"
pnpm typecheck        # tsc --build; NOT tsc -p --noEmit, which let a red run through once
pnpm test             # vitest; 1,138 at PR #151
```
`pnpm typecheck` does not cover `console/web`; the console has its own `tsc --build`. Stale `tsbuildinfo` can fake a red typecheck in untouched files; `tsc --build --clean` first. Scan tools (syft, osv-scanner, grype, semgrep, gitleaks, checkov) live in `~/.local/bin`; without that `PATH` the tool recipes go silently unevidenced.

**Ground rules that bite most often** (`CONTRIBUTING.md`, ten of them; `PLAN-SOUNDNESS.md` §0 adds four):
- **Rule 4, computed never typed.** A number enters a published document only in the change that regenerates it. Since S2 the README's figures are gated: `published-numbers.test.ts` and the suite reporter fail the run on drift, and a rephrased gated sentence fails too — regenerate from the command, in the same change.
- **Rule 7, no vacuous passes.** Absence of evidence is never evidence of absence. "0 of 0" is not a pass. This is the rule behind GHSA-7jff-6v53-r56x, #147, and the runner plan's ground rule 2.
- **The console smoke reads the basis statement.** Keep "Unknowns count against us", "declared route" and `src/index.js` verbatim in `OVER_APPROXIMATION_STATEMENT` and the fixture.

**Repository hygiene.** `rampscan-out/` and `rampscan-keys/` are gitignored and must stay so (`SECURITY.md`). Never surface the `sharma.trapti` identity anywhere. No AI attribution in commit messages or PR bodies. Reports go in `docs/` as local files, not published artifacts.

**Shell.** Use `/usr/bin/grep`, not bare `grep` (a shell function shadows it and silently finds nothing in single files). Quote glob patterns under zsh. `echo ===` errors in zsh.

## 6. Documents, by when to read them

| Read when | Document |
|---|---|
| Every session | this file; `docs/PLAN-SOUNDNESS.md` §5 (checkboxes and session log) |
| Touching reachability | `docs/FINDING-VACUOUS-NOT-AFFECTED.md`; `packages/collectors/src/reachability.ts`; `packages/collectors/test/reachability-soundness.test.ts` |
| Touching ingest, AWS, or the runner | `docs/SPEC.md` §12.8–§12.10; `docs/PLAN-CLOUD-RUNNER.md`; `docs/RESEARCH-PARAMIFY-PILOT.md` §8 |
| Touching the register, board, or gap classes | `docs/SPEC.md` §12; `docs/RESEARCH-KSI-GAP-ENGINE.md`; `docs/PLAN-KSI-PIVOT.md` |
| Touching the console | `console/web/PRODUCT.md`, `console/web/DESIGN.md` |
| Resuming R | `docs/PLAN-ARTIFACT-PLANE.md` — but not before the S3 exit |
| Architecture | `docs/ARCHITECTURE.md` — §3's table has a *Today (built)* and an *Appliance (design)* column since S2-3; §7 marks each control the same way |

## 7. What a good session looks like

Start: read §2 and §3 here, then the plan's session log, then `gh issue view` the next item. Confirm `main` is clean and CI is green. Work one item. Before the PR: failing test existed and now passes, `pnpm typecheck` and `pnpm test` clean, plan checkbox and session log updated, numbers in prose came from a command. End: move the pointer in §8 below.

Do not: start R work, start T code before S1 closes, add a `not_affected` path that rests on anything but a node the walk did not reach, type a number into README, or ask the owner a question the plans already answer.

---

## 8. Session log

- **2026-09-14** — Written at `c0a4d0a` after S1-1 merged, the cloud-runner plan was drafted (#146), and the Paramify pilot re-read surfaced #147 and the package-YAML adapter gap (#148). Next item: S1-2 (#129).
- **2026-09-14 (S1-2)** — PR #150 opened. Verifying it against this repository's own artifacts found that finding §4.4 was wrong: `next` is not reached from the configured entry point, so S1-2 moves nothing on the self-scan and S1-5 waits on S1-4. Next item: S1-3 (#130).
- **2026-09-14 (S1-3)** — PR #151 opened, stacked on #150. Measuring the width of the walk on this repository found a third application the plan had not counted (the workspace root's own 28 files) and a second extractor hole: `export … from` produces no edge, so every package barrel stops the walk. Recorded under S4-1 and put first in §3. Next item: the barrel edge, then S1-4 (#131).
- **2026-09-14 (barrel edge)** — #150 and #152 merged (S1-2, S1-3; #151 was auto-closed by the base branch's deletion and reopened as #152 with the same commit rebased — merge a stack bottom-up *without* `--delete-branch`, or retarget the upper PR first). The barrel edge landed in PR #153: nine lines in `extract.ts`, a planted-barrel test, extractor 0.4.0. Measured before opening the PR: 60 → 109 files reached, 12 → 12 dependency packages — recorded in the plan's S4-1 and the finding's §3.3 as a closed shape that moved no verdict on this tree. Next item: merge #153, then S1-4 (#131).
- **2026-09-14 (S1-4)** — #153 merged (barrel edge). S1-4 in PR #154: detection over every application root, `scripts` command lines, Next.js and PocketBase conventions; config honoured for the walk, its exclusions recorded on graph.db, basis, VEX scope and console; an unreached exclusion refuses the negative (the one judgment call, flagged in the PR). Measured: config 1 → 109 files / 12 packages / 2 roots never entered; detection 57 → 184 files / 15 packages / every root entered. S1-5 is now a config deletion. Suite 1,150. Next item: merge #154, then S1-5 (#132).
- **2026-09-14 (S1-5)** — #154 merged. S1-5 in PR #155: the override deleted, the board moved 12/2 → 11/3 exactly as the plan said and wider than it predicted (`next` CRITICAL ×2 reachable by one exact hop). One earned `not_affected` (`vitest`) that the exit gate's text forbids — flagged in the PR with the stricter alternative. FRONTIER-PIPELINE.md regenerated; its committed copy was a month stale. Next item: merge #155 → S1 closes; then #147, then S2.
- **2026-09-15 (S1 closed; S3-0 / #147)** — #155, #149, #148 merged; S1 closed at `286c566` with the `vitest` negative standing as recorded. #147 taken before S2 as S3-0: failing test first at `f4c27bd` (`expected 'evidenced' not to be 'evidenced'`), then the fix — manifest entries may declare structured assertions in `aws-evidence.json`'s vocabulary, evaluated by the appliance with the pipeline's own evaluator; no assertion signs `unevidenced`; a non-zero exit is a skipped failed run, never a bundle. SPEC §12.8 rewritten. Next item: S2-1 (#133).
- **2026-09-15 (S2, #133–#136)** — #156 merged (S3-0). S2 in one PR: the numbers gate written first and run at `679744b` against the stale README (46 vs 41, 33 vs 28, named line by line), the suite arm as a reporter because the count exists only at the end of the run (`vitest list` measured at 62 s and rebuilds fixtures under running tests), shown red on `1,001 tests across 81 files` before the README moved. README regenerated from the command; ARCHITECTURE split built from design per row and per control; CONTRIBUTING rules 4 and 9 gained *Enforced by*. S2 closes on merge. Next item: S3-1 (#137) — the package-YAML adapter first.
- **2026-09-15 (S3-1, #137)** — #157 merged (S2). The package adapter: `rampscan ingest <package.yaml>` with `--crosswalk` and `--cadence`; the failing test first at `71e45a9` (the adapter read the package as JSON). One correction to the research note's own design: `assessmentStatus` is not signed as an assertion — every bundle is `unevidenced`, `point-in-time`, `automated: false` (a new contract field the method derivation reads), and the package file is the one digested subject with the named artifacts riding by reference. The crosswalk `recipes/crosswalks/ksi-phase-one-to-2026.07.14.01.json` is the reviewed artifact §4 of the note budgeted for. The register over the 8/29 package is `docs/RESEARCH-PARAMIFY-REGISTER.md`. The register renders `+N` non-automated methods beside the floor cell, only when a row holds any. Next item: S3-2 (#138) — send it.
