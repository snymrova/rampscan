# rampscan — plan of action: per-KSI reach (Phases N0–N4)

**Status:** proposed 2026-09-21 at `main` = `0e9c8a8`, rules 2026.09.13.02. **Adopted 2026-09-21** by the owner ("go ahead"); building on stacked branches from N0. Milestones N0–N4 and one issue per numbered item are still to be created on GitHub, the way S, T, R and U were — the session that started N0 could not create them (see the log).
**Reads from:** `docs/RESEARCH-KSI-REACH.md` (the ladder, the table, the ranked moves). This document is the build list; that one is the argument.
**North star:** KSIs with at least one automated method inside its owed window, over the 41 class b obliges. Reads **0 / 41** today. Ceiling **40 / 41** (three required KSIs are attestation-only).

---

## 0. Ground rules, active from N0

The ten in `CONTRIBUTING.md`, the four in `PLAN-SOUNDNESS.md` §0 and the five in `PLAN-CLOUD-RUNNER.md` §0 stay active. Three are specific to this plan.

1. **A rung is earned by the ledger, never by the catalog.** `wired` is the highest rung a recipe or adapter can confer by existing. `run` and above come only from signed bundles the fold reads. A tool on the shelf moves nothing.
2. **Every item names the rows it moves before it is started, and the number after it lands comes from `frontier`.** The projections in this document are arithmetic; the plan's session log records what the command printed.
3. **A second plane is only counted as distinct when it observes a different thing.** A checkov row proves declared state; a runner row proves account state. Both on one KSI is two planes. Two SARIF tools over the same checkout is one.

---

## 1. Your dependencies, and what each unblocks

These are the things only the owner can supply. Nothing below waits on them except where the table says so.

| # | Owner input | Unblocks | Without it |
|---|---|---|---|
| D1 | **Adopt this plan** (milestones + issues) | N0 onward as tracked work | items still buildable on stacked branches, untracked |
| D2 | **A signing keypair as a repository secret** for the scheduled self-scan (`rampscan-keys/` contents, or a fresh pair minted for CI only) | N1-2 | N1-1 runs unsigned and its ledger is a rehearsal, not evidence |
| D3 | **Where the persistent ledger lives** — a private `rampscan-ledger` repository, or release assets on this one (recommendation: private repo; §4 N1-2) | N1-2, R3 history accumulating | N1 proves the clock for one run and history never accumulates |
| D4 | **Sandbox AWS account** (already owed to T3/T4 exit gates; cost question open since 2026-09-17) | N3-2, N3-3, T3/T4 exit gates | the cloud plane stays at `wired`; ~17 to 26 rows never reach `run` |
| D5 | **A GitHub token or App** with read on pull requests and security advisories | N4-1 (forge plane, R4.4) | `KSI-CMT-RVP` stays on one plane; `KSI-PIY-RVD` stays on `SECURITY.md` presence |
| D6 | **Three attestations**, signed by you as approver, for `KSI-CED-RAT`, `KSI-PIY-RES`, `KSI-PIY-RIS` | N4-3 | three required rows stay G1 forever; the ceiling is 37 not 40 |
| D7 | **The R4 re-scope call** (VER plane vs three exports) | out of this plan; R4 | nothing here |

D2 and D3 are the only two the first non-zero north star waits on. Both are an afternoon.

---

## 2. Blockers that are not yours

| Blocker | Affects | Resolution in plan |
|---|---|---|
| The self-scan's collectors need `syft`, `osv-scanner`, `grype`, `semgrep`, `gitleaks`, `checkov`, `spectral` on `PATH` in CI; today `smoke.yml` and `test.yml` may not install all of them | N1-1 | N1-1 pins each tool version in the workflow; a tool absent in CI is a **blocked** coverage unit, printed, never a silent skip (`tools.ts` already returns `absentReason`) |
| Checkov's rule ids move between versions | N2-1 | the crosswalk is pinned to a checkov version; drift fails the golden test, like the Prowler pin |
| SARIF rule ids are per tool and unmapped to KSIs anywhere upstream | N2-2 | the crosswalk is ours, reviewed, per tool version; an unknown rule id refuses the batch |
| `rampscan recipes --aws` reads 47 runnable only when every placeholder is bound, including ids a previous step would discover (detector id, finding id) | N3-1 | bind what config can own; the rest stay `manual` with their reason and are counted as such |
| `KSI-SVC-RUD` is optional at class b and reachable by nothing | N4-3 | left G1 and labelled optional; not in the 41 |
| Next 16 / TypeScript 7 upgrades (#30, #29) can break the console smoke mid-plan | every item that touches `console/web` | do not upgrade inside this plan |

---

## 3. Sequencing

| Phase | Item | Rows moved (projected) | Days | Waits on |
|---|---|---|---|---|
| N0 | the ladder, printed | 0, and says so | 1 | nothing |
| N1 | the clock | 13 → `fresh` | 2 | D2, D3 |
| N2 | commit plane widened | up to +8 → `run`; SARIF wired for clients | 4 | nothing |
| N3 | cloud plane lit | up to +13 → `run` (26 with N1), up to 38 with params bound | 1 + owner | D4 |
| N4 | the reviewing KSIs, and the four | +1 plane on `CMT-RVP`; +3 covered | 3 + owner | D5, D6 |

Total: about 11 working days of build, spread around the owner inputs. N0 and N2 need nothing from you. N1 needs two afternoons of yours. N3 and N4 are gated on the account, the token and three signatures.

---

### Phase N0 — the ladder, printed (1 day)

- [x] **N0-1. `reachOf(ksi)` in the fold.** A pure function over the register row: returns the rung (`unreachable | reachable | wired | run | fresh | floor | distinct`) and the reason for the rung below it not being earned. `reachable` reads the three pins (`recipes/commit/`, `aws-evidence.json`, `docs/context/prowler/`); `wired` reads catalog methods plus `classifyAwsRecipe` plus the ingest adapters' declared coverage; `run`, `fresh`, `floor` read what G1, G3, G2 already compute; `distinct` counts distinct `source` among automated methods meeting the floor. **Where:** `packages/projector/src/fold.ts` beside the G-class assignment; type in `packages/schema/src/method.ts`. **Test first:** a fixture ledger where one KSI sits on each rung; `KSI-CED-RAT` must read `unreachable` with the three pins as the reason.
- [x] **N0-2. `frontier` prints it.** One column, `reach`, and a footer line: `fresh: N of 41 — the north star`. `packages/cli/src/frontier.ts`. **README-gated:** `published-numbers.test.ts` gains the footer arm, README regenerated in the same PR (ground rule 4).
- [ ] **N0-3. The KSI page shows it.** *(waits on U1, #236 — the projection already carries `reach` per row, so U1 renders a field rather than computing one.)* U1's `/ksi/[id]` (#236) gets the ladder as its first section: the rung, and the sentence saying what earns the next one. This is the only console work in the plan and it rides U1 rather than preceding it.

**Exit gate:** `pnpm rampscan frontier` prints `fresh: 0 of 41` on this checkout, the README carries that line from the command, and the fixture test pins one KSI per rung.

---

### Phase N1 — the clock (2 days, plus D2 and D3)

- [x] **N1-1. `scan.yml`: a scheduled self-scan.** `on: schedule` weekly (the tightest declared cadence in `recipes/commit/` is daily on 4 recipes; weekly matches the 14 and the class-b MVX window of 7 days), plus `workflow_dispatch`. Installs the seven pinned tools at pinned versions, runs `rampscan scan --out rampscan-out`, then `rampscan verify`, then `rampscan frontier`. Uploads `rampscan-out/` as a workflow artifact. **Test first:** a workflow-level assertion that every collector in the manifest either ran or is named in the outcome with `absentReason`; a run where one tool is deliberately absent must fail that check. **Waits on:** nothing; without D2 it signs with a throwaway pair and says so in the artifact name.
- [ ] **N1-2. The ledger persists.** The workflow checks out the ledger repository (D3), appends the run's statements, pushes. Signing uses D2 from a secret; the key never enters this repository. `rampscan rebuild` over the persisted ledger must reproduce the projection (`projection ≡ ledger`, the existing proof). **Waits on:** D2, D3.
- [ ] **N1-3. The README follows the clock.** `published-numbers.test.ts` reads the register from the persisted ledger's latest fold, not from a local `rampscan-out`; the README's `frontier` block is regenerated by the scheduled workflow in a PR it opens (never a direct push to `main`; #11 branch protection is still owner-blocked). **Waits on:** N1-2.
- [x] **N1-4. `daemon` parity.** `rampscan daemon` (the local scheduler) is documented as the appliance form of N1-1; one test that its `ensureCadence` tick would have requested the same scan the workflow ran. No new code beyond the test unless it fails.

**Exit gate:** two consecutive scheduled runs have landed in the persisted ledger; `frontier` over it prints `fresh: 13 of 41`, and the number in the README came from that run's PR.

---

### Phase N2 — the commit plane widened (4 days)

- [x] **N2-1. Checkov rule → KSI crosswalk.** `recipes/crosswalks/checkov-<version>-to-2026.09.13.02.json`, one entry per checkov rule id we admit, with `ksi`, `basis`, and `proves: "declared-state"`. Reviewed by hand; a rule id absent from the pinned checkov version fails the golden test. Then `methodsOf` derives one recipe per KSI over the same `checkov-results.json`, each with its own assertion (`count_eq 0 where check_id in <the KSI's rules>`) and its own population sentence. **Candidate rows:** `CNA-MAT`, `CNA-RNT`, `CNA-ULN`, `IAM-SNU`, `MLA-LET`, `MLA-OSM`, `RPL-ABO`, `SVC-VCM`, `SVC-SIN`. **Test first:** the soundness test — a KSI whose rule set matched no file in the tree is `unevidenced`, never `evidenced` (empty means clean only when the framework was present; `checkov.ts` already skips honestly per framework, and this must survive the split). **Where:** `packages/collectors/src/checkov.ts`, `packages/schema/src/recipe.ts` (a `derived_from` field so the register can say these rows share one artifact), `packages/cli/src/frontier.ts` (print `declared` beside the method). 2 days.
- [x] **N2-2. SARIF ingest adapter.** `rampscan ingest <file.sarif>`, sniffed on `$schema`/`version`. Prowler-shaped: a reader (`sarif.ts`), the adapter (`sarif-ingest.ts`), a per-tool crosswalk pinned to the tool version (`recipes/crosswalks/sarif-<tool>-<version>.json`), and the same four refusals (our assertion `count_eq 0 where level = error`; the tool's `kind`/`level` is data; a run with zero results must carry `invocations[].executionSuccessful = true` and a stated population or it is `unevidenced`; `--exit-code` declared because SARIF records none; a `ruleId` the crosswalk does not carry refuses the batch). Rows carry `reachable: unknown`, printed, because there is no graph behind a client's SARIF. `--signer`, `--cadence`, `--tool` required. **Test first:** `sarif-ingest-soundness.test.ts`, red first, on: an empty `results[]` from a failed invocation; a suppressed result (`suppressions[]` present → counted, not waived, the Prowler mute rule); a rule id outside the crosswalk. **First crosswalks:** semgrep (so our own collector's output round-trips), zizmor, trivy. 2 days.

**Exit gate:** `frontier` on this checkout prints checkov-derived methods on at least four KSIs beyond `SVC-ACM`, each labelled `declared`; `rampscan ingest fixtures/ingest-sarif/semgrep.sarif` mints bundles whose verdicts equal the pipeline collector's over the same tree; the soundness suite is green with every refusal exercised.

---

### Phase N3 — the cloud plane lit (1 day, plus D4)

- [ ] **N3-1. Bind `aws.params`.** `rampscan.config.json` gains the `aws` block for the self-scan's account (the sandbox, once D4) and every placeholder `recipes --aws` lists that a config can own (`TRAIL_ARN`, `LOG_BUCKET`, `KMS_KEY_ARN`, `BACKUP_VAULT_NAME`, …). The command's runnable count is pasted into this plan's log from its output. Placeholders a previous step must discover (`FINDING_ID`, `DETECTOR_ID`) stay `manual` with the reason. Half a day. **Waits on:** nothing to write; D4 to mean anything.
- [ ] **N3-2. T3/T4 exit gates.** The sequence the way-ahead already spells out: `rampscan-runner init`, `rampscan runner register`, `rampscan runner policy` → attach, `rampscan serve --repo .`, *Collect evidence* on `KSI-IAM-APM`; then remove `iam:GetCredentialReport` and click again for the `failed(denied)` row. Half a day. **Waits on:** D4.
- [ ] **N3-3. Prowler run and ingest.** `prowler aws --compliance fedramp_20x_ksi_2026 -M ocsf-json` against the sandbox, then `rampscan ingest <file>` with `--signer`, `--exit-code`, `--cadence`. The `MANUAL` rows for the 13 uncovered KSIs must be skipped and named. Half a day. **Waits on:** D4.
- [ ] **N3-4. T5-1 (#186) becomes N1's cloud twin.** Scheduled `RunRequest`s ahead of each MVX window, so the cloud rows stay `fresh` without a click. Already specified in `PLAN-CLOUD-RUNNER.md`; 1 day. **Waits on:** N3-2.

**Exit gate:** `frontier` over the persisted ledger prints `run` on every KSI the runner's executable set and Prowler reach; `distinct ≥ 2` on the KSIs both the pipeline and AWS reach; the two exit-gate rows (`evidenced` then `failed(denied)`) are in the ledger.

---

### Phase N4 — the reviewing KSIs, and the four (3 days, plus D5 and D6)

- [ ] **N4-1. The forge plane (R4.4, #112).** `RepoSource` gains `reviewsOf(path, commit)` on the GitHub adapter; the local adapter returns `unknown`, printed. A recipe `change-review-recorded` over pull-request approval metadata for the scanned commit's merge, `KSI-CMT-RVP`, `automated: true` because the forge produced the row. The `review` field on authored artifacts (`packages/core/src/artifact.ts:53`) is filled from the same call. 2 days. **Waits on:** D5.
- [ ] **N4-2. Advisories for `KSI-PIY-RVD`.** A second method beside `security-disclosure-published`: the repository's published advisories and their acknowledgement times, over the GitHub API, asserting the `SECURITY.md` windows were met (7-day acknowledgement, 14-day assessment). `automated: true`. Half a day. **Waits on:** D5.
- [ ] **N4-3. Attestations for the three required unreachable KSIs.** `recordAttestation` for `KSI-CED-RAT`, `KSI-PIY-RES`, `KSI-PIY-RIS` with a real statement each; `KSI-SVC-RUD` left G1 and labelled optional. The console's attestation form (built) is the path; the 3-month `VDR-TFR-NMV` clock then ages them. Half a day of yours. **Waits on:** D6.
- [ ] **N4-4. Tracker ingest, manifest-shaped.** `rampscan ingest <dir>` already accepts an evidence tree with an `ingest-manifest.json`; document the manifest for an incident tracker export (`INR-AAR`, `INR-RIR`, `INR-RPI`) and a log-review schedule (`MLA-RVL`), `automated: false` unless the tracker's own API produced the rows on a clock. No code beyond a fixture and its test unless the manifest schema needs a field. Half a day.

**Exit gate:** `frontier` prints `covered` on 41 of 41 and `automated` on 40; `KSI-CMT-RVP` shows `distinct: 2`; the three attestations sit on the non-machine clock with their dates.

---

## 4. Decisions to make at adoption

1. **D3, where the ledger lives.** Recommendation: a private `snymrova/rampscan-ledger` repository. Reasons: `git` gives append-only-by-review for free, R3's history folds over it, and a release asset cannot be diffed. The alternative, workflow artifacts, expire.
2. **Whether N2-1's checkov-derived methods count toward the class-b floor.** Recommendation: yes at class b (floor 1, and declared state is a real observation), and the register prints `declared` so an assessor sees it; at class c a KSI whose only two methods are both `declared` does not meet the floor of 2 (ground rule 3 above).
3. **N1's cadence.** Recommendation: weekly, `main` only. Daily costs seven times the CI minutes for a register that changes when the code does.

---

## 5. What is true when it is done

- `frontier` prints a rung per KSI and one north-star line, from the ledger, README-gated.
- The self-scan runs itself, signs itself, and persists; its register is fresh without anyone remembering.
- The commit plane reaches up to 21 KSIs, two of them on a second plane; a client's own CI output can join the register through one adapter.
- The cloud plane has run against a real account and the runner has produced both the pass row and the denied row.
- 41 of 41 are covered, 40 by machine, and the three that cannot be are signed by a person and on a clock.

## 6. Honest constraints

- **The account is the schedule.** N3 is one day of build and every projected row above 26 waits on D4. If the account is not coming this quarter, N3 should be re-ordered behind N4 rather than left open.
- **Declared state is not account state.** N2-1 will look like a large jump on the table. The `declared` label and ground rule 3 are what keep it honest, and the way-ahead should say so where it quotes the number.
- **This plan adds one crosswalk per tool version.** Pin drift on checkov and each SARIF tool is ongoing maintenance, the same class as the runner's allowlist. `pin-drift.yml` should learn each new pin.
- **CI minutes.** A weekly self-scan with seven tools is small; a daily one is not free. Measured, not guessed, at N1's exit.

## Session log

- **2026-09-21** — proposed, from `docs/RESEARCH-KSI-REACH.md`. Not adopted.
- **2026-09-21 (adopted; N0-1, N0-2 built)** — The owner adopted the plan ("go ahead"). Built on `feat/n0-reach-ladder` from `main` = `0e9c8a8`. The ladder is `reachOf(subject, pins)` in `packages/projector/src/fold.ts`, pure over a row's cells and a per-KSI `ReachPin[]` (`packages/schema/src/method.ts`: `ReachRung`, `ReachPlane`, `ReachPin`, `KsiReach`); the fold sets `row.reach` when handed `reach` pins and never opens a pin itself; `packages/cli/src/reach-pins.ts` reads the three pins once per command. Both projection stores round-trip the field; the console record type carries it for U1. `frontier` prints a `reach` column and, under the covering line, `fresh: N of 41 — the north star` (README-gated, the gate's fifth line) and a rung tally. Two calls made in the build, both to review: **(a) the Prowler plane counts as `wired`**, not merely `reachable`, because the ingest adapter is pinned to the framework and mints a method from any of its checks — the plan text says "the ingest adapters' declared coverage" wires, and this is that; the research table's hand count (wired-only 12) read Prowler as reachable, so the printed tally differs from it (ground rule 2: the number is the command's). **(b) `floor` is judged over the FRESH automated methods**, not G2's count of methods that exist: every rung implies the ones below it, and a floor met by a stale method would be a rung earned by evidence outside its window; at class b the two readings coincide. Attestations do not climb the ladder (`automated: false`), which is what keeps `KSI-CED-RAT` at `unreachable` with the three pins as the reason, as N0-1's test demands. The command printed, on this checkout over the local self-scan ledger: `fresh: 0 of 41 — the north star` and `reach: unreachable 3 · reachable 4 · wired 26 · run 8 · fresh 0 · floor 0 · distinct 0`; over no ledger, `wired 34 · run 0`. The README block was regenerated from that run; SPEC §12.5 was amended for the column and the two lines. **N0's exit gate is met** except N0-3, which rides U1 (#236) by design. **GitHub adoption is owed:** the session's attempt to create milestones N0–N4 was refused by the tool permission layer, so the milestones and the seventeen issues are still to be created (titles in §3; the descriptions are the exit gates).
- **2026-09-21 (N2-1 built)** — On `feat/n2-checkov-crosswalk`, stacked on N0. `recipes/crosswalks/checkov-3.3.11-to-2026.09.13.02.json` admits 187 rule ids from the pinned image, each filed under exactly one KSI with a basis, over nine rows: `CNA-MAT` (21), `CNA-RNT` (15), `CNA-ULN` (12), `IAM-SNU` (6), `MLA-LET` (27), `MLA-OSM` (10), `RPL-ABO` (17), `SVC-SIN` (69), `SVC-VCM` (10, optional at b); `SVC-SIN` was already on the commit plane, so the table moves by seven obliged rows. The pinned image's full rule list is vendored beside it (`checkov-3.3.11-checks.json`, 1,179 rules; regenerated by the command in its header) and `checkov-crosswalk.test.ts` refuses an id it does not carry and a version the three pins disagree on. **The derived recipes are generated files in `recipes/commit/`** (`scripts/derive-recipes.ts`; `iac-*-declared.json`), not values conjured at load, so every catalog invariant — plain prose on disk, manifest ↔ file agreement, the empty-set declaration — holds for them unchanged, and the test fails the build when a file stops equalling `deriveCheckovRecipes(crosswalk, base)`. `PipelineRecipe.derived_from` (recipe, crosswalk, `proves: declared-state`, checks) rides into `PipelineProvenance.derived_from` and onto the method cell as `derivedFrom`/`proves`. **The soundness rule** is `derivedObservations` in the checkov collector, tested red-first: a derived recipe's observation set exists only when at least one of its rules was EVALUATED this run (present in checkov's passed or failed checks, now written to the artifact as `evaluated_check_ids`); a tree where none applied gets no key and stays `unevidenced` — the Guard pattern, one level above the base recipe's Skip. The collector reads its rule sets from `CollectContext.recipes`, which the local runner now hands every collector; the scan cache is salted with the derived rule sets. `frontier` prints `N declared` in the methods cell and a legend line. **§4 decision 2 taken as recommended, on the ladder rather than on G2:** `reachOf` counts fresh methods by OBSERVATION (`source` × the artifact's recipe) toward the floor, so at class c two declared rows over one checkov result are one; G2 stays as the rules define it. Fifteen controls newly claimed (none on upstream's `pipeline` plane; none adjudicated), so `--by-controls` reads 38 of 209 covered · 47 reachable. `frontier` now prints `floor met on 20 of 41 · no method on 21` (was 13 / 28); `fresh: 0 of 41` unchanged — the clock is N1's. README regenerated from the command; the "twenty recipes" sentence corrected to twenty-nine.
- **2026-09-21 (N2-2 built)** — On `feat/n2-checkov-crosswalk` beside N2-1. `rampscan ingest <file.sarif>`, sniffed on content (`runs[]` plus a SARIF `$schema` or `version: 2.1.0`), `--tool`, `--exit-code`, `--signer`, `--cadence` required, and `--timestamp` when the log records no `invocations[].endTimeUtc` (neither semgrep nor zizmor writes one) — the ingest instant is never used as the run's clock, so the same bytes declared the same way are the same bundle. The reader (`packages/cli/src/sarif.ts`) takes two SARIF facts at the spec's word — a result's missing `level` is its rule's `defaultConfiguration.level` (Semgrep writes ERROR on the rule, nothing on the result), a missing `kind` is `fail` — and refuses another SARIF version, a log from two tools, and a result naming no rule. The adapter (`sarif-ingest.ts`) is Prowler-shaped and carries the five refusals as a red-first suite: the assertion is rampscan's (`count_eq 0` where `level = error`; the tool's verdict is data); a suppressed result is counted, never waived; a declared non-zero exit or the log's own `executionSuccessful: false` skips every rule, named; a zero-result rule is clean only when the driver DECLARED it ran (`tool.driver.rules`) on a successful invocation, else skipped and named; a rule the crosswalk does not file refuses the batch. Every row states **reachability unknown** (no graph behind a client's log) and **plane `commit`**. **Two crosswalks**, each with a vendored rule list pinned to the version: `sarif-semgrep-oss-1.173.0` (the three ids of rampscan's own vendored ruleset at the image `tools.json` pins, so the collector's SAST round-trips — the fixture is semgrep over `fixtures/vulnerable-app`: `dangerous-eval` violated under `PIY-RSD`, the pipeline's verdict on the same tree) and `sarif-zizmor-1.30.1` (all 41 documented audits filed, pedantic ones included, because an unfiled audit refuses the batch — the fixture is zizmor over this repository's own workflows: `excessive-permissions` violated under `CNA-MAT`). trivy is not done: its SARIF rule ids are CVE ids for vulnerabilities and `AVD-*` for misconfigurations, an unbounded set the batch-refusal rule cannot admit without a different design (a rule-family crosswalk); left for a follow-up and said so. **The plane call:** `MethodSource` stays closed (`aws-ingested` names the mechanism the bytes came in by); the submission, the bundle's `ingest` block and the method's provenance gain `plane: commit | cloud` (absent reads cloud, what every earlier submission was about), the cell gets `plane` (`planeOf` / `planeOfCell`), and `reachOf`'s `distinct` counts planes, so a client's SAST beside the pipeline reads one plane. Renaming the source is a reviewed schema change deliberately not made here. The crosswalk `rule` headers and `checkov-crosswalk.test.ts`'s siblings (`sarif-crosswalk.test.ts`) pin the versions three ways. N2's exit gate is met: checkov-derived methods on eight KSIs beyond `SVC-ACM` labelled `declared`; `rampscan ingest fixtures/ingest-sarif/semgrep.sarif --tool semgrep-oss` mints bundles whose verdicts equal the pipeline collector's over the same tree; the soundness suites are green with every refusal exercised.
- **2026-09-21 (N1-1, N1-4 built; N1-2, N1-3 wait on D2 and D3)** — On `feat/n1-clock`, stacked on N2. `.github/workflows/scan.yml`: weekly (`0 6 * * 1`, the class-b window) plus `workflow_dispatch`; installs the four binaries at the versions `tools.json` pins and pulls the three pinned images; `rampscan scan .` → the coverage assertion → `rampscan rebuild` (projection ≡ ledger) → `rampscan frontier`; uploads `rampscan-out/` and the ledger as an artifact named `self-scan-<repository-key|throwaway-key>-<sha>`. Without D2 the signer mints a throwaway pair on the runner and the artifact name says so. **The coverage assertion** (`packages/cli/src/self-scan-assert.ts`, `scripts/self-scan-assert.ts --require-tools`), test-first: every registered collector either ran (its tool version is in the result) or is named in `skipped_collectors` with its reason; a collector neither run nor named fails in every mode; a skip whose reason is an absent tool fails under `--require-tools`, the workflow's mode — a tool absent in CI is a blocked coverage unit, printed, never silent. Over the scratch self-scan of this checkout it reads eleven ran, two honestly skipped (spectral: nothing API-shaped; grype: no root Dockerfile), ok. **N1-4** is `daemon-parity.test.ts`: the cron is read from the file, held to be no slower than the class-b window, and `assessCadence` over evidence from the previous run must already say `scanDue` (reason `cadence`) by the time the next run fires — the daemon would have requested the same scan. No new daemon code. **N1's exit gate is not met and cannot be from here:** it wants two consecutive scheduled runs in the *persisted* ledger and a README number from that run's PR — N1-2 needs the signing key as a secret (D2) and the ledger home (D3), N1-3 needs N1-2. The workflow will run on its schedule once merged and upload a throwaway-signed rehearsal until then.
