# rampscan — implementation plan: depth (Phases N0–N3)

**Status:** task breakdown and scope for `docs/PLAN-OF-ACTION-DEPTH.md`. That document owns the *argument* — why coverage leads, why languages stay deferred, what the fork is. This one owns **what gets built, where, in what order, and what test closes it**. On a scope dispute this document wins over the checklist; on an architecture dispute `docs/SPEC.md` wins over this one.
**Date:** 2026-08-16
**Reads against:** the code, and `docs/PLAN-OF-ACTION-DEPTH.md`. Nothing else was opened.
**Supersedes as plan of record:** `docs/IMPLEMENTATION-PLAN-ONTOLOGY-ONDEVICE-LLM.md` (L0–L3c landed; L3d deferred; L4/L5 cancelled 2026-08-16).

```
N0  the catalog's honesty test         2.5–3 d   ← the spine; everything else rests on it
N1  the pipeline adjudication          12–15 d   ← the lead axis
N2  the loop                            3.5 d
N3  claim fidelity                      6–7 d
                                       ────────
                                       24–29 d
```

---

## 1. N0 — the catalog's honesty test

The plan-of-action's ground rule 7 says a recipe may never report `evidenced` from the *absence* of something to check. Today that rule is real but unwritten: it is enforced by hand, in four different patterns, verified by per-collector tests, with **no catalog-wide check**. N1 is about to triple the catalog. This gets built first.

### 1.1 Where the vacuous pass actually lives

Located precisely, so the test aims at the right thing.

`join.ts` returns `unevidenced` when `run.observations[recipe.id] === undefined`. **An empty array is defined.** So a collector that emits `observations: { "some-recipe": [] }` sends zero rows into `evaluateAssertions`, where `assert.ts` gives them both:

- `count_eq 0` over an empty filtered set → `filtered.length === 0` → **passes**
- a row-wise op over an empty filtered set → `offenders.length === 0` → **passes vacuously** (correct for "every active key is rotated"; catastrophic for "the repo has a security policy")

Every assertion passing → `verdict: "evidenced"`. That is the whole failure mode, and it is one line of collector code away at all times.

### 1.2 The four patterns the catalog already uses, named for the first time

All four are in the tree and none has a name. Naming them is most of the work of testing them.

| Pattern | Mechanism | Where | Join result on a barren repo |
|---|---|---|---|
| **Guard** | omit the observation key entirely when there is nothing to observe | `graph.ts:156` (`rows.length > 0 ? {…} : {}`), `repo-facts` for `ci-actions-pinned` / `container-runs-nonroot` / `lockfile-pinned-deps` | `unevidenced` — "ran but produced no observation" |
| **Skip** | collector returns `skipped: { reason }` | `checkov`, `spectral`, `grype`, `contract` | `unevidenced` — with the stated reason |
| **Witness** | emit exactly **one** row carrying the existence boolean; assert on it | `codeowners_present`, `automated`, `nonroot`, `lockfile_present` | `violated` — honestly |
| **Counter** | emit one summary row of counts; assert `gte 1` | `ci-provenance-present`, `tests-in-ci` → `{workflow_count, …}` | `violated` — honestly |

Plus a fifth used only by `contract.ts`: the **negative witness** — a `matched: false` row per declared-but-unmatched rule, asserted `count_eq 0`, so a typo'd rule fails instead of guarding nothing.

**The anti-pattern is the absence of all five:** emit `[]`, assert `count_eq 0`, report `evidenced`.

### 1.3 The empirical baseline — what the barren fixture says today

`fixtures/bare-app` (a library with no pipeline, no container, no API surface, no contract) already has a recorded scan at `e2e/.smoke/out-bare/scan-result.json`. Its verdict split is **5 evidenced · 4 violated · 8 unevidenced**, and the five defences hold cleanly: every guard and skip lands `unevidenced`, every witness and counter lands `violated`.

So there is no clear-cut vacuous pass in the catalog today. But the five `evidenced` rows do not all mean the same thing:

| Recipe | Passes because | Reading |
|---|---|---|
| `lockfile-pinned-deps` | `lockfile_present: true` — the file is really there | genuine |
| `sbom-exists-and-fresh` | syft ran and produced a real SBOM | genuine |
| `no-secrets-in-history` | gitleaks searched the whole history, found nothing | genuine — **exhaustive search over a real domain** |
| `no-critical-reachable-advisories` | `count 0` — over a repo with **zero dependencies** | true, and **the domain is empty** |
| `no-reachable-dangerous-code` | `count 0` — over 3 semgrep rules on a trivial file | true, and **the domain is nearly empty** |

That last pair is the finding worth acting on. Both are honest — the collectors genuinely ran — but an auditor shown `evidenced` against `ra-5`, `si-2` and `si-5` on a repository with no dependencies has been told something much weaker than the badge suggests. **`count 0` is ambiguous: "0 of 412" and "0 of 0" are different facts, and only one of them is evidence.**

### 1.4 The build

**N0-T1 — `population` on count-based claims.** Every count assertion states the population it counted over.

- `packages/core/src/assert.ts`: on `count_eq`/`count_lte`, carry the pre-filter row count onto `AssertionResult` as `population` alongside the existing `detail`. **Do not touch `detail`** — it participates in `sameEvidence` and must stay byte-identical, the same discipline I2c used for `offenders`.
- `packages/schema`: `population?: number` on `AssertionResult`; excluded from `sameEvidence` for the same reason, so nothing re-keys.
- Surfaces: the board row and the evidence page render `0 of 412` / `0 of 0`. An empty-domain pass is visibly different from an exhaustive one.

**N0-T2 — `empty_means` on the recipe.** The one thing a static test cannot infer: whether an empty observation set is a genuine clean result or a missing domain. The recipe declares it.

```
empty_means: "clean"        the collector searched an existing domain and found nothing
                            (no-secrets-in-history: gitleaks walked every commit)
empty_means: "unevidenced"  an empty set means there was nothing to search;
                            the collector MUST guard or skip, never emit []
```

- `packages/schema/src/recipe.ts`: optional in the shape, **required in the shipped catalog** — the exact split `plain` already uses, and for the same stated reason (the recipe shape mirrors `aws-evidence.json`, which has no such field, so an imported recipe must still parse). Shape is the schema's job; completeness is policy's.
- Backfill all 17 existing recipes.

**N0-T3 — `packages/cli/test/catalog.test.ts`, the static half.** Modelled on `plain.test.ts`, which is the house precedent for "policy lives in a test that fails CI, not in a convention someone remembers."

1. Every recipe in `recipes/pipeline/` declares `empty_means`.
2. Every recipe whose assertions are *all* count-ops or row-wise ops (i.e. every recipe that can pass over zero rows) declares it explicitly rather than inheriting a default — there is no default.
3. Every `empty_means: "clean"` recipe's `notes` states what domain was searched exhaustively. A clean claim that cannot say what it searched is not a clean claim.
4. Every recipe names a collector that exists and whose manifest declares it — this closes the `tools`-map link at catalog level rather than only in `rampscan tools`.

**N0-T4 — the dynamic half, and the real teeth.** A vitest run of the full collector set against `fixtures/bare-app`, joined, asserting:

1. **No recipe declaring `empty_means: "unevidenced"` reaches `evidenced`.** This is the regression that N1 needs and the one a hand-written recipe will break first.
2. Every `evidenced` row on the barren fixture is either `empty_means: "clean"` **or** carries a non-zero `population`. A pass over an empty domain that has not declared itself is a failure.
3. The verdict split is pinned against the recorded baseline (5/4/8), so any movement is deliberate and reviewed rather than discovered.

This extends a property the repo already wrote down once — *anything reachable only from an empty row is testable only on `bare-app`* — from the console's affordances to the catalog itself. `e2e/smoke-server.mjs:117` already asserts bare-app produces at least one unevidenced recipe; nothing yet asserts it produces no *falsely evidenced* one.

**N0-T5 — record the six decisions** from the plan-of-action §3 into this document's changelog, including the N2a-vs-deferred-engine-CI distinction, so that deferral is not reopened by accident.

**Exit test (N0):** adding a deliberately vacuous recipe — one that emits `[]` and asserts `count_eq 0` — fails CI with a message naming the recipe and the pattern it should have used; all 17 existing recipes pass unchanged; no bundle digest in `rampscan-ledger/` changes as a result of the `population` addition.

*Estimate: 2.5–3 days.*

---

## 2. N1 — the pipeline adjudication (the lead axis)

### 2.1 N1a — adjudicate the 121 from the pipeline source

`automation-frontier.json` carries 121 uncovered controls adjudicated from **one** source: `rollup.bySource.aws` reads covered 88 / partial 21 / narrative 27 / unreviewed 73, while `rollup.bySource.pipeline` reads **0 covered, 121 unreviewed, ceiling 0**. Every reviewed rationale reasons about CloudTrail, Config, Access Analyzer, KMS. Nobody has asked what a *repository* can answer.

**N1a-T1 — the adjudication record.** `recipes/adjudications/<control-id>.json`, one file per control, exactly as SPEC §10.2 specifies. **Not** written back into `automation-frontier.json`, which is upstream's file behind a version pin the dataset client hard-fails on (ground rule 2).

```
controlId · displayId · family · disposition · rationale
source: "pipeline" · recipeIds[] · candidateCollectors[]
remainder            ← required when disposition is "partial"
reviewed · datasetVersion
```

Field names mirror the frontier's own vocabulary because SPEC §10.2's stated goal is that this overlay be *contributable upstream* — mirroring now makes that a merge, diverging now makes it a rewrite. Zod schema in `packages/schema/src/adjudication.ts`; loader beside `loadRecipes` in `packages/cli/src/adjudications.ts`.

**N1a-T2 — `rampscan frontier`.** A pure derivation in the shape of `rampscan tools` and `rampscan model`: catalog × adjudications × pinned frontier → coverage, `--json`, nothing probed, nothing written, non-zero exit on a broken link (an adjudication naming a recipe or collector that does not exist, or a control not on the frontier). This is ground rule 9's enforcement — **after N1a the coverage number is a command's output**, and every later claim about coverage quotes it.

**N1a-T3 — write the 121.** The data work. Disposition plus an authored paragraph each, in the upstream voice. Start with the 44 in scope for class b (the CLI default), then the 80 in repo-plausible families (CM SA SR SI RA CA AU SC AC IA), then the remainder.

**Exit test:** `rampscan frontier` reports a pipeline disposition for all 121 with zero unreviewed; every `automatable`/`partial` record names a collector that exists or is named in the Tier-2 cheap-win list; every `partial` names its remainder; every `narrative` states what specifically cannot be read from a commit; the emitted coverage figure equals an independent recount from the records.

*Estimate: 4–5 days.*

### 2.2 N1b — wave 1: the class-b SA/SR set

Seven controls, all leverage 6, all unreviewed by the AWS pass, all in scope for class b:

```
SA-02  KSI-PIY-RIS     SR-02 (01)  KSI-PIY-RIS
SA-05  KSI-SVC-ACM     SR-08       KSI-SCR-MON
SA-08  KSI-PIY-RSD     SR-11 (01)  KSI-CED-RAT
SA-22  KSI-SCR-MIT
```

Expect two to four recipes over **existing** collectors — `repo-facts` and `contract` carry most of SA and SR — plus the Tier-2 cheap wins where one unlocks a control: `zizmor`/`actionlint`, `dockle`, a **license recipe over the syft data already collected**, `trivy config`. Each is an H-phase-shaped single-collector move, already scoped upstream, none on anyone's critical path — which is exactly why they ride this wave.

Every recipe carries the full `plain` block (`checks` / `violation` / `fix`), `empty_means`, and one of the five patterns from §1.2 named in its `notes`.

**Exit test:** each new recipe evidences on `fixtures/vulnerable-app` **and** is shown by N0-T4 to reach `unevidenced` — never `evidenced` — on `fixtures/bare-app`; `rampscan frontier` moves by exactly the number of controls discharged; the self-scan board renders every new row with its plain-language block.

*Estimate: 4–5 days.*

### 2.3 N1c — wave 2: the partials where the repo answers the half AWS cannot

17 of the 80 repo-plausible controls are adjudicated `partial` from the AWS side, several at leverage 7 — `SA-09`, `SR-05`, `CM-03 (02)`, `CA-07 (04)`. In each the AWS source gets the runtime half and stops. Take the repository half; state the remainder.

**Exit test:** every wave-2 recipe's adjudication names its remainder in one sentence, and that sentence renders on the board beside the row. A partial claim that does not show its boundary is not shipped.

*Estimate: 3–4 days.*

### 2.4 N1d — publish the ceiling

The honest counterweight, and the most rampscan-shaped deliverable here. CP is the **largest family on the frontier at 19 controls** and a repository cannot answer contingency planning; neither can it answer PS (7), AT (6), or most of IR. `rampscan frontier --ceiling` emits what the pipeline source cannot answer and why, control by control, attributable to a rationale.

**Exit test:** the ceiling is computed, not typed; no document states a coverage or ceiling number the command does not produce; every uncovered control maps to a rationale.

*Estimate: 1 day.*

---

## 3. N2 — the loop

### 3.1 N2a — `rampscan check` gets a consumer

`check` is finished, correct, exits 1 on a would-be violation, and nothing in the world calls it. The comment payload already exists and is unused: `RegisterDiff` classifies `newly-violated`, `OffenderPointer` carries file/line/call-path, `introducedAt`/`introducingCommit` walk the violated streak back through the bundle chain, and every recipe carries an authored `plain.fix`. That is a pull-request comment nobody has rendered.

- `packages/cli/src/pr-comment.ts` — a pure function `(CheckOutcome, RegisterDiff) → markdown`, unit-tested against fixture outcomes. Pure so it is testable without a network.
- `.github/actions/rampscan-check/` + a workflow. Pure gates only: no tool binaries, so **the deferred engine-track CI decision is not reopened** — that deferral is about running the Phase H collector families in CI, and `check`'s gates spawn no external tool by construction (`isPure` in `check.ts`).
- The comment must distinguish "you broke this" from "this was already broken." `check` already computes both sides against the board for exactly this reason; the renderer must not flatten it.

**Exit test:** a PR breaching a declared boundary gets a comment naming the file, the import chain and the authored fix sentence, and the job exits 1; a clean PR gets no comment and exits 0; a PR touching an already-violated row is described as inheriting it; the ledger is byte-identical across the whole run and no artifact lands in the output dir.

*Estimate: 2 days.*

### 3.2 N2b — the assessor package

One signed, self-verifying takeaway: board + rollups + the DSSE envelopes + the public key + the as-of instant. `/api/verify/bundle` and `/api/verify/key` already stream exactly the bytes; I3e already proves export row counts against the screen; the I3b smoke already verifies a downloaded bundle with `node:crypto` alone. This is assembly, not architecture.

**Exit test:** a third party with the package, no network and no rampscan installation verifies every bundle in it with standard tooling, and the coverage figures inside it recount from its own rows.

*Estimate: 1.5 days.*

**Fork, decided at N1b's exit, not now:** whether N2a jumps ahead of N1c. Take the jump if wave 1 landed clean; hold if it needed more than one collector change. A moving catalog makes a noisy gate.

---

## 4. N3 — claim fidelity

No new language. `IMPLEMENTATION-PLAN-REMAINING.md` Tier 3 defers "languages beyond TS/JS in the graph" by name and this plan re-confirms it.

**N3a — grow the ruleset.** `packages/collectors/semgrep-rules.yaml` holds **three** rules, all `[javascript, typescript]`, behind a gate sophisticated enough to reason about their reachability. The gate is out-running its input. Growth must flow through `cacheKeySalt()`, which already folds the ruleset into every cache key, so editing a rule still re-keys evidence. *2 days.*

**N3b — drive down `inferred`.** Edges carry `exact` vs `inferred`, where inferred means "unique name match across the project." `extract.ts` states in its own comments that scip-typescript slots in later behind the same node/edge schema — that seam is designed and unused. Because the gate is deliberately over-approximate, every inferred edge removed converts an `unknown` into a decided answer. *3–4 days.*

**N3c — surface confidence where the claim is made.** `query.ts` carries `resolutions[]` per path and I3f renders entry-point provenance on the evidence page. Lift it to the board row: a claim resting on inference should say so where a human reads it, next to N0-T1's `population`. Together those two fields answer "how much did you look at, and how sure are the edges" — the two questions a gated claim has always implied and never stated. *1 day.*

**Exit test:** on the self-scan and on `fixtures/vulnerable-app`, the share of gated claims resting on at least one inferred edge falls measurably against a recorded pre-N3 baseline; **no claim moves from `not_affected` to a weaker state** (the walk only ever tightens); every gated row states its resolution.

---

## 5. Decisions to settle before code starts

1. **`empty_means` values.** Two (`clean` / `unevidenced`) or three (adding `partial` for a domain that exists but was incompletely searched)? *Recommendation: two.* A partially-searched domain is a `population` fact, which N0-T1 already carries, not a second kind of emptiness.
2. **Does `population` re-key evidence?** *Recommendation: no* — excluded from `sameEvidence`, same as `offenders`/`pointers` in I2c, so no existing bundle re-keys and old evidence honestly shows no population until real drift refreshes it.
3. **Does `rampscan frontier` fail the build on unreviewed controls?** *Recommendation: yes, after N1a completes* — exit 1 on any pipeline-unreviewed control, so the 121 cannot silently regrow.
4. **Where does `remainder` render?** *Recommendation: on the board row beside the state*, not only on the evidence page. A partial claim whose boundary is one click away reads as a full claim.
5. **Class d.** Still correctly refused (no MVX window). Unchanged; restated so N1's class filtering does not quietly invent one.

---

## 6. Risks

1. **Vacuous passing.** N0 is the mitigation and it is why N0 is first. Forty recipes that pass because there was nothing to check is worse than seventeen that are true.
2. **The L4/L5 cancellation taxes N1 directly.** Every recipe needs three authored paragraphs, enforced by `plain.test.ts`, in operator English, with **no drafting assistant by decision** — on evidence that a small local model fabricates verdicts. Forty recipes is ~120 paragraphs of careful human writing. That decision was right; this is its bill, budgeted rather than discovered.
3. **Adjudication drifting into opinion.** 121 dispositions written fast become a wall of assertions. If the reasoning cannot be written, the disposition is not known.
4. **Upstream frontier drift.** Records key on `controlId` + `datasetVersion`; a re-publish must fail loudly (ground rule 2 applied to a new file class).
5. **Board noise scaling with the catalog.** The action queue, guided empty states and `classifySkip` were tuned against 17 recipes and will meet skip reasons nobody has written yet. Re-check at the end of N1b, not at the end of N1.
6. **The ceiling disappoints before it reassures.** N1d will likely show the pipeline source topping out well below half the frontier. Publish it anyway and early — it is the number that makes every other number believable.

---

## 7. What "done" looks like

- A deliberately vacuous recipe cannot reach `main`; CI names it and the pattern it should have used.
- Every count-based claim on every surface states the population it counted over — `0 of 412` and `0 of 0` never look alike again.
- `rampscan frontier` reports a pipeline disposition for all 121 controls with an authored rationale each, in a shape offerable upstream.
- Two waves of recipes, every one shown to go `unevidenced` rather than `evidenced` on the barren fixture.
- The pipeline ceiling is published, computed and attributable.
- A pull request that breaks a control is told so, in the recipe's authored words, when it is opened.
- An assessor is handed one file and verifies all of it without rampscan.
- Gated claims rest on measurably fewer inferred edges, and each says on the board what it rested on.

---

## 8. Changelog

### N0 — the catalog's honesty test (landed 2026-08-16)

**The six decisions from `PLAN-OF-ACTION-DEPTH.md` §3, recorded here so they are not re-taken by accident.**

1. **Pipeline adjudications live in `recipes/adjudications/<control-id>.json`**, one file per control, exactly as SPEC §10.2 specifies — *not* written back into `automation-frontier.json`, which is upstream's file behind a version pin the dataset client hard-fails on (ground rule 2). Each record carries `datasetVersion`, so an upstream re-publish invalidates loudly instead of silently re-basing our reasoning.
2. **The record schema mirrors the frontier's own vocabulary** (`controlId · disposition · rationale · source: "pipeline" · recipeIds[] · candidateCollectors[] · reviewed · datasetVersion`), because SPEC §10.2's stated goal is that the overlay be contributable upstream. Mirroring now makes that a merge; diverging now makes it a rewrite.
3. **`partial` does not count as covered.** A control is covered only when a recipe's assertions fully discharge it; otherwise the record names the *remainder* — the specific thing a repository cannot see — and the control stays uncovered. This is the rule that keeps the ceiling honest.
4. **Class b leads.** 44 of 121 are in scope for it, it is the CLI default, and it is the class a first customer certifies at.
5. **Ground rule 7 is a test, not a norm** — which is this phase, and is described below.
6. **N2a does not reopen the deferred engine-track CI decision.** `IMPLEMENTATION-PLAN-REMAINING.md` Tier 2 defers *engine-track CI wiring for the Phase H collector families* by user decision (engine-first). N2a wires `rampscan check`, whose gates are pure by construction (`isPure` in `check.ts`) and spawn no external tool at all. Different thing, adjacent name; the deferral stands untouched and N2a proceeds without asking for it back.

**And the five from §5 of this document, settled as recommended:** `empty_means` takes **two** values, not three · `population` **does not** re-key evidence · `rampscan frontier` **will** exit non-zero on a pipeline-unreviewed control, from N1a's completion · `remainder` renders **on the board row** beside the state · **class d stays refused** (no MVX window), restated so N1's class filtering does not quietly invent one.

**What landed.**

- **N0-T1 — `population`.** `AssertionResult.population` carries the collector's pre-filter observation-row count; `assert.ts` sets it and never folds it into `detail`, which participates in `sameEvidence` and stays byte-identical. The register row carries it too (`ports.ts` → `fold.ts` → sqlite + PocketBase), and the board and evidence page draw an empty domain differently from an exhaustive one.
- **N0-T2 — `empty_means`.** Two values, optional in the schema and required in the shipped catalog — the exact split `plain` already uses, and for the same reason: the recipe shape mirrors `aws-evidence.json`, which has no such field, so an imported recipe must still parse. All 17 recipes backfilled.
- **N0-T3/T4 — `catalog.test.ts` + `catalog-bare.e2e.test.ts`.** The static half over the catalog; the dynamic half over a real scan of `fixtures/bare-app`, plus synthetic broken wiring so the checker is shown to notice.
- **617 vitest** (601 + 16: 7 in `catalog.test.ts`, 8 in `catalog-bare.e2e.test.ts`, and 1 in `packages/core/test/bundle.test.ts` pinning `sameEvidence`'s indifference to `population` — the ledger property below, held by a unit test so it survives without re-running an eight-minute scan), root and console typecheck clean.

**Three deviations from the plan as written, each with its reason.**

1. **`population` rides EVERY assertion, not only the count ops.** §1.4 T1 says "on `count_eq`/`count_lte`" — but §1.1, four paragraphs earlier, names *both* failure modes: a count op over an empty filtered set passes, **and** a row-wise op over an empty filtered set passes vacuously. N0-T4's own second check ("every `evidenced` row is `empty_means: clean` **or** carries a non-zero `population`") cannot be evaluated at all for `lockfile-pinned-deps` or `sbom-exists-and-fresh`, both of which are evidenced on the barren fixture through row-wise ops. Restricting the field to count ops would have made the check unrunnable on two of the five rows it was written to judge.
2. **Every recipe names its empty-set pattern in `notes`, and a test enforces it.** §1.2 says the four patterns are all in the tree and none has a name, and that "naming them is most of the work of testing them"; §2.2 then requires new N1b recipes to name theirs. Naming them for the 17 that already exist costs one sentence each while every recipe file is open anyway, and it means N1b inherits a convention with a test behind it rather than a paragraph in a plan. The five names are `Guard`, `Skip`, `Witness`, `Counter`, `Negative witness`.
3. **The shape-probe adjudication record is folded into N1a-T1, not written here.** `PLAN-OF-ACTION-DEPTH.md` §3's exit asks for one hand-written record as a shape probe. This document supersedes it on scope, its N0 is T1–T5, and a record written before `packages/schema/src/adjudication.ts` exists is a JSON file no loader validates — the probe is worth more written *against* the zod schema, on the same day, which is where it now is.

**Two things the phase found that the plan did not predict.**

- **The `unevidenced` declaration is not the whole check, and the second half is the one that bites.** A recipe can also reach `evidenced` over zero rows while declaring *nothing* — `empty_means` absent is caught statically, but `empty_means: "clean"` asserted falsely is not. So the dynamic check has two arms: a declared-`unevidenced` recipe passing over zero rows, **and** any evidenced row that is neither `clean` nor counted over a non-empty domain. The first arm is the regression N1 needs; the second is the one a hand-written recipe trips while trying to make the first arm quiet.
- **`clean` needed a cost, or it becomes the value people write to make the test go away.** That cost is N0-T3's third rule: a `clean` recipe's `notes` must state what domain was searched exhaustively. The test can only verify the claim was *stated* — no test can walk gitleaks' history traversal — but stating it is what a reviewer disagrees with, and an undefended `clean` is now a CI failure rather than a quiet default.

**The ledger exit test, run rather than argued.** The criterion was "no bundle digest in `rampscan-ledger/` changes as a result of the `population` addition", so it was measured the only way that means anything: `fixtures/vulnerable-app` scanned into a fresh ledger with `assert.ts` reverted to its pre-N0 form, then re-scanned into the *same* ledger with `population` restored and nothing else changed. **16 of the 17 recipes' bundles survived untouched** — the evaluator gained a field and the ledger gained nothing.

The seventeenth re-keyed, and it is worth writing down because it is **not** `population`: `no-secrets-in-history` supersedes because **gitleaks reports its two findings in a different order run to run**, so the `e.g. {…}` example row embedded in `detail` flipped from `generic-api-key` to `aws-access-token` — and `detail` *is* in evidence identity. That bundle re-keys on any re-scan of an entirely unchanged repository, with or without N0. Recorded here and **not fixed**: the fix is to sort the collector's rows, which changes `detail` and therefore spends one deliberate supersede, and that is a decision to take on purpose rather than smuggle into a phase about something else. (`sameEvidence`'s indifference to `population` is separately pinned by a unit test in `packages/core/test/bundle.test.ts`, so the property survives without re-running an eight-minute scan.)

**The empirical baseline holds.** `fixtures/bare-app` still reads **5 evidenced · 4 violated · 8 unevidenced**, verified from a live scan rather than the recorded smoke output, and the split is now pinned by a test so movement under N1 is deliberate. Of the five passes, three are genuine (`lockfile-pinned-deps` over a real manifest, `sbom-exists-and-fresh` over a real SBOM, `no-secrets-in-history` over every commit) and two count zero over an empty domain (`no-critical-reachable-advisories`, `no-reachable-dangerous-code`) — which is exactly what `population` now says out loud on both surfaces.

