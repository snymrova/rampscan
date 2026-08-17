# rampscan — implementation plan: depth (Phases N0–N3)

**Status:** task breakdown and scope for `docs/PLAN-OF-ACTION-DEPTH.md`. That document owns the *argument* — why coverage leads, why languages stay deferred, what the fork is. This one owns **what gets built, where, in what order, and what test closes it**. On a scope dispute this document wins over the checklist; on an architecture dispute `docs/SPEC.md` wins over this one.
**Date:** 2026-08-16 · **revised 2026-08-17** (§2.1a N1a′, §2.1b's resizing, decisions 6–10, risks 7–8 — the sibling plane)
**Reads against:** the code, and `docs/PLAN-OF-ACTION-DEPTH.md`. Nothing else was opened. **The 2026-08-17 revision also reads the sibling** — `ramprules.com/fedramp-rules-hub`, which publishes the pinned dataset: its overlay-loop skill and both plane cards, `pipeline-evidence.schema.json`, and the live frontier at overlay 0.7.1. Every number in the revision is computed from those two files, not quoted from either project's prose.
**Supersedes as plan of record:** `docs/IMPLEMENTATION-PLAN-ONTOLOGY-ONDEVICE-LLM.md` (L0–L3c landed; L3d deferred; L4/L5 cancelled 2026-08-16).

```
N0  the catalog's honesty test         2.5–3 d   ← the spine; everything else rests on it  ✓ landed
N1  the pipeline adjudication          12–15 d   ← the lead axis
    └ N1a′  reconcile the sibling plane  1.5–2 d  ← 2026-08-17; out of N1a-T3, not added to N1
N2  the loop                            3.5 d
N3  claim fidelity                      6–7 d
                                       ────────
                                       24–29 d
```

**N1's shape changed on 2026-08-17 and its total did not.** N1a no longer runs to 121 before N1b authors a recipe — §2.1a explains why (upstream's alternation rule, against our own risk 3), §2.1b resizes the near-term target from 114 to **37**, and N1a′ is the reconciliation that has to land first.

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

### 2.1a N1a′ — reconcile with the sibling plane (blocks the rest of T3)

`PLAN-OF-ACTION-DEPTH.md` §1a is the argument; this is the work. Ordered so the two bugs land before the re-pin that would otherwise expose them, and the decision lands before the records that depend on it.

**N1a′-T1 — pin the field that actually moves.** `packages/dataset/src/client.ts` checks `dataset_version` and nothing else. Both copies of `automation-frontier.json` read `2026.07.14.01`; the fifteen new dispositions arrived as `overlay_version` 0.6.0 → 0.7.1. Add the overlay pin **per slice**, because `overlay_version` is a property of the overlay a slice was derived from and not of the dataset — a single global constant would be wrong the first time two slices move independently. Then re-pin to 0.7.1 in the same commit, so the tree never holds a checked pin against an unread file.

*Test:* the loader refuses a slice whose `overlay_version` differs from its pin, with the slice named; the existing `dataset_version` refusal is unchanged; the mismatch error distinguishes the two so a reader knows which pin to move.

**N1a′-T2 — stop attributing upstream's pipeline work to AWS.** `frontier.ts` copies `f.disposition` into `row.aws` unconditionally, and `dataset/src/types.ts` documents an invariant that is already false upstream — *"every reviewed row in the published file carries `sourcesConsidered: ["aws"]`"*. After the re-pin, fifteen rows carry `["pipeline"]`, and `rampscan frontier` would print their reasoning in the AWS column, on the same rows where our own pipeline column disagrees or duplicates. Read `sourcesConsidered`, key upstream's disposition by the source that wrote it, and correct the comment.

*Test:* a synthetic frontier row carrying `sourcesConsidered: ["pipeline"]` does not populate `row.aws`; a row carrying `["aws"]` does; a row carrying both populates both and the renderer says so rather than picking one. Over the real pinned file at 0.7.1, the count of rows with an AWS disposition equals `rollup.bySource.aws.adjudicated`, recounted from the rows — the same independent-recount discipline T2 already holds itself to.

**N1a′-T3 — the plane-identity decision, then the schema.** Decision 6 below. Whatever it settles, `source: z.literal("pipeline")` in `packages/schema/src/adjudication.ts` is either confirmed with a stated reason or changed, and the seven existing records migrate in the same commit.

**N1a′-T4 — two fields every record owes, both from §1a.**

- `boundaryRemainder` (or a standing sentence in `remainder`): the "one repository out of forty" arm of the vacuity trap. `population` says how many rows a verdict counted; nothing says the scanned repository is the whole authorization boundary, multi-repo joins are deferred by name, and upstream's card states the consequence — *expect `partial`, because the repository set inside the boundary is named by a human.* Whether this is a new field or a required clause of the existing `remainder` is decision 7.
- `externalSystem`: the term three of upstream's four overlapping rationales end on — *"the platform … is itself an external system, raising SA-09 and CA-03."* **Ours is the negative answer**, and it is the strongest thing this overlay can say that upstream's cannot: no network in collectors by decision, local execution, `node:crypto` signing, so adopting rampscan does not enlarge the boundary it reports on. A field rather than a habit, because a differentiator stated in four records out of a hundred and twenty-one is a differentiator nobody can count.

*Test:* the catalog-test posture applied to the overlay — every record carries both, and the `externalSystem` text is asserted longer than a stub so an empty gesture fails, exactly as the L4b affordance test asserted its reason longer than its own prefix.

**N1a′-T5 — read upstream's fifteen before writing over them (ground rule 10).** Four are already ours and agree; eleven are new and every one is class c/d. For the four: rewrite each record to cite the upstream disposition and state only what a commit adds that an API does not — SA-08's contract-versus-policy-rule and SA-22's inventory-versus-detection are the two where our route is stronger and the record should say so plainly. For the eleven: they are outside decision 4's lead set, so they are read and cited when their class comes up, not adjudicated now.

*Test:* `rampscan frontier` grows a column for upstream's pipeline disposition beside ours, and a check fires when the two differ and our `rationale` does not name theirs — undeclared disagreement is the failure risk 7 names, and it is catchable by the same class of link check that caught the `sr-8` over-claim.

**N1a′-T6 — the cheapest thing available, and it is a contribution rather than a fix.** `data/overlays/pipeline-tools.json` upstream **ships empty**, and their own card says the gate that fails an unresolvable spelling had to exist before the first spelling was written — so their plane cannot author its first recipe until someone writes the vocabulary. We have `tools.json`, a tested manifest with pinned versions for gitleaks, syft, grype, osv-scanner, semgrep, checkov and spectral, plus the Tier-2 names. Offering it is one commit, it unblocks their authoring phase, and it makes SPEC §10.2's "contributable upstream" true of something *today* instead of at the end of N1.

**Exit (N1a′):** both bugs fixed and the re-pin landed at overlay 0.7.1; the plane-identity decision recorded with its reasoning; the seven records carrying both new fields and citing upstream where it has spoken; `rampscan frontier` printing both sources without conflating them; the tools contribution offered. **Then** T3 resumes.

*Estimate: 1.5–2 days, and it comes out of T3's 4–5 rather than adding to the phase — see the revised sizing below.*

### 2.1b N1a-T3, resized and reshaped

The original T3 says "write the 121." Two things changed on 2026-08-17.

**The sizing, computed from both files rather than from the pinned one:**

```
class b on the frontier      44     ← decision 4's lead set
  adjudicated by us           7
  adjudicated by upstream     4     (all four inside our seven)
  class-b REMAINING          37     ← the real near-term number

class c/d-only                77
  adjudicated by upstream    11     (every one of them c/d)
  adjudicated by us            0

neither project has adjudicated  103 of 121
```

So the honest T3 target is **37 in the lead set**, not 114, and the 103 that nobody has touched is the number that describes the whole job. The 4–5 day estimate stands for the lead set at ground rule 8's bar; the full 121 was always going to overrun it.

**The shape: interleave with N1b.** `PLAN-OF-ACTION-DEPTH.md` §2's alternation rule now forbids running T3 to completion before a recipe is authored. Batches of ~15 class-b controls, then the recipes that batch made available, then the next batch. `--strict` still lands at the last batch, for the reason already recorded.

**The gate: an independent auditor per batch.** Upstream's definition-of-done requires a separate agent to attack the batch and its findings reported verbatim, clean results included, on the stated grounds that the reading which produced a claim cannot check it. Their step-7 audit re-rated two of its own dispositions and caught a real queue bug. Ground rule 8 has had no enforcement; this is it. A batch is not done until an independent pass has attacked every disposition in it.

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

**Added 2026-08-17, from §1a. These block N1a′ and therefore the rest of T3.**

6. **What is our source, relative to upstream's two planes?** Upstream's `pipeline` plane covers our exact subject matter — SAST, dependency, secret, IaC, attestation — and differs in trust model, not scope: their plane reads a SaaS platform's API, ours reads a checkout offline and signs it. Their schema requires `platform` ("the exact offering", their plane's `govcloud`), `external_system` and `scan_scope`; their `collection.kind` already includes `cli`, so mechanically a rampscan recipe fits, and only `platform`/`external_system` need a defined answer for a self-hosted tool. Three options: **(a)** we are a platform on their `pipeline` plane; **(b)** we are a third plane, named for the anchor rather than the subject; **(c)** we keep a separate overlay and reconcile at re-pin, which is the status quo. *Recommendation: **(b)**.* Our own recipe schema already votes for it — `anchor: z.literal("commit")` is a field their plane has no concept of — and (a) requires either a `platform` value that is not an offering or a change to someone else's schema, while (c) is what produced two silent overlays in the first place. (b) also keeps the name collision from propagating: `pipeline` is taken, and it was taken by the project that publishes the register.
7. **Is the boundary gap a field or a clause?** Every claim here is at most `partial` because the scanned repository may be one of forty and nothing in the evidence says otherwise. *Recommendation: a required clause of `remainder`, not a new field* — the schema already refuses a `partial` with no remainder and refuses a non-`partial` that has one, so the gap has a home with a rule behind it. A separate field would let a record carry the boundary sentence while claiming `automatable`, which is the contradiction the existing rule exists to prevent. The consequence is worth stating: **`automatable` becomes nearly unreachable on this plane**, which matches both upstream's card ("expect `partial`") and our own first seven records (0 automatable of 7).
8. **Does `rampscan frontier` render upstream's pipeline disposition beside ours?** *Recommendation: yes, and it fails on undeclared divergence* — the same class of link check that caught the `sr-8` over-claim, applied to reasoning rather than to wiring. The alternative is that the two overlays disagree in a file nobody joins, which is risk 7.
9. **Do our recipes gain `references[]`?** Upstream requires at least one verified `https://` source on **every** recipe on **both** planes, and our recipe schema has no such field — all 17 recipes fail that gate today, so the overlay is not offerable upstream whatever §10.2 intends. *Recommendation: yes, but as its own task in N1b rather than inside N1a′* — it is 17 recipes' worth of citation-fetching, it is orthogonal to adjudication, and bundling it here would stall the reconciliation behind a research errand. Record it now so it is scheduled rather than remembered.
10. **The one thing not to do:** re-adjudicate upstream's eleven class-c/d controls to make our column look complete. They are outside decision 4's lead set, upstream reasoned about them first, and ground rule 10 says the cheap correct move is to cite. A column filled for symmetry is the "wall of assertions" risk 3 names, arriving by a route the plan had not considered.

---

## 6. Risks

1. **Vacuous passing.** N0 is the mitigation and it is why N0 is first. Forty recipes that pass because there was nothing to check is worse than seventeen that are true.
2. **The L4/L5 cancellation taxes N1 directly.** Every recipe needs three authored paragraphs, enforced by `plain.test.ts`, in operator English, with **no drafting assistant by decision** — on evidence that a small local model fabricates verdicts. Forty recipes is ~120 paragraphs of careful human writing. That decision was right; this is its bill, budgeted rather than discovered.
3. **Adjudication drifting into opinion.** 121 dispositions written fast become a wall of assertions. If the reasoning cannot be written, the disposition is not known.
4. **Upstream frontier drift.** Records key on `controlId` + `datasetVersion`; a re-publish must fail loudly (ground rule 2 applied to a new file class). **Found false 2026-08-17:** the adjudications are versioned by `overlay_version`, which the loader does not read, and 0.6.0 → 0.7.1 moved fifteen dispositions under an unchanged `dataset_version`. This risk was already realised when it was written down. N1a′-T1.
5. **Board noise scaling with the catalog.** The action queue, guided empty states and `classifySkip` were tuned against 17 recipes and will meet skip reasons nobody has written yet. Re-check at the end of N1b, not at the end of N1.
6. **The ceiling disappoints before it reassures.** N1d will likely show the pipeline source topping out well below half the frontier. Publish it anyway and early — it is the number that makes every other number believable. §1a sharpens it: upstream's own pipeline ceiling computes to **0.062**, on a reason that applies to us unchanged.
7. **Two overlays diverging in silence** (2026-08-17). Not disagreement — *undeclared* disagreement. A reader holding both files finds two confident paragraphs and no way to choose, which is worse than one and worse than none. Ground rule 10 and N1a′-T5 are the mitigation, cheap at four overlapping controls and expensive at forty.
8. **Adjudicating for symmetry rather than for a reader** (2026-08-17). With a second overlay visible, the temptation is to fill our column wherever theirs is filled. Decision 10 refuses it; the eleven class-c/d controls are cited, not re-derived.

---

## 7. What "done" looks like

- A deliberately vacuous recipe cannot reach `main`; CI names it and the pattern it should have used.
- Every count-based claim on every surface states the population it counted over — `0 of 412` and `0 of 0` never look alike again.
- `rampscan frontier` reports a pipeline disposition for all 121 controls with an authored rationale each, in a shape offerable upstream — and prints upstream's own disposition beside ours wherever it has one, so agreement is cited and divergence is argued rather than left in two files nobody joins.
- Every record names the boundary it could not see (the repository set) and the boundary it does not enlarge (no external system), which are the two halves of what this evidence path is and is not.
- Two waves of recipes, every one shown to go `unevidenced` rather than `evidenced` on the barren fixture.
- The pipeline ceiling is published, computed and attributable.
- A pull request that breaks a control is told so, in the recipe's authored words, when it is opened.
- An assessor is handed one file and verifies all of it without rampscan.
- Gated claims rest on measurably fewer inferred edges, and each says on the board what it rested on.

---

## 8. Changelog

### N0 — the catalog's honesty test (landed 2026-08-16)

**The six decisions from `PLAN-OF-ACTION-DEPTH.md` §3, recorded here so they are not re-taken by accident.**

1. **Pipeline adjudications live in `recipes/adjudications/<control-id>.json`**, one file per control, exactly as SPEC §10.2 specifies — *not* written back into `automation-frontier.json`, which is upstream's file behind a version pin the dataset client hard-fails on (ground rule 2). Each record carries `datasetVersion`, so an upstream re-publish invalidates loudly instead of silently re-basing our reasoning. **Corrected 2026-08-17** — it does not, because the dispositions are versioned by `overlay_version` and nothing here reads it; the decision stands and N1a′-T1 is its missing half.
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

### N1a — the pipeline adjudication (T1 and T2 landed 2026-08-16; T3 started, 7 of 121)

**N1a-T1 — the record.** `packages/schema/src/adjudication.ts` holds `PipelineAdjudication`, field-for-field in the frontier's own vocabulary (`recipeIds` where it has `coveredBy`, `candidateCollectors` where it has `candidateServices`), so the overlay stays a merge rather than a rewrite. Two rules are enforced by the type rather than by review: a `partial` **must** name its remainder, and anything that is not `partial` **may not** — a disposition with a boundary it did not draw is as wrong as one that hid the boundary it did. `packages/cli/src/adjudications.ts` loads them beside `loadRecipes`, tolerating a missing directory (a checkout with no adjudications is valid and should read "121 unreviewed", not crash) and refusing a malformed record outright.

**N1a-T2 — `rampscan frontier`.** A pure derivation in the shape of `tools` and `model`: catalog × adjudications × the pinned frontier, nothing probed, nothing written. The frontier slice joined the dataset client so it is read *under the same version pin* as every other slice — risk 4 bought at the loader rather than discovered in a number. Exits 1 on a broken link; `--strict` also exits 1 on any unreviewed control, which is decision 3's gate held back until N1a completes, because a command that is red from its first run teaches people to ignore it.

Its output today, and every figure in this paragraph is the command's:

```
frontier 121 uncovered controls · dataset 2026.07.14.01
  adjudicated  0 automatable · 4 partial · 3 narrative
  unreviewed   114
  discharged   0        (automatable AND a recipe exists today)
  catalog covers   22 of 209 controls a KSI reaches
  reachable        25 of 209 — 12.0%
```

**The command found a real over-claim on its first run, which is the argument for building it before the recipes.** The first draft of `sr-8` named `dependency-update-automation` in `recipeIds`. That recipe exists, and it does *not* claim `sr-8` — so the board, the rollups and every coverage count, all of which join on the recipe's own `control_ids`, would never have recorded the discharge. The overlay would have said "covered" and every surface would have said "unevidenced", with nothing to reconcile them. That check is now permanent (`does not claim this control`), and it turned up a genuine wave-1 opportunity in passing: `sr-8`'s indicator IS among that recipe's `ksi_ids`, so the claim is *available* to N1b — it just has to be made in the catalog, deliberately, rather than asserted in an overlay.

**N1a-T3 — the data work, 7 of 121 written.** The sharpest starting set the plan names: the class-b, leverage-6, AWS-unreviewed SA/SR controls. **4 partial · 3 narrative · 0 automatable**, which is worth stating plainly rather than softening — the first seven controls nobody had asked a repository about produced no outright automatable answer, and the ceiling is going to be lower than the enthusiasm for it. The four partials are the interesting ones and they are the plan's thesis in miniature: `SA-05` (documentation exists, is current and is anchored — distribution is the remainder), `SA-08` (the architecture contract makes domain separation *demonstrated* rather than asserted — the design phase is the remainder), `SA-22` (the lockfile and SBOM are the component inventory an assessment normally takes on trust — vendor support status needs a feed collectors may not reach), `SR-08` (a committed dependabot config is the monitoring subscription itself — the supplier agreements are the remainder). The three narratives are refusals taken on purpose: `SR-02 (01)` in particular, where CODEOWNERS is the nearest committed artifact and reading it as a supply-chain risk team would spend the credibility every other row depends on.

**114 records remain**, and at the quality bar ground rule 8 sets they are the 4–5 days the plan budgets, not an afternoon. 13 vitest cover the command over the real overlay (every printed number recounts from its own rows) and over synthetic broken records (each of the six link checks shown to fire), bringing the suite to **630** with root and console typecheck clean.
