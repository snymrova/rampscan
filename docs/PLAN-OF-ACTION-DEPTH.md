# rampscan — plan of action: depth (Phases N0–N3)

**Status:** proposed plan of record. The previous one — `docs/IMPLEMENTATION-PLAN-ONTOLOGY-ONDEVICE-LLM.md` (L0–L5) — is spent: L0–L3c landed 2026-08-15/16, L3d is deferred until an external user asks, and **L4/L5 were cancelled 2026-08-16 on evidence from a live draft**. There is currently no active plan of record; this document proposes one.
**Date:** 2026-08-16 · **revised 2026-08-17** (§1a, ground rule 10, §2's alternation rule, risks 7–8 — the sibling plane, found after N0 and N1a-T1/T2 landed)
**Reads against:** the code first (see `docs/PRODUCT-READ.md`, a code-only reading), then `SPEC.md` §10.2 (which already specifies the central deliverable here), `IMPLEMENTATION-PLAN-REMAINING.md` §1 (which flags it as the largest undone product scope), and the two existing checklists for phase-letter continuity. **The 2026-08-17 revision also reads the sibling** — `ramprules.com/fedramp-rules-hub`, which publishes the dataset this repo pins: its `docs/code-scanning-overlay-plan.md`, its `.claude/skills/overlay-loop/` (SKILL.md and both plane cards), its `pipeline-evidence.schema.json`, and the live `data/derived/automation-frontier.json` at overlay 0.7.1.
**Phase letter:** **N**. A–H, I, J, K and L are taken, M0–M5 are the original milestones, and "Phase L" already collides once (L0–L5 vs the Tier-2 DAST entry). N avoids a third.

**Thesis in one line:** rampscan's differentiator is proven; its *coverage* is 17 recipes against 22 of 209 controls. Go deeper on the substrate that exists — more of the standard answered, the claims answered harder, and the answers delivered to someone — rather than wider across languages, which the docs already defer by name.

---

## 0. Ground rules

The six from `PLAN-OF-ACTION.md` §0 stay active unchanged. Four more are specific to a coverage push, and exist because a coverage push is the single easiest way to destroy this product's credibility. (Ground rule 10 was added 2026-08-17, after §1a.)

7. **No vacuous passes — ever.** A recipe may not report `evidenced` from the *absence* of something to check. The catalog already holds this line in two places and both are load-bearing: `route-auth-coverage` says "a repo with no detected routes stays honestly unevidenced, never vacuously evidenced," and `arch-boundaries-hold` fails a rule whose module path matches nothing, because "a module path that matches nothing is guarding nothing." Every recipe added under this plan inherits that, and N0 turns it into a test over the catalog rather than a convention.
8. **A disposition is reasoning, not a label.** Every adjudication record carries an authored paragraph in the frontier's own voice. The upstream AWS adjudication set the bar — read `automation-frontier.json`'s rationale for AC-01 and match it. An adjudication without reasoning is an opinion, and this repo does not ship opinions as evidence.
9. **Coverage is computed, never typed.** No coverage number appears in a document, a README or a slide unless a command emitted it. This is ground rule 4 applied to the one number this plan exists to move, and it is why N1a ships `rampscan frontier` before it ships recipes.
10. **An adjudication upstream has already written is read before it is re-written.** §1a is why. Where we agree with a published disposition, the record cites it and adds only what a *commit* answers that an *API* does not — a shorter and better record than a fresh derivation. Where we disagree, the record says so and argues, because a silent disagreement between two overlays is the one outcome that makes both of them worthless. This is ground rule 2's posture — upstream's file is upstream's — applied to upstream's *reasoning* rather than only its bytes.

---

## 1. The finding that sets the agenda

The pinned dataset already carries the frontier. `docs/context/ramprules/derived/automation-frontier.json` holds **121 uncovered controls**, each with a family, the KSIs that reach it, the classes it is in scope for, a leverage score, and — where reviewed — a disposition and an authored rationale.

It has been adjudicated **from exactly one source, and that source is not ours**:

```
rollup.bySource.aws       covered 88 · partial 21 · narrative 27 · unreviewed 73 · ceiling 0.52
rollup.bySource.pipeline  covered  0 · partial  0 · narrative  0 · unreviewed 121 · ceiling 0
```

Every rationale in the file reasons about AWS services — CloudTrail, Config, Access Analyzer, KMS, Backup — and every reviewed row carries `sourcesConsidered: ["aws"]`. **Nobody has ever asked which of the 121 a repository can answer.** That question is rampscan's whole reason to exist, and the answer is unwritten.

It matters that the answer will be *different*, not merely smaller. 27 controls are marked `narrative` on the grounds that "no API reports that a document exists or that anyone read it." A repository is a document store under version control, with authorship, review and a content hash per commit — and `arch-boundaries-hold` has already proved the move by turning "the design is still the design" into signed evidence mapped to `cm-2`/`cm-6`. In the SA, SR and CM families the pipeline source is not a weaker substitute for the AWS one. It is the better one.

Sizing, computed from the file:

| Slice | Count |
|---|---|
| Frontier total | 121 |
| In scope for **class b** (the CLI default, `--class b`) | 44 |
| …of those: narrative · partial · **unreviewed** | 23 · 14 · **7** |
| In families where committed-repo evidence is plausible (CM SA SR SI RA CA AU SC AC IA) | 80 |
| …of those: unreviewed | 53 |
| Largest families on the frontier | CP 19 · AC 12 · SI 12 · IA 11 · SA 9 · SC 9 · CM 8 |

The seven class-b unreviewed controls in the repo-plausible families are the sharpest starting set in the dataset — all at leverage 6, all in SA and SR, none of them touched by the AWS adjudication:

```
SA-02  KSI-PIY-RIS     SR-02 (01)  KSI-PIY-RIS
SA-05  KSI-SVC-ACM     SR-08       KSI-SCR-MON
SA-08  KSI-PIY-RSD     SR-11 (01)  KSI-CED-RAT
SA-22  KSI-SCR-MIT
```

And the honest counterweight, which this plan states up front rather than discovering in month two: **CP is the largest family on the frontier at 19 controls, and a repository cannot answer contingency planning.** Neither can it answer PS (7), AT (6) or most of IR. The pipeline ceiling is real and lower than 121. Publishing that ceiling is a deliverable here (N1d), not a concession.

---

## 1a. The sibling plane — found 2026-08-17, after §1 was written

§1's sharpest sentence — *"Nobody has ever asked which of the 121 a repository can answer"* — was true of the file this repo pins and already false of the world. `ramprules.com/fedramp-rules-hub`, the project that **publishes** the dataset this one pins, has opened a second evidence plane of its own and **named it `pipeline`**. Its first triage batch landed fifteen controls before N1a wrote its seventh. Neither project's tree mentions the other.

Read side by side, the two copies of the same file disagree about the one column this phase exists to fill:

| `rollup.bySource.pipeline` | pinned here (overlay **0.6.0**) | upstream today (overlay **0.7.1**) |
|---|---|---|
| partial · narrative · unreviewed | 0 · 0 · 121 | **13 · 2 · 106** |
| reachable · ceiling | 0 · 0 | 13 · 0.062 |

**Both files carry `dataset_version: 2026.07.14.01`.** The adjudications are versioned by `overlay_version`, which this repo does not read — see risk 8.

> **Overtaken 2026-08-17, later the same day.** This section was written against upstream at **0.7.1**; the re-pin (N1a′-T1) landed at **0.7.2**, and two of the numbers above have moved. The frontier is now **119**, not 121 — `sr-6` and `sr-8` left the uncovered set because upstream authored two pipeline recipes over them. So the four overlaps below are now **three**: `SA-08`, `SA-22` and `SR-02 (01)` still agree independently, and `SR-08` is no longer an overlap because upstream answered it and **argued our route**, which this overlay conceded rather than contested. The retired record carries that reasoning; `rampscan frontier` prints it. The section stands as the argument that produced N1a′ and is not rewritten to match its own outcome — see the implementation plan's N1a′ changelog for what the reconciliation actually cost.

### The four overlaps agree, and that is the most valuable fact in this section

Four controls are now adjudicated by both projects, independently, from different evidence. All four match:

```
SA-08  partial / partial      SR-08       partial   / partial
SA-22  partial / partial      SR-02 (01)  narrative / narrative
```

The *remainders* converge too — the specification-and-design phase, support status plus the replacement decision, the agreements limb, a team's charter. Two passes that never saw each other reaching the same four verdicts with the same boundaries is the strongest evidence either project has that ground rule 8's bar is real rather than self-congratulatory. It should be read as validation, not waste, and it is the reason ground rule 10 says *cite* rather than *avoid*.

The routes differ, and in two cases ours is the stronger one: upstream reaches SA-08 through an IaC policy rule passing over a deployed artifact, we reach it through the architecture contract checked against the actual import graph; upstream reaches SA-22 through scanner detection, we reach it through the lockfile and SBOM as the component inventory itself.

### The two `pipeline`s are not the same plane

Upstream's plane card defines it as *"the overlay that reads the pipeline that produces the estate: SAST, dependency scanning, secret scanning, IaC policy scanning, build attestation."* That is our collector set exactly. The difference is not subject matter but **trust model**: their plane reads a SaaS platform's API, ours reads a checkout offline and signs the result. Their schema encodes the SaaS assumption in three *required* fields — `platform` (the exact offering, "never a bare vendor name", described as this plane's `govcloud`), `external_system`, and `scan_scope`.

So the name is taken and the collision is real. Deciding what our source *is* relative to their two planes is now the first thing N1a owes, and it is posed in the implementation plan's decision list rather than settled here. The recipe schema already votes: `anchor: z.literal("commit")` is a field their plane has no concept of.

### The division of labour already exists, and nobody arranged it

Computed from both files:

```
class b on the frontier      44     ← decision 4's lead set
  adjudicated by us           7
  adjudicated by upstream     4     ← all four inside our seven
  class-b REMAINING          37

class c/d-only                77
  adjudicated by upstream    11     ← every one of them c/d
  adjudicated by us            0

neither project has adjudicated  103 of 121
```

**Every one of the eleven controls upstream adjudicated beyond the overlap is class c/d.** Their loop triages by leverage across all classes; ours leads on class b because it is the CLI default and the class a first customer certifies at. The two orders barely intersect, which means the duplication risk is far smaller than the shared plane name suggests — and it means the honest revision to N1a's sizing is not "121 to write" but **37 in the lead set and 103 nobody has touched**.

### Two things their loop knows that this plan did not

1. **An independent auditor closes a batch.** Their definition-of-done requires the batch be attacked by a separate agent — *"you cannot do this to your own work, because the reading that produced the claim is the reading that would check it"* — and reported verbatim, clean results included. It earns its keep: their step-7 audit re-rated two of its own dispositions and caught a queue bug that had let four controls leave a backlog on a rationale which only argued about scanners. Ground rule 8 sets our bar and *nothing enforces it*; the seven records were written and self-reviewed. This becomes N1a's exit gate.
2. **The alternation rule, which N1a as written violates by design.** See §2.

### And one thing their card knows that N0 did not

Their pipeline card leads — before the field list, deliberately — with the vacuity trap in a longer form than N0 found it: *"An empty alert list is indistinguishable from four different worlds: the scanner found nothing, the scanner never ran, scanning is switched off, or the scan covered one repository out of forty."* N0's `population` closes the first two. Their `scan_scope: {inventory, enumerated_by[]}` closes the fourth, and requires the inventory be **outside the scanner**, warning explicitly that naming the scanner's own repository list satisfies the validator and closes nothing.

rampscan enumerates from the checkout it was handed, and multi-repo joins are deferred by name at the foot of this document. So *"is this repository the whole authorization boundary"* is unanswered here, and their card states the consequence plainly: **"Expect `partial`. Most of this plane is honestly partial, because the repository set inside the authorization boundary is named by a human."** That is N1d's ceiling argument, already written by someone else, and it belongs in every record as a standing remainder rather than being rediscovered at control ninety.

The counterweight to it, which is ours alone: three of upstream's four overlapping rationales end *"the platform … is itself an external system, raising SA-09 and CA-03."* Their research calls this their sharpest finding — the plane that would close SA-11 raises SA-09. **Our answer is negative**: collectors take no network by decision, execution is local, signing is `node:crypto`. Adopting rampscan to collect evidence does not enlarge the boundary it reports on. That sentence appears in none of our seven records and is the single strongest thing this overlay can say that upstream's cannot.

---

## 2. Sequencing, and the one real fork

```
N0  →  N1  →  N2  →  N3
 ·      ·      ·      ·
decisions  coverage  the loop  claim fidelity
```

**Why coverage leads.** It is the largest undone *product* scope in the docs by the docs' own assessment, it is the axis on which a buyer judges the tool, and — unlike the other two — it is mostly data and recipe work over collectors that already exist, so it is the axis least likely to be blocked by engineering.

**Why the loop is second and fidelity third.** The instinct is to protect the moat first. The mechanical argument goes the other way: N1's recipes will ride `repo-facts`, `contract`, `checkov`, `spectral` and the Tier-2 cheap-win collectors, none of which are graph-gated — so coverage growth adds almost no load to the graph and does not compound fidelity debt. Meanwhile N2 is cheap and is what makes N1 *measurable*: with no PR gate there is no way to tell whether forty recipes helped anyone. Fidelity is the long game and it can be the long game.

**The alternation rule (added 2026-08-17, from §1a).** N1a as originally written adjudicates **all 121 before a single recipe is authored**, and that is precisely the drift upstream's loop forbids: *"triage is cheap and moves `unreviewed`/`reachable`/`ceiling`, authoring is expensive and moves `covered`/`recipes`, and a loop that prices only the cheap one drifts."* Their rule is never two triage batches in a row while an authoring backlog stands above ~15. The mechanical case for adopting it here is that our own risk 3 — *121 dispositions written fast become a wall of assertions* — is the same failure, and we listed it without a mitigation beyond willpower.

So **N1a and N1b interleave**: a triage batch of ~15, then the recipes that batch made available, then the next batch. The `--strict` gate still lands at the end of the last triage batch rather than the first, for the reason already recorded (a command red from its first run teaches people to ignore it). This changes N1's *shape*, not its scope or its estimate, and it makes N1b's exit — the fork below — arrive after the first fifteen instead of after all one hundred and twenty-one.

**The one real fork:** whether **N2a (the PR gate) jumps ahead of N1c**. The argument for jumping is that N1b's first recipes are the ones most worth putting in front of a developer, and shipping the gate at that moment is the cheapest possible test of whether coverage is landing. The argument against is that a moving catalog makes a noisy gate. *Recommendation: take the jump if N1b lands clean; hold if wave 1 needed more than one collector change.* Decide at the N1b exit, not now.

One dependency worth flagging early: `IMPLEMENTATION-PLAN-REMAINING.md` Tier 2 records that **engine-track CI wiring for the Phase H collector families is deferred by user decision (engine-first)**. N2a is adjacent but not the same thing — it wires `rampscan check`, whose gates are pure by construction and need no tool binaries at all. That distinction is what lets N2a proceed without reopening the deferred decision, and N0 should record it as such.

Estimates, focused-work days, honest but rough: N0 0.5 · N1a 4–5 · N1b 4–5 · N1c 3–4 · N1d 1 · N2a 2 · N2b 1.5 · N3a 2 · N3b 3–4 · N3c 1. **Total ≈ 23–27 days.**

---

## 3. Phase N0 — decisions locked before code

No code. L0 set this precedent and it paid for itself twice.

1. **Where pipeline adjudications live.** `recipes/adjudications/<control-id>.json`, one file per control, exactly as SPEC §10.2 specifies — *not* written back into `automation-frontier.json`, which is upstream's file behind a version pin the dataset client hard-fails on (ground rule 2). Each record carries `datasetVersion`, so an upstream re-publish of the frontier invalidates loudly instead of silently re-basing our reasoning. **Corrected 2026-08-17:** it does not. The dispositions move with `overlay_version`, which nothing here reads — see §1a and risk 8. The decision was right and its enforcement was incomplete.
2. **The record schema mirrors the frontier's vocabulary** — `controlId · disposition · rationale · source: "pipeline" · recipeIds[] · candidateCollectors[] · reviewed · datasetVersion` — because SPEC §10.2's stated goal is that this overlay be **contributable upstream**. Mirroring now makes that a merge; diverging now makes it a rewrite.
3. **`partial` does not count as covered.** A control is covered only when a recipe's assertions fully discharge it; otherwise the disposition is `partial`, the control stays uncovered, and the record names the *remainder* — the specific thing a repo cannot see. This is the rule that keeps the ceiling honest.
4. **Class b leads.** 44 of 121 are in scope for it, it is the CLI default, and it is the class a first customer certifies at.
5. **Ground rule 7 becomes a test, not a norm.** Extend `packages/cli/test/plain.test.ts`'s posture with a catalog-wide check: every recipe whose observation set can be empty must declare what an empty set means, and no recipe may reach `evidenced` through a vacuously-satisfied assertion over zero rows. The join already passes empty filtered sets vacuously by design (`assert.ts`) — that is correct for "every active key is rotated" and catastrophic for "the repo has a security policy," so the discrimination belongs in the catalog test.
6. **Record the N2a/CI distinction** from §2 so the deferred engine-CI decision is not reopened by accident.

**Exit:** the six decisions written into this document's changelog with their reasoning; one adjudication record hand-written as a shape probe; no other code.

---

## 4. Phase N1 — control coverage: the pipeline adjudication (leads)

### N1a — adjudicate the 121 from the pipeline source

The core data deliverable, and the one the docs have owed since the founding document.

- Walk all 121 frontier controls. For each, answer one question: **can evidence committed to a repository discharge this, in whole or in part?** Write the disposition and the paragraph.
- Reasoning quality is the deliverable. Match the upstream voice: name the artifact, name why it does or does not settle the control, and where it settles only half, name the half it leaves.
- Ship **`rampscan frontier`** alongside it — a pure derivation in the shape of `rampscan tools` and `rampscan model`: catalog × adjudications × pinned frontier → coverage, with `--json`. Nothing probed, nothing written. This is ground rule 9's enforcement: after N1a the coverage number is a command's output, and every later claim about coverage in any document quotes it.
- Recipes are **not** written in this step. Adjudication first is what stops the catalog filling with recipes that pass vacuously because the control was never really answerable.

**Exit test:** `rampscan frontier` reports a disposition for all 121 with zero unreviewed from the pipeline source; every `automatable` or `partial` record names at least one candidate collector that exists or is named in Tier 2; every `narrative` record's rationale names what specifically cannot be read from a commit; and the emitted coverage figure equals an independent recount from the records.

### N1b — wave 1: the class-b SA/SR set

The seven leverage-6 controls from §1, plus whatever the adjudication promoted next to them.

- Expect two to four new recipes over **existing** collectors (`repo-facts` and `contract` carry most of SA and SR), plus the Tier-2 cheap wins where they unlock a control: `zizmor`/`actionlint` (workflow hardening), `dockle` (image hygiene), a **license recipe over the syft data already collected**, and `trivy config`. Each is an H-phase-shaped single-collector move, already scoped upstream, and none is on anyone's critical path — which is exactly why they should ride this wave.
- Every recipe carries the full `plain` block. See §7 for why this is the real cost.

**Exit test:** each new recipe evidences on `fixtures/vulnerable-app` *and* is shown to reach `unevidenced` — never `evidenced` — on a repo that simply lacks the thing being checked; `rampscan frontier` moves by exactly the number of controls the new recipes discharge; the self-scan board renders every new row with its plain-language block.

### N1c — wave 2: the partials where the repo answers the half AWS cannot

17 of the 80 repo-plausible controls are already adjudicated `partial` from the AWS side, several at leverage 7 — `SA-09`, `SR-05`, `CM-03 (02)`, `CA-07 (04)`. In each the AWS source gets the runtime half and stops. Take the repository half and state the remainder.

**Exit test:** every wave-2 recipe's adjudication record names its remainder in one sentence, and that sentence is rendered on the board beside the row — a partial claim that does not show its boundary is not shipped.

### N1d — publish the ceiling

The honest counterweight, and the most rampscan-shaped deliverable in this plan: a computed statement of **what the pipeline source cannot answer and why** — CP's 19, PS's 7, AT's 6, and every control adjudicated narrative — emitted by `rampscan frontier`, not written by hand.

**Exit test:** the ceiling figure is computed; no document states a coverage or ceiling number that the command does not produce; the uncovered set is attributable control-by-control to a rationale.

---

## 5. Phase N2 — the loop: make the evidence reach someone

### N2a — `rampscan check` gets a consumer

`check` is finished, correct, exits 1 on a would-be violation, and **nothing in the world calls it.** The PR-comment payload already exists and is unused: `RegisterDiff` classifies `newly-violated`, `OffenderPointer` carries file, line and call path, `introducedAt`/`introducingCommit` walk the violated streak back through the bundle chain, and every recipe carries an authored `plain.fix` sentence written for a human. That is a pull-request comment nobody has ever rendered.

- A GitHub Action wrapping `check`, and a PR comment assembled from those four existing pieces.
- The comment distinguishes "you broke this" from "this was already broken" — `check` already computes both sides against the board for exactly this reason.
- Pure gates only, so no tool binaries and no reopening of the deferred engine-CI decision.

**Exit test:** a PR that breaches a declared boundary gets a comment naming the file, the import chain and the authored fix sentence, and the job exits 1; a PR that breaches nothing gets no comment and exits 0; a PR that touches an already-violated row is described as inheriting it, not causing it; the ledger is byte-identical across the whole run.

### N2b — the assessor package

One signed, self-verifying takeaway: board + rollups + the DSSE envelopes + the public key + the as-of instant, in a single artifact. `/api/verify/bundle` and `/api/verify/key` already stream exactly the bytes; the I3e export already proves row counts against the screen; the I3b smoke already verifies a downloaded bundle with `node:crypto` alone. This is assembly.

**Exit test:** a third party with the package, no network and no rampscan installation verifies every bundle in it with standard tooling, and the coverage figures inside it recount from its own rows.

---

## 6. Phase N3 — claim fidelity: the gate answered harder

The moat, deepened rather than widened. Nothing here adds a language; `IMPLEMENTATION-PLAN-REMAINING.md` Tier 3 defers "languages beyond TS/JS in the graph" by name, and this plan re-confirms that deferral rather than revisiting it.

- **N3a — grow the ruleset.** `packages/collectors/semgrep-rules.yaml` holds **three** rules, all `[javascript, typescript]`, behind a gate sophisticated enough to reason about their reachability. The gate is out-running its input.
- **N3b — drive down `inferred`.** Edges are already labelled `exact` vs `inferred`, where inferred means "unique name match across the project." `extract.ts` states in its own comments that scip-typescript slots in later behind the same node/edge schema. That seam is designed and unused. Because the gate is deliberately over-approximate, every inferred edge removed converts an `unknown` into a decided answer.
- **N3c — surface confidence where the claim is made.** `query.ts` already carries `resolutions[]` per path and I3f already renders entry-point provenance on the evidence page. Lift it to the board row, so a claim resting on inference says so at the point a human reads it.

**Exit test:** on the self-scan and on `fixtures/vulnerable-app`, the share of gated claims resting on at least one inferred edge falls measurably against a recorded pre-N3 baseline; no claim changes from `not_affected` to a weaker state as a result (the walk only ever gets tighter); every gated row on the board states its resolution; and the semgrep ruleset's growth is reflected in `cacheKeySalt`, so editing a rule still re-keys evidence.

---

## 7. Risks worth naming

1. **Vacuous passing is the failure mode that ends the product.** Forty recipes that pass because there was nothing to check is worse than seventeen that are true, and it is *the* thing a coverage push produces if unguarded. Ground rule 7 and N0 item 5 exist for this and should be treated as the plan's spine, not its paperwork.
2. **The L4/L5 cancellation taxes N1 directly, and the plan should budget it rather than discover it.** Every recipe needs three authored paragraphs — `checks`, `violation`, `fix` — enforced by `plain.test.ts`, in operator English, with no drafting assistant *by decision*, on evidence that a small local model fabricates verdicts. Forty recipes is a hundred and twenty paragraphs of careful human writing. That decision was right and this is its bill.
3. **Adjudication drifting into opinion.** 121 dispositions written quickly become a wall of assertions. Ground rule 8, and the discipline of matching the upstream rationale voice, are the mitigation. If the reasoning cannot be written, the disposition is not known.
4. **Upstream frontier drift.** Our adjudications are keyed to `controlId` + `datasetVersion`. A re-published frontier must fail loudly. This is ground rule 2 applied to a new file class, and N0 item 1 is where it is bought.
5. **Board noise scaling with the catalog.** The action queue, the guided empty states and the skip classifier were built and tuned against 17 recipes. At 40 they need re-checking — particularly `classifySkip`, whose whole job is telling a fixable skip from an honest one, and which will meet skip reasons no one has written yet.
6. **The ceiling disappoints before it reassures.** N1d will likely show the pipeline source topping out well below half the frontier. That number should be published anyway and early — it is the number that makes every other number in this system believable, and it positions rampscan correctly as the *evidence engine* rather than the whole binder. §1a sharpens this: upstream's own pipeline ceiling computes to **0.062**, and their card's reason for it — the repository set is named by a human — applies to us unchanged.
7. **Two overlays diverging in silence** (added 2026-08-17). The failure is not disagreement; it is *undeclared* disagreement. If both projects adjudicate a control and neither cites the other, a reader holding both files has two confident paragraphs and no way to choose, which is worse than one paragraph and worse than none. Ground rule 10 is the mitigation and it is cheap while the overlap is four controls. It stops being cheap at forty.
8. **The version pin does not cover the field that moves** (added 2026-08-17). Ground rule 2 and risk 4 assume a re-published frontier fails loudly. It does not: adjudication content is versioned by `overlay_version` (0.6.0 → 0.7.1 changed fifteen dispositions) while `dataset_version` — the only field the client checks — stayed identical at 2026.07.14.01. Every record written under this plan is keyed to a snapshot the loader cannot detect moving. This is the one item on this list that is a bug rather than a hazard, and it is the first task N1a owes.

---

## 8. What "done" looks like at the end of N3

- `rampscan frontier` reports a pipeline disposition for all 121 controls, zero unreviewed, with an authored rationale each — and the overlay is in a shape that could be offered upstream, as SPEC §10.2 intends. Every control upstream has also adjudicated is *declared* as agreement or as argued disagreement, never left as two silent paragraphs (ground rule 10).
- The catalog has grown by two waves of recipes, every one of which has been shown to go `unevidenced` rather than `evidenced` on a repo that lacks the thing it checks.
- The pipeline ceiling is a published, computed, attributable figure.
- A pull request that breaks a control gets told so, in the authored words of the recipe, at the moment it is opened.
- An assessor can be handed one file and verify all of it without rampscan.
- Gated claims rest on measurably fewer inferred edges than they do today, and every one of them says on the board what it rested on.

---

## Deferred by name (unchanged; restated so this plan is honest about its boundary)

Terraform / Fargate / Step Functions / EventBridge and the AWS adapters behind the six ports · KMS + S3 Object Lock · GitHub App repo access · Bedrock and the micro-LLM cascade · **languages beyond TS/JS in the graph** · OSCAL assessment-results emission · multi-repo joins · GovCloud · the React Flow graph canvas · webhooks · auditor SSO · console access audit log · acknowledge-as-ledger-event · PDF rendering service.

**One of those deferrals stopped being neutral on 2026-08-17.** `multi-repo joins` is now the named reason every claim this overlay makes is at most `partial` — it is the "one repository out of forty" arm of §1a's vacuity trap, and no `population` figure reaches it. The deferral stands (it is a product scope, not a phase), but it must be *stated in the records* rather than left implicit, and N1d's ceiling has to attribute part of itself to it.

Held at a go/no-go, unchanged: **DAST / ZAP** (runtime evidence is a second anchor class, parked 2026-08-15) · **L3d, the MCP agent surface** (un-defer when an external user asks) · **engine-track CI wiring for the Phase H collector families** (deferred by user decision; see §2 for why N2a does not reopen it).

Cancelled, with the reasoning kept: **L4/L5, the on-device model tier** — cancelled 2026-08-16 after a 0.5B model, given a context that stated nothing had been recorded, drafted a passing verdict about the repository. The un-defer trigger is not a better prompt; it is a model in the hundreds of megabytes that can be shown on the fixture pair never to state a condition it was not given.
