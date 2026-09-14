# rampscan — plan of action: soundness, and the first stranger (Phases S0–S4)

**Status:** **adopted** plan of record (merged as `2801f8c`, PR #123; milestones S0–S4 exist) for one deliverable — *every claim rampscan publishes is one a stranger can check, and one stranger has checked*. This document decides nothing until it is merged and its milestones exist on GitHub; that is the adoption bar the KSI pivot and the artifact plane both cleared.
**Date:** 2026-09-13
**Phase letter:** **S**. A–H, I, J, K, L are taken, M0–M5 are the original milestones, N is depth, P is launch, Q is the KSI pivot, R is the artifact plane. S follows R and reads as *soundness*, which is what the first and largest phase buys.
**Reads against:** the repository at `764a819` (post-R1.6), the committed scan output in `rampscan-out/`, `docs/SPEC.md` §12–§13, `docs/ARCHITECTURE.md` §9, `CONTRIBUTING.md` ground rules 4, 7 and 9, `SECURITY.md`, and `docs/PLAN-ARTIFACT-PLANE.md` §5 (phase R4). Every number below was produced by a command run against this working tree on 2026-09-13 and the command is named beside it.

**Thesis in one line:** rampscan's entire value proposition is *this claim is true because it was computed, signed and anchored* — and right now the load-bearing claim is false in this repository's own committed output, two published documents assert numbers no command produces, and in the twenty-six days since the repository went public **no person outside this machine has read it**; S closes all three, in that order, because the second and third are worthless while the first is open.

---

## 0. Ground rules, active from S0

The ten in `CONTRIBUTING.md` stay active unchanged, and rules 4, 7 and 9 are the ones this plan exists to honour. Four are specific to this plan.

1. **The finding is handled as `SECURITY.md` defines it, not as a bug.** `SECURITY.md` names one threat as specific to what this tool is — *a check that reports `evidenced` without the evidence being there* — and says it "is a security report, not a bug report, and it is the most valuable one this project can receive." §2 is an instance of exactly that class, found internally. A project that routes its own instance through an ordinary commit has decided its security policy binds strangers only.
2. **Unreachability is proven positively or it is not claimed.** The general form of the defect: *the absence of a node in a graph is the absence of evidence, never evidence of absence.* Any code path that converts "we did not see it" into a signed `not_affected` is the same bug wearing different data, and this rule is what makes it findable next time.
3. **A number enters a published document only in the same change that regenerates it.** Ground rule 4 ("computed, never typed") is the only one of the ten with no *Enforced by* line, and §3 is what happens to a rule with no gate. S2 gives it one.
4. **No phase of this plan is exited by its author.** S3's exit gate is a response from someone who does not work on rampscan. Every exit gate in every prior plan — M, N, P, Q, R — was satisfiable by the person who wrote it, which is why the project can be this good and this unread at the same time.

---

## 1. What this plan is — three closures, one argument

rampscan is, by construction, a machine for turning measurements into claims a stranger is supposed to trust without re-running them. That is the product. It is also the whole attack surface, and it fails in three places today, all in the same direction — **something is asserted that was not verified**:

| Where | What is asserted | What was verified |
|---|---|---|
| `openvex.json` | "`postcss@8.4.31` is not reachable from any entry point" — signed, digest-pinned as a bundle subject | that `postcss` has no node in a graph built only from first-party `import` statements |
| `README.md` | 46 KSI rows · 13 of 46 · 1,001 tests · 720 passed | `frontier` prints 41 and 13 of 41; `vitest run` prints 1,117 |
| `docs/ARCHITECTURE.md` | Step Functions, Fargate task classes, EventBridge, S3 Object Lock, KMS, Bedrock — in a table headed "Runs as" | a local-adapter prototype; `find` returns no `.tf`, and no `@aws-sdk` dependency exists in any `package.json` |

And one closure that is not a defect but its precondition: **nobody has checked any of it.** `gh api repos/snymrova/rampscan/traffic/views` returns **2 views, 2 uniques, over fourteen days**; the repository has **0 stars, 0 forks, 0 watchers** and has been public since 2026-08-18.

S fixes the first, gates the second and third so they cannot silently recur, and then spends two days finding out whether any of it matters to somebody else.

### 1.1 Why this precedes R2–R5 rather than following them

`docs/PLAN-ARTIFACT-PLANE.md` §5, phase R4, states its own dependency:

> The reachability tier earns its keep here: a non-accepted vulnerability carrying a signed not-affected OpenVEX with the call path attached is a record an assessor can interrogate.

R4 is built on the soundness of the artifact §2 shows to be unsound, and R2's entire premise — that an SDR carrying rampscan's signature is worth more than the spreadsheet it replaces — is the same premise. Building R2–R5 first produces a better-looking container for a claim that does not hold. **S is not a detour from R; it is a prerequisite R named and nobody checked.** R2–R5 (issues #102–#115) pause at the end of S1, unchanged, and resume at the end of S3.

---

## 2. The finding: `not_affected` is emitted from an absence

Every fact in this section came from a command against this working tree; no claim here is inferred.

### 2.1 What the committed output says

`rampscan-out/exports/openvex.json`, written by a real scan at commit `306ca63` and digest-pinned as a subject of a signed bundle, contains **five statements. All five are `status: not_affected` with justification `vulnerable_code_not_in_execute_path`.** Four are `postcss@8.4.31`, one is `sharp@0.34.5`. The source advisory set — `rampscan-out/artifacts/osv-scanner/osv-results.json` — contains exactly five advisory rows, **three of them `HIGH`**.

> **Correction, 2026-09-13 (S0-4).** Everywhere this document calls that file *committed* or *published*, it is wrong: `rampscan-out/` is gitignored (`.gitignore:9`) and `git ls-files rampscan-out` returns **0** files. The artifact exists in the maintainer's working tree and has never left this machine. The mechanism, the five statements, the 17 dependency packages and the `next → postcss` SBOM edge are all exactly as described below — only the publication status was overstated, and it was overstated in the direction that made the finding look worse than it is. Recorded rather than quietly edited, because a plan whose thesis is *every claim is one a stranger can check* does not get to silently fix its own.

**Every advisory this repository has was suppressed, and the suppression is signed.**

### 2.2 The mechanism

`packages/collectors/src/reachability.ts:142`:

```ts
const notAffected = gated && (dep === undefined || !dep.reachable);
```

`dep === undefined` means *the package has no node in the code graph*, and it is treated as a proof of unreachability equal in standing to a completed walk that failed to arrive. But dependency nodes exist only where first-party source names them: `packages/graph/src/extract.ts:324` creates a `kind: "dependency"` node from an import specifier, and `dependencyReachability` (`packages/graph/src/query.ts:151-156`) builds its entire map from `SELECT id, package FROM nodes WHERE kind = 'dependency'`. **There are no package→package edges anywhere in `graph.db`.**

Queried against the committed `rampscan-out/artifacts/graph/graph.db`: **17 dependency nodes** — `next`, `react`, `zod`, `vitest`, `typescript`, `yaml`, `pocketbase`, `@playwright/test` and nine `node:` builtins. `postcss` is absent. `sharp` is absent.

The operative rule, restated plainly: **an advisory in any package your first-party source does not `import` directly becomes a signed "not affected."** On a typical Node service that is the overwhelming majority of advisories, and it is precisely the population that matters, because transitive depth is where advisories live.

### 2.3 The code's own stated safety argument does not hold

`packages/graph/src/query.ts:11-13`:

> dependency reachability walks EVERY edge kind (over-approximate): a not-affected VEX claim is only made when even the loose walk cannot reach the package.

The walk is over-approximate *within the edges the graph has*. The graph is missing the entire package-dependency subgraph, so the over-approximation the argument rests on is not present in the data. The recipe states the same contract and is bound by it — `recipes/commit/no-critical-reachable-advisories.json`, `notes`: "An advisory is `not_affected` only when the code graph PROVES the package is beyond every entry point and declared route." The implementation does not meet the contract its own recipe publishes.

### 2.4 This is ground rule 7, exactly

> **7. No vacuous passes — ever.** A recipe may not report `evidenced` from the *absence* of something to check. […] a boundary rule whose module path matches nothing fails, because a module path that matches nothing is guarding nothing.

A `not_affected` derived from a package having no node is structurally identical to a boundary rule whose module path matches nothing: the check found nothing to check and reported success. Ground rule 7 is enforced by `catalog.test.ts` and `catalog-bare.e2e.test.ts` over recipe *verdicts*; it was never extended to the reachability collector's *gating*, which is where the same failure mode moved.

The consequence flows straight through: the recipe's assertion is `count_eq 0` where `severity in (CRITICAL, HIGH)` **and `not_affected == false`**. Suppressing the three `HIGH` rows is what makes `no-critical-reachable-advisories` read `evidenced` in this repository today.

### 2.5 The data that disproves the claim is already in the same output directory

`rampscan-out/artifacts/syft/sbom.cdx.json` is CycloneDX 1.7 with **173 components and a populated `dependencies` array carrying `dependsOn`**. Walking it:

- **`postcss`**: the edge `next@15.5.23 → postcss@8.4.31` is present in the SBOM. `next` **is** a dependency node in `graph.db` and **is** reachable from the declared entry point. So `postcss` is provably **reachable** from data rampscan already collected, wrote to disk, and signed a contradicting statement about in the same run.
- **`sharp`**: no path from `next` in the SBOM's `dependsOn` (15 nodes walked). syft's graph is partial — **34 of 173 components carry outgoing edges** — so `sharp` is genuinely **unknown**: not provably reachable, and not provably unreachable either.

Those two packages are the two halves of the correct answer, and the correct answer is three-valued. That is the whole fix.

### 2.6 A second, independent soundness hole in the same claim

`rampscan.config.json` declares `graph.entrypoints: ["packages/cli/src/main.ts"]`, and `detectEntrypoints` (`packages/graph/src/entrypoints.ts:44-56`) returns **only** the configured entries when any are configured — package.json detection is skipped entirely. This repository contains **two** applications: the CLI, and `console/web`, a 13,148-line Next.js app. The console's entry points are not declared, so nothing the console imports is on any walk, and every advisory in that half of the tree is not-affected by construction.

`basis.entrypoints` records the narrowing and the `impact_statement` names the file, which is honest as far as it goes. It does not go far enough: an assessor reading `status: not_affected` will not read "(packages/cli/src/main.ts)" as *we walked one of your two applications*. **A negative claim must state the scope it is negative over, or refuse to be made.** Configuring one entry point to quiet a warning currently converts a whole repository into not-affected territory, silently.

### 2.7 Severity, stated plainly

There are zero external adopters (§1), so nobody holds a false VEX document from this tool today — and, per the correction in §2.1, the artifact was never published at all: it is an untracked file under a gitignored directory. That bounds the blast radius to zero as of today; it does not change the class. The defect is in the load-bearing claim of the product, and the first person to run `rampscan scan` against a real repository receives a signed false negative over their `HIGH` advisories. The finding is recorded in full, with its reproduction, in [`docs/FINDING-VACUOUS-NOT-AFFECTED.md`](FINDING-VACUOUS-NOT-AFFECTED.md).

---

## 3. The claims that no command produces

Ground rule 4 is the house rule `CONTRIBUTING.md` itself calls "the house rule most often broken by accident, usually by copying a figure that was true last month." Measured against `README.md` at `764a819`:

| README | Says | `pnpm rampscan frontier` / `vitest run` says |
|---|---|---|
| L32, L34–39, L46 | **46** KSI rows; floor met on 13 of 46; no method on 33 | **41** rows; 13 of 41; no method on **28** |
| L30–31 | `artifacts 2/5` for two sample rows | `0/5` on all 41 |
| L14 | **1,001** tests across 81 files, 996 + 5 skipped | **1,117** tests across **90** files, 0 skipped |
| L83 | `720 passed \| 3 skipped (723)` | same run, same command, 1,117 passed |

The 46→41 drift is the sharpest of the four, because **41 is the number R0 shipped**: `docs/PLAN-ARTIFACT-PLANE.md` §7.1 identified the `varies_by_class` denominator bug, R0 fixed it, and `frontier` has printed the honest denominator ever since. The code got more truthful and the document did not follow. Three test counts appear in one README and none of them is the one the suite prints.

`docs/ARCHITECTURE.md` is the same failure at a different scale, and worse in kind because its audience is an assessor. §3's component table is headed **"Runs as"** and its rows read `EventBridge Scheduler`, `Step Functions DAG`, `Fargate task`, `S3, Object Lock (compliance mode), KMS`, `Fargate tasks → Bedrock via VPC endpoint`. §7 describes a proxy allowlist and task IAM scoping as operating controls. None of it exists: no `.tf` or `.tfvars` anywhere in the tree, no `@aws-sdk` or `cosign` dependency in any `package.json`, and `packages/core/src/` contains exactly one adapter family — `local.ts`. The ports-and-adapters design is real and good, and §3's own "Ports and adapters" table states the split correctly one screen further down. The problem is that a document cannot use present tense for a roadmap and past tense for a build in the same section and expect a stranger to tell which is which.

---

## 4. Target state

```
┌─ A CLAIM rampscan SIGNS ───────────────────────────────────────┐
│                                                                │
│  positive claim         negative claim        no claim         │
│  "reachable: true"      "not_affected"        "unknown"        │
│  ├ a walk arrived       ├ a walk completed    ├ the walk was   │
│  │  (source graph or    │  over a graph that  │  not possible, │
│  │   SBOM dependsOn)    │  CONTAINS the node  │  or the node   │
│  └ path is the artifact └ scope is stated     │  was never in  │
│                            in the document    └  the graph     │
│                                                                │
│  absence of a node ────────────────────────────► unknown       │
│                         (never not_affected)                   │
└────────────────────────────────────────────────────────────────┘
```

Three-valued, with one rule doing all the work: **`not_affected` requires a node.** Everything else follows.

### 4.1 Where the code changes

| Package | Change | Phase |
|---|---|---|
| `collectors` | `reachability.ts` — `dep === undefined` yields `unknown`; `not_affected` emitted only for a walked-and-missed node; VEX carries its entry-point scope as a first-class field | S1 |
| `graph` | `query.ts` — `dependencyReachability` accepts the SBOM `dependsOn` edge set and continues the walk through it; SBOM-derived hops marked `sbom` beside `exact`/`inferred` | S1 |
| `graph` | `entrypoints.ts` — configured entries no longer suppress detection silently; undeclared application roots are reported | S1 |
| `cli`, `docs` | README and ARCHITECTURE regenerated / re-tensed; the numbers gate | S2 |
| `cli` | `packages/cli/test/published-numbers.test.ts` — new; ground rule 4's missing *Enforced by* | S2 |
| `schema`, `ledger`, `signer`, `projector`, `scheduler`, `console` | **no change** | — |

Nothing in this plan touches a ledger format, a signature, or any of the ten `ARCHITECTURE.md` §9 invariants.

---

## 5. Sequencing

```
S0 ──► S1 ──► S2 ──► S3 ──► S4
 ·      ·      ·      ·      ·
record  fix   gate  stranger  depth
              the           the fix
             numbers        leans on
```

**Why the record precedes the fix.** S0 is the only phase whose window closes: once the fix lands, the pre-fix state is reconstructible from git but the *decision* about how this project handles its own security class is retroactive and unconvincing. It also front-loads the two judgments that cannot be defaulted (§5.0).

**Why the stranger comes after the fix and before the depth.** rampscan cannot be put in front of an assessor while it signs false not-affected statements — S3 would burn the one first impression it gets. But S4 is polish, and polish ahead of the first external signal is how the last four weeks were spent.

**The one external deadline.** Issue #72 — the RFC-0033 comment — closes **2026-10-09**, twenty-six days out. S0–S3 is ≈5.5 focused days, so the deadline is comfortable if S3 is not deferred again.

Estimates, focused-work days: S0 0.5 · S1 2 · S2 1 · S3 2 · S4 2. **Total ≈ 7.5 days**, of which 5.5 precede the deadline.

### Phase S0 — the finding, recorded before it is fixed (0.5 day)

No product code. Two decisions need the owner and cannot be defaulted:

- [x] **S0-1. Disclosure posture.** **Decided 2026-09-13: advisory filed, no embargo, fix in the open.** `SECURITY.md` directs this class to GitHub private vulnerability reporting; the private channel exists to protect adopters during a fix, and there are none — 0 stars, 0 forks, 2 views in fourteen days (`gh api …/traffic/views`), and nothing under `rampscan-out/` has ever been published (§2.1, corrected). With no one to protect, an embargo buys nothing and costs the one thing the advisory is for: a published advisory that *names the tool's own defect in its own signed output* is, for a compliance-evidence product, an asset rather than a liability. Filed as `docs/FINDING-VACUOUS-NOT-AFFECTED.md` and as a repository security advisory.
- [x] **S0-2. What happens to the `openvex.json` carrying the false statements.** **Decided 2026-09-13: supersede, never delete.** The document is wrong and it is also the evidence that the defect was real; deleting it is the one move inconsistent with everything the ledger stands for. S1-5 regenerates it post-fix and the diff is the proof. Note the correction in §2.1: the file is **not** committed — `rampscan-out/` is gitignored and untracked — so what is superseded is a working-tree artifact and the record of it in this document, not anything a reader can fetch.
- [x] **S0-3. The failing test, first.** `packages/collectors/test/reachability-soundness.test.ts` — `minimist` absent from `graph.db`, present in a CycloneDX SBOM as a dependency of the reachable `lodash`, asserting that no `not_affected` may follow. It fails at `2801f8c` with `expected true to be false` at the `not_affected` assertion, output recorded in the finding §4.7. Committed wrapped in `it.fails` so `main` stays green; **S1-1 unwraps it**, and the wrapper fails the moment the behaviour is corrected, so the unwrapping cannot be forgotten.
- [x] **S0-4. Record the pre-fix state.** `docs/FINDING-VACUOUS-NOT-AFFECTED.md` §4 — the five statements, the three `HIGH` rows, the 17 dependency packages and the absent edge kind, the `next → postcss` SBOM edge, and the fact that `packages/collectors/test/reachability.test.ts:110` is a **passing test asserting the defect is correct** — each with the command that produced it.

**Exit gate — met 2026-09-13:** the advisory exists (`docs/FINDING-VACUOUS-NOT-AFFECTED.md`); `S0-3` fails reproducibly, naming `reachability.ts:142`; S0-1 and S0-2 are recorded decisions above, not preferences.

### Phase S1 — reachability soundness (2 days)

- [x] **S1-1. Absence becomes `unknown`.** `dep === undefined` no longer reaches the `notAffected` branch. `not_affected` is emitted **only** where the package has a node and the walk did not arrive. Ground rule 2, in one edit. *Done 2026-09-14:* an absent node yields `reachable: unknown`, `not_affected: false`, a `gate_note` naming the gap, and an `under_investigation` OpenVEX statement carrying the same sentence. S0-3 is unwrapped and passes. `reachability.test.ts` no longer asserts the defect; because the fixture has no package with a node the walk cannot reach, the earned `not_affected` is now covered by a planted mini-repo (`minimist` imported only by an orphan file). Real-tool scan of the fixture: flagship offenders 2 → 3.
- [x] **S1-2. The SBOM graph joins the walk.** `dependencyReachability` takes the CycloneDX `dependencies[].dependsOn` edges and continues through them from any reachable dependency node, so a transitive dependency of a reachable direct dependency resolves `reachable: true` with the package chain as its path. Hops sourced from the SBOM are marked `sbom`, distinct from `exact` and `inferred`, because their provenance is a package manifest rather than a parsed call site and a reader is owed the difference. **This upgrades `unknown` to `true`; it may never downgrade anything to `not_affected`** — the SBOM graph is partial by measurement (34 of 173 components carry edges), so it can prove presence and never absence. *Done 2026-09-14:* `packages/graph/src/sbom.ts` reads the npm `dependsOn` edges by package name; `dependencyReachability(db, sbom)` walks forward from every code-reached package and only ever adds to the reachable set — a package with no node and no chain is absent from the result, never `false` (asserted as an invariant: every package `false` with the SBOM was already `false` without it). `sbom` is a third hop mark through the schema, `assert.ts`, the console's `CallPath`, and artifact 4's limits. The basis signs the manifest graph's shape (`sbom: { component_count, components_with_edges, edge_count }`). The reachability collector declares `sbom.cdx.json` as an input, so the cache key covers it. **On this repository's own artifacts nothing moves yet, and the reason is the finding's §3.3, not this item:** `next` is imported only by `console/web/app/layout.tsx`, outside the one configured entry point, so it is a node the walk never reaches and no SBOM chain can start from it — finding §4.4 said otherwise and is corrected there. `postcss` flips when S1-4 lets the console's root into the walk.
- [x] **S1-3. A negative claim states its scope.** The VEX statement carries the entry-point set and the walked application roots as structured fields, not only inside prose. Where the tree contains an application root that no declared entry point covers, `not_affected` is **refused** for that run and the reason is recorded — a negative claim scoped to half a repository is not a negative claim. *Done 2026-09-14:* an application root is a directory with its own `package.json` that owns source files by nearest manifest — not a heuristic over `bin` or framework markers, because `console/web` declares none and is the case the definition exists for. `detectApplicationRoots` records them in `graph.db` (extractor 0.3.0); `applicationRootCoverage` counts how many of each root's files the gating walk reached; the reachability collector refuses `not_affected` for the run while any root reads zero, or while the graph predates recorded roots (an unknown width is not a full width). The refusal is the row's `gate_note`, the VEX statement's `impact_statement`, and `basis.degraded`; `basis.application_roots` signs the width; every OpenVEX statement of a gated run carries `rampscan:scope` — commit, entry points, their source, and each root with `walked`. The SAST gate (`no-reachable-dangerous-code`) makes the same negative over the same walk and now refuses it the same way, through one shared `walkWidth` in `packages/collectors/src/scope.ts`. The console renders the roots and names the ones never entered. **Measured on this repository's own graph:** twelve roots, two never entered — `console/web` (41 files) and the workspace root itself (28 files: the PocketBase hooks and migrations, the scripts, the e2e, the two config files), which the plan had not counted as a third application. Under S1-3 the self-scan signs no negative until both are covered, which is S1-4's job.
- [ ] **S1-4. Configured entry points stop hiding detection.** `detectEntrypoints` still honours config, and additionally reports what package.json detection *would* have found and config excluded, so narrowing is visible instead of silent.
- [ ] **S1-5. Regenerate, and let the board move.** Re-run the self-scan. Expected: `postcss` resolves `reachable: true` via `next` — **which requires S1-4 first**, because `next` is reached only through `console/web`, and the configured entry point set does not include it (S1-2 measured this; finding §4.4 corrected); `sharp` resolves `unknown`; `openvex.json` carries **zero** `not_affected` statements; and `no-critical-reachable-advisories` flips **`evidenced` → `violated`**, because two `HIGH` advisories are in fact reachable. The self-scan line moves from `12 evidenced · 2 violated` to `11 evidenced · 3 violated`. **This is the fix working, and the README must say so** — a third standing violation, explained, is worth more than the suppression it replaces.

**Exit gate:** S0-3 passes; `openvex.json` has no `not_affected` statement; `postcss` carries an SBOM-sourced path through `next` and `sharp` reads `unknown`; the self-scan reports three violations and the README's "It scans itself" section explains the third; `rebuild` is byte-equal; the suite green.

### Phase S2 — the numbers gate (1 day)

- [ ] **S2-1. `published-numbers.test.ts`.** Ground rule 4's missing enforcement. The test runs `frontier` and the suite's own reporter, extracts the numbers the README asserts, and fails on drift. It is deliberately narrow — KSI denominator, floor-met count, no-method count, test count, test-file count, the self-scan verdict line — because a gate that tries to parse prose will be deleted within a month.
- [ ] **S2-2. README regenerated.** Every figure in §3's table, from the command, in the same commit as S2-1. The `frontier` sample block is pasted from real output including the class-optional line it currently omits.
- [ ] **S2-3. `ARCHITECTURE.md` separates built from planned.** Not a rewrite — a tense and a marking pass. §3's "Runs as" column gains an explicit *today / appliance* split matching the ports table that already sits below it, and §7's operating controls are marked as design rather than deployed. The document's value is that it is the only place the whole machine is visible; that value survives honesty about which half runs.
- [ ] **S2-4. `CONTRIBUTING.md` ground rule 4 gains its *Enforced by* line**, naming S2-1, so rule 4 reads like rules 1, 2, 3 and 7 instead of like an aspiration.

**Exit gate:** `published-numbers.test.ts` is in CI and fails on a hand-edited README figure; no number in README or ARCHITECTURE lacks a command that produces it; a reader can tell from ARCHITECTURE alone which components exist.

### Phase S3 — the first stranger (2 days)

The first exit gate in this project's history that the author cannot satisfy alone.

- [ ] **S3-1. Run the gap engine over a real authorized package.** `paramify/fedramp-20x-pilot` is, per `docs/RESEARCH-PARAMIFY-PILOT.md`, the only publicly assessed, 3PAO-signed 20x package known to exist, and its `Evidence/` tree is the exact shape `rampscan ingest` was built for (§12.8). Ingest it and produce the gap register for a package that has already passed. Licence caveat from that note holds unchanged: consume outputs, vendor nothing.
- [ ] **S3-2. Send it to the three parties named in the research.** Paramify, Coalfire, and the FedRAMP 20x community channel. Not a pitch — the register, the three places `RESEARCH-PARAMIFY-PILOT.md` §5 already documents rampscan as stronger (signatures, assertion strength, gap computation), and one question: *is the gap register the thing you are missing, or is the SDR?* That question is what decides whether R2–R5 is the right six weeks, and it has never been asked of anyone.
- [ ] **S3-3. File the RFC-0033 comment (#72).** Due 2026-10-09. It is a free, dated, public distribution channel into precisely the audience this tool is for, and it has been open since 2026-09-11.
- [ ] **S3-4. File the two upstream schema findings.** `docs/PLAN-ARTIFACT-PLANE.md` §2.6 has them written and verified against `FedRAMP/schemas@main`; `RESEARCH-UPSTREAM-READINESS.html` has the playbook. They are R2 deliverables today and they need none of R2 to be filed — they are diagnoses, and diagnoses are what that repository adopts.

**Exit gate — not self-satisfiable:** at least one response from someone outside this repository. A refusal, a correction, or "we already have this" all pass. Silence from every channel also resolves the gate, in the direction the plan most needs to know about, and is recorded in the session log with what was sent and where.

### Phase S4 — the surface S1 now leans on (2 days)

S1 makes the extractor load-bearing for a *stronger* claim: before, a missing edge produced a false negative that suppressed a finding; after, the remaining `not_affected` statements rest entirely on the walk being complete over the nodes it does have. The extractor's test surface has to move with that.

- [ ] **S4-1. Extractor tests against the false-negative failure modes.** `packages/graph/src/` is **1,338 lines** against **one** test file of 424 lines, which is dense and good and exercises one hand-built fixture tree. Add the patterns that produce a missing edge in real trees — re-export barrels, `export *`, dynamic `import()`, `require` with a non-literal, conditional exports, and a second application root — each asserting `unknown` rather than a verdict. **The barrel case is measured, not hypothetical (S1-3, 2026-09-14):** `extract.ts` records an `export … from "x"` declaration's names and emits **no edge** to `x`, so every `@rampscan/*` package's `index.ts` is a wall — the self-scan walk enters `packages/core` and reaches **1 of 13** files, `packages/schema` 1 of 14, `packages/projector` 1 of 10, and so on for every package but `collectors` (whose index imports before it re-exports). A dependency imported only behind a barrel has a node the walk never arrives at, which is the one shape that signs `not_affected`; S1-3's refusal covers it on this repository only because two roots are unwalked anyway, and would not cover it on a single-application repository built the same way. The edge is a lexical fact (`exact`), so this belongs to the extractor, not to a test asserting `unknown` — it should be pulled forward, ahead of S1-5.
- [ ] **S4-2. A lint gate.** No eslint, prettier or biome exists in a 42,000-line TypeScript repository that gates pull requests on architectural boundaries. `strict` plus `noUncheckedIndexedAccess` plus `exactOptionalPropertyTypes` is carrying real weight and is a different axis. One config, one CI step, no reformat-the-world commit.
- [ ] **S4-3. A console test floor.** `console/web` is **13,148 lines** with zero unit tests and one Playwright smoke. Not a coverage push — ground rule 7's own warning applies to test counts too. The floor is the pure functions the board's correctness depends on: `lib/types.ts` and `lib/emptystate.ts`.

**Exit gate:** each S4-1 pattern has a test asserting `unknown`; the lint gate runs in CI; `console/web/lib` has tests.

### Explicitly not in this plan

- **The O(n) fold.** Measured, not assumed: `pnpm rampscan board` is **6.02 s** against a 280-object ledger and `pnpm rampscan` with no fold at all is **5.92 s**. The fold is ~0.1 s; the six seconds is `tsx` startup. It is a real cliff at 100k objects and it is not a problem today, and a plan that fixed it now would be optimising against a number nobody has hit. Filed as an issue, not a phase.
- **Splitting `packages/cli`** (11,724 lines of src; `main.ts` 973, `frontier.ts` 847). The KSI register and gap computation belong below the CLI so a future API shares one implementation. Correct, and it is a refactor with no external signal attached — it waits for S3's answer.

---

## 6. What is true when it is done

- `rampscan` signs no negative claim it cannot prove, and says `unknown` where it does not know — which on this repository means it stops suppressing three `HIGH` advisories and starts reporting them.
- A transitive dependency of a reachable dependency reads `reachable: true` with a package chain as its path, from the SBOM rampscan already collects.
- A negative claim states the scope it is negative over, and refuses to be made over half a repository.
- Every number in the README and the ARCHITECTURE document comes from a command, and a test fails when one does not — ground rule 4 finally enforced like the other nine.
- A reader of `ARCHITECTURE.md` can tell which components run today.
- The project's own security policy has been applied to the project, once, in public.
- **Somebody who does not work on rampscan has looked at it and said something**, and the R roadmap resumes knowing whether it is the right roadmap.

---

## 7. Honest constraints and risks worth naming

1. **S1 makes rampscan's own board worse, on purpose, and the README must lead with it.** Three standing violations instead of two. The temptation to suppress the third — declare it accepted, widen a config, narrow an entry point — is the exact pressure this product exists to resist, and the first time the project has felt it about itself.
2. **`unknown` is less impressive than `not_affected` and that is the point.** After S1 this repository proves zero advisories unreachable, where yesterday it proved five. The honest reading is that it never proved five. A tool whose reachability tier mostly returns `unknown` on small repositories is a tool telling the truth about what a first-party import graph can see; the fix for that is a real dependency graph in S1-2 and better extraction in S4-1, never a looser gate.
3. **The SBOM dependency graph is partial and cannot be trusted downward.** 34 of 173 components carry `dependsOn` edges in this repository's own SBOM. S1-2 is therefore strictly a presence-prover. Any later change that lets the SBOM graph justify a `not_affected` reintroduces §2 in a new place — this is the single most likely way this fix regresses, and ground rule 2 exists to catch it.
4. **S3 may return nothing.** Four channels, two days, no obligation on anyone to reply. Silence is data and the plan treats it as such, but it must be *recorded* silence — sent, dated, named — or the next plan will repeat the last four weeks with a different phase letter.
5. **S3 can embarrass.** Running the gap engine over somebody's authorized package and mailing them the gaps is a strong opening move and also an easy one to resent. The framing in S3-2 is a question, not a scorecard, and the register goes to them before it goes anywhere public.
6. **Pausing R has a cost.** R2–R5 are scoped, argued and ready, and #102–#115 are open. The cost of the pause is ≈5.5 days. The cost of not pausing is shipping the SDR — the document whose whole purpose is to be handed to an assessor — with a reachability tier that suppresses `HIGH` advisories, which R4's own exit gate assumes is sound.
7. **`ARCHITECTURE.md` gets less impressive and more useful.** A document that reads as a built appliance is better marketing than one that reads as a prototype with a designed appliance behind it. The second one is the one that survives contact with an assessor, and this project has no adopters to disappoint yet — which makes now the only cheap moment to do it.

---

## 8. Adoption

This document decides nothing until it is merged and `S0`–`S4` exist as milestones on GitHub, with S0-1 and S0-2 recorded as decisions in §5.0 rather than as recommendations. R's milestones stay open and unchanged; #102–#115 are paused at the S1 exit and resume at the S3 exit.

---

## Session log

- **2026-09-13** — Drafted after a full read of the repository. The plan turned on four things read out of the tree rather than inferred: `openvex.json` in the committed output contains five `not_affected` statements and the advisory set contains exactly five advisories, three of them `HIGH`; `graph.db` holds 17 dependency nodes and neither suppressed package is among them, because dependency nodes come only from first-party import specifiers and no package→package edge exists anywhere; the SBOM in the same output directory already carries the `next → postcss` edge that disproves one of the five; and `gh api …/traffic/views` returns 2 views over fourteen days against a repository public since 2026-08-18. `SECURITY.md` defines the first of those as a security report rather than a bug report and calls it the most valuable report this project can receive — which is what set S0 ahead of S1. Not yet adopted as plan of record.
- **2026-09-13 (S0 complete)** — Adopted at `2801f8c`. Every fact in §2 re-derived from a command before anything was written, and one of them did not survive: `rampscan-out/` is gitignored and `git ls-files rampscan-out` returns 0, so the `openvex.json` this plan called *committed, published, reachable on GitHub* was never published at all. Corrected in §2.1 and §2.7 rather than edited away; it moves today's blast radius to zero and leaves the class untouched. Two things found while reproducing that the draft had not seen: the SBOM's `next → postcss` edge is real but `postcss@8.5.26` sits beside `8.4.31` under the same parent, and `packages/collectors/test/reachability.test.ts:110` is a **green test asserting the defect is correct behaviour** — S1-1 has to change a passing test, which is the sharpest evidence that the gate was never a slip. S0-1 decided: public advisory, no embargo. S0-2 decided: supersede, never delete. S0-3 fails at `2801f8c` with the output recorded; committed under `it.fails` so `main` stays green and the wrapper breaks the moment S1 fixes it. Next: S1-1 (#128).
- **2026-09-14 (S1-1)** — GHSA-7jff-6v53-r56x published. The one-line fix landed with its blast radius read first: every test and document that leaned on "absent means unreachable" — the flagship unit test, the scan e2e, the fixture builder's description of fault 6, and the recipe basis statement signed into every bundle (which said "a package the graph never saw as a node is only unreachable because nothing imports it", the defect in prose). The statement now says such a package was never walked and counts; "Unknowns count against us" is kept verbatim because the console smoke reads it. Suite 1,121 passed, 0 expected failures, 91 files. Next: S1-2 (#129).
- **2026-09-14 (S1-2)** — The SBOM's `dependsOn` edges continue the walk forward from every package the code walk reached, hops marked `sbom`, and the join is written so that it cannot move a verdict downward: it adds to the reachable set and touches nothing else, and a graph test asserts the invariant over a mini-repo that has the one shape the code walk can call unreachable. The soundness test now carries both halves of the finding's worked example — `minimist` reachable through `lodash ⇒ minimist`, `sharp` unknown with no chain — and asserts the signed document says `affected` and `under_investigation` respectively, with zero `not_affected`. Probed against this repository's own `rampscan-out/` before writing this: the SBOM parses to 173 components, 33 edge-carrying by name (34 by purl — two `postcss` versions), and `postcss` **stays unknown**, because `next` is not a reached node: its only importer is `console/web/app/layout.tsx` and the configured entry point is `packages/cli/src/main.ts` alone. Finding §4.4 claimed `next` was reachable; it was not, on the graph it cites, and the correction is recorded there. So the board does not move at S1-2 and S1-5's expectation now names S1-4 as its precondition — the second hole (§3.3) is what stands between the SBOM edge and the verdict, which is the plan's own argument for S1-4 made concrete. Suite 1,127 passed, 91 files. Next: S1-3 (#130).
- **2026-09-14 (S1-3)** — A negative claim now states its width and refuses to be made at less than the whole tree. An application root is any directory with its own `package.json` that owns source files (nearest manifest wins); the graph collector records them, the gate measures which ones the walk entered, and while any is never entered — or the graph predates the record — every would-be `not_affected` reads `unknown` with the refusal as its note, the VEX statement says `under_investigation` with the same sentence, and the basis signs the roots beside `degraded`. Every OpenVEX statement of a gated run carries `rampscan:scope` as structured fields. The soundness test has the finding's §3.3 in miniature — two packages, one named as an entry point, a vulnerable package imported only under the other — and the same miss is refused with one root named and earned with both, so the mechanism is the width and not a blanket. Measured on this repository's graph before writing: twelve roots, `console/web` and the workspace root itself never entered, the latter holding 28 files the plan had not counted (PocketBase hooks and migrations among them). And a second measurement the coverage table made impossible to miss: `export … from` declarations produce no edge, so the walk stops at every package barrel — 1 of 13 files reached in `core`, 1 of 14 in `schema`. Recorded under S4-1 with the recommendation to pull that one edge forward before S1-5, because it is the barrel, not only the entry-point set, that decides what `console/web`'s walk will see. Suite 1,138 passed, 91 files. Next: S1-4 (#131).
