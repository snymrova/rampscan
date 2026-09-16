# rampscan — plan of action: the KSI pivot (Phases Q0–Q5)

**Status:** proposed plan of record for one deliverable — *rampscan re-founded as a KSI-native gap engine*, per the decision of 2026-09-11. `docs/RESEARCH-KSI-GAP-ENGINE.md` proposes and this plan decides; the GitHub milestones carry the decision once this document is adopted.
**Date:** 2026-09-11
**Phase letter:** **Q**. A–H, I, J, K, L are taken, M0–M5 are the original milestones, N is depth, O is skipped (reads as a zero), P is the launch. Q is free and follows P, which is the right accident: the pivot is what comes after launching.
**Reads against:** the repository as it stands (`packages/schema`, `packages/dataset`, the twenty recipes, `rampscan frontier`'s output), `docs/SPEC.md`, `docs/ARCHITECTURE.md` §9 invariants, and the verified regulatory ground truth in `docs/RESEARCH-KSI-GAP-ENGINE.md` §2–3. Every rule ID cited here (`FRC-CSX-VVK`, `VDR-TFR-MVX`, …) is FedRAMP's canonical identifier, verified in that report against `fedramp-consolidated-rules.json` 2026.07.14.01 — the version this checkout pins.

**Thesis in one line:** rampscan already built the hard half of a KSI gap engine — the signed, anchored, freshness-clocked proven-state — around the wrong spine; the pivot inverts the register from *recipe → controls* to *KSI → validation methods → evidence* so that the numbers CR26 actually prices (methods per KSI against a class floor, history against `FRC-CSX-MOT`, artifacts against the five) become computable, and everything else in this plan is what falls out of that inversion in dependency order.

---

## 0. Ground rules, active from Q0

Rules 1–10 of the depth and launch plans stay active unchanged — the ledger is the record, every number comes from a command, no vacuous passes, pins are decisions, tier 3 never borrows tier 1's credibility. Five new rules are specific to the pivot, and each exists because the pivot is the one operation in this repository that changes what a number *means* rather than what it is.

1. **The denominator change is announced, never slipped.** Today's headline is `23 of 209 controls · 38 reachable`. After Q2 the headline is per-KSI. Both numbers stay printable during the transition (`frontier --by-controls` keeps the old view), and no published surface swaps denominators without saying so in the same breath — a coverage number whose denominator moved silently is the marketing edition of a vacuous pass.
2. **Cover ≠ automate, stated everywhere the numbers appear.** The gap engine *covers* 46 of 46 KSIs — every one gets a row, including the row that says "nothing can evidence this from a pipeline." It *automates* far less. Conflating the two is the false-attestation failure mode (research §6.1), and the board's design carries the distinction structurally: a row is never green because it is empty.
3. **The owed side is dual-source from birth.** The KSI catalog port reads ramprules slices *and* can read `fedramp-consolidated-rules.json` directly, with ramprules' adjudication overlay as enrichment rather than the sole path (research §6.4). This is cheap while the port is being written and expensive to retrofit; the single-upstream concentration is a named risk, not an accepted one.
4. **Re-pin at the start of every batch.** Already the pins.ts lesson (the overlay moved 0.7.2 → 0.7.5 inside a single day); restated here because the pivot reasons against *two* moving catalogs — dataset and overlay — and RFC-0033 will move the KSI catalog again for Class D.
5. **No schema change without its spec section first.** The `ValidationMethod` entity is the costly-to-reverse decision in this entire plan. Its shape is locked in Q0 as a written spec amendment, reviewed, before a line of `packages/schema` changes. Everything else on this plan can be fixed in a follow-up commit; a register keyed on the wrong entity cannot.

---

## 1. What the pivot is — one inversion, precisely

**Today** the register's unit is the recipe. A recipe declares `control_ids` (primary join) and `ksi_ids` (annotation along for the ride — see any file in `recipes/commit/`). `rampscan frontier` counts controls: 209 KSI-reached controls, 23 covered, 38 reachable, 68 unreviewed. The board's row is a control.

**Under CR26** the unit of compliance is the KSI validation. Each of the 46 KSIs, for a given certification class, *owes*:

| Obligation | Rule | The number |
|---|---|---|
| Automated validation methods | `FRC-CSX-VVK` | ≥1 (B, SHOULD) · ≥2 (C, MUST) · ≥4 (D, MUST) |
| Machine re-verification cadence | `VDR-TFR-MVX` | monthly (A, SHOULD) · 7 days (B) · 3 days (C) |
| Non-machine evidence cadence | `VDR-TFR-NMV` | 3 months |
| Persistent-validation history | `FRC-CSX-MOT` | ≥6 months (C) · ≥18 months (D) |
| Artifacts | `default_artifacts.KSI` | 5 per KSI |
| Failure handling | `VDR-CSO-FAV` | a failed validation is a vulnerability |

None of these is computable over a recipe → controls register, because none of them is *about* controls. All of them are computable over:

```
KSI ──1:n── ValidationMethod ──1:n── evidence bundles (ledger, unchanged)
 │                │
 │                ├─ source: pipeline | aws-ingested | attestation
 │                ├─ automated: boolean        (the FRC-CSX-VVK numerator)
 │                ├─ cadence class + window    (the MVX clock, already built)
 │                └─ provenance: collector/recipe | ingested digest | two-key
 │
 └─ controls[]  ← the NIST crosswalk, demoted to annotation (the dataset
                  already carries it per KSI; CONTROLS-TO-REPORTS.md rides it)
```

**The inversion in one sentence:** a recipe stops being the register's unit and becomes one *kind* of validation method (`source: pipeline`); the KSI becomes the row; the method count per KSI against the class floor becomes the product's first-class computation; controls become the expandable crosswalk annotation they already are in the dataset.

Three facts make this an inversion rather than a rebuild:

- Recipes already carry `ksi_ids` — the join exists, it is just pointed the wrong way.
- The pinned dataset already contains the 46-KSI catalog with statements, the controls crosswalk, and the five default artifacts (`FrontierControl.ksis` is already read today).
- The ledger, signer, projector, scheduler, and check gate are KSI-agnostic — they store, sign, fold, clock, and gate *bundles*, and do not care what the register above them is keyed on.

### 1.1 The one genuinely open shape question, named for Q0

`FRC-CSX-VVK` counts methods **per KSI**. A recipe can claim several KSIs. So: is a method (a) the recipe, contributing itself to each KSI it claims, or (b) the *(recipe × KSI)* pair? This plan recommends **(b)** — a method validates exactly one KSI, and a recipe claiming two KSIs *derives* two methods — because the method-count floor, the artifact linkage, and the assessor's interrogation view are all per-KSI, and because (b) makes "this recipe genuinely evidences KSI-SCR-MIT but only gestures at KSI-CMT-xxx" expressible as two methods with different standing rather than one method with a footnote. Locked at Q0, not before.

---

## 2. What already transfers — the inventory, verified against the code

From research §7, checked against the packages as they stand:

| Gap engine needs | rampscan today | Pivot work |
|---|---|---|
| Signed, anchored, append-only proven-state | ✅ `ledger` + cosign + anchor death | none |
| Freshness clocks on the MVX window | ✅ `scheduler` + clock view (7d/3d) | re-key rows to KSI (Q3) |
| Computed-never-typed reporting | ✅ rules 4 & 9, `frontier` | none |
| Adjudication-gap surfacing (G8) | ✅ `frontier` — unique in the field | keep; becomes a tab (Q2) |
| Absence-as-verdict | ✅ `unevidenced` / `empty_means` posture | none |
| PR-time gap prevention | ✅ `rampscan check` | none |
| Two-key judgment writes | ✅ scoping events through the ledger | reused for artifact sufficiency (Q3) |
| **KSI-native register** | ❌ recipe → controls | **Q2 — the inversion** |
| **Method-count floors (G2)** | ❌ not modeled | Q1 owed-side + Q2 |
| **History floors (G4)** | ⚠️ ledger holds history; nothing counts 6/18 months | Q3 |
| **Five artifacts per KSI (G5)** | ❌ `plain` text exists; artifacts unmodeled | Q3 |
| **Evidence-class labeling (G6)** | ⚠️ true (all process-generated) but unasserted | Q3 |
| **Failure-as-vulnerability (G13)** | ❌ | Q3 |
| **Multi-source method counting** | ❌ pipeline only | Q4 |
| **FedRAMP/schemas exports (G10, G12)** | ❌ OpenVEX + frontier report only | Q5 |
| **Trust-center surface (G11)** | ❌ console is inside the boundary | **deferred, explicitly** (§7) |

Ten rows of the architecture already exist. The pivot is the seven bold-or-flagged rows, in that order.

---

## 3. Target architecture

`ARCHITECTURE.md` §3's deployment diagram (Step Functions DAG, Fargate collectors, S3 Object Lock ledger, PocketBase projection) is untouched — the pivot happens in the layer *between* the dataset port and the projection. The four planes, with what changes marked:

```
┌─ OWED (Q1) ──────────────────────────┐  ┌─ PROVEN (built; Q4 widens) ─────────┐
│ KSI catalog port, pinned:            │  │ evidence ledger: signed, anchored,  │
│  · 46 KSIs × statements × controls   │  │ content-addressed, append-only      │
│    crosswalk × 5 artifacts           │  │                                     │
│  · floors as data: VVK 1/2/4,        │  │ sources:                            │
│    MVX 7d/3d, NMV 3mo, MOT 6/18mo    │  │  · pipeline (20 recipes, today)     │
│  · dual-source: ramprules slices ∪   │  │  · ingested signed results of       │
│    fedramp-consolidated-rules.json,  │  │    client-run AWS recipes (Q4)      │
│    adjudication overlay = enrichment │  │  · human attestations, two-key (Q4) │
│ × certification class (offering cfg) │  │ each labeled process|point-in-time  │
└──────────────┬───────────────────────┘  │ at ingestion (G6, Q3)               │
               │                          └──────────────┬──────────────────────┘
               │                                         │
               └───────────► GAP ENGINE (Q2–Q3) ◄────────┘
                    register: KSI → ValidationMethod → evidence
                    taxonomy G1–G13 evaluated per KSI × class,
                    every row citing the rule ID and the evidence;
                    the projector stays the only writer (invariant 6)
                              │
                              ▼
┌─ SURFACES ─────────────────────────────────────────────────────────────────┐
│ Q2: per-KSI board (methods n/floor · age vs window · artifacts k/5 ·       │
│     worst gap class as row color) · frontier v2 · G8 adjudication tab      │
│ Q3: history meter (MOT) · artifact checklist · failure→vulnerability feed  │
│ Q5: OCR fragments + Certification Package fragments (FedRAMP/schemas       │
│     JSON, generated from the projection like OpenVEX — no new state) ·     │
│     package conformance check (FRC-CSO-JSN)                                │
│ deferred: trust-center export (G11) · remediation hand-off (PR drafts)     │
└────────────────────────────────────────────────────────────────────────────┘
```

All ten §9 invariants survive unchanged; two get sharper. Invariant 3 (the ontology gate) now reads "no evidence without *method* ID + artifact + passing assertions + live anchor" — a stricter gate, since a method names exactly one KSI. Invariant 4 (the unevidenced register is always visible) becomes per-KSI: a KSI with zero methods is a G1 row on the board, never an absent row.

### 3.1 Where the code changes, package by package

| Package | Change | Phase |
|---|---|---|
| `schema` | `method.ts` — the ValidationMethod entity; `recipe.ts` gains a derivation (recipe → methods), loses nothing | Q2 |
| `dataset` | KSI catalog surface (statements, crosswalk, artifacts, floors-as-data); dual-source loader; pins extended to the direct FedRAMP/rules path | Q1 |
| `projector` | folds the ledger into per-KSI projections: method counts, freshness per method, gap-class per KSI; stays pure, stays sole writer | Q2–Q3 |
| `cli` | `frontier.ts` v2 (per-KSI, `--by-controls` legacy view); `board.ts` re-keyed; new `gaps` output naming rule IDs; `scan`/`check` unchanged except join direction | Q2–Q3 |
| `ledger`, `signer`, `scheduler`, `collectors`, `graph` | **no structural change** — bundles, signatures, clocks, and collection are register-agnostic; scheduler window becomes a per-method property read from the owed side | Q2 touch-only |
| console (`serve`) | board rows become KSIs; crosswalk drawer; G8 tab; clock view re-keyed | Q2–Q3 |
| `recipes/commit/*` | mechanical migration: each recipe declares itself a pipeline method; `ksi_ids` becomes the primary key of the join | Q2 |

---

## 4. Sequencing

```
Q0 ──► Q1 ──► Q2 ──► Q3 ──► Q4 ──► Q5
 ·      ·      ·      ·      ·      ·
spec   owed   the    gap    ingest schema
       side   pivot  taxon.  srcs  exports

RFC-0033 comment ──────────────► closes 2026-10-09   (parallel; not a phase)
```

**Why the owed side precedes the inversion.** Q2's register needs the floors, windows, and artifact counts as *data* to key against; building the KSI-keyed register before the catalog port would mean typing the floors into code — the exact sin rule 2 exists to prevent.

**Why the taxonomy is split across Q2 and Q3.** G1 (coverage) and G2 (method count) are *properties of the register itself* — they fall out of the inversion for free. G3–G6 and G13 are computations *over* the register and land after it exists. Building them together would put six gap classes on the critical path of the schema change.

**Why ingestion (Q4) precedes exports (Q5).** An OCR generated from a pipeline-only ledger is honest but nearly empty for a real provider — one pipeline method per KSI rarely meets even Class B's floor alone. Exports become worth generating when method counting spans sources.

Estimates, focused-work days: Q0 1 · Q1 2 · Q2 4 · Q3 3 · Q4 3 · Q5 2. **Total ≈ 15 days**, plus 0.5 for the RFC-0033 comment. Q2 is the long pole and the one to protect from scope creep.

### Phase Q0 — decisions locked before anything is written (1 day)

The spec amendment (`SPEC.md` §12 or a section replacing §11's open questions), containing:

1. **The ValidationMethod shape**, including the §1.1 recipe×KSI decision.
2. **Certification class as offering config** — one value (A/B/C/D), set per scanned offering, the multiplier on everything owed. Default for the fixture and self-scan: the class whose floors make the demo honest (recommend B — floors of 1 make a 20-recipe pipeline demonstrably meaningful).
3. **Catalog source strategy** (ground rule 3): loader contract for the dual path, and which fields ramprules' overlay is allowed to enrich vs. define.
4. **frontier v2 output format** — the exact text the README will quote, designed before implementation because it *is* the product's headline (ground rule 1).
5. **Issue #16 answered in passing**: scan scope (gitignored paths in or out) becomes a declared property of each pipeline method's provenance — the G7 interrogation surface — rather than a global toggle. A method that read gitignored paths says so; one that didn't says that.
6. **The launch-plan convention carried forward**: this plan's phases land as GitHub milestones (`Q1 — owed side`, `Q2 — the KSI pivot`, …) with issues per numbered item; the milestones remain the plan of record after adoption.

**Exit gate:** spec section merged; ValidationMethod shape reviewed against all four Q1–Q3 consumers on paper.

### Phase Q1 — the owed side (2 days)

1. KSI catalog surface in `packages/dataset`: 46 KSIs, statements, controls crosswalk, the five default artifacts, all pinned (`dataset_version`, hard-fail on mismatch — existing discipline).
2. Floors and windows as data: `FRC-CSX-VVK`, `FRC-CSX-MOT`, `VDR-TFR-MVX`, `VDR-TFR-NMV`, keyed by class, sourced from the rules JSON, never typed into logic.
3. Dual-source loader per ground rule 3, with a test proving both paths yield the same 46 KSIs at the pin.
4. Fix **#23** (`ci-actions-pinned` misses composite actions) here, before the pivot touches recipes: under the pivot it is a G7 measurement-system defect in our own machinery — a recipe claiming to read every `uses:` reference while reading one directory is precisely the "untrustworthy green" `FRR-PVA-AA-06` instructs assessors to reject. Fixing it first also makes it the worked example for the interrogation view.

**Exit gate:** a command prints the owed state for any (KSI, class) pair — statement, floor, window, artifact count — every number traceable to the pinned JSON.

### Phase Q2 — the inversion (4 days; the pivot proper)

1. `ValidationMethod` in `packages/schema`, per the Q0 spec. **#31** (pin zod's `.strict()`/`.passthrough()` edges with tests) lands in the same PR — the pivot rewrites this package's highest-traffic files, which is when those pins pay for themselves.
2. Recipe → method derivation: the twenty recipes migrate mechanically (`source: pipeline`, one method per claimed KSI). No recipe content changes.
3. Projector folds per-KSI: methods with live evidence, counts against the floor, G1/G2 computed.
4. `frontier` v2: per-KSI rows — methods `n / floor`, freshest evidence age vs window, worst gap class as color; `--by-controls` preserves today's view (ground rule 1); the G8 adjudication queue becomes its own section, sorted by the dataset's existing `leverage` field.
5. Console board re-keyed to KSI; controls as the expandable crosswalk drawer; every green expands to query, scope, signature — the assessor-interrogation view as the *default* detail view.
6. `rampscan check` joins through methods; behavior at the gate unchanged.

**Exit gate:** `pnpm rampscan frontier` prints the per-KSI board over the self-scan; `rebuild` proves byte-equality of the new projection; the full suite and both typechecks green (`pnpm typecheck`, per the standing rule — `tsc --build`, not `--noEmit`); old and new coverage numbers printed side by side once in the PR description, per ground rule 1.

### Phase Q3 — the gap taxonomy built out (3 days)

In leverage order:

1. **G4 history:** compute persistent-validation history per KSI from the ledger (the data exists; nothing counts it) against the 6/18-month floors. The meter starts honest: a young ledger shows a young number. *Corrected 2026-09-16 (#159): the meter as first built measured reach-back alone, which one stale capture satisfies; it now walks the instants on the owed clock.*
2. **G3 freshness** re-keyed: the clock view's row becomes (KSI, method), window read from the owed side per class.
3. **G5 artifacts:** the five artifacts modeled per KSI. Presence is mechanical (artifact 5 is the method's evidence itself; artifact 2 is the cadence record the scheduler already keeps); sufficiency of 1, 3, and 4 is judgment — routed through the existing two-key pattern, a signed ledger event, never a checkbox. Artifact 4 (accuracy of the measurement system) is where the #23 class of defect formally lives from now on.
4. **G6 evidence-class labeling:** every bundle asserts `process-generated` vs `point-in-time` at ingestion. Everything rampscan produces today is process-generated; the assertion exists so Q4's ingested evidence can be classified — and rejected as standalone evidence when point-in-time.
5. **G13:** a validation flip to `violated` emits a vulnerability-shaped record into the projection (`VDR-CSO-FAV`), feeding the same drift view that already names verdict flips.

**Exit gate:** a `rampscan gaps` output (name per Q0) listing every G1–G6, G8, G13 row with its rule ID and evidence digest — the gap register as a computation.

### Phase Q4 — ingest, don't execute (3 days)

The no-SaaS / no-execution boundary holds: ramprules' AWS recipes remain the client's to run. What changes is that their *signed results* become ledger citizens.

1. An ingestion contract: a signed result bundle (recipe ID, KSI, artifacts, assertion outcomes, timestamp, signer identity) appended like any pipeline bundle, `source: aws-ingested`, evidence-class labeled per G6.
2. Human attestations through the existing two-key path become `source: attestation` methods — automated: false, `VDR-TFR-NMV`'s 3-month clock.
3. Method counting per KSI now spans sources; the board's `n / floor` becomes honest for a real provider.
4. Verification: `rampscan verify` checks ingested bundles offline, same as native ones.

**Exit gate:** a fixture ingestion of a synthetic AWS result raises a KSI's method count on the board, and its removal lowers it; nothing in the appliance ever executed an AWS call.

### Phase Q5 — schema-target exports (2 days)

1. OCR fragments and Certification Package fragments as FedRAMP/schemas JSON, generated from the projection exactly as OpenVEX is — an export, no new state, regenerated per scan.
2. Package conformance check (G10, `FRC-CSO-JSN`): validate our own exports against the pinned FedRAMP/schemas versions; a nonconforming export fails CI, not the client.
3. Freshness stamping per `FRC-APP-FCP` (status verified within the previous 7 days) computed from the ledger, never typed.

**Exit gate:** `out/exports/` contains schema-valid OCR and package fragments for the self-scan; the conformance check gates them in CI.

### Parallel, time-boxed: RFC-0033 (before 2026-10-09; 0.5 day)

Class D's floors (≥4 automated methods/KSI, 18 months history) are where a pipeline evidence plane is most valuable — pipeline methods are the cheapest marginal automated method most providers can add. File the comment while the window is open; it is the research doc's argument, not the code's, so it does not wait for Q1. It is also the positioning statement, drafted once, used twice.

---

## 5. Existing open issues, re-triaged under the pivot

| Issue | Standing under the pivot | Lands in |
|---|---|---|
| #23 ci-actions-pinned misses composite actions | **Promoted**: a G7/Artifact-4 measurement-system defect in our own recipe; the worked example of "greens that survive interrogation" | Q1.4 |
| #31 zod strict/passthrough edges untested | Do inside the schema rewrite, where the pins pay off | Q2.1 |
| #16 gitignored-path scan scope | Stops being standalone: scope becomes declared method provenance | Q0.5 |
| #29 TypeScript 7 compiler API | Parked; no dependency majors mid-pivot (`packages/graph` is untouched by Q0–Q5) | after Q5 |
| #30 Next 16 / Turbopack | Parked, same rule; console changes in Q2–Q3 stay on Next 15 | after Q5 |
| #11 / #13 launch close-out | Owner-blocked; unchanged | — |

---

## 6. What the engineer sees when it is done

Per the ramprules PRODUCT.md tie-breaker — a developer told to "do FedRAMP," not a compliance specialist:

- **One board, one row per KSI, 46 rows always.** Methods `n / floor` · freshest evidence age vs window · artifacts `k / 5` · worst gap class as the row's color. Never a bare percentage.
- **Every red names its rule ID and its fix.** Every green expands to its query, its scope, its signature — because that expansion is exactly what `FRR-PVA-AA-06` tells the assessor to pull on, and the tool that shows it first wins the interrogation.
- **The clock is ambient:** what expires within 3 days is the top of everything. (Already the scheduler contract; the pivot re-keys it, it does not reinvent it.)
- **The unanswered questions are a first-class tab:** the G8 queue, sorted by leverage — "68 unreviewed" printed as a question stays the differentiator no competitor surfaced.

---

## 7. Honest constraints, deferrals, and risks worth naming

1. **The ceiling stays on the box.** At the pin, the commit plane reaches 38 of 209 KSI-reached controls (18.2%); the combined aws+pipeline frontier ceiling is ~58%. Re-expressed per-KSI those numbers will *look* different — that is ground rule 1's moment. The remainder is acts-on-people, which is what `VDR-TFR-NMV`'s attestation clock exists for; Q4 makes that path a counted method rather than an apology.
2. **Trust-center (G11) is deferred, deliberately.** It is a public serving surface with uptime, access-logging (`CDS-TRC-ACL`), and product-boundary questions the appliance model doesn't answer today. Deferral is recorded here so it is a decision, not a blind spot; the Q5 exports are designed to be what a trust center would serve.
3. **Remediation hand-off (draft PRs — the Boundera pattern) is out of scope** for Q. It is a different product muscle; the gap register's `fix` text (the `plain` layer, which survives the pivot untouched) is the hook it would hang from later.
4. **The catalog will move during this plan.** RFC-0033 closes mid-plan and Class D is being designed now; RFC-0014 moved the catalog three times during the pilots. Ground rule 4 (re-pin at batch start) is the mitigation; a pin bump mid-phase is a reviewed commit, not a surprise.
5. **Positioning changes last.** The README currently opens "pipeline-source evidence for FedRAMP 20x… the other half of ramprules." After Q2 the true sentence is "the open-source KSI gap engine, with pipeline as its first evidence plane and ramprules as its enrichment." That rewrite happens only when `frontier` v2 prints the numbers it quotes — computed-never-typed applies to the pitch — and the same pass retires the legacy "Minimum Validation Expectations" expansion of MVX (flagged unverified in the research doc; officially Persistent Machine Verification and Validation).
6. **Scope-creep risk concentrates in Q2.** The inversion invites "while we're in here" work (console redesign, new collectors, G7 tooling). The counter is the Q2 exit gate: byte-equal rebuild, green suite, side-by-side numbers — nothing else.

---

## 8. What "pivoted" looks like

- `pnpm rampscan frontier` prints a per-KSI board: 46 rows, methods against the class floor, ages against windows, artifacts against five, worst-gap coloring — and still answers `--by-controls` for the old view.
- `rampscan gaps` (name per Q0) emits the gap register: every row a (KSI, gap class, rule ID, evidence-or-absence digest) tuple.
- A synthetic ingested AWS result and a two-key attestation each raise a method count; removing them lowers it; the appliance executed neither.
- `out/exports/` carries schema-valid OCR and Certification Package fragments, conformance-gated in CI.
- The RFC-0033 comment is filed and linked from the README's regulatory section.
- The README's first sentence names a KSI gap engine, and every number in it still comes from a command.

**Status at the Q5 exit (2026-09-12): every line above holds except the RFC-0033 comment (#72), which is a filing rather than a build and stays open until 2026-10-09.**

---

## Session log

- **2026-09-11** — Plan drafted from `docs/RESEARCH-KSI-GAP-ENGINE.md` §7's recommended sequencing, adopted as phases Q0–Q5; pivot decision recorded the same day. Not yet adopted as plan of record: adoption = this document merged + Q-milestones created on GitHub.
- **2026-09-11 (later)** — Adopted: merged in #46; milestones `Q0`–`Q5` created with issues #47–#71 per numbered item, RFC-0033 comment tracked as #72; existing issues re-triaged per §5. Phase Q0 drafted as `SPEC.md` §12 the same day — the ValidationMethod shape (§1.1 decision **(b)** confirmed, with the Paramify package as the assessed-in-the-wild comparator), class-as-config, the dual-source contract, frontier v2's format, and the #16 scope resolution.
- **2026-09-12** — **Q5 complete, and with it Q0–Q5: the pivot is done.** Q5.1 landed the two schema-target exports (#69); Q5.2 added `rampscan conformance` (#70) — the package conformance check as a command over documents ON DISK, which is the half `exports` structurally cannot do: it re-validates a file and checks the file's own `x-rampscan.conformance` stamp against that fresh validation, so a document whose self-description has gone false under moved pins fails rather than passing quietly. It fails closed in the same direction as the validator it calls — an unresolvable schema and an empty directory are both exits, and the schema is never inferred from a document's shape. The CI step in `test.yml` generates both documents from this repository's own declared offering and checks them, with the overclaim named in the workflow itself: CI has no ledger, so that step gates the DECLARED half, and the unit suite gates the computed half over a fixture register. Q5.3 added `FRC-APP-FCP` freshness (#71) as a computed stamp on the package overview — its own flat 7-day constant, never the class window, with `OfferingConfig` refusing (not stripping) any key that would let a provider declare their own package fresh. The rules text supports two readings of what the window governs, so both are computed and published (`fresh`, `machineOnlyFresh`) rather than one being chosen silently. **The self-scan's own package reads `fresh: false`** — 28 methods in scope, 0 verified within 7 days — which is the correct answer for a ledger last appended to on 2026-08-18 and exactly the kind of number ground rule 1 exists to make printable. §7.5's positioning rewrite landed in the same pass, its trigger having fired: `frontier` v2 prints the numbers, so the README now opens on the KSI gap engine and quotes the register rather than the control view. That was overdue as a correctness matter and not only a positioning one — the README was quoting a `$ pnpm rampscan frontier` block the command had stopped producing at Q2.5, which is exactly the kind of typed number ground rule 1 forbids. Both denominators stay printable (`--by-controls`, 23 of 209 against a ceiling of 38), and MVX is expanded correctly on first use — Persistent Machine Verification and Validation — retiring the legacy phrasing the research doc flagged. Deferred by name, and the only §8 item still open: RFC-0033 (#72, before 2026-10-09). The parked dependency majors (#29, #30) are unblocked by this exit.
