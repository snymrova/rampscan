# rampscan — plan of action: the artifact plane and the Security Decision Record (Phases R0–R5)

**Status:** proposed plan of record for one deliverable — *rampscan produces the FedRAMP Certification Package's artifact half, not only its measurement half*. Proposed 2026-09-13. This document decides nothing until it is merged and its milestones exist on GitHub; that is the same adoption bar the KSI pivot cleared.
**Date:** 2026-09-13
**Phase letter:** **R**. A–H, I, J, K, L are taken, M0–M5 are the original milestones, N is depth, P is launch, Q is the KSI pivot. R follows Q and reads as *record*, which is what this plan builds.
**Reads against:** the repository at `8275e33` (post-Q5), `docs/SPEC.md` §12, `docs/ARCHITECTURE.md` §9 invariants, `docs/PLAN-KSI-PIVOT.md` §7 deferrals, `docs/RESEARCH-KSI-FULFILMENT.html`, `docs/RESEARCH-UPSTREAM-READINESS.html`, and the pinned `fedramp-consolidated-rules.json` 2026.07.14.01. Every rule ID below (`SDR-CSX-KSI`, `FRC-CSX-VVR`, `SDR-CSX-KMT`, …) is FedRAMP's canonical identifier and was read out of that file, not from a summary. Schema facts were read from `FedRAMP/schemas@main`, fetched 2026-09-13.

**Thesis in one line:** the five artifacts rampscan's board reports as `0 of 46` are not an abstraction of the rules — they are the *required content of the Security Decision Record*, the document that replaces the SSP under CR26, and rampscan already computes the two hardest fields that document demands (`ksiTests`, `ksiEvidence`) while shipping neither; the artifact plane closes that gap by making an artifact a first-class signed object with the same lifecycle as evidence, and the SDR is what falls out of it.

---

## 0. Ground rules, active from R0

Rules 1–10 of the depth and launch plans and the five pivot rules stay active unchanged. Four are specific to this plan, and each exists because this is the first plane in which rampscan handles *prose a human wrote* rather than *a measurement a tool took*.

1. **rampscan never authors a claim.** It may scaffold an artifact's structure, fill computed fields, and refuse an incomplete one. It must never generate the provider's explanation of a measure, their statement of customer risk, or their acceptance of a reason. The moment this tool emits plausible compliance narrative it becomes the all-green dashboard FedRAMP warns about, and every signature in the ledger becomes worth less. The generator's output for an unwritten artifact is an *absence with a reason*, never a draft.
2. **An artifact is evidence about a decision, and it is signed like evidence.** Same content-addressing, same anchor discipline, same supersession-not-deletion, same two-key path for anything a human asserts. An artifact plane that stored prose in a database beside the ledger would reintroduce exactly the typed, unfalsifiable state the ledger exists to refuse.
3. **Schema-valid is not rule-compliant, and the tool must say both.** Two divergences are already known (§2.6). A document that validates against the published JSON Schema can still violate a `MUST` in the rules JSON. `conformance` reports both verdicts separately from R2 onward, and never lets the schema's silence stand in for the rule's demand.
4. **Declared and computed stay labelled, everywhere, as in Q5.** `x-rampscan.fieldSources` is the pattern and it extends to the SDR unchanged: an assessor holding the JSON alone must be able to tell which half this appliance stands behind. The SDR is mostly provider prose; the labelling is what keeps rampscan's signature meaningful inside a document it did not mostly write.

---

## 1. What this plan is — one addition, precisely

**Today** rampscan has two planes. The *owed* plane reads the pinned catalog and knows what each KSI costs at a class. The *proven* plane holds signed, anchored, freshness-clocked evidence from three sources — pipeline recipes, ingested client-run results, human attestations. The gap engine diffs them and prints `G1`–`G13`.

**What is missing** is the plane between them: the artifacts. `rampscan frontier` prints `artifacts: 0 of 46 KSIs hold all five owed artifacts` and it is right, but the tool holds no artifact and offers no way to make one. `ArtifactJudgment` (`packages/schema/src/artifact-judgment.ts`) signs a *justification about* an artifact — its subject is the approver's justification text, and the predicate carries `ksi_id`, `artifact`, `justification`, `approved_by`. There is no artifact body anywhere in the ledger. The system can sign "artifact 3 is sufficient" and cannot show you artifact 3, cannot age it, cannot put it in a package, and cannot tell an assessor where it came from.

That is the whole plan: **make the artifact a thing the ledger holds**, then let the deliverable documents fall out of it.

---

## 2. Why this is needed, and what it is worth to a CSP

This section is the argument, and every claim in it is sourced to a rule, a schema, or a named external report.

### 2.1 The five artifacts are not a rampscan abstraction — they are the SDR's required content

`info.default_artifacts.KSI` in the rules JSON is the list rampscan's board counts against. The rule that makes it binding is **`SDR-CSX-KSI` (MUST)**:

> Providers MUST also include short and simple high-level summaries of at least the following for each applicable Key Security Indicator:
> 1. Explanation of measures (and their objectives) that demonstrate the Key Security Indicator, **or an explanation of the reason and resulting risk to customers for not having measures available** for that Key Security Indicator.
> 2. Explanation of the cycle for any measures that are implemented persistently (if applicable).
> 3. Verification that the measures demonstrate the Key Security Indicator, or that the reason for not having them is accepted.
> 4. Verification that the automation in place is accurate and sufficient to demonstrate appropriate measures for the Key Security Indicator, or that automation is not necessary for each measure.
> 5. Validation that the measures are accurately produced and are in place and working as intended, or that the reason for not having them is valid.

The word *also* points at its siblings: `SDR-CSO-FRR` (MUST, seven items per applicable FedRAMP rule) and `SDR-CSF-CTF` (MUST, nine items per applicable Rev5 control). All three are content requirements of one document.

### 2.2 That document replaces the SSP, and it is a MUST in two formats

**`FRD-SDR`**, the definition:

> A persistently maintained, verified, and validated record of the security decisions made by a provider over the lifecycle of a cloud service offering. The Security Decision Record replaces the traditional System Security Plan and documents how applicable FedRAMP Practices are addressed, including implementation rationale, resulting customer risk, assessment findings, and supporting artifacts.

**`SDR-CSO-FRR` (MUST)**: "Providers MUST supply a Security Decision Record, **in both human-readable and JSON formats**…", with a `schema` block naming `fedramp-security-decision-record-schema-2026-06-24.json`.

Two consequences rampscan should care about. The *human-readable* half is not an afterthought — it is half of a MUST, and it is a rendering problem rampscan's console already solves for evidence. And `IVV-IAS-SUM` (MUST) puts the independent assessor's summary *inside the provider's SDR*: "Assessors MUST supply the provider with a high-level summary of their assessment process and findings for each FedRAMP Practice; this summary will be included by the provider in the FedRAMP Security Decision Record." Its note adds that FedRAMP requires no separate SAP or SAR — that information is expected in the SDR. **The SDR is the join point between the provider's evidence and the assessor's findings**, and nothing in the ecosystem currently holds that join under signature.

### 2.3 The SDR schema asks for exactly the two things rampscan already computes

`keySecurityIndicators[]` in the published schema, with the `required` array read from the file:

| Field | Required | What it wants | Where rampscan already has it |
|---|:--:|---|---|
| `ksiId` | ✔ | the KSI | the register's row key since Q2 |
| `ksiImplementation` | ✔ | implementation statement (Markdown) | **nowhere** — artifact 1 |
| `ksiValidation` | ✔ | how the CSP validates internally | partly: the cadence the scheduler keeps — artifact 2 |
| `ksiAssessment` | ✔ | how an independent validator assessed it | **nowhere** — the `IVV-IAS-SUM` inbound |
| `ksiTests` | ✔ | "List of tests used to validate the KSI implementation" | **the method register** — Q2.3/Q4.3, already computed |
| `ksiEvidence` | ✔ | "Results of the security test used to validate the KSI" | **the signed bundles** — the whole ledger |
| `ksiImplementationStatus` | | `Implemented` / `Partially Implemented` / `Not Implemented` | computable from the register today |

`$defs.evidence` wants `evidenceType` (one of `Log`, `Report`, `Screenshot`, `Configuration`, `Policy`, `Procedure`, `Audit Record`), `evidenceDescription`, `evidenceLocation` (a URI), `evidenceText`, `lastUpdated`. Every one of those is either in a rampscan bundle already or is a labelling decision over one. `lastUpdated` is the freshness clock. `evidenceLocation` is the digest-addressed artifact resolver built in J4 (`packages/cli/src/artifact.ts`).

**This is the finding that should reorder the roadmap.** Six fields are required per KSI. rampscan can compute two of them — the two that are hardest for everyone else, because they require signed, anchored, clocked measurement — and it currently writes them into an `x-rampscan` side-channel of a different document.

### 2.4 It is, by outside accounts, the CSP's single worst bottleneck

The pattern reported across assessors and platform vendors in 2026 is consistent: the KSI *evidence* problem is understood and tooled, and the *documentation* problem is where cohorts stall. Schellman's assessor-side write-ups describe most CSPs landing in "partially automated," which forces assessors to narrate where automation exists, where it does not, and whether the pulled results are accurate — which is an artifact-4 question ("verification that the automation in place is accurate and sufficient") asked by the person who decides. Vendor guidance on CR26 readiness consistently names the SSP's split into the Certification Package Overview and the Security Decision Record, both in machine-readable JSON, as the largest new lift, and describes it as new territory for most providers.

That matches what `docs/RESEARCH-KSI-FULFILMENT.html` recorded from the Paramify/Coalfire session independently: the assessor's central objection to tool-verdict evidence — *how do I know you configured the scanner to see everything?* — is an artifact-4 objection, and rampscan's population pill was built to answer it. The artifact plane is what lets that answer be written down, signed, and shipped inside the document the assessor reads.

Sources for this subsection, fetched 2026-09-13 — secondary reporting, unlike the rule and schema citations elsewhere in this plan, and flagged as such: [Schellman, *FedRAMP 20x: An Assessor's Perspective*](https://www.schellman.com/video/federal-compliance/fedramp-20x-updates) · [Schellman, *FedRAMP 20x Decoded*](https://www.schellman.com/blog/federal-compliance/fedramp-20x-decoded) · [Coalfire, *Class B and Class C Pipelines Are Open*](https://coalfire.com/the-coalfire-blog/fedramp-20x-class-b-and-class-c-pipelines-are-open-which-path-fits-your-cloud-service) · [Paramify, *What is an SDR?*](https://www.paramify.com/blog/sdr) · [RKON, *Why the SSP Is Being Replaced*](https://www.rkon.com/articles/fedramp-cr26-deleted-300-page-ssp/) · [FedRAMP, *Security Decision Record* (CR26)](https://www.fedramp.gov/2026/providers/20x/rules/security-decision-record/).

### 2.5 The history requirement cannot be retrofitted, and that is the clock

Two rules, both read from the pinned JSON:

- **`FRC-CSX-MOT`** — class A `MAY`, class B `SHOULD`, **class C `MUST` supply historical metrics including status from persistent validation over at least the past 6 months** for all KSIs, class D at least 18 months.
- **`SDR-CSX-KMT`** — class A `MAY`; **class B `MUST` include historical metrics in the SDR** with a summary of each metric over the past 30 days and up to the past year where available; **class C `MUST` add all daily metric data up to the past year.**

CR26 became optionally adoptable 2026-07-04 and is **mandatory for all stakeholders on 2027-01-01**. A provider certifying at class C in mid-2027 needs persistent-validation history reaching back into 2026. History you did not record is not available, and no amount of tooling bought later manufactures it.

rampscan's ledger is an append-only, signed, timestamped record of exactly these metrics, and `board --as-of` already refolds the register at any past instant. **rampscan is structurally able to produce SDR historical metrics as a computation rather than a claim, and a provider who starts recording later cannot.** That is the single strongest thing this project can say to a CSP engineer in September 2026, and it is currently unsayable because nothing renders that history into the document that must carry it.

### 2.6 Two upstream defects fall out of reading the schema against the rules

Both verified 2026-09-13 against `FedRAMP/schemas@main`:

1. **`keySecurityIndicators` is absent from the SDR schema's top-level `required` array** (which contains only `certificationPackageOverviewUri` and `fedRampRequirements`), while `SDR-CSX-KSI` is a `MUST`. A schema-valid SDR can omit every KSI.
2. **The SDR schema has no slot for historical metrics at all** — no property matches, and `SDR-CSX-KMT` is a `MUST` at classes B and C. There is nowhere conformant to put the 30-day and one-year summaries the rule demands.

`docs/RESEARCH-UPSTREAM-READINESS.html` established the playbook: FedRAMP does not merge outside code, but it *adopts outside diagnoses* — issue #3 named two schema defects found while building a provider tool, the pull request was closed unmerged, and staff then fixed both. These two findings are the same shape, found the same way, and R2 is where the tool that finds them exists.

### 2.7 What the CSP engineer actually gets

Concretely, for a class-B offering with 41 required KSIs:

- **41 rows they can act on this week, not 13.** Artifact 1 explicitly permits "the reason and resulting risk to customers for not having measures available." The 33 KSIs with no pipeline method still owe an artifact, and that artifact is writable today — no live cloud evidence, no ingest adapter, no new collector. Today the board tells an engineer they have 33 empty rows and hands them nothing to do about them.
- **The two hardest required fields, generated.** `ksiTests` and `ksiEvidence`, 41 times, from signed measurement rather than from a spreadsheet a human maintains beside the truth.
- **Artifact 4 about the measurement system itself, computed.** The exec journal (`packages/collectors/src/journal.ts`) records every tool resolution and every invocation *whether the collector cooperates or not*, alongside pinned versions and the graph's exact-vs-inferred edge labels. That is the raw material for "verification that the automation in place is accurate and sufficient," and no GRC platform sitting outside the pipeline can produce it honestly.
- **An artifact that ages.** Every other document tool treats a written artifact as done. Under `VDR-TFR-NMV` a non-machine validation is owed every 3 months, and most document-shaped KSIs demand the artifact be *persistently reviewed*. An artifact on a clock, in the same view as the evidence clocks, is the thing nobody ships.
- **A history they can only have if they start now.**

---

## 3. What already transfers — inventory, verified against the code

| Asset | Where | What it becomes |
|---|---|---|
| Two-key write pattern | `scoping.ts`, `artifact-judgment.ts`, `attestation.ts` | unchanged; the judgment finally judges a thing the ledger holds |
| Content-addressed ledger + DSSE | `packages/ledger`, `packages/signer` | artifacts are objects in it, no format change |
| Supersession-not-deletion | all three event types | an artifact is revised by a later artifact, never edited |
| Digest-addressed artifact resolver | `packages/cli/src/artifact.ts` (J4) | becomes `evidenceLocation` for `$defs.evidence` |
| Method register | Q2.3 / Q4.3, `MethodRegisterRow` | becomes `ksiTests` |
| Signed bundles + freshness clocks | the ledger, `packages/scheduler` | become `ksiEvidence` + `lastUpdated` |
| Exec journal | `packages/collectors/src/journal.ts` | becomes computed artifact 4 |
| Declared/computed labelling | `fedramp-exports.ts`, `x-rampscan.fieldSources` | extends to the SDR unchanged |
| Pinned-schema loader with dual pins | `packages/cli/src/fedramp-schemas.ts` | extends to the SDR and the VER schemas |
| Conformance-over-files | `fedramp-conformance.ts` (Q5.2) | gains the rule-compliance verdict of ground rule 3 |
| `board --as-of` refold | `packages/cli/src/board-asof.ts` (I1b) | becomes the historical-metrics series |
| Documents collector | `packages/collectors/src/documents.ts` | the authored-artifact source, generalized |

Nothing in this plan requires a new store, a new signature format, or a change to the ten `ARCHITECTURE.md` §9 invariants.

---

## 4. Target architecture

```
┌─ OWED (built) ───────────────┐   ┌─ PROVEN (built) ──────────────┐
│ KSI catalog, floors as data  │   │ signed evidence: pipeline ·   │
│ × certification class        │   │ ingested · attested           │
└──────────────┬───────────────┘   └───────────────┬───────────────┘
               │                                   │
               │     ┌─ ARTIFACT (R0–R1, new) ─────┴──────────────┐
               │     │ Artifact = (ksi, n∈1..5, body, source,     │
               │     │   anchor?, digest, signature, clock)       │
               │     │ sources: authored · computed · attested ·  │
               │     │          assessed                          │
               │     │ judged by the existing two-key event       │
               │     └─────────────────┬──────────────────────────┘
               │                       │
               └──────► GAP ENGINE ◄───┘   G5 stops being unanswerable
                             │
                             ▼
┌─ DELIVERABLES ─────────────────────────────────────────────────────┐
│ R2  Security Decision Record — JSON (SDR-CSO-FRR schema) AND       │
│     human-readable (the other half of the same MUST)               │
│ R3  historical metrics from the ledger (FRC-CSX-MOT, SDR-CSX-KMT)  │
│ R4  the VER trio: VER-RPT-VDT · VER-RPT-AVI · VER-TFR-MRH          │
│ R5  reviewer-facing package surface                                │
│ standing: CPO + OCR (Q5) · OpenVEX · evidence packages             │
└────────────────────────────────────────────────────────────────────┘
```

### 4.1 The Artifact object

```
Artifact
  ksi_id            exactly one, mnemonic form
  artifact          1 | 2 | 3 | 4 | 5   (the rules' own order)
  source            authored | computed | attested | assessed
  body              markdown; the SDR's statements are Markdown-typed
  body_digest       sha256 — the address, as everywhere else
  anchor            commit + path, when source = authored; absent otherwise
  generator         when source = computed: the pin set, tool versions,
                    and journal digest that produced it
  review            when known: the record that this was reviewed, with
                    its source (R4 forge plane) — never asserted
  supersedes        the digest this revises, when it revises one
  valid_from        the clock's start; NMV owes 3 months
```

Four sources, and the distinction is load-bearing rather than decorative:

- **`authored`** — a file in the repository, commit-anchored, discovered by a generalized `documents` collector. This is the CSP engineer's habitat and the reason this plan exists: the artifact lives beside the code, moves through the same review, and dies by anchor drift like any other evidence when the thing it describes changes.
- **`computed`** — rampscan generates the body from the fold. Legitimate for **artifact 2** (the persistent-validation cycle is the scheduler's own contract), **artifact 5** (validation that the measures are in place and working *is* the register), and **artifact 4** (accuracy and sufficiency of the automation, from the exec journal). Never legitimate for artifacts 1 and 3 — see ground rule 1.
- **`attested`** — the existing two-key path, unchanged, for the acts-on-people remainder.
- **`assessed`** — the `IVV-IAS-SUM` inbound: the assessor's summary, ingested like a client-run result rather than typed, so the SDR's `ksiAssessment` has a provenance instead of a paste.

Judgment stays exactly where it is. `ArtifactJudgment` keeps its closed union of `1 | 3 | 4` — artifacts 2 and 5 are computed by the fold and no signature may override a computation — and it now judges a body that exists.

### 4.2 Where the code changes, package by package

| Package | Change | Phase |
|---|---|---|
| `schema` | `artifact.ts` — the Artifact statement type; `artifact-judgment.ts` gains a `subject` pointing at the judged body's digest | R0 |
| `core` | `toArtifact()` beside `toAttestation()`; the artifact clock (`NMV`, 3 months) | R0 |
| `collectors` | `documents.ts` generalized: from two declared kinds to per-KSI artifact declarations | R1 |
| `projector` | folds artifacts into the register; `k / 5` stops being `0 / 5`; historical-metric series | R1, R3 |
| `cli` | `artifacts` (list, show, scaffold, check); `sdr` (generate, both formats); `conformance` gains rule-compliance; `exports` gains the VER trio | R1–R4 |
| `dataset` | class-optional KSIs honoured (the `varies_by_class` denominator bug, §7.1) | R0 |
| `ledger`, `signer`, `graph`, `scheduler` | **no structural change** | — |
| console | artifact editor is *not* built; the artifact view is read-only with a "where this came from" drawer; the assessor summary lands through ingest | R1, R5 |

---

## 5. Sequencing

```
R0 ──► R1 ──► R2 ──► R3 ──► R4 ──► R5
 ·      ·      ·      ·      ·      ·
 object  plane  SDR   history  VER  surface
```

### Phase R0 — the object, locked before anything is written (1 day)

Per pivot ground rule 5, the costly-to-reverse decision is the entity. `SPEC.md` §13 is written and reviewed first: the Artifact shape above, the four sources, what `computed` may and may not cover, the clock, and the supersession rule. Two small corrections ride along because they are prerequisites for honest numbers: the class-optional denominator (§7.1) and the `conformance` default-path collision (§7.2).

**Exit gate:** spec section merged; `frontier --class b` prints a 41 denominator with the 5 optional KSIs named; `rampscan exports && rampscan conformance` succeeds on the default paths.

### Phase R1 — the artifact plane (4 days)

The `Artifact` statement type, `toArtifact()`, ledger append, projector fold. The generalized documents collector for `authored`. Computed generators for artifacts 2, 4 and 5 — artifact 4 assembled from the exec journal, which is the differentiator and should be built before the easy two so its shape drives the object rather than the reverse. `rampscan artifacts` lists per KSI with source and clock; `artifacts scaffold <ksi>` writes a structured stub with the computed fields filled and the human fields left conspicuously empty, refusing to invent them.

**Exit gate:** `frontier` prints a non-zero `k / 5` for a KSI whose artifacts were authored and computed; removing the authored file drops it back; byte-equal `rebuild`; the suite green.

### Phase R2 — the Security Decision Record (4 days)

`rampscan sdr` generates both formats from the fold: JSON against the newly vendored, dual-pinned SDR schema, and the human-readable rendering that is the other half of `SDR-CSO-FRR`. `keySecurityIndicators[]` is populated per KSI, `ksiTests` from the method register, `ksiEvidence` from the bundles with `evidenceLocation` resolving through J4's digest addressing. `fedRampRequirements[]` is populated where the register speaks and declared where it does not, labelled as always. `conformance` gains the rule-compliance verdict of ground rule 3, and reports the two divergences of §2.6 by name rather than passing them.

**Exit gate:** a schema-valid SDR generated from this repository's own offering, gated in CI beside the Q5 documents; the rule-compliance verdict distinguishes schema-valid from `SDR-CSX-KSI`-compliant; the two upstream findings filed as issues on `FedRAMP/schemas` in the shape issue #3 established.

### Phase R3 — historical metrics (3 days)

`SDR-CSX-KMT` and `FRC-CSX-MOT` from the ledger: the 30-day summary, the up-to-a-year summary, and at class C the daily series, each refolded rather than accumulated in a side table, so the metric is reproducible from the record. Because the schema has nowhere conformant to put them (§2.6), they ride `x-rampscan` with the divergence stated in the document — which is the honest move and also the evidence behind the upstream filing.

**Exit gate:** the series is reproducible — two runs over the same ledger at the same instant produce identical bytes; a metric for a day the ledger does not cover reads as absent, never as zero.

### Phase R4 — the VER trio and the forge plane (4 days)

Three published schemas rampscan can fill from data it already holds: `VER-RPT-VDT` (vulnerability detail), `VER-RPT-AVI` (accepted vulnerabilities), `VER-TFR-MRH` (historical VER activity). This retires the `x-rampscan.validationVulnerabilities` side-channel Q5 shipped as a stopgap and makes the OCR's `acceptedVulnerabilities` pointer resolve to a real document. The reachability tier earns its keep here: a non-accepted vulnerability carrying a signed not-affected OpenVEX with the call path attached is a record an assessor can interrogate.

The **forge plane** lands in the same phase because it is the honest cost of the authored artifact: proving an artifact was *persistently reviewed* needs pull-request approval metadata, which is an API call through the `RepoSource` port, not a checkout read. `packages/collectors/src/documents.ts:25` records that the batch-1 audit cut the currency limb for exactly this reason. This is a new evidence source and gets a spec section, not a quiet addition.

**Exit gate:** the three VER documents validate against their pinned schemas; an authored artifact whose PR carries an approval reads with a review record and one whose does not reads without, with the difference visible on the board.

### Phase R5 — the reviewer surface (3 days)

The Q5 exports have no presence in the UI at all. The operator console stays as it is — dark, dense, built for the person running scans. The certification package gets its own surface, built to be read by someone who has never run a scan: the SDR rendered, each KSI expanding to its five artifacts, each artifact naming its source, its clock, its judgment and its evidence. This is the `SDR-CSO-FRR` human-readable half as a product rather than a printout.

**Exit gate:** the surface is navigable by keyboard end to end — the finding `RESEARCH-UPSTREAM-READINESS.html` raised about the KSI board applies double to a surface built for assessors.

---

## 6. What the engineer sees when it is done

- **`rampscan artifacts`** — 46 rows, five cells each, every cell naming its source and its age. The empty cells are a work queue with a command attached, not a scold.
- **`rampscan artifacts scaffold KSI-CED-RAT`** — a file appears in the repository with the computed halves filled, the human halves empty and labelled, and the reason-for-absence path offered as a first-class option rather than a failure.
- **`rampscan sdr`** — the document that replaces the SSP, in both formats the rule demands, with `ksiTests` and `ksiEvidence` computed from signed measurement and every field labelled declared or computed.
- **The history is there**, because the ledger was recording it before anyone asked.
- **The board's `0 / 46` moves**, and it moves for the 33 KSIs that have no pipeline method — which is the population that has had nothing to do since Q2.

---

## 7. Honest constraints, deferrals, and risks worth naming

1. **Two known defects gate the honest numbers, and R0 fixes both.** (§7.1) Five KSIs carry `varies_by_class` with a class-B statement beginning `**Optional:**` — `CNA-EIS`, `MLA-ALA`, `SVC-PRR`, `SVC-RUD`, `SVC-VCM`. The catalog loader reads `varies_by_class` for the three class-varying FRR floors and only those — `FRC-CSX-VVK`, `FRC-CSX-MOT`, `VDR-TFR-MVX` at `packages/dataset/src/catalog.ts:498-509` — and never for the KSI indicators themselves, so `frontier` prints a 46 denominator at every class when class B's honest figure is 41. (§7.2) `scan` writes `openvex.json` into `<out>/exports/` and `conformance` defaults to that directory and exits 1 on it; CI dodges this by exporting into a temp dir with an absent ledger (`test.yml:87`). Both are small; both are the kind of thing a tool whose pitch is *computed, never typed* cannot leave standing.
2. **This makes rampscan partly a document product, which is somebody else's muscle.** Paramify and the GRC platforms sell document generation well. The defensible version is narrow and must stay narrow: artifacts *bound to evidence, to an anchor, and to a review record*, with a clock. A general document editor loses that fight; "artifacts whose freshness and review are computed" is a seam nobody ships. If R1 starts growing an editor, the plan has failed.
3. **Ground rule 1 will be under constant pressure.** Every user will want the tool to write artifact 1 for them, and an LLM in the loop makes it trivially possible. The refusal is the product. If rampscan generates compliance prose, `SDR-CSX-KSI` becomes a text-generation benchmark and the ledger's signature stops meaning anything an assessor should care about.
4. **The forge plane is a new evidence source, with the cost that implies.** Credentials, an API dependency, rate limits, and a GitLab/GitHub divergence, in an architecture whose entire pitch is that nothing leaves the boundary. It is scoped to R4 and behind its own spec section so it is a decision rather than a discovery.
5. **The SDR schema is `1.1.1` and draft.** It will move. The dual-pin discipline (`$schemaVersion` plus sha256) is the mitigation and it is already built; the schemas README's argument for not vendoring what we do not generate is correct and simply inverts as we start generating them.
6. **Trust center (G11) stays deferred**, unchanged from pivot §7.2. R5's reviewer surface is deliberately *not* a trust center — it is a local rendering, inside the boundary, of documents a trust center would serve.
7. **The `assessed` source depends on an assessor cooperating.** `IVV-IAS-SUM` obliges them to supply the summary, not to supply it in a shape rampscan can ingest. R4 ships a documented shape and an adapter; a paste-in path is the honest fallback and it is labelled as declared.

---

## 8. What "done" looks like

- `rampscan artifacts` holds bodies, not judgments about absent bodies, and the board's `k / 5` moves for a KSI with no automated method.
- `rampscan sdr` emits the document that replaced the SSP, in both required formats, schema-valid and rule-checked, with `ksiTests` and `ksiEvidence` computed from the ledger.
- The 30-day and one-year metric summaries are refolded from the ledger, not accumulated.
- The three VER documents replace the `x-rampscan` vulnerability side-channel.
- An authored artifact carries a review record from the forge, and one without says so.
- Two upstream findings are filed against `FedRAMP/schemas`, each naming the tool that found it.
- Every number on every surface still comes from a command.

---

## Session log

- **2026-09-13** — Drafted. The argument turned on three things read out of the sources rather than inferred: `SDR-CSX-KSI` makes the five artifacts the required content of the Security Decision Record; the SDR schema's `keySecurityIndicators[]` requires `ksiTests` and `ksiEvidence`, which are the method register and the signed bundles rampscan already computes and ships only into a side-channel; and `FRC-CSX-MOT` at class C requires six months of persistent-validation history, which cannot be retrofitted after the fact. Two upstream defects fell out of reading the schema against the rules and are carried as R2 deliverables. Not yet adopted as plan of record: adoption = this document merged + `R0`–`R5` milestones created on GitHub.
