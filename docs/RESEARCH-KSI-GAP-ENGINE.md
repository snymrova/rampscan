# Deep research — software that helps a FedRAMP engineer find gaps, keyed to KSIs and 20x

**Status:** research report, not a decision document. It proposes; the spec and the GitHub milestones decide.
**Date:** 2026-09-11
**Method:** two parallel web-research passes (regulatory state of FedRAMP 20x as of September 2026, verified against fedramp.gov and the FedRAMP GitHub org; tooling and methodology landscape), joined against this repository's pinned ramprules dataset (`2026.07.14.01`) and its automation-frontier adjudication model. Every load-bearing regulatory claim below was verified against the machine-readable `fedramp-consolidated-rules.json` in [github.com/FedRAMP/rules](https://github.com/FedRAMP/rules) or a fedramp.gov page; claims that could not be verified are flagged inline. Rule IDs (e.g., `VDR-TFR-MVX`, `FRC-CSX-VVK`) are FedRAMP's own canonical identifiers.

---

## 1. Executive summary

FedRAMP 20x has crossed from pilot to rulebook. The **Consolidated Rules for 2026 ("CR26")** launched June 24–25, 2026, became optionally adoptable July 4, 2026, and are **mandatory for all stakeholders on January 1, 2027**. The unit of compliance is no longer the control narrative — it is the **KSI validation**: 46 Key Security Indicators across 10 themes, each mapped explicitly to NIST 800-53 controls, each owing five defined artifacts, each requiring a stated number of *automated validation methods* per certification class, re-verified on a machine cadence (7 days Class B, 3 days Class C) with quarterly public reporting through a machine-readable trust center.

This changes what "finding a gap" means. Under Rev5 a gap was a control without a convincing paragraph. Under CR26 a gap is one of roughly a dozen **computable conditions** — a KSI with too few automated methods, evidence older than its window, an artifact of the five missing, a validation process an assessor is instructed to distrust — and nearly all of them can be detected mechanically because both sides of the comparison are now data: FedRAMP publishes *what is owed* as versioned JSON, and the provider's *what is proven* is required to be JSON conforming to FedRAMP schemas.

**The product thesis this research supports:** the winning gap tool is a **diff engine between two machine-readable states** — the owed catalog (FedRAMP/rules JSON, versioned) and the proven state (the provider's evidence, signed and fresh) — with a gap taxonomy as its type system and assessor-grade traceability behind every green cell. The commercial field (Paramify, Vanta, RegScale, Boundera) has converged on pieces of this; nobody, commercial or open-source, ships the full seam. rampscan already implements the hardest parts of the proven-state side (signed commit-anchored evidence, freshness clocks, anchor death, computed-never-typed reporting) and one gap class outright (`rampscan frontier` is an adjudication-gap finder). Section 7 maps the distance from here to a full KSI gap engine.

---

## 2. Regulatory ground truth, September 2026

### 2.1 Where 20x stands

- **Phase 1** (Low pilot): April–September 2025; 26 complete submissions, first pilot authorizations late July 2025. Proved automation-based validation works in practice.
- **Phase 2** (Moderate pilot): November 2025–March 2026, 14 qualifying submissions; first cohort authorized March 6, 2026, six more by April 27, 2026.
- **Phase 3 (now, FY26 Q3–Q4):** formalization around CR26 at [fedramp.gov/2026](https://www.fedramp.gov/2026/). FedRAMP Ready closed July 28, 2026; **Class A applications opened Aug 3, 2026; Class B & C opened Aug 31, 2026**. New Rev5 certifications end June 11, 2027.
- **Phase 4** (FY27) adds Class D; **RFC-0033** (Class D development tracks) is open now, closing **2026-10-09** — a live window to influence the class this project's ceiling most depends on.

CR26 replaces Low/Moderate framing with **Certification Classes A–D** (minimal → significant assurance). Class A enters via an accepted external framework (SOC 2 Type II, Rev5, or GovRAMP within 12 months, `FRC-CLA-ASF`) plus 23 mandatory rules including 7 KSIs. A provider MUST NOT pursue Rev5 and 20x for the same offering (`FRC-CSO-POP`) and MUST NOT apply through a third party (`FRC-APP-NTP`).

### 2.2 The KSI catalog

The authoritative machine-readable source is `fedramp-consolidated-rules.json` in [FedRAMP/rules](https://github.com/FedRAMP/rules) — dataset version **2026.07.14.01**, which is **exactly the version this repository pins**. Verified contents: 75 FRD definitions, 246 FRR rules across 17 rulesets, **46 KSIs across 10 themes**, 79 CTL control-parameter entries.

| Theme | Name | KSIs |
|---|---|---|
| KSI-CED | Cybersecurity Education | 1 |
| KSI-CMT | Change Management | 4 |
| KSI-CNA | Cloud Native Architecture | 8 |
| KSI-IAM | Identity & Access Management | 6 |
| KSI-INR | Incident Response | 3 |
| KSI-MLA | Monitoring, Logging, Auditing | 5 |
| KSI-PIY | Policy and Inventory | 5 |
| KSI-RPL | Recovery Planning | 4 |
| KSI-SCR | Supply Chain Risk | 2 |
| KSI-SVC | Service Configuration | 8 |

Each KSI carries a `statement` (a measurable outcome), a `controls` array (**the explicit NIST 800-53 crosswalk** — the join this repository's `CONTROLS-TO-REPORTS.md` already rides), and change history. IDs moved from numbered (`KSI-IAM-01`) to mnemonic (`KSI-CNA-RNT`); the old KSI-TPR theme became KSI-SCR. Third-party KSI counts in circulation (51, 56/61, 63, 65) are pre-CR26 snapshots — **the catalog itself is a versioned, moving dataset**, which is a design input, not trivia: RFC-0014 alone retired 3 KSIs, updated 23, and added 8 between phases. A gap tool that hard-codes the catalog is wrong within months; this repository's pin-and-re-pin discipline (three guarded pins in `packages/dataset/src/pins.ts`) is the correct posture.

**Five required artifacts per KSI** (from the dataset's `info.default_artifacts.KSI`):

1. Explanation of the measures and objectives (or the reason for absence + customer risk).
2. Explanation of the persistent-validation cycle.
3. Verification that the measures demonstrate the KSI.
4. Verification that the automation is accurate and sufficient.
5. Validation that the measures are in place and working.

Artifact 4 deserves emphasis: **the accuracy of the measurement system is itself an owed artifact.** A gap tool must therefore audit not only evidence but the machinery producing it.

### 2.3 Cadences and quantitative floors (all verified from the rules JSON)

| Rule | Requirement |
|---|---|
| `VDR-TFR-MVX` | Persistent machine verification: Class A SHOULD monthly; **Class B MUST every 7 days; Class C MUST every 3 days** |
| `VDR-TFR-NMV` | Non-machine-based resources: MUST every **3 months** |
| `FRC-CSX-VVK` | Automated KSI validation: Class B SHOULD ≥**1 automated method per KSI**; Class C MUST ≥**2**; Class D MUST ≥**4** |
| `FRC-CSX-MOT` | Historical metrics: Class C MUST show ≥**6 months** of persistent-validation history; Class D ≥**18 months** |
| `FRC-APP-FCP` | Initial package must show status verified/validated **within the previous 7 days** |
| `FRC-APP-FIA` | Initial B/C/D application needs an independent assessment completed within the previous **3 months** |
| `IVV-CSX-AIA` | Annual independent assessment covering **all KSIs** (B/C/D) |
| `VDR-CSO-FAV` | **A validation failure is treated as a vulnerability** |

`VDR-TFR-MVX` is the clock this repository's scheduler already runs. `FRC-CSX-VVK` and `FRC-CSX-MOT` are new load-bearing numbers rampscan does not yet model — see §7.

### 2.4 Reporting and the trust-center obligation

- **Collaborative Continuous Monitoring (CCM ruleset, 19 rules)** replaces monthly ConMon: a public **Ongoing Certification Report (OCR) every 3 months** (`CCM-OCR-AVL`), publicly posted next-report date, async feedback with anonymized Q&A; Class C adds a synchronous **Quarterly Review** meeting (`CCM-QTR-MTG`).
- **Certification Data Sharing (CDS ruleset, 21 rules):** providers MUST publish offering data in **both human- and machine-readable form** (`CDS-CSO-PUB`), through a FedRAMP-compatible **trust center** as the definitive source (`CDS-CSO-UTC`), **use automation to keep the two formats consistent** (`CDS-CSO-CBF`), supply OCR-aligned historical snapshots (`CDS-CSO-HAD`), provide documented programmatic access (`CDS-TRC-PAC`), and log access for ≥6 months (`CDS-TRC-ACL`).
- **All certification package information must be JSON matching FedRAMP schemas** (`FRC-CSO-JSN`) — 11 draft CR26 schemas live in [FedRAMP/schemas](https://github.com/FedRAMP/schemas) (Certification Package Overview, Ongoing Certification Report, Incident Report, Vulnerability Detail Report, Significant Change Notifications, Security Decision Record, …), independently semver'd.

The Rev5 track runs in parallel on **OSCAL** (RFC-0024: machine-readable Rev5 packages due **September 30, 2026** — this month). 20x is the JSON-schema track, not OSCAL. A gap tool for 20x targets FedRAMP/schemas; OSCAL matters only at the Rev5 boundary and for crosswalk tooling.

### 2.5 What the assessor is now told to do — and reject

The IVV ruleset and RFC-0017 make assessment **process/review-based, not point-in-time test-based**:

- Assessors **"MUST NOT rely on screenshots, configuration dumps, or other point-in-time output as evidence"** except when evaluating the systems that generate them (`FRR-PVA-AA-06`).
- They must trace validations end-to-end — data source → collection → transformation logic → failure detection → response — and are explicitly warned **"do not stop at the dashboard."**
- They must distinguish *a sound process reporting a security problem* from *an unsound process reporting an unreliable answer* — **a failing KSI is not automatically a compliance failure**, but an untrustworthy green is.

This is the single most important design input in this report. It means a gap tool's job is not to produce green cells; it is to produce **greens that survive interrogation** — every status must expose its query, its scope, its freshness, and its failure path, because that is precisely what the assessor is instructed to pull on. It is also a direct vindication of this repository's founding rule that a vacuous pass is a security vulnerability, not a bug.

---

## 3. The gap taxonomy — what a gap *is* under 20x

The report's core synthesis. Under CR26, "gap" decomposes into distinct, mostly computable conditions. Any serious gap engine should carry this taxonomy as its type system; each entry names the rule that makes it a gap and whether a machine can detect it.

| # | Gap class | Definition | Made a gap by | Detectable |
|---|---|---|---|---|
| G1 | **Coverage gap** | A KSI (or a control a KSI reaches) with no validation addressing it at all | `FRC-CSX-VVK`, IVV "all KSIs" | Mechanical |
| G2 | **Method-count gap** | KSI validated, but by fewer automated methods than the class floor (1/2/4 for B/C/D) | `FRC-CSX-VVK` | Mechanical |
| G3 | **Freshness gap** | Evidence older than its window: 7d (B) / 3d (C) machine, 3 months non-machine, 7-day staleness at application | `VDR-TFR-MVX`, `VDR-TFR-NMV`, `FRC-APP-FCP` | Mechanical |
| G4 | **History gap** | Fewer than 6 months (C) / 18 months (D) of persistent-validation metrics | `FRC-CSX-MOT` | Mechanical |
| G5 | **Artifact gap** | Any of the five per-KSI artifacts missing or vacuous | `default_artifacts.KSI` | Mechanical for presence; judgment for sufficiency |
| G6 | **Evidence-class gap** | Point-in-time evidence (screenshots, config dumps) offered where process evidence is owed | `FRR-PVA-AA-06` | Mechanical (classify evidence provenance) |
| G7 | **Measurement-system gap** | The validation itself is unsound: wrong scope, missing accounts, silent failure path — the "green dashboard" problem | Artifact 4, assessor guidance | Partially — scope/inventory reconciliation is mechanical; logic soundness needs review |
| G8 | **Adjudication gap** | Nobody has decided whether a KSI/control *can* be machine-validated from a given evidence source — the question unasked | (product-level, not a rule) | Mechanical to *surface*; human to close |
| G9 | **Crosswalk-drift gap** | The KSI catalog or its control mappings moved (new dataset version) and validations still target the old shape | Catalog versioning; RFC-0014 precedent | Mechanical |
| G10 | **Package-conformance gap** | Certification JSON not matching FedRAMP schemas | `FRC-CSO-JSN` | Mechanical |
| G11 | **Trust-center gap** | Human/machine format drift, missing OCR-aligned snapshots, no programmatic access, access logs short of 6 months | `CDS-CSO-CBF/HAD`, `CDS-TRC-PAC/ACL` | Mechanical |
| G12 | **Reporting-cadence gap** | OCR overdue, next-report date unposted, quarterly review unscheduled | `CCM-OCR-*`, `CCM-QTR-*` | Mechanical |
| G13 | **Validation-failure handling gap** | A failed validation not treated as a vulnerability with detection/response obligations | `VDR-CSO-FAV` | Mechanical |

Two observations fall out of the table:

1. **Eleven of thirteen gap classes are mechanically detectable end-to-end.** This is the structural difference from Rev5, where the dominant gap class was narrative insufficiency — judgment all the way down. Under 20x, the gap register is mostly a computation.
2. **The two that are not (G5-sufficiency, G7-soundness) are exactly where assessors are told to spend their time.** A gap tool that only computes G1–G4 and G9–G13 produces the green dashboard the guidance warns about. The differentiating work is making G7 tractable: exposing every validation's query, scope, inventory reconciliation, and failure path as first-class inspectable objects.

---

## 4. Landscape — who does what today

### 4.1 Commercial

- **[Paramify](https://www.paramify.com/fedramp-20x)** — most credentialed: first GRC tool with 20x **Class C certification**; its Phase 1 pilot submission is [fully public](https://github.com/paramify/fedramp-20x-pilot). Gap model: per-validation **True/False/Partial** implementation and assessment status rolling up to KSI Complete/Incomplete, with per-evidence assessor remarks. Generates SDRs, Significant Change Records, OCRs; sells a public trust center. Targets federal-heavy complexity.
- **[Vanta](https://www.vanta.com/products/fedramp-20x)** — 20x **Class B certified** for its own platform (July 2025). Hourly integration-driven tests mapped to KSIs, cross-framework evidence reuse (SOC 2/ISO → KSI), AI flagging of "weak or missing evidence." Published a candid [pilot retro](https://www.vanta.com/resources/lessons-learned-from-vantas-fedramp-20x-pilot) admitting KSIs "lack definitive implementation guidelines."
- **[RegScale](https://regscale.com/blog/fedramp-20x-compliance-as-code-ksis/)** — the most technically explicit gap engine: KSIs as deterministic **OPA/Rego checks** against live infrastructure, **showing the Rego rule behind every pass/fail**; markets "75% KSI automation out of the box"; August 2026 Microsoft collaboration for Azure. Its show-the-rule posture is the state of the art for G7.
- **[Boundera](https://boundera.io/)** — 20x-native entrant: continuous validation of all 46 KSIs from cloud/repo/identity/scanner reads, and — the notable methodology move — **remediation proposed as draft PRs and Jira tickets** with human approval. Published pricing $5k/$25k/$50k per year. Dogfoods its own Class C pursuit via public trust center.
- **Anitian FedFlex, Knox Systems, stackArmor/Telos Xacta, Coalfire** — respectively: agentic-AI platform with embedded 3PAO (pilot submission [public](https://github.com/anitianinc/anitian-fedflex-fedramp-20x)); managed platform + AI reporting (depth unverified); in-boundary security stack, with Xacta remaining Rev5/RMF-centric (KSI support unverified); 3PAO plus advisory services rather than product. **Secureframe/Drata**: strong content, unverified KSI-native validation.

### 4.2 Open source — four layers, no stitch

- **[FedRAMP/rules](https://github.com/FedRAMP/rules)** — the *owed* side as canonical JSON, with a schema and an `AGENTS.md` written for AI consumption. The sleeper asset; every gap engine should treat it as the upstream catalog. (This repository already does, via the ramprules pin.)
- **[NIST OSCAL](https://csrc.nist.gov/projects/open-security-controls-assessment-language)** — component-definition ("how X satisfies Y"), assessment-results/POA&M, and the mapping model explicitly built for "gap analysis, harmonization, inheritance evaluation." The Rev5 interchange layer; not the 20x package format.
- **[Lula](https://github.com/defenseunicorns/lula)** (Defense Unicorns) — the closest open-source analog to a KSI gap engine: OSCAL component-definitions with embedded validations (Kyverno, API providers) run in CI, emitting assessment-results. Declarative expected-vs-observed, versioned in git.
- **[GSA/fedramp-automation](https://github.com/gsa/fedramp-automation)** — Schematron/XSpec validation of OSCAL package *well-formedness* (G10's Rev5 cousin), not security posture.
- Lineage and adjacent: OpenControl/Compliance Masonry (proved the component→control YAML data model, dormant → OSCAL), InSpec/MITRE SAF (profile-as-code, mature in DoD, no public KSI profile set), opencomply (SQL-defined controls, no KSI mapping).

**The composite finding:** FedRAMP/rules gives requirements-as-data; OSCAL gives interchange; Lula/OPA/InSpec give validation execution; fedramp-automation gives package linting. **Nobody open-source stitches all four into a KSI gap product. That seam is the opportunity**, and it is the seam rampscan is already standing in.

### 4.3 Published failure modes of the current tooling

1. **KSI ambiguity** — the #1 practitioner complaint since [RFC-0006 comments](https://github.com/FedRAMP/community/discussions/3): unclear what constitutes acceptable evidence, onus pushed to auditors.
2. **The green-dashboard problem** — passing status hiding missing accounts, incomplete inventory, broken integrations; official guidance now instructs assessors to read the source, queries, and thresholds ("automation is not proof by itself" — [Schellman](https://www.schellman.com/blog/federal-compliance/fedramp-20x-decoded)).
3. **"Partially automated" purgatory** — most CSPs land partial and drown in narratives about where automation exists; pilot packages under ~70% automation were reportedly rejected.
4. **Rev5-era GRC tools don't transfer** — they model controls and documents, not capabilities and validations.
5. **Package-schema fragmentation** — every pilot vendor invented its own format; standardization is only now arriving via FedRAMP/schemas and CR26.

Each failure mode maps to a gap class above (1→G5/G8, 2→G7, 3→G2/G5, 4→G9, 5→G10) — evidence that the taxonomy carves the field where it actually breaks.

---

## 5. The product: a KSI gap engine

### 5.1 Thesis

**A gap engine is a diff between two versioned, machine-readable states**, plus judgment surfaces for the residue:

```
owed(catalog version V, class K)  −  proven(evidence, signed, fresh)  =  gap register
```

- **Owed** = FedRAMP/rules JSON at a pinned version × the provider's certification class → the set of (KSI, validation-method floor, cadence, artifacts, reporting obligations).
- **Proven** = the provider's evidence corpus, where each item carries: what it validates (KSI + method), its provenance (query/collector + tool versions), its anchor (commit / API-response digest / timestamp), its signature, and its age.
- **Gap register** = the taxonomy of §3 evaluated over the diff, every row carrying the rule ID that makes it a gap and the evidence (or absence) that makes it true.

### 5.2 Design principles (each earned by a finding above)

1. **Both catalogs are pinned and versioned; every number is computed, never typed.** The KSI catalog moved three times during the pilots; the automation-frontier overlay moved twice in two days of this project's own history. (Already this repository's rules 2, 4, 9.)
2. **No vacuous passes — a green that cannot survive `FRR-PVA-AA-06`-style interrogation is a defect of the highest class.** Every pass exposes: the query/rule that produced it, the scope it ran over, the inventory it reconciled against, its freshness, and what happens when it fails. RegScale's show-the-Rego is the market's floor here; signed provenance is the ceiling.
3. **Absence is a first-class verdict.** `unevidenced` with a recorded reason, never a silent skip — a control with no evidence is never a control that passed. (Already the doctor/collector posture.)
4. **A failing validation is a vulnerability, not an embarrassment** (`VDR-CSO-FAV`): the gap register feeds detection-and-response machinery, not just a report.
5. **The unreviewed question is itself a gap** (G8). Printing "68 unreviewed" as a question rather than smoothing it into a percentage is a differentiator no competitor surfaced in this research — keep it.
6. **Honest ceilings.** Most FedRAMP obligations are acts performed on or by people; a repository or an API holds evidence *about* the act, not the act. The tool states what its evidence plane can never answer, per class, as a computed number.
7. **Evidence-class labeling** (G6): every artifact is classified process-generated vs point-in-time at ingestion, because the assessor must reject the latter as standalone evidence.

### 5.3 Architecture sketch

Four planes, three of which this repository has already built for the commit plane:

```
┌─ OWED ─────────────────────┐   ┌─ PROVEN ──────────────────────────────┐
│ FedRAMP/rules JSON (pinned)│   │ evidence ledger: signed, anchored,    │
│ × class (A/B/C/D)          │   │ content-addressed, append-only        │
│ × adjudications (per-KSI:  │   │ sources: pipeline/repo (rampscan) ·   │
│   automatable? which       │   │ cloud APIs (ramprules recipes) ·      │
│   sources? which methods?) │   │ human attestations (two-key)          │
└──────────┬─────────────────┘   └──────────────┬────────────────────────┘
           │                                    │
           └────────────► GAP ENGINE ◄──────────┘
                 taxonomy G1–G13, evaluated per KSI × class,
                 every row citing the rule ID and the evidence
                          │
                          ▼
┌─ SURFACES ──────────────────────────────────────────────────────────────┐
│ gap register (console + CLI) · MVX/NMV freshness clocks ·               │
│ method-count board (n of floor, per KSI) · artifact checklist (5/KSI) · │
│ OCR generator (quarterly, FedRAMP/schemas JSON) ·                       │
│ trust-center export (human+machine from one source, CDS-CSO-CBF) ·      │
│ package conformance check (FRC-CSO-JSN) · remediation hand-off (PR/     │
│ ticket drafts, human-approved — the Boundera pattern)                   │
└─────────────────────────────────────────────────────────────────────────┘
```

The data-model pivot the research demands: today's register is **recipe → controls**. CR26's native unit is **KSI → validation methods → evidence**, with controls as the crosswalk annotation. Concretely: a *validation method* becomes a first-class entity (id, KSI, automated?, evidence source, cadence class, provenance), a recipe is one *kind* of validation method (source: `pipeline`), and the method-count floor (`FRC-CSX-VVK`) is evaluated per KSI over all methods across all sources. That pivot is what makes G1/G2 computable and is the largest single schema change this research recommends.

### 5.4 What the engineer sees (the user, per the ramprules PRODUCT.md tie-breaker: a developer told to "do FedRAMP," not a compliance specialist)

- **One board, per KSI:** methods `n / floor`, freshest evidence age vs window, artifacts `k / 5`, and the *worst* gap class for that KSI as the row's color — never a bare percentage.
- **Every red names its rule ID and its fix**; every green expands to its query, scope, and signature — the assessor-interrogation view is the *default* detail view, not an export.
- **The clock is ambient**: what expires in the next 3 days is the top of everything (the MVX window is the product's heartbeat, and it already is this repository's scheduler contract).
- **The unanswered questions are a first-class tab**: G8 adjudication queue, sorted by leverage (the frontier's `leverage` field already exists in the dataset for exactly this).

---

## 6. Honest constraints

1. **The ceiling is real and must stay on the box.** At the pinned dataset: 209 KSI-reached controls; the commit plane reaches 38 (18.2%); the upstream frontier's combined aws+pipeline ceiling is ~58%. The remainder is acts-on-people (training delivered, screening completed, agreements signed) plus the classes of evidence only a human attestation can carry (`VDR-TFR-NMV`'s 3-month cycle exists precisely for these). A gap engine *covers* 100% of KSIs — every one gets a row — while *automating* far less; conflating the two is the false-attestation failure mode.
2. **G5 sufficiency and G7 soundness resist full automation.** The tool's honest posture: mechanical presence checks + structured judgment surfaces (the two-key pattern) + optionally model-assisted review that is visually quarantined and never the last step before an assertion (the Tier-3 rule already in `ARCHITECTURE.md`).
3. **The catalog will move again.** Phase 4 / Class D is being designed *now* (RFC-0033, closes 2026-10-09); Class D floors (≥4 methods/KSI, 18 months history) are already in the rules. Re-pin at the start of a batch, not the end.
4. **Single-upstream concentration.** This project's owed-side depends on the ramprules derivation of FedRAMP/rules. Mitigation worth considering: the engine's catalog port should also be able to ingest `fedramp-consolidated-rules.json` directly, with ramprules' adjudication overlay as an enrichment rather than the sole path.

---

## 7. What this means for rampscan, specifically

rampscan is not starting this product from zero — it *is* this product for one evidence plane, missing the KSI-native gap model. Standing inventory against the architecture in §5.3:

| Gap engine needs | rampscan today |
|---|---|
| Signed, anchored, append-only proven-state | ✅ ledger + cosign + anchor death |
| Freshness clocks on the MVX window | ✅ scheduler + clock view (7d/3d) |
| Computed-never-typed reporting | ✅ rules 4 & 9, `frontier` |
| Adjudication-gap surfacing (G8) | ✅ `frontier` — unique in the field per this research |
| Absence-as-verdict (part of G1) | ✅ `unevidenced` posture |
| PR-time gap prevention | ✅ `rampscan check` gate |
| **KSI-native register (KSI → methods → evidence)** | ❌ register is recipe → controls |
| **Method-count floors per class (G2, `FRC-CSX-VVK`)** | ❌ not modeled |
| **Metrics-history tracking (G4, `FRC-CSX-MOT`)** | ⚠️ ledger holds the history; nothing computes the 6/18-month floor |
| **Five-artifacts-per-KSI checklist (G5)** | ❌ recipes have `plain` authored text; the five artifacts are not modeled |
| **Evidence-class labeling (G6)** | ⚠️ implicit (everything is process-generated); not asserted |
| **OCR generation + package conformance (G10, G12)** | ❌ exports exist (OpenVEX, frontier report); no FedRAMP/schemas targets |
| **Trust-center export (G11)** | ❌ console is inside the boundary; CDS wants a public machine surface |
| Cloud-API evidence source | ❌ out of scope by decision — ramprules recipes are the client's to run; the gap engine still needs to *ingest their results* to count methods per KSI |

**Recommended sequencing (for the roadmap, not decided here):**

1. **The KSI pivot** — make validation-method the register's unit; recipes become methods with `source: pipeline`. Everything else in this list depends on it.
2. **`rampscan frontier` grows the class dimension** — per KSI: methods counted against the class floor, history counted against `FRC-CSX-MOT`, artifacts against the five. The gap taxonomy becomes the frontier's second act.
3. **Ingest, don't execute, other sources** — accept signed results of client-run AWS recipe executions (and human attestations, already two-keyed) into the ledger so method counting spans sources without breaching the no-SaaS/no-execution decision.
4. **Schema-target exports** — OCR and Certification Package fragments as FedRAMP/schemas JSON, generated from the projection (an export, like OpenVEX — no new state).
5. **Engage RFC-0033** before 2026-10-09 — Class D's ≥4-methods floor is where a pipeline evidence plane is most valuable, because pipeline methods are the cheapest additional automated methods most providers can add.

---

## 8. Sources

**Primary (verified):** [fedramp.gov/20x](https://www.fedramp.gov/20x/) · [fedramp.gov/2026](https://www.fedramp.gov/2026/) ([timeline](https://www.fedramp.gov/2026/timeline/), [definitions](https://www.fedramp.gov/2026/definitions/), [assessors](https://www.fedramp.gov/2026/assessors/fedramp-assessments/20x/), [KSI reference](https://www.fedramp.gov/2026/reference/20x/b/key-security-indicators/)) · [FedRAMP/rules](https://github.com/FedRAMP/rules) (`fedramp-consolidated-rules.json` 2026.07.14.01, parsed directly) · [FedRAMP/schemas](https://github.com/FedRAMP/schemas) · [FedRAMP RFC index](https://www.fedramp.gov/rfcs/) (0005–0034; esp. [0014](https://www.fedramp.gov/rfcs/0014/), [0017](https://www.fedramp.gov/rfcs/0017/), [0024](https://www.fedramp.gov/rfcs/0024/)) · [FedRAMP/community](https://github.com/FedRAMP/community) · local: `docs/context/ramprules/` snapshot (DATASET-FACTS, automation-frontier 0.7.5, PRODUCT.md).

**Secondary (tooling/practitioner):** [Paramify pilot repo](https://github.com/paramify/fedramp-20x-pilot) · [Vanta 20x](https://www.vanta.com/products/fedramp-20x) + [pilot retro](https://www.vanta.com/resources/lessons-learned-from-vantas-fedramp-20x-pilot) · [RegScale KSI compliance-as-code](https://regscale.com/blog/fedramp-20x-compliance-as-code-ksis/) · [Boundera](https://boundera.io/) · [Anitian pilot repo](https://github.com/anitianinc/anitian-fedflex-fedramp-20x) · [Schellman: 20x decoded](https://www.schellman.com/blog/federal-compliance/fedramp-20x-decoded) · [Lula](https://docs.lula.dev/) · [GSA/fedramp-automation](https://github.com/gsa/fedramp-automation) · [OSCAL mapping model](https://pages.nist.gov/OSCAL/learn/concepts/layer/control/mapping/) · [AWS 63-KSI deep-dive](https://aws.amazon.com/blogs/publicsector/deep-dive-into-fedramp-20x-key-security-indicators-decoding-the-63-ksis/) (pre-CR26 snapshot) · [Quzara KSI evidence model](https://quzara.com/fedramp/ksi) · [Teuscher, SiRAcon '25 field report](https://arxiv.org/pdf/2510.09613) · NIST IR 8011v1r1 (testable-controls taxonomy).

**Unverified / flagged:** "Minimum Validation Expectations" as an official term (MVX officially = Persistent Machine Verification and Validation; the expansion used in this repository's README is legacy phrasing) · exact Phase 2 authorized-provider count beyond the two announced cohorts · Telos Xacta, Knox, Drata, Secureframe KSI-native depth (marketing only) · the RFC-0024 "all providers" scope (secondary sources; verify against RFC text) · pilot-era ≥70% automation floor (pilot guidance, superseded by CR26 class rules) · absence of Reddit-visible practitioner critique (search limitation, not evidence of absence).
