# Page plan — "The Gap Engine" explainer for ramprules.com

**Status:** page plan, ready to build. Derived from `docs/RESEARCH-KSI-GAP-ENGINE.md` (2026-09-11).
**Publishes to:** ramprules.com (the public site in `fedramp-rules-hub`), not the rampscan console — the console lives inside a client boundary; this page is the public explanation of the model.
**Date:** 2026-09-11

---

## 1. What the page is for

One page that answers two questions a visitor actually has:

1. **What is a gap engine?** — the CR26 idea that a compliance gap is no longer a weak paragraph but a computable condition, and that finding gaps is a diff between two machine-readable states.
2. **What are the gaps, concretely?** — the 13 gap classes (G1–G13), each in plain language with the FedRAMP rule ID that makes it a gap, plus an honest map of which classes our tooling detects today and which it doesn't yet.

**Audience** (per PRODUCT.md tie-breaker): a developer told to "do FedRAMP," not a compliance specialist. Assume they know CI/CD and JSON; do not assume they know what a KSI, an OCR, or a 3PAO is — define each on first use, the way the /learn pages do.

**The one takeaway** if they read nothing else: *Under FedRAMP 20x, "find my gaps" is mostly a computation — `owed − proven = gap register` — and the part that isn't computable is exactly where assessors will spend their time.*

---

## 2. Where it lives

- **Route:** `/gap-engine` (new top-level route in `fedramp-rules-hub/app`).
- **Cross-links in:** from `/frontier` (the adjudication-gap page — G8 is its formal home in the taxonomy), from `/learn` (as a referenced concept page, not a course step), from `/automation` and `/coverage` (their numbers are the "proven" side of the diff).
- **Cross-links out:** every rule ID on the page links to its rule on the explorer (`FRC-CSX-VVK`, `VDR-TFR-MVX`, etc. — these already resolve on the site); KSI theme names link to their indicator pages.
- **Title:** `The Gap Engine` · **Meta description:** "Under FedRAMP 20x, a compliance gap is a computable condition. The 13 gap classes, the rule IDs that define them, and how much of the register a machine can actually fill."

---

## 3. Hard rules for the build (inherited from the repo's doctrine)

1. **Every number is computed, never typed.** 46 KSIs, 10 themes, 209 KSI-reached controls, 38 commit-plane controls, the ~58% frontier ceiling, dataset version `2026.07.14.01` — all of these come from the pinned dataset / coverage computation at build time, same as `/coverage` and `/frontier` do it. If a number in this plan appears hardcoded in the built page, that is a defect.
2. **The dataset version is on the page.** A visible "computed against dataset 2026.07.14.01" line (rendered from the pin, not typed), because the whole point of G9 (crosswalk drift) is that the catalog moves.
3. **No vacuous marketing greens.** The "what we detect today" section shows ❌ rows as prominently as ✅ rows. The honest-ceiling section is mandatory, not a footnote — conflating "covers 100% of KSIs" with "automates 100%" is the false-attestation failure mode the research names.
4. **Follow the site's existing design system** (fonts, tokens, components in `fedramp-rules-hub`). This plan specifies content and structure; it does not invent a new visual identity.

---

## 4. Page structure, section by section

### §A — Hero: the equation

- **Headline:** "A gap is now a computation."
- **Sub:** "Under Rev5, a gap was a control without a convincing paragraph. Under the 2026 Consolidated Rules, a gap is one of thirteen defined conditions — and eleven of them can be detected by a machine."
- **The visual is the equation itself,** set large, as the site sets code:

  ```
  owed(catalog, class) − proven(evidence) = gap register
  ```

  with three short annotations under each term:
  - *owed* — FedRAMP publishes the requirements as versioned JSON (`fedramp-consolidated-rules.json`) × your certification class (A–D).
  - *proven* — your evidence corpus: what it validates, its provenance, its signature, its age.
  - *gap register* — every row citing the rule ID that makes it a gap.
- Dataset-version line sits here (rule 3.2).

### §B — What changed (short context, ~4 paragraphs)

Purpose: give the developer just enough regulatory ground to understand why the taxonomy exists. Content, in order:

1. CR26 became adoptable July 2026, mandatory 2027-01-01. The unit of compliance moved from control narrative to **KSI validation**: {46} KSIs across {10} themes (numbers computed).
2. Each KSI owes: five artifacts, an explicit NIST 800-53 crosswalk, and a floor of automated validation methods by class — B ≥1, C ≥2, D ≥4 (`FRC-CSX-VVK`) — re-verified every 7 days (B) or 3 days (C) (`VDR-TFR-MVX`).
3. The assessor's instructions changed too: **"MUST NOT rely on screenshots, configuration dumps, or other point-in-time output as evidence"** (`FRR-PVA-AA-06`), trace every validation end-to-end, "do not stop at the dashboard."
4. The pivot sentence: *a failing KSI is not automatically a compliance failure — but an untrustworthy green is.* This sentence earns visual emphasis (the site's callout treatment); it is the thesis of §E.

### §C — The 13 gap classes (the centerpiece)

Render as a structured list/table (site's existing table or definition-list components). One row per class; each row carries **four fields**:

| Field | Treatment |
|---|---|
| ID + name | `G1 · Coverage gap` — stable anchors (`#g1` … `#g13`) so /frontier and /learn can deep-link |
| Plain-language definition | One sentence, rewritten for the developer audience (below) |
| Made a gap by | Rule ID(s), each linking to the explorer |
| Detectable | Badge: `Mechanical` / `Mechanical to surface, human to close` / `Partly mechanical` |

Plain-language definitions to use (rewritten from the research table — keep this register, not the research's compression):

- **G1 Coverage** — a KSI, or a control it reaches, that nothing validates at all. (`FRC-CSX-VVK`, IVV "all KSIs")
- **G2 Method count** — validated, but by fewer automated methods than your class requires: 1 for B, 2 for C, 4 for D. (`FRC-CSX-VVK`)
- **G3 Freshness** — evidence older than its window: 7 days (B) / 3 days (C) for machine checks, 3 months for human ones. (`VDR-TFR-MVX`, `VDR-TFR-NMV`, `FRC-APP-FCP`)
- **G4 History** — fewer than 6 months (C) / 18 months (D) of validation metrics on record. (`FRC-CSX-MOT`)
- **G5 Artifact** — any of the five documents each KSI owes is missing — or present but says nothing. Presence is mechanical; *sufficiency* is judgment. (`default_artifacts.KSI`)
- **G6 Evidence class** — a screenshot or config dump offered where a process is owed. Assessors must reject these as standalone evidence. (`FRR-PVA-AA-06`)
- **G7 Measurement system** — the validation itself is unsound: wrong scope, missing accounts, a failure path that fails silently. The "green dashboard" problem. Scope reconciliation is mechanical; logic soundness needs review. (Artifact 4, assessor guidance)
- **G8 Adjudication** — nobody has yet decided whether this KSI *can* be machine-validated from a given source. The question unasked. Mechanical to surface, human to close. *(This is what [/frontier] computes — link.)*
- **G9 Crosswalk drift** — the KSI catalog moved and your validations still target the old shape. The catalog moved three times during the pilots. (catalog versioning, RFC-0014)
- **G10 Package conformance** — your certification JSON doesn't match FedRAMP's schemas. (`FRC-CSO-JSN`)
- **G11 Trust center** — human and machine formats drifted apart, snapshots missing, no programmatic access, access logs under 6 months. (`CDS-CSO-CBF/HAD`, `CDS-TRC-PAC/ACL`)
- **G12 Reporting cadence** — quarterly report overdue, next-report date unposted, review meeting unscheduled. (`CCM-OCR-*`, `CCM-QTR-*`)
- **G13 Failure handling** — a failed validation not treated as a vulnerability with detection-and-response obligations. (`VDR-CSO-FAV`)

**Below the table, the two observations, verbatim in spirit:**
1. Eleven of thirteen are mechanically detectable end-to-end — under Rev5 the dominant gap class was narrative insufficiency, judgment all the way down.
2. The two that resist (G5 sufficiency, G7 soundness) are exactly where assessors are told to spend their time. A tool that computes only the mechanical eleven produces the green dashboard the guidance warns about.

### §D — How the engine works (one diagram + short prose)

Redraw the research's four-plane sketch with the site's diagram conventions (the /learn claim-split diagram style — SVG, theme-token colors):

- **OWED plane** (FedRAMP/rules JSON, pinned × class × adjudications) and **PROVEN plane** (signed, anchored, append-only evidence from pipeline · cloud APIs · human attestations) feeding the **GAP ENGINE** (taxonomy evaluated per KSI × class), emitting **SURFACES** (gap register, freshness clocks, method-count board, artifact checklist, report generators, trust-center export).
- One prose paragraph on the data-model pivot: the native unit is **KSI → validation methods → evidence**, with controls as the crosswalk annotation — a recipe is one *kind* of validation method (`source: pipeline`), and the class floor is counted per KSI across all sources.

### §E — Greens that survive interrogation

Short section (3 paragraphs + one illustrative expandable). The design principle that differentiates:

- The job is not green cells; it is greens that survive `FRR-PVA-AA-06`-style interrogation. Every pass must expose its query, its scope, the inventory it reconciled against, its freshness, and what happens when it fails — because that is exactly what the assessor pulls on.
- **Interactive moment (optional but recommended):** one example "green cell" that expands to show the anatomy — query, scope, anchor, signature, freshness, failure path — labeled as an illustration, not live data.
- Absence is a verdict: `unevidenced` with a reason, never a silent skip.

### §F — What our tooling detects today (the honesty table)

Frame explicitly: *"rampscan is this engine for one evidence plane — the pipeline — and here is exactly which gap classes it computes today."* Rendered as the research §7 table, simplified to gap-class rows:

| Gap class | Today |
|---|---|
| G8 adjudication | ✅ `frontier` — surfacing the unasked question is the register's second act |
| G3 freshness | ✅ scheduler + clock on the 7d/3d windows |
| G1 coverage (absence half) | ✅ `unevidenced` is a first-class verdict |
| G13 failure handling | ✅ a validation failure is a finding, not an embarrassment |
| G4 history | ⚠️ the ledger holds the history; nothing computes the 6/18-month floor yet |
| G6 evidence class | ⚠️ everything is process-generated by construction; not yet asserted as a label |
| G2 method floors, G5 artifacts, G9 drift, G10 conformance, G11 trust center, G12 cadence | ❌ not yet — the KSI-native register (methods as first-class entities) comes first |

Legend under the table: ✅ computed today · ⚠️ data exists, computation doesn't · ❌ not yet modeled. Every ❌ stays visible; that's the point.

### §G — The honest ceiling (closing)

- The numbers, computed: {209} KSI-reached controls; the commit plane reaches {38} ({18.2%}); the combined aws+pipeline ceiling is {~58%}.
- The sentence that carries it: *"A gap engine covers 100% of KSIs — every one gets a row — while automating far less. The remainder is acts performed on or by people: training delivered, screening completed, agreements signed. A repository holds evidence about the act, not the act."*
- Close with the pointer to `/frontier` (see the uncovered questions yourself) and `/coverage` (see what's computed today).

---

## 5. Diagrams to produce

1. **§A** — the equation, typographic (no drawing).
2. **§C** — optional 13-cell strip showing detectability at a glance (11 solid, 2 half-toned); skip if it fights the table.
3. **§D** — the four-plane architecture diagram, one SVG, both themes, redrawn in site style (do not paste the ASCII).
4. **§E** — the "anatomy of a green" expandable (component, not image).

## 6. Acceptance criteria

- [ ] No literal occurrence of 46, 10, 209, 38, 18.2, 58, or the dataset version as typed constants in the page source — all flow from the dataset/coverage layer.
- [ ] All 13 gap-class anchors resolve; every rule ID links to the explorer; /frontier links to `#g8` and this page links back.
- [ ] The ❌ rows of §F render with the same visual weight as ✅ rows.
- [ ] Passes the repo's fast gates (skip the a11y sweep per working agreement; run it only if this page ships in a batch that warrants it).
- [ ] Reads end-to-end without requiring the reader to know Rev5 — every acronym defined on first use.

## 7. Open questions (decide at build time, none blocking)

1. Does `/gap-engine` join the `/learn` course sequence as a step, or stay a standalone concept page linked from it? (Plan assumes standalone.)
2. Should §F's table be computed from a small machine-readable capability manifest (so the page can't drift from the code), or authored? Recommendation: authored now, manifest when the KSI pivot lands — and note the irony explicitly in the PR if authored.
3. The §E expandable: worth building interactive in v1, or ship as a static annotated figure first?
