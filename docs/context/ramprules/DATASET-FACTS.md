# Dataset facts

GENERATED FILE — DO NOT EDIT. Regenerate with `pnpm derive`.

Read this instead of scanning `docs/fedramp-consolidated-rules.json` (567 KB).
Every number here is computed from the index at derive time, so it cannot
disagree with the site. Machine-readable slices live in `data/derived/`.

- **Dataset version** `2026.07.14.01` (last updated 2026-07-14)
- **Title** FedRAMP Consolidated Rules for 2026

## KSI graph

| Measure | Count |
|---|---|
| Themes | 10 |
| Indicators | 46 |
| KSI→control edges | 373 |
| Distinct controls reached | 209 |
| Control families reached | 17 |
| FRD terms | 75 |

`controlsById` is **KSI-edge-only**. It deliberately excludes baseline-only
and CTL-only controls; coverage is a set intersection against these keys.

## FRR

| Measure | Count |
|---|---|
| Documents | 17 |
| Requirements | 246 |
| Timeframed entries | 68 |
| ...at requirement level | 17 |
| ...inside `varies_by_class` | 51 |
| Notification items | 31 |
| PAIN grids | 16 |
| Rollout calendar entries | 106 |

**Force distribution** — two totals, and quoting either without saying which
is a known way to get this wrong:

- Requirement level only: MUST 136 · MUST NOT 11 · SHOULD 45 · SHOULD NOT 5 · MAY 20 (total 217)
- Including `varies_by_class`: MUST 189 · MUST NOT 11 · SHOULD 84 · SHOULD NOT 5 · MAY 39 (total 328)

**Who the rules bind** (`affects`, requirement level, sums to 246):

| Party | Requirements | Deadlines |
|---|---|---|
| Providers | 180 | 61 |
| Agencies | 24 | 0 |
| Assessors | 23 | 6 |
| FedRAMP | 16 | 1 |
| Advisors | 3 | 0 |

Beware: a naive recursive walk for `affects` returns 300, because
`FRR.<doc>.info.subsets.*` carries the same key as a subset-applicability
declaration. Only the requirement-level field is counted above. `Everyone` is
in the schema enum and unused in the data.

**Deadline units** (never converted for display): months 24 · years 17 · days 15 · bizdays 8 · weeks 3 · hours 1

Tightest deadline: **VDR-TFR-PSD class d at 1 day**.

## Rev5 baselines vs KSI coverage

| Class | Baseline controls | Covered by KSI | Orphans | Families |
|---|---|---|---|---|
| b | 155 | 95 | 60 | 18 |
| c | 322 | 199 | 123 | 18 |
| d | 409 | 199 | 210 | 18 |

Class A has **no baseline** — an absence, not a zero. Baseline and KSI family
sets are **not nested**: MP and PE are in every baseline and reached by no KSI;
PM is reached by KSIs and is in no baseline.

## Identifier namespaces

Every canonical id below is FedRAMP's own machine form, read off the `$defs`
of `docs/fedramp-consolidated-rules.schema.json`. URLs are the lowercase of
the canonical id, site-wide. See `docs/NOMENCLATURE.md` for the rules and
`/nomenclature` for the rendered vocabulary.

| Namespace | Named | Addressable | FedRAMP `$def` | Example canonical | Example slug |
|---|---|---|---|---|---|
| NIST 800-53 control | 419 | 209 | `control_id` | `ac-2.13` | `ac-2.13` |
| Control family | 19 | — | — (ours) | `AC` | `ac` |
| KSI indicator | 46 | 46 | `ksi_indicator_id` | `KSI-CNA-DFP` | `ksi-cna-dfp` |
| KSI theme | 10 | 10 | `ksi_theme_key` | `CNA` | `cna` |
| FRR requirement | 246 | 246 | `frr_requirement_id` | `AFC-CSO-EMR` | `afc-cso-emr` |
| FRR document | 17 | — | `frr_document_key` | `AFC` | `afc` |
| Certification class | 4 | 3 | `class_key` | `b` | `b` |
| ODP parameter | 19 | — | — (ours) | `ac-6.1_odp.2` | `ac-6.1_odp.2` |
| AWS evidence recipe | 49 | 49 | — (ours) | `iam-credential-report` | `iam-credential-report` |
| Affected party | 5 | 5 | — (ours) | `Providers` | `providers` |
| FRD term anchor | 75 | — | — (ours) | `fedramp-authorized` | `fedramp-authorized` |

**Named is not addressable.** An id can normalize cleanly and still have no
page: addressability is keyed to KSI edges, not to the id space.

### The control universe

| Set | Count |
|---|---|
| Reached by ≥1 KSI (`controlsById`) | 209 |
| In some Rev5 baseline (b∪c∪d) | 409 |
| Carrying `CTL` guidance | 79 |
| **Union — every control the dataset names** | **419** |

33 controls carry FedRAMP-authored guidance and ODP values but have no page, because addressability is keyed to KSI edges. Their guidance is reachable in `ctlGuidanceById`; their URL is not.

FedRAMP's schema constrains every id form except one: ODP parameter ids are typed `{"type":"string"}` upstream, so their format is ours to define. 19 distinct ids, 19 of which resolve to a control that exists.

## Export slices

- `data/derived/coverage.json` — Rev5 baseline coverage per certification class, with orphan controls.
- `data/derived/baseline.json` — Full Rev5 baseline enumeration per class: every control id with family, annual-assessment and KSI-coverage flags.
- `data/derived/checks.json` — Per-KSI collector scaffold: statement, terms, controls, classes in scope and the class vulnerability-response clock.
- `data/derived/aws-evidence.json` — AUTHORED overlay: AWS calls that collect evidence per KSI/control, with cadence, GovCloud notes and an automatable-honesty rating. Versioned separately from the dataset.
- `data/derived/automation-frontier.json` — AUTHORED overlay: per-control dispositions for KSI-reached controls no AWS recipe covers — automatable, partial, or honestly closed as narrative, each with a stated reason. Versioned separately from the dataset.
- `data/derived/evidence-plan.json` — The Evidence Plan: per class, authored AWS recipes grouped by KSI theme (densest first), the class clock, and the orphan/narrative register.
- `data/derived/obligations.json` — Every timeframed deadline, PAIN grid, notification and rollout date.
- `data/derived/evidence.json` — Every artifact the rules demand, by requirement and deduplicated by artifact.
- `data/derived/crosswalk.json` — Bidirectional KSI to NIST 800-53 control mapping.
- `data/derived/families.json` — KSI density per control family and theme.
- `data/derived/glossary.json` — FRD terms with the KSIs and rules that reference each.
- `data/derived/indicator-weight.json` — KSI indicators ranked by control footprint.
- `data/derived/readiness.json` — Per-class readiness pack: baseline, KSI coverage, artifacts and provider deadlines.
- `data/derived/roles.json` — Requirements, deadlines and documents grouped by the party they bind.
- `data/derived/search.json` — Flat list of every addressable entity, for the global search palette.
