# rampscan — research note: the Paramify FedRAMP 20x pilot repository

**Status:** reference material for the KSI pivot (phases Q0–Q5, `docs/PLAN-KSI-PIVOT.md`). This note records what `github.com/paramify/fedramp-20x-pilot` contains, what it validates about the pivot's design, and what it must not be used for.
**Date:** 2026-09-11
**Source examined:** `paramify/fedramp-20x-pilot` at `main`, shallow clone, 122 files. All file paths below are relative to that repository.
**License caveat, up front:** the repository has **no LICENSE file**. Everything in it is all-rights-reserved reference material. We may learn from its shapes and consume outputs produced by clients running their own copies; we may not vendor a line of its scripts or fixture YAML into rampscan. Where a compatible fixture is wanted, we write our own from the published schema.

---

## 1. What the repository is

Paramify's FedRAMP 20x Phase One Pilot final submission — the public artifact of an actual assessed, 3PAO-signed (Coalfire) 20x package, plus the tooling that produced it:

| Path | Contents |
|---|---|
| `evidence/` | 23 bash evidence-collection scripts (AWS CLI + jq), an orchestrator (`run_evidence_validations.sh`), a scaffolder (`generate_directories.sh`) |
| `machine-readable-package/` | `schema.yaml`; two assessed submissions (`7_10_25_…` and `8_29_25_paramify_coalfire_20x_machine_readable.yaml`); two synthetic fixtures (`acme.yaml`, `lorem-ipsum.yaml`) |
| `CR26/` | `FedRAMP_CR26_catalog.json` — an OSCAL serialization of the CR26 catalog (groups `FRR` + `KSI`), with 20x and rev5 profiles and an XLSX converter |
| `FR_docs_to_OSCAL/` | `process_frmr_to_oscal.py` — converts FedRAMP's raw `FRMR.documentation.json` (from `github.com/FedRAMP/docs`) into OSCAL catalogs/profiles; handles both the legacy multi-file and the ≥v0.9.0-beta consolidated formats |
| `OSCAL/` | The converter's output, one directory per catalog version: `v0.9.0-beta` … `v0.9.43-beta`, `v25.12A` |
| `KSI_comparison/` | A diff tool between KSI catalog versions (`build_comparison_v0943_vs_v2512.py`) plus rendered comparisons |
| `html-dashboard/` | A single-file offline HTML viewer (`js-yaml` from CDN) that loads a package YAML client-side |
| `fedramp_20x_trust_center.md` | Their actual Phase One trust-center page |
| Root PDF | The Coalfire validated-assessment report |

---

## 2. The headline: the assessed package is already KSI-inverted

The `schema.yaml` hierarchy of the submitted, authorized package is:

```
Package → Assessment → KSIs[] → Validations[] → Evidences[] → Artifacts[]
```

This is the pivot's inversion (`PLAN-KSI-PIVOT.md` §1), observed in the wild in an assessed artifact rather than proposed on paper:

- **The KSI is the row; the validation is the unit.** No controls anywhere in the package. Controls appear only in their catalog crosswalk tooling — annotation, exactly where the pivot demotes them.
- **A validation belongs to exactly one KSI**, and evidence hangs off the validation, never off the KSI directly. This independently confirms the plan's §1.1 choice **(b)** — method = (source × KSI) pair, one KSI per method.
- **`automated: True|False` is a per-evidence field** — the `FRC-CSX-VVK` numerator flag, present in the field-tested shape.
- **Provenance fields per evidence:** `instructions`, `commands`, `scriptName`, `validationRules` (rule id + `textValue`), `validatedBy`, `validateDate`. This is a field-tested *minimum* for "what the assessor pulls on"; the `ValidationMethod` provenance block locked in Q0 should be a superset.
- **Artifacts per evidence:** `name`, `reference` (file), `outputResults` (inline script output), `effectiveDate` — a partial precedent for the five-artifacts modeling in Q3 (G5), though see §5: nothing in their tooling counts artifacts against a floor.

**Use in Q0:** cite `machine-readable-package/schema.yaml` in the spec amendment as the assessed-in-the-wild comparator for the `ValidationMethod` shape.

---

## 3. The evidence scripts: the de facto shape of client-run AWS recipes (Q4)

The 23 scripts in `evidence/` are a live specimen of exactly what the Q4 ingestion contract anticipates — "ramprules' AWS recipes remain the client's to run; their signed results become ledger citizens." Observed conventions:

1. **Uniform invocation contract:** `script.sh <profile> <region> <output_dir> <output_csv>`. Each script emits a per-component JSON (`{"results": […]}`) into `output_dir` plus CSV rows appended to `output_csv`. Exit code is the validation outcome.
2. **Directory convention** (from `generate_directories.sh` + `run_evidence_validations.sh`): `Evidence/<family>/<KSI-ID>/<KSI-ID>.{sh,json,csv}`, orchestrated per family or per KSI ID.
3. **Failure logging:** the orchestrator writes per-KSI failure records (KSI ID, timestamp, exit code, captured output) as txt, JSON, and CSV under `logs/`. This maps directly onto G13 — a validation flip is already a structured, timestamped record in their world; ours additionally makes it a vulnerability-shaped ledger event (`VDR-CSO-FAV`).
4. **Coverage spread:** WAF/DoS, encryption status (S3/RDS/EBS/LB/SSL), IAM (users/roles/policies/Identity Center), EKS (inventory, least-privilege, segmentation), GuardDuty, AWS Config (monitoring + conformance packs, including the FedRAMP Low operational-best-practices pack), KMS rotation, drift (`detect_new_aws_resource.sh`), and two training scripts (the acts-on-people edge — evidence that even they reach for scripts where the true source is HR records).

**Use in Q4:** the ingestion contract should be able to consume a bundle shaped like this ecosystem — an adapter that walks an `Evidence/` tree (or the package YAML's `Evidences` blocks) and appends each result as a `source: aws-ingested` method carrying `scriptName`/`commands`-grade provenance meets clients where they already are. The synthetic ingestion fixture for the Q4 exit gate should mirror these output shapes (JSON-results-array + CSV + exit code) — written by us, not copied (license caveat).

---

## 4. Catalog drift, demonstrated (ground rules 3 and 4)

Two findings, one per ground rule:

**Dual-source is practical (ground rule 3).** `FR_docs_to_OSCAL/process_frmr_to_oscal.py` reads FedRAMP's raw `FRMR.documentation.json` directly from `github.com/FedRAMP/docs` and has already absorbed the format break between the legacy multi-file layout and the consolidated ≥v0.9.0-beta layout. Read it before writing the Q1 dual-source loader — the parsing edge cases are pre-paid. Additionally, `CR26/FedRAMP_CR26_catalog.json` is an independent OSCAL serialization of the same CR26 rules our checkout pins from `fedramp-consolidated-rules.json` — a cheap third leg for the Q1 test that both source paths yield the same 46 KSIs at the pin.

**Pin bumps across a catalog major are not mechanical renames (ground rule 4).** Their own repo carries the drift internally: `generate_directories.sh` still scaffolds the *old* pilot catalog — 9 families, IDs like `KSI-CNA-1`, family acronyms `KSI-SC`, `KSI-CM`, `KSI-3IR` — while their newer tooling uses the current three-letter forms (`SVC`, `CMT`, `PIY`, `SCR`, `CED`, `RPL`, `INR`, `AFR`) and two-digit numbering (`CNA-01`). Family acronyms *and* numbering changed between versions, and `KSI_comparison/build_comparison_v0943_vs_v2512.py` exists because matching across versions required fuzzy prose matching plus hand-maintained cohort aliases (`SCR` → `TPR`, `FRR.SCG` → `RSC`, …). Implication: when RFC-0033/Class D moves the catalog mid-plan, budget for a reviewed crosswalk commit, not a rename.

---

## 5. Where rampscan is strictly stronger — positioning ammunition

Three observations, each citable when the README's positioning sentence is rewritten (plan §7.5):

1. **Signatures.** The package's `digitalSignature` fields are bare SHA strings with no stated key, chain, or verification path — and in the assessed 8/29/2025 submission the per-validation signatures are literally `""` (empty). An authorized package shipped with empty signature fields. rampscan's cosign-signed, anchored, append-only ledger with offline `verify` is a categorical difference, not an increment.
2. **Assertions.** Their `validationRules` model is substring matching — e.g. the WAF evidence passes if `RateBasedStatement` appears in the output file (`schema.yaml`; `waf_DoS_rules.sh`). That is a green that fails `FRR-PVA-AA-06` interrogation: the string can be present in a rule that doesn't block, in the wrong scope, on the wrong ACL. Structured assertions plus the assessor-interrogation view are the answer to precisely this weakness; the WAF script is the citable worked example.
3. **No gap computation.** The package is a Phase One snapshot: one implementation per validation, status `True|False|Partial`, no method-count floors, no freshness windows, no history meters. Nothing in the repository computes what CR26 prices — `FRC-CSX-VVK` floors, `VDR-TFR-MVX` windows, `FRC-CSX-MOT` history. The gap *engine* remains uncontested territory; this repo is evidence plumbing plus a snapshot report.

---

## 6. Secondary reference material

- **Q5 / exports:** the package YAML is the only publicly assessed 20x machine-readable package we know of — a second conformance target alongside FedRAMP/schemas JSON, with a viewer ecosystem already keyed to it (`html-dashboard/`).
- **Deferred G11 / trust center:** their dashboard is a static single file over the package YAML — proof that a trust-center-shaped surface can be an *export artifact* rather than a serving product, which is how plan §7.2 hoped to defer it. `fedramp_20x_trust_center.md` shows what a Phase One trust-center page actually contained (POCs, package links, conmon cadence, AI-use statement) — the checklist for whenever G11 is un-deferred.
- **Assessor workflow:** the Coalfire remarks in the 8/29 package describe their methodology as completeness / accuracy / timeliness / exceptions, with per-evidence `validatedBy`/`validateDate` — corroboration for routing artifact-sufficiency judgments through signed two-key events (Q3) rather than checkboxes.

---

## 7. What this repository must not be used for

1. **No code or fixture reuse** — no license (see header). Shapes yes, bytes no.
2. **No owed-side numbers.** It is a Phase One artifact: old catalog, Low impact, pre-floors. Every owed number continues to come from our pinned rules JSON, never from this repo's serializations (the CR26 folder is a cross-check, not a source).
3. **Not a model for assertion strength or signing.** §5 is the reason it exists in our references.

---

## Session log

- **2026-09-11** — Repository examined (shallow clone at `main`); note drafted and filed as reference for Q0 (schema comparator), Q1 (dual-source loader), Q4 (ingestion contract shape), and the §7.5 positioning rewrite.
