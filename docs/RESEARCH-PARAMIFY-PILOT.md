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

1. **Uniform invocation contract:** `script.sh <profile> <region> <output_dir> <output_csv>`. Each script emits a per-component JSON (`{"results": […]}`) into `output_dir` plus CSV rows appended to `output_csv`. ~~Exit code is the validation outcome.~~ **Corrected 2026-09-14 (§8.1): the exit code is the *collection* outcome.** A script exits 0 whenever it finished reading the account, including when what it read is non-compliant.
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

## 8. Re-read on 2026-09-14, for the cloud runner (`docs/PLAN-CLOUD-RUNNER.md`)

Re-cloned at `51de49c` (2026-06-04, "Add FedRAMP 2026 Consolidated Rules OSCAL profiles and catalogs"). Still 122 files, still no LICENSE. Nothing upstream changed since §1; what changed is the question being asked of it. The first read looked for shapes. This one looked at what the scripts actually do when run, because the runner plan proposes running recipes of this kind on a click.

### 8.1 Correction: the exit code is not a verdict, and our tree adapter treats it as one

§3.1 said "exit code is the validation outcome". It is not. Reading all 23 scripts:

- **Non-zero exit means the script could not read the account** — a usage error, a failed `list-*`/`describe-*` call, or (EKS) no cluster processed. Every script has exactly one class of `exit 1`, and it is that.
- **Zero exit means it finished reading.** `s3_encryption_status.sh` exits 0 at 0% encrypted buckets. `guard_duty.sh` prints "No GuardDuty detectors configured" and exits 0. `waf_DoS_rules.sh` exits 0 on "No Web ACLs found". The orchestrator's `FAILED (exit code N)` log records collection failures, not findings.
- **The assessed package holds no machine assertion at all.** In `8_29_25_…yaml` every one of the 140 evidence blocks has `scriptName: ""`, `validationRules: []`, `validatedBy: ""`. The verdict is `assessmentSteps[].status: PASS` (51 of 51) with a prose `result`, method `Examine` (34) or `Test` (17), and `assessmentStatus: "True"` (49) or `Partial` (2). §5.2's substring-matching critique was aimed at `schema.yaml`; the shipped package is weaker than that — the field is empty and a person read the artifacts.

`packages/cli/src/ingest.ts:157` does `passed: entry.exit_code === 0`, and SPEC §12.8 says the same ("exit code → the single assertion"). So a client who runs these scripts over an account with no GuardDuty and no encrypted bucket, scaffolds the tree exactly as `run_evidence_validations.sh` does, and hands it to `rampscan ingest`, receives a signed **`evidenced`** bundle per KSI. That is the `SECURITY.md` class — a check that reports `evidenced` without the evidence being there — introduced by trusting a convention this note misread. Filed as #147; the fix belongs before S3-1, which is the first time a real tree of this shape will be ingested.

The correct reading, which is also what `PLAN-CLOUD-RUNNER.md` §2 already says for recipes without structured assertions: **exit 0 proves collection**; the bytes then need either a structured assertion evaluated by the appliance, or a two-key sufficiency judgment, before anything is `evidenced`. Exit non-zero is a failed run, never a `violated` — the account was not seen.

### 8.2 The scripts through the runner's allowlist

Every AWS action across the 23 scripts is `describe-*`, `get-*`, or `list-*` **except** `aws eks update-kubeconfig` (writes `~/.kube/config` on the runner host, not the account) and one `aws sso login` (interactive). So the whole set is admissible under T1-1's allowlist as-is, with those two handled as runner-local setup rather than as recipe steps. Compared with the pinned ramprules overlay (49 recipes, one of which runs a shell on production hosts), this set is the safer of the two and the one written by people who actually ran it on a 7-day clock.

Two things the runner plan did not account for and now must:

1. **Kubernetes is a second axis.** Four scripts (`eks_*`, `kubectl_security.sh`) run `kubectl get/describe` inside the cluster. That needs cluster RBAC, an `aws-auth`/access-entry mapping for the runner's role, and a read-only `ClusterRole` — none of which an IAM policy generated from an action allowlist provides. T1 needs a `kubectl` allowlist (`get`, `describe` on named resource kinds) and T3-3 a cluster-side least-privilege check, or these four are `manual` in the first release.
2. **Parameters are fewer and simpler.** Their scripts take `<profile> <region>` and discover everything else. The 23 example literals in the ramprules overlay are avoidable by following this shape: enumerate, then describe each, rather than describing a named resource.

### 8.3 What to include in the app, and what not to

| Include | How | Phase |
|---|---|---|
| The `Evidence/<family>/<KSI>/` tree as an ingest input | Already done (`rampscan ingest <dir>`), **but** its verdict rule is wrong per §8.1 and must change before it meets a real tree | before S3-1 |
| The assessed package YAML as an ingest input | **Not done, and S3-1 needs it.** The repository contains no `Evidence/` tree output, only scripts and the package. Ingesting "a package that has already passed" means a `machine-readable-package` adapter: one `IngestSubmission` per (KSI × evidence), `assessmentStatus` as the assertion, `assessedBy` as `signer_identity`, `evidence_class: point-in-time` (they are screenshots and exports), artifacts by `reference` | S3-1 |
| Their 23 scripts' *shapes* as the reference for runner-executed recipes | Enumerate-then-describe; `{"results": […]}` + CSV; exit code = collected. Written by us, not copied | T1, T3 |
| `CR26/FedRAMP_CR26_catalog.json` as a third leg of the catalog cross-check | Unchanged from §4 | S2 / R |
| `security-inbox/` | A Gmail→Slack automation for FRR-FSI (security inbox deadlines). It is process evidence, not a scan; a candidate `attestation` statement template, nothing more | none |

Not to include: any byte of a script or fixture (no license); their exit-code convention as a verdict (§8.1); their `validationRules` model as an assertion language (§5.2, and the shipped package does not use it either).

### 8.4 Positioning, restated with the 8/29 numbers

The assessed package is **51 KSIs, 140 evidence blocks, 394 artifacts (86 JSON, 45 `.sh`, 47 screenshots/PNG), 0 machine assertions, 51 empty per-KSI signatures and 1 package-level bare SHA.** Coalfire's methodology (completeness, accuracy, timeliness, exceptions) was applied by reading. That is what an authorized 20x package looked like in Phase One, and it is the baseline S3-2's question is asked against: rampscan's register would have 51 rows of `G5`-shaped artifacts each waiting on a sufficiency judgment, and zero automated methods until someone runs the scripts under a contract that judges the bytes.

---

## Session log

- **2026-09-14** — Re-read at `51de49c` for `PLAN-CLOUD-RUNNER.md`. §3.1 corrected: exit 0 is collection, not compliance (`s3_encryption_status.sh`, `guard_duty.sh`, `waf_DoS_rules.sh` all exit 0 on a non-compliant or empty account). That convention is what `ingest.ts:157` and SPEC §12.8 encode, so the tree adapter signs `evidenced` for a violating account of this shape — filed as #147 under the `SECURITY.md` class, fix owed before S3-1. Also found: S3-1 needs a package-YAML adapter, not the tree adapter, because the repository ships no tree output; and four scripts need `kubectl`, an axis the runner plan lacked. §8 added; nothing earlier rewritten except the strikethrough in §3.1.
- **2026-09-11** — Repository examined (shallow clone at `main`); note drafted and filed as reference for Q0 (schema comparator), Q1 (dual-source loader), Q4 (ingestion contract shape), and the §7.5 positioning rewrite.
