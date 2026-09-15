# rampscan — the gap register for a package that has already passed

**Status:** plan S3-1 (`docs/PLAN-SOUNDNESS.md`, issue #137) — the deliverable S3-2 sends. Reference, not a scorecard.
**Date:** 2026-09-15, at the rampscan commit that landed the package adapter.
**Input:** `paramify/fedramp-20x-pilot` at `51de49c`, `machine-readable-package/8_29_25_paramify_coalfire_20x_machine_readable.yaml` — the FedRAMP 20x Phase One package Paramify submitted and Coalfire assessed (`recommendation: Authorize`, `date: 7/10/25` as the file states it). The only publicly assessed, 3PAO-signed 20x package this project knows of (`docs/RESEARCH-PARAMIFY-PILOT.md`).
**Licence posture, unchanged:** that repository has no LICENSE file. This document consumes the package's *outputs* — ids, counts, statuses, artifact names — and vendors nothing: no implementation prose, no script, no fixture. The package file itself is not in this repository; the commands below read it from a local clone.

---

## 1. How the register was produced

```
$ pnpm rampscan ingest <clone>/machine-readable-package/8_29_25_paramify_coalfire_20x_machine_readable.yaml \
    --repo paramify-cloud \
    --crosswalk recipes/crosswalks/ksi-phase-one-to-2026.07.14.01.json \
    --cadence monthly \
    --ledger <scratch>/ledger --keys <scratch>/keys
$ pnpm rampscan frontier --ledger <scratch>/ledger                       # class b, with rampscan's recipes
$ pnpm rampscan frontier --ledger <scratch>/ledger --recipes <empty dir>  # the package alone
$ pnpm rampscan frontier --ledger <scratch>/ledger --class c             # what-if
$ pnpm rampscan frontier --ledger <scratch>/ledger --class d             # what-if
```

Three things about that invocation are declared by the operator and not read from the package, and each is a place Paramify may correct this document:

- **`--cadence monthly`.** The package schema has no cadence field, and the appliance never guesses one. `monthly` is read from the pilot's own trust-center page, which states a monthly ConMon status cadence. It is recorded on every bundle as a declaration and moves no meter.
- **`--crosswalk`.** The package names its KSIs in the Phase One numbering (`CNA-01` … `INR-03`, 51 indicators); the 2026 Consolidated Rules this register prices against (`2026.07.14.01`) carry 46 mnemonic KSIs (`KSI-CNA-RNT` …). Nothing upstream publishes the mapping — family acronyms, numbering and scope all moved (RESEARCH-PARAMIFY-PILOT §4) — so it is a reviewed artifact in this repository with a stated basis per row, and the rows marked *judgment* there are the ones to argue with. §2 gives its result.
- **`--repo paramify-cloud`.** The register's row key; the offering the package names.

What the adapter signs, and what it refuses to (SPEC §12.8): every evidence in the package becomes a signed, offline-verifiable ledger bundle **`unevidenced`, `point-in-time`, and not an automated method**. The package carries a person's reading — `assessmentStatus`, `assessmentSteps[].status: PASS` — and `validationRules: []` on all 140 evidences; there is no machine assertion in it for the appliance to evaluate, so it signs the handoff (these artifacts, named by this assessor, at these dates) and no verdict. The 3PAO's `True` is Coalfire's to sign, on the attestation path, if they want it in a ledger.

The ingest log, verbatim on the lines that matter:

```
package: Paramify Cloud assessed by Coalfire: Jorden Foster — 51 validations (49 True, 2 Partial), 140 evidences (80 marked automated by the package), 394 artifacts named by reference
package: no assertion is read from it — every bundle is unevidenced, point-in-time, and not an automated method; the assessor's reading is the package's, not a verdict this appliance signs
package: load-balancer-encryption-status#KSI-SVC-SIN cited by SVC-02 and SVC-03 — one record, kept once
package: appendix-q-paramify-encryption-implementation-status#KSI-SVC-SIN cited by SVC-02 and SVC-03 — one record, kept once
package: okta-authenticators#KSI-IAM-APM cited by IAM-01 and IAM-02 — one record, kept once
package: change-management-gitlab-cloudops-self-hosted#KSI-CMT-RVP cited by CMT-04 and CMT-05 — one record, kept once
package: change-management-gitlab-cloudops-self-hosted#KSI-SCR-MIT cited by PIY-07 and TPR-03 — one record, kept once
package: leveraged-authorizations#KSI-SCR-MIT cited by TPR-01 and TPR-03 — one record, kept once
…
ingest: 116 bundle(s) appended, 0 unchanged, 20 skipped — no AWS call was executed by this appliance
```

116 = 140 evidences − 20 under retired indicators − 6 cited twice under merged indicators + 2 (one indicator, PIY-06, lands on two 2026 KSIs, so its one evidence is two methods).

## 2. Where 51 Phase One validations land in the 2026 catalog

| | count | which |
|---|---|---|
| Phase One indicators with a 2026 successor | 43 | 42 one-to-one; PIY-06 → KSI-PIY-RES + KSI-PIY-RIS |
| …of which merged, two or three into one | 9 → 4 | SVC-02 + SVC-03 → KSI-SVC-SIN; IAM-01 + IAM-02 → KSI-IAM-APM; CMT-04 + CMT-05 → KSI-CMT-RVP; TPR-01 + TPR-03 + PIY-07 → KSI-SCR-MIT |
| Phase One indicators with **no** 2026 KSI | 8 | SVC-07, MLA-03, MLA-04, MLA-06 (vulnerability handling and patching — now FRR-VDR requirements, not KSIs); PIY-02 (policy documents); PIY-05 (assessment-method documentation — FRR-IVV); TPR-02 (third-party authorization — an FRR matter); INR-01 (incident reporting — FRR-IEC) |
| 2026 KSIs the package reaches | 38 of 46 | |
| 2026 KSIs **obliged at class b** with nothing in the package | 3 | KSI-IAM-AAM (automating account management), KSI-INR-RIR (reviewing incident response procedures), KSI-MLA-LET (logging event types) |
| 2026 KSIs optional at class b, nothing in the package | 5 | KSI-CNA-EIS, KSI-MLA-ALA, KSI-SVC-PRR, KSI-SVC-RUD, KSI-SVC-VCM |

Twenty of the 140 evidences sat under the eight retired indicators and are skipped, named in the log, and in no ledger. That is not a finding against them — their subjects are still obligations, they are just no longer priced as KSIs at this pin. Four of the placements are judgments rather than restatements (SVC-01 → EIS, IAM-05 → ELP, CMT-05 → RVP, PIY-07 and TPR-01 → SCR-MIT); each says so in the crosswalk file.

## 3. The register, class b — the package alone

`pnpm rampscan frontier --ledger … --recipes <empty dir>`: what the assessed package evidences under the 2026 rules with no rampscan recipe in the picture. *Methods* is the count of ingested evidences on the row; every one is non-automated, so the `automated/floor` cell reads `0/1` on every row that has any.

| KSI | Phase One sources | methods | worst gap |
|---|---|---|---|
| KSI-CED-RAT | CED-01, CED-02 | 2 | G2 |
| KSI-CMT-LMC | CMT-01 | 4 | G2 |
| KSI-CMT-RMV | CMT-02 | 6 | G2 |
| KSI-CMT-RVP | CMT-04, CMT-05 | 2 | G2 |
| KSI-CMT-VTD | CMT-03 | 2 | G2 |
| KSI-CNA-DFP | CNA-04 | 4 | G2 |
| KSI-CNA-EIS | — | 0 | G1 *(optional at b)* |
| KSI-CNA-IBP | CNA-07 | 1 | G2 |
| KSI-CNA-MAT | CNA-02 | 4 | G2 |
| KSI-CNA-OFA | CNA-06 | 3 | G2 |
| KSI-CNA-RNT | CNA-01 | 1 | G2 |
| KSI-CNA-RVP | CNA-05 | 3 | G2 |
| KSI-CNA-ULN | CNA-03 | 4 | G2 |
| KSI-IAM-AAM | — | 0 | **G1** |
| KSI-IAM-APM | IAM-01, IAM-02 | 1 | G2 |
| KSI-IAM-ELP | IAM-05 | 4 | G2 |
| KSI-IAM-JIT | IAM-04 | 4 | G2 |
| KSI-IAM-SNU | IAM-03 | 5 | G2 |
| KSI-IAM-SUS | IAM-06 | 1 | G2 |
| KSI-INR-AAR | INR-03 | 1 | G2 |
| KSI-INR-RIR | — | 0 | **G1** |
| KSI-INR-RPI | INR-02 | 4 | G2 |
| KSI-MLA-ALA | — | 0 | G1 *(optional at b)* |
| KSI-MLA-EVC | MLA-05 | 1 | G2 |
| KSI-MLA-LET | — | 0 | **G1** |
| KSI-MLA-OSM | MLA-01 | 1 | G2 |
| KSI-MLA-RVL | MLA-02 | 3 | G2 |
| KSI-PIY-GIV | PIY-01 | 6 | G2 |
| KSI-PIY-RES | PIY-06 | 2 | G2 |
| KSI-PIY-RIS | PIY-06 | 2 | G2 |
| KSI-PIY-RSD | PIY-04 | 1 | G2 |
| KSI-PIY-RVD | PIY-03 | 1 | G2 |
| KSI-RPL-ABO | RPL-03 | 2 | G2 |
| KSI-RPL-ARP | RPL-02 | 4 | G2 |
| KSI-RPL-RRO | RPL-01 | 3 | G2 |
| KSI-RPL-TRC | RPL-04 | 2 | G2 |
| KSI-SCR-MIT | PIY-07, TPR-01, TPR-03 | 5 | G2 |
| KSI-SCR-MON | TPR-04 | 1 | G2 |
| KSI-SVC-ACM | SVC-04 | 4 | G2 |
| KSI-SVC-ASM | SVC-06 | 2 | G2 |
| KSI-SVC-EIS | SVC-01 | 4 | G2 |
| KSI-SVC-PRR | — | 0 | G1 *(optional at b)* |
| KSI-SVC-RUD | — | 0 | G1 *(optional at b)* |
| KSI-SVC-SIN | SVC-02, SVC-03 | 11 | G2 |
| KSI-SVC-VCM | — | 0 | G1 *(optional at b)* |
| KSI-SVC-VRI | SVC-05 | 5 | G2 |

The command's own summary lines for that run:

```
  floor met on 0 of 41 KSIs · at least one automated method on 0 · no method on 3
  covering all 41 — a row that says "nothing evidences this from a pipeline" is a row
  5 optional at class b, outside every meter above — KSI-CNA-EIS, KSI-MLA-ALA, KSI-SVC-PRR, KSI-SVC-RUD, KSI-SVC-VCM (0 evidenced anyway)
  clocks: 0 of 41 KSIs hold every method inside its owed window — VDR-TFR-MVX (MUST)
  history: no floor at class b — FRC-CSX-MOT (SHOULD, unquantified)
  artifacts: 0 of 41 KSIs hold all five owed artifacts — default_artifacts.KSI (2, 5 computed · 1, 3, 4 two-key judged)
  evidence class: 38 of 41 KSIs hold point-in-time evidence, rejectable when standalone — FRR-PVA-AA-06 (pipeline mints assert process-generated)
```

Read as gaps, 41 obliged rows: **3 × G1** (nothing in the package reaches the KSI), **38 × G2** (the KSI has methods — 116 in all, 1 to 11 per row — and none is automated, so the class-b floor of ≥1 automated method, `FRC-CSX-VVK` SHOULD, is met on none). Behind every G2 sit the next three arms, which the chain only reaches after G2 clears: every method is outside its `VDR-TFR-NMV` window (the freshest evidence is dated 2025-07; the register was run 2026-09), none of the five owed artifacts exists, and 38 of 41 rows hold point-in-time evidence with nothing process-generated beside it.

## 4. The same ledger, with rampscan's recipes in the register

`pnpm rampscan frontier --ledger …` without `--recipes` derives methods from the twenty commit-plane recipes as well. **No scan of Paramify's code ran** — those rows say what a pipeline over a checkout *would* add, and their evidence column is empty:

```
  floor met on 13 of 41 KSIs · at least one automated method on 13 · no method on 3
```

The 13 are the same 13 the empty-ledger register prints, and each of those rows moves from G2 to **G3 freshness** — the automated floor is met by a recipe that has never run here, and the package's non-automated methods beside it are stale. The register renders them as `1/1 ok +2` and the like: automated over floor, plus the non-automated methods the row holds (that `+N` is new with this item; a register with no such method prints exactly as before).

**What-if at higher classes**, same ledger, recipes included: class c (floor ≥2 automated, MUST) — floor met on 6 of 46, history ≥6 mo on 38 of 46; class d (≥4, MUST) — floor met on 3 of 46, history ≥18 mo on 0 of 46. The class-c history figure is generous and is called out in §6.

## 5. What this says, in the S3-2 framing

An authorized Phase One package, read under the 2026 rules, is **116 human-read artifacts across 38 KSIs, 0 machine-validated methods, 0 fresh, 0 of the five owed artifacts, and 3 obliged KSIs with nothing at all** — with 8 of its 51 validations addressed to obligations that are no longer KSIs. None of that is a mark against the assessment; it is what "assessed" meant in Phase One (RESEARCH-PARAMIFY-PILOT §8.4: 0 machine assertions, 51 empty per-KSI signatures, one package-level bare hash) put next to what `FRC-CSX-VVK`, `VDR-TFR-MVX`/`NMV`, `FRC-CSX-MOT` and `default_artifacts.KSI` now price.

The question S3-2 asks, unchanged: *is the gap register the thing you are missing, or is the SDR?* The register above is the first one ever computed over a real authorized package, and it is what a class-b certification would be measured against on the day the 2026 rules apply.

## 6. Caveats, all of them the operator's

1. **The crosswalk is a reading.** 42 rows restate; 4 are judgments and say so; 8 retirements cite the FRR family the subject moved to. A different reviewer moves a handful of methods between rows and changes nothing in §5.
2. **`automated: false` on every method is the adapter's rule, not the package's field.** The package marks 80 of 140 evidences `automated: Yes` — a script produced them. rampscan counts a method as automated when a machine evaluated an assertion over what was collected, and the package carries no assertion (`validationRules: []`, all 140). Paramify's scripts under a contract that judges the bytes — the tree adapter with structured assertions, or the cloud runner's — would make many of these rows `1/1 ok`.
3. **The history meter reads the earliest instant** a KSI's chains reach back to, so one 2025 snapshot satisfies class c's 6-month floor on 38 rows. A single stale capture is not "persistent validation", and this run is the first to make that reading visible; filed as #159 rather than fixed here.
4. **The 3PAO's `True` is not in the ledger.** Deliberately (§1). If the assessor wants their reading to count, the attestation path signs it under their key, `automated: false`, on the non-machine clock — which is exactly where a human reading belongs.
5. **Nothing here executed against Paramify's account or code.** The ledger holds the package's bytes and the handoff; the appliance vouches for neither the account nor the artifacts the package names.

---

## Session log

- **2026-09-15** — Produced with the package adapter (S3-1). The failing test first at `71e45a9`: `rampscan ingest` read the package as JSON (`Unexpected token '#'`). Then the adapter, the crosswalk, and this register. Next: S3-2 sends it.
