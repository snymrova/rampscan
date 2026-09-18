# FedRAMP/rules — the canonical upstream (Path B)

`fedramp-consolidated-rules.json` vendored verbatim from
[github.com/FedRAMP/rules](https://github.com/FedRAMP/rules), the file that
repository names as its source of truth. This is the SECOND leg of the
dual-source catalog contract (SPEC §12.4): the ramprules snapshot next door is
a *derivation* of this file, and the loader proves the two agree at the pin
rather than trusting either alone.

## Provenance

| | |
| --- | --- |
| Upstream | `FedRAMP/rules` @ `58487bda77d7` (2026-09-13) |
| Dataset version | `2026.09.13.02` — `info.version`, the same pin as the ramprules snapshot; no fourth pin exists because ramprules' `dataset_version` IS this version (SPEC §12.4 rule 1) |
| Fetched | 2026-09-17, `sha256 64915d8…4c8fc8` verified identical between `main` and the commit above |
| License | U.S. Government work; upstream publishes it as the canonical machine-readable rules with no license file — cite the repo, not this copy |

## What the loader reads from it (and only it can define)

Owed facts, per SPEC §12.4 rule 2 — on EITHER path these are defined by this
file alone:

- the 46 KSIs across 10 themes (`KSI`): ids, names, statements, controls crosswalk
- the five KSI default artifacts (`info.default_artifacts.KSI`)
- method-count floors per class (`FRR.FRC` → `FRC-CSX-VVK`, prose in `varies_by_class`)
- history floors per class (`FRC-CSX-MOT`, prose)
- MVX validation windows per class (`FRR.VDR` → `VDR-TFR-MVX`, structured `timeframe_num`/`timeframe_type`; **no class-d entry** — SPEC §11 open question 6)
- the non-machine window (`VDR-TFR-NMV`, prose, 3 months)

Refreshing this snapshot is a re-pin — a reviewed change, never a side effect
(`packages/dataset/src/pins.ts` says why). Refresh both legs together or the
equivalence test will say so for you.

## What the 2026.07.14.01 → 2026.09.13.02 re-pin changed

Nothing in the list above. Every owed fact is byte-identical across the two
versions: the 46 KSIs with their statements and controls, the five default
artifacts, the floors 1/2/4, the history floors 6/18 months, the MVX windows
1 month / 7 days / 3 days with still no class-d entry, and the 3-month
non-machine window. Of roughly 250 changed rules, 242 changed only by dropping
"Provider" and "Agency" from their `terms` list — upstream added an
`ignore_in_terms` mechanism for words common enough to be noise. The rest:
five rules gained structured `timeframe_num_min`/`timeframe_num_max` fields,
`CCM-OCR-AVL` gained "(if applicable)", `IEC-CSO-OIR` lost a doubled "the",
two `reference_url`s were corrected, and the file now defines MUST, SHOULD,
MAY, MUST NOT and SHOULD NOT itself as five `FRD` force definitions. The NIST
control set did not move — all 1014 control titles are identical.
