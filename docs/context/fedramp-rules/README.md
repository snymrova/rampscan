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
| Upstream | `FedRAMP/rules` @ `58efbf3d8984` (2026-08-13) |
| Dataset version | `2026.07.14.01` — `info.version`, the same pin as the ramprules snapshot; no fourth pin exists because ramprules' `dataset_version` IS this version (SPEC §12.4 rule 1) |
| Fetched | 2026-09-11, `sha256 1357070…7e5ae8e` verified identical between `main` and the commit above |
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
