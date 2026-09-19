# R3 — historical metrics in the Security Decision Record

**Status:** adopted 2026-09-18, when the owner unpaused R3 after R2 merged. Issues #106 (R3.1), #107 (R3.2) and #108 (R3.3), under `docs/PLAN-ARTIFACT-PLANE.md` §5-R3.
**Reads against:** rules 2026.09.13.02 (`SDR-CSX-KMT`, `FRC-CSX-MOT`, `FRD-PER`), the SDR schema pinned in R2 (1.1.1), and FedRAMP/schemas#10 (open, unanswered by FedRAMP on 2026-09-18).

---

## 1. What the rules ask for

`SDR-CSX-KMT` asks for historical metrics in the Security Decision Record, for each applicable KSI:

| Class | Force | What |
|---|---|---|
| a | MAY | historical metrics, unspecified |
| b | MUST | a summary of each metric over the past 30 days; a summary up to the past year (where available) |
| c | MUST | the above, plus all daily metric data up to the past year (where available) |
| d | MUST | "significantly supersede" the lower classes, with specifics set in the Phase 4 pilot |

`FRC-CSX-MOT` asks for "historical metrics including status from persistent validation" over at least the past 6 months at class c and 18 months at class d. It is SHOULD at b and MAY at a.

Neither rule defines a *metric*. That is question 3 on FedRAMP/schemas#10 ("Does 'metrics' mean numeric values, or does an evaluated KSI status over time also satisfy it?"). The schema has no field for any of it (#10 again, and `PLAN-SDR.md` §2 defect 2).

## 2. The decisions

**H1 — A KSI's metric for a day is its computed status, plus the counts it was computed from.** The status is the one D6 already computes for `ksiImplementationStatus` (`ksiStatus` in `sdr-build.ts`), and the counts are its published basis: methods in scope, methods passing, violated, stale, automated methods with evidence, and artifacts present. `FRC-CSX-MOT` itself names "status from persistent validation", so status is the one metric the rules name. The counts come with it so the status can be re-derived. A number rampscan invented for this purpose would be a claim with no rule behind it. This answers #10's question 3 by doing, and the record says so.

**H2 — Each day is refolded, never accumulated.** The metric for UTC day *D* is `ksiStatus` over the projection folded as of *D*'s last millisecond (`foldEntries(entries, end(D), { …, asOf: end(D) })`), which is what `sdr --as-of end(D)` would have said. Nothing is stored in a side table. Two runs over the same ledger at the same instant produce identical bytes (the R3 exit gate). The cost is one fold per day, measured in §4.

**H3 — A day the ledger does not cover is absent, never zero.** The series starts on the UTC day of the offering's first evidence statement in the ledger. Days before it are counted as `daysAbsent` in each summary, and no status is written for them. A day after it with no new scan is **covered**: the fold still knows the status, which is usually older evidence going stale, and that is a real status. Only completed UTC days are in the series. The day containing the fold instant is not, because its status is the document's own current row.

**H4 — Which windows at which class.** The 30-day and one-year summaries are written at every class (MAY at a costs nothing and is honest). The daily data is written at class c and d. The series reaches back 365 days, or `FRC-CSX-MOT`'s floor where that is longer: 18 months (548 days) at class d. That is where the two rules meet.

**H5 — The daily data is lossless run-length.** Each KSI's daily data is written as runs of consecutive days with identical metrics (`{ from, to, days, status, counts }`), not one object per day. A year of a KSI that sat in one state is one run. The runs expand to exactly one entry per covered day, and a test holds that. This keeps a class-c record at kilobytes, not megabytes.

**H6 — Carriage under `x-rampscan.metrics`, with the divergence stated in the record.** The schema has no conformant place (FedRAMP/schemas#10). The metrics sit in the extension block with a `divergence` sentence citing #10, and the Markdown half renders the summaries as a table per KSI. `conformance`'s `SDR-CSX-KMT` verdict stays `unmet`, because it cannot be met in-schema. It now says what is carried outside the schema and names anything missing, such as the daily data at class c.

**H7 — The summary of each metric.** The status gets days per status value, plus the first and last status in the window. Each count gets its minimum, maximum and value on the last covered day. `daysInWindow`, `daysCovered` and `daysAbsent` are always stated, so a year with three weeks of history reads as three weeks.

## 3. The build

| Item | Issue | What |
|---|---|---|
| R3.1 | #106 | `sdr-metrics.ts`: the day fold (H2), coverage (H3), the 30-day and one-year summaries (H7). Pure over the entries and fold options. Tests: determinism, absent-before-coverage, a status change on the day it happens, a stale-by-time change with no new statement. |
| R3.2 | #107 | The daily series at c and d (H4) as runs (H5), with the reach-back tied to `FRC-CSX-MOT` at d. Tests: runs expand to exactly the covered days; the class-d reach-back is 548 days. |
| R3.3 | #108 | Carriage (H6): `sdr-build` writes `x-rampscan.metrics` and drops the "lands in R3" problem; `sdr-render` renders the summaries; `sdr-rules` reports what is carried; `main.ts` wires the ledger entries in. The golden file is regenerated. |

Stacked, coding straight through, as R2 was.

## 4. Cost

One fold per day, and a fold is O(ledger) (#142). It was measured on a synthetic ledger (below). If a class-c record over a year of daily scans takes minutes, the fix is a prefix fold over pre-sorted entries, not a side table. H2 is the exit gate, and a cache would put it at risk.

**Measured 2026-09-18** on a synthetic ledger of 20 recipes scanned daily for a year (7,300 statements, all 46 KSIs, class c windows): **18.4 s** for the 365-day series, about 50 ms a fold. The summaries for 46 KSIs are 50 KB. That is acceptable for a command that writes a certification document, and it is not acceptable for the console. Nothing here is on a request path, so no optimization is taken now. The first one, if needed, is to sort once and fold prefixes. The fold's own per-call work is #142's subject.

## 5. Session log

- **2026-09-18** — Written and adopted. H1–H7 were taken without the owner, following the owner's standing instruction to code straight through. H1 is the call worth a second look, because it answers #10's open question with our reading rather than FedRAMP's.
