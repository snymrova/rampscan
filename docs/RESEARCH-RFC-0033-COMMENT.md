# RFC-0033 comment — draft for filing (#72, S3-3)

**Status:** draft, 2026-09-16, at `main` = `09d5b42`. Not filed.
**Where it goes:** [FedRAMP/community #170](https://github.com/FedRAMP/community/discussions/170), the formal comment thread (opened 2026-09-09, closes **2026-10-09**, two comments so far; FedRAMP does not reply there). Not #172, the informal thread, and not a new thread — `docs/RESEARCH-S3-2-OUTREACH.md` §1 keeps the RFC channel separate from the S3-2 sends.
**When:** early. Pete's note on the RFC asks for it, and the full Class D requirements RFC lands 2026-10-14, five days after this one closes — anything filed here that FedRAMP intends to act on has to be in hand before that draft is final.
**Reads against:** the RFC body (fetched 2026-09-16 via `gh api`), `docs/context/fedramp-rules/fedramp-consolidated-rules.json` (2026.07.14.01), `docs/RESEARCH-PARAMIFY-REGISTER.md` §3–§6, `docs/RESEARCH-KSI-GAP-ENGINE.md` §2.3, `docs/PLAN-KSI-PIVOT.md` §4 ("the positioning statement, drafted once, used twice"), `docs/RESEARCH-S3-2-OUTREACH.md` §2 (the community answers diagnoses and ignores pitches).

---

## 1. What the RFC asks for, and what this comment answers

The RFC wants "explicit targeted feedback rather than general commentary". Of its five anticipated Class D expectations, two are in this project's evidence: **(4)** "ongoing support for integrating assurance data into agency GRC systems" and **(5)** "new Key Security Indicators related to assurance engineering, automation capabilities". The two comments already posted are both about item (3), the certified-third-party rule, and the Rev5-High transition path. Nothing posted yet touches the automation floor that already defines Class D in CR26: `FRC-CSX-VVK` (MUST ≥4 automated methods per KSI) and `FRC-CSX-MOT` (MUST 18 months of persistent-validation history).

Everything below is a fact from the pinned rules or a number the register computed. The tool is named once, as provenance for the numbers. Nothing is asked of FedRAMP that is a feature request for us.

**Facts the comment rests on, each checked this session:**

| Claim | Where it was checked |
|---|---|
| CR26 has no definition of "automated method" | `FRD` in `fedramp-consolidated-rules.json` 2026.07.14.01: no term matching *automat*, *method*, *evidence*, or *objective*; `FRC-CSX-VVK` lists its terms as `Persistently`, `Provider`, `Validation`, `Verification` |
| `FRC-CSX-VVK` d: MUST ≥4 per KSI; c: MUST ≥2; b: SHOULD ≥1 | same file, `varies_by_class` |
| `FRC-CSX-MOT` d: MUST 18 months; c: 6 months; the initial-certification note exists | same file — the note reads "providers will need to have mechanisms in place and agree to meet this requirement" when the history is not there yet, so *the 18 months cannot be met by any pilot participant* is **not** a point worth making; the rule already answers it |
| `VDR-TFR-MVX` has entries for classes a, b, c and **none for d** | same file; also `docs/SPEC.md` §12 note 6 |
| `FRD-PER` "Persistently": "the status of persistent activities will always be known" | same file |
| `VDR-CSO-FAV`: failures of detection and response are vulnerabilities | same file |
| `default_artifacts.KSI` #4: "Verification that the automation in place is accurate and sufficient" | same file, `info.default_artifacts` |
| Two public Phase One packages, both Coalfire-assessed, both exported by Paramify, ingest to the same register | `RESEARCH-PARAMIFY-REGISTER.md` §3, §3b |
| Paramify's package: 140 evidences, **80 marked `automated: Yes`**, `validationRules: []` on all 140 → 0 machine-validated methods | §6 caveat 2 |
| Filevine's package: 237 evidences, 0 marked automated, 0 machine-validated | §3b |
| 116 and 157 human-read methods on 38 KSIs; 3 KSIs unreached (`IAM-AAM`, `INR-RIR`, `MLA-LET`) | §3, §3b, §5 |
| What-if class d, with 20 pipeline recipes counted: floor met on **3 of 46**; class c on 6 of 46 | §4 |
| A meter that reads the earliest instant satisfies class c's 6-month floor on 38 of 46 rows from one 2025 snapshot; walking the instants on the owed clock reads 0 of 46 | §6 caveat 3; issue #159, fixed 2026-09-16 |
| Package-level: 1 bare hash, 51 empty per-KSI signature fields | `RESEARCH-PARAMIFY-PILOT.md` §8.4 |

---

## 2. The comment, as it would be posted

Markdown, for GitHub Discussions. `[register]` and `[repo]` are filled at post time with a commit-pinned link on `main`.

> **On the automation floor Class D already carries — four targeted points**
>
> Feedback on anticipated expectations (4) and (5), and on the two CR26 rules that already define what Class D owes per KSI: `FRC-CSX-VVK` (MUST ≥4 automated methods for each KSI) and `FRC-CSX-MOT` (MUST 18 months of persistent-validation history). The numbers below come from reading the two public Phase One machine-readable packages (Paramify's 8/29/2025, Filevine's 2025-08-18, both Coalfire-assessed) under the 2026.07.14.01 rules with an open-source gap engine I maintain ([repo]); the full per-KSI register and method are at [register]. Neither package is at fault for any of it — the Phase One format predates these rules. They are simply the only two authorized packages anyone can measure.
>
> **1. "Automated method" is undefined, and Class D counts four of them per KSI.** CR26 defines *Validation*, *Verification*, and *Persistently* (FRD-VLN, FRD-VRF, FRD-PER) but not the unit `FRC-CSX-VVK` counts. The two public packages show why that matters: Paramify's marks 80 of its 140 evidences `automated: Yes` — a script produced the artifact — while `validationRules` is empty on all 140. Under a reading where "automated" means *a script collected it*, many of those rows already meet a floor of 4; under a reading where it means *a machine evaluated a stated assertion over what was collected*, both packages hold 0. Both readings are currently defensible. **Ask:** the October 14 RFC define an automated validation method as, at minimum, (a) an assertion evaluated by machine over collected evidence, (b) with a stated population, so that "0 findings in 0 resources" is distinguishable from "0 in 412" — an empty account passes every `count == 0` check — and (c) capable of failing. `VDR-CSO-FAV` already makes a validation failure a vulnerability; a validation that cannot fail has nothing for that rule to act on, and should not count toward the floor.
>
> **2. Four methods should mean four independent sources, or the floor is met by splitting one API call four ways.** One `iam get-credential-report` yields four assertions (MFA, key age, password age, console access) without adding any assurance the first assertion did not. **Ask:** the Class D requirements state what makes two methods distinct. A workable rule is *distinct evidence plane*: the running environment (cloud API, agent), the code and pipeline that produced it (commit-anchored — SBOM, IaC, CI configuration), the assessor's independent validation, and human attestation, with attestation counting toward coverage but never toward the automated floor. For what it is worth, the pipeline plane is the cheapest additional automated method most providers can add — they already run it and do not count it — and even counting twenty of them, the class-d floor is met on 3 of 46 KSIs in the register. The floor is high enough that the definition of the unit is the whole question.
>
> **3. "Historical metrics including status from persistent validation" should mean status per cycle, not the age of the oldest capture.** FRD-PER says the status of a persistent activity "will always be known". Our own meter initially read the earliest instant a KSI's evidence reached back to, and on that reading a single 2025 snapshot satisfied class c's 6-month floor on 38 of 46 KSIs. Tooling will take the lenient reading unless the rule prices the strict one. **Ask:** (a) history under `FRC-CSX-MOT` be the sequence of validation statuses on the `VDR-TFR-MVX` clock, gaps declared; and (b) `VDR-TFR-MVX` gain a Class D entry — it defines windows for a (1 month), b (7 days) and c (3 days) and none for d, so "18 months of persistent validation" at Class D currently has no stated cadence to be persistent at.
>
> **4. Agency GRC integration (item 4) needs the validation result, not the package, to be the signed unit.** The Phase One packages carry one package-level hash, 51 empty per-KSI signature fields, and artifacts by reference. A GRC system consuming that cannot verify a single KSI's status without the whole package and a phone call. **Ask:** at Class D, each validation result carry the digest of the bytes it judged, the assertion, the population, the clock time, and a signature, and the package be an index over those. That is also what `default_artifacts.KSI` #4 ("verification that the automation in place is accurate and sufficient") needs to be checkable rather than asserted.
>
> One observation on item (5): three 2026 KSIs (`KSI-IAM-AAM`, `KSI-INR-RIR`, `KSI-MLA-LET`) are reached by no Phase One indicator at all, because no Phase One subject lands on them. New Class D KSIs will start the same way. Shipping each with one worked automated method — the kind of thing the FedRAMP/schemas examples could carry — would make a floor of four reachable in principle on day one.

---

## 3. What was left out, and why

- **The `TRUE`/`true` credential-report finding** (WAY-AHEAD §3(b)). It is about the sister dataset's recipes (`docs/context/ramprules`), not FedRAMP's rules or schemas. It goes to that project, not this RFC. It is the best concrete example of point 1(b) — an assertion that passes over nothing — but citing it before it is filed there is poor form. If the owner files it first, one sentence can cite it by number.
- **The `where`-alignment limit of labeled assertions** (SPEC §14.4a). Same channel, same reason.
- **The 18-months-is-impossible-for-pilot-participants argument.** Tempting, and wrong: `FRC-CSX-MOT` carries a note that already answers it (table in §1).
- **The S3-2 question** ("register or SDR?"). Wrong channel by design; the RFC thread is not where FedRAMP answers and not where 3PAOs read.
- **Anything about the certified-third-party rule or the Rev5 transition.** Both are covered by the two existing comments and neither is in this project's evidence.
- **The name of the tool more than once.** #153 got a substantive reply from the Director in nineteen minutes for a data-quality writeup posted in personal capacity; #151's project introduction has zero replies after two months.

## 4. Judgment calls for the owner

1. **Point 2's "distinct evidence plane" is a proposal, and it is ours.** It is the positioning statement the pivot plan budgeted for. It is framed as one workable rule, not the rule; if it reads as self-serving, cut the "for what it is worth" sentence and keep the ask.
2. **Point 1(c) "capable of failing" as a definitional requirement** is the strongest ask in the comment and the one most likely to be pushed back on ("a control with no findings is still validated"). The defence is `VDR-CSO-FAV` and the stated population in 1(b); the two together say a passing validation must be able to say over what it passed.
3. **Whether to post before or after the S3-2 sends.** The comment names both packages and links the register; the S3-2 plan says the CSPs see the register before it is cited anywhere public (§5 step 1). Posting this first breaks that. Either the S3-2 emails go first (a week's wait), or the comment links a register with the package names removed — the numbers survive, the provenance is thinner. Recommendation: send the emails, wait seven days, post; there is time (23 days) and the emails are drafted.
4. **README link-back** (`PLAN-KSI-PIVOT.md` §8): when filed, the comment's URL goes in the README's "How much of FedRAMP this actually answers" section, and #72 closes with the URL in the closing comment.

## 5. After filing

- Record: date, URL, in `PLAN-SOUNDNESS.md` S3-3's line and `WAY-AHEAD.md` §8. Close #72.
- Watch #170 until 2026-10-09 and #172 for any reply; watch for the 2026-10-14 requirements RFC and re-read it against points 1–4. Anything adopted is a line in the README; anything not adopted is a line in `RESEARCH-KSI-GAP-ENGINE.md` §7's risk list.

---

## Session log

- **2026-09-16** — Drafted at `09d5b42`. RFC body and both existing comments fetched; the four points chosen for being in this project's evidence and absent from the thread. One planned point (18 months unreachable by pilot participants) dropped on reading the rule's own note. Not filed; owner's go, and the S3-2 ordering question in §4.3, first.
