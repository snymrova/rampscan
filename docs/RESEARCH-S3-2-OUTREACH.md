# S3-2 — where the register goes, and what was found on the way

**Date:** 2026-09-15. **Item:** PLAN-SOUNDNESS S3-2 (#138): send `docs/RESEARCH-PARAMIFY-REGISTER.md` to Paramify, Coalfire and the FedRAMP 20x community channel with one question — *is the gap register the thing you are missing, or is the SDR?* The plan names the parties and no channels. This note is the research that fixes the channels, plus two findings the research turned up that change what gets sent.

Nothing has been sent. Every send is the owner's, under the owner's name; §5 is a recommendation and §6 holds the drafts.

## 1. The channels, as they exist

**FedRAMP's community is one place: [`FedRAMP/community` GitHub Discussions](https://github.com/FedRAMP/community/discussions).** There is no mailing list or Slack in play; the "20x Discussion" category is where CSPs, 3PAOs and tool vendors post, and FedRAMP staff (`pete-gov` — Pete, FedRAMP Director; `emu-gov`; `nicole-gov`) answer in it. A Wednesday "20x Community Update" call exists with slides posted afterwards ([#148](https://github.com/FedRAMP/community/discussions/148)). FedRAMP states it will not recommend platforms ([#124](https://github.com/FedRAMP/community/discussions/124)) but will host the discussion.

**Paramify's public voice there is Isaac Teuscher (`iteuscher`, Sr. Security Engineer),** the pilot repository's principal author (33 of 45 commits). His threads: the draft submission ([#32](https://github.com/FedRAMP/community/discussions/32), 2025-05-29), the **KSI comparison tool** mapping draft KSIs 25.04 → 25.05 ([#36](https://github.com/FedRAMP/community/discussions/36), 2025-06-03 — a crosswalk artifact of exactly our kind, one catalog revision earlier), the final submission ([#58](https://github.com/FedRAMP/community/discussions/58), 2025-07-14, zero comments), and three 2025 Q&A threads. [`paramify/fedramp-20x-pilot`](https://github.com/paramify/fedramp-20x-pilot) has issues enabled (two, both closed; discussions off). The pilot's own trust-center page (`fedramp_20x_trust_center.md`, in the clone) lists four points of contact by name, role and address — CEO, CISO, Sr. Security Engineer, and the Coalfire lead assessor — plus a `federal@` mailbox for questions and 3PAO access. Addresses are on that page, not repeated here.

**Coalfire has no public handle in the community threads.** The 3PAO surfaces in exactly two places: as `assessorOrg: Coalfire` / `leadAssessor: Jorden Foster` (Sr. Director) in the assessed packages, listed as a POC on Paramify's trust-center page; and a [Coalfire case study on Paramify](https://coalfire.com/insights/resources/paramify) (quotes Paramify's COO, names no Coalfire person, ends in a "connect with our FedRAMP advisors" form). The route to Coalfire is the lead assessor's address on Paramify's page, or through Paramify.

**The RFC channel is separate and must stay so.** [#170](https://github.com/FedRAMP/community/discussions/170) is the formal RFC-0033 comment thread (open 2026-09-09, **closes 2026-10-09**, FedRAMP does not participate; two comments so far). [#172](https://github.com/FedRAMP/community/discussions/172) is the informal thread where FedRAMP does answer. S3-3 (#72) goes to #170; the register does not.

## 2. What the community is discussing this month, and why it matters for the question

- **[#169](https://github.com/FedRAMP/community/discussions/169) "SDR — Independent Assessor content vs. providers"** (2026-09-08): a CSP asked which SDR fields the assessor fills. Pete's answer: the provider owns *all* SDR content; the assessor supplies a per-practice summary (`IVV-IAS-SUM`) and verifies inclusion (`IVV-IAS-VIP`). **The SDR half of S3-2's question is live this week, asked by a CSP, and the answer defines the SDR as the provider's document with the assessor's summary inside.** A gap register per KSI is not the SDR and is not in it; the question stands.
- **[#167](https://github.com/FedRAMP/community/discussions/167) Class B/C submissions opened 2026-08-31.** The rejection reasons FedRAMP lists: trust center behind an NDA; no SDR; a KSI or rule omitted rather than declared unmet ("say so and tell us why, don't just omit"); JSON not following schema; assessor content missing from CPO and SDR. Three of five are things a computed register makes visible before submission (unmet KSIs named, method counts, assessor content present or not).
- **[#162](https://github.com/FedRAMP/community/discussions/162)**: pilot participants must show quarterly progress to keep pilot certification and can submit for B/C now. Phase One pilots are, this quarter, deciding what they need to add.
- **[#153](https://github.com/FedRAMP/community/discussions/153)**: a data-quality writeup on the CR26 rules JSON, posted in personal capacity, got a substantive reply from the FedRAMP Director within nineteen minutes. **[#151](https://github.com/FedRAMP/community/discussions/151)**: a signed-receipt evidence project's introduction post has zero replies after two months. The community answers diagnoses and ignores pitches; S3-2's "question, not scorecard" rule is also the rule for being read.
- **[#166](https://github.com/FedRAMP/community/discussions/166)**: the web schema validator is broken and FedRAMP says not to rely on it — context for S3-4's two schema findings, which are of the kind that thread rewards.

## 3. Finding: there is a second public package, and it is the same shape

`RESEARCH-PARAMIFY-PILOT.md` §6 and the register's header call the Paramify package "the only publicly assessed 20x machine-readable package we know of". **That is wrong.** [`Filevine/fedramp20x-low-submission`](https://github.com/Filevine/fedramp20x-low-submission) is Filevine's Phase One Low pilot final submission (Vinesign in scope; last push 2025-08-19; no LICENSE — same caveat, outputs only). It ships `machine-readable-package/filevine-coalfire-2025-assessment.yaml` (427 KB), `data_schema.yaml`, an `html-dashboard/`, and a signed **Validated Assessment Letter** PDF from Coalfire. Its README says the package was generated by Paramify's export and validated in Paramify by the 3PAO; evidence came mostly from Wiz.

Measured on the file:

| | Paramify 8/29 | Filevine 2025-08-18 |
|---|---|---|
| assessor / lead | Coalfire / Jorden Foster | Coalfire / Jorden Foster |
| validations | 51 (49 True, 2 Partial) | 51 (**51 False**) |
| `recommendation` | Authorize | `""` |
| evidences / `automated: Yes` | 140 / 80 | 237 / **0** |
| artifacts named | 394 | 708 |
| `validationRules: []` | all | all |
| per-validation `digitalSignature` | all `""` | all `""` |

Two things follow.

**3.1 The adapter ingested it unchanged.** Same crosswalk, `--cadence monthly` declared (their trust-center statement, like Paramify's, would be the operator's source to confirm), scratch ledger:

```
package: Filevine for Government assessed by Coalfire: Jorden Foster — 51 validations (51 False), 237 evidences (0 marked automated by the package), 708 artifacts named by reference
ingest: 157 bundle(s) appended, 0 unchanged, 73 skipped — no AWS call was executed by this appliance
floor met on 0 of 41 KSIs · at least one automated method on 0 · no method on 3
clocks: 0 of 41 KSIs hold every method inside its owed window — VDR-TFR-MVX (MUST)
artifacts: 0 of 41 KSIs hold all five owed artifacts
evidence class: 38 of 41 KSIs hold point-in-time evidence, rejectable when standalone
```

157 methods on 38 KSIs, 73 skipped under the eight retired indicators (13 of them `*-pol-and-proc` policy documents under PIY-02 alone), freshest method 393 days old, every row `G2 methods`. **The three KSIs no method reaches are the same three — `KSI-IAM-AAM`, `KSI-INR-RIR`, `KSI-MLA-LET`.** That is not a fact about either CSP: the crosswalk has no Phase One indicator whose subject lands on them. They are new at 2026, and a Phase One validations set cannot reach them by construction. Checkable against `recipes/crosswalks/ksi-phase-one-to-2026.07.14.01.json` — no entry's `to` names any of the three.

**3.2 The register stops being about Paramify.** Two CSPs, two impact levels, one 3PAO, one exporting tool, and the same register: 0 automated, 0 in-window, 0 of five owed artifacts, the same three KSIs unreached, 8 of 51 validations aimed at obligations that left the KSI catalog. What the register measures is *the Phase One package format under the 2026 rules*, and the PLAN's "S3 can embarrass" risk shrinks accordingly — the finding is structural, and Paramify is the party best placed to act on it (their export is the format). This changes the send (§5): the register should carry both packages before it goes out.

**3.3 A file that says `False` under a letter that says validated.** Filevine's YAML has all 51 `assessmentStatus: "False"`, empty recommendation and remarks, beside a signed assessment letter in the same repository. Almost certainly an export with the assessment fields unpopulated — but it is upstream's own data making #147's point: the machine-readable file and the human reading disagree, and the adapter's rule of signing neither `True` nor `False` as a verdict is what keeps a ledger honest over a file like this. Worth one sentence in the message to Paramify, as a question about the export, not a finding about Filevine.

## 4. Corrections owed in this repository before the send

1. `RESEARCH-PARAMIFY-PILOT.md` §6 and `RESEARCH-PARAMIFY-REGISTER.md` header: "only publicly assessed" → "one of two"; Filevine named with the same licence caveat.
2. `RESEARCH-PARAMIFY-REGISTER.md`: a §3b with the Filevine register (package alone) and the two-package summary in §5; the ledger run is repeatable from `--repo filevine-for-government` with the same flags. The three-unreached-KSIs fact restated as a catalog fact.
3. PLAN-SOUNDNESS S3-1 record: the "only" clause corrected in the session log, not rewritten in the item (ground rule 3).

Small PR, before anything is sent, so the register that goes out is the one in `main`.

## 5. Recommended send, in order

**Step 1 — Paramify and Coalfire together, privately, by email.** One message to the Sr. Security Engineer (the engineer who publishes the repo and the KSI comparison tool, and the person who would read a crosswalk), cc the CISO and the Coalfire lead assessor — all three are named as POCs on the pilot's trust-center page, and the assessor signed both packages. Attach the register as a PDF or link the file at a commit on `main`; the repository is public either way, so "to them before anywhere public" means *before it is posted or cited anywhere*, not that the file is hidden. Not a GitHub issue on their repo: an issue is public and dated on their board before they have read it.

**Step 2 — wait.** Seven days is enough for a reply or a request to hold; silence past that is the data the plan says to record.

**Step 3 — the community, as a new thread in "20x Discussion".** Title on the finding, not the tool: *A gap register computed over the two public Phase One packages, under the 2026 rules — and one question.* Body per §6.3. Do not post it under #169 (their SDR thread) or #170 (the RFC); cite #169's answer as the reason the question is worth asking. Post on a Tuesday, ahead of the Wednesday call.

**Step 4 — record.** Sent-to, date, channel, and what came back, in PLAN-SOUNDNESS's S3-2 line and WAY-AHEAD §8. Step 3 goes ahead whether or not step 1 answers, unless step 1 asks for a hold — in which case the hold and its reason are recorded and the exit gate reads that.

**Filevine.** Not one of the plan's three parties. Their package is now in the register, so they receive the same email as a courtesy at step 1 (their repo README names no contact; their trust center would), or the community post is how they hear of it. Owner's call; the recommendation is the courtesy email, because the community post names their repository.

**Judgment calls flagged:** (a) adding the Filevine package to the register is a scope addition to S3-1 after its close — justified because it changes the message from "your package" to "the format", but it is an addition; (b) the courtesy email to a fourth party; (c) whether the send names the `False`-under-a-letter observation at all.

## 6. Drafts

Plain text, a screen each. Names and addresses from the trust-center page go in at send time.

### 6.1 To Paramify, cc Coalfire

> Subject: your 20x pilot package, read under the 2026 consolidated rules — one question
>
> I build rampscan, an open-source appliance that keeps signed evidence in an append-only ledger and computes the FedRAMP 20x gap register — FRC-CSX-VVK method floors, VDR-TFR-MVX/NMV windows, FRC-CSX-MOT history, the five owed artifacts — per KSI against the pinned 2026.07.14.01 rules. I ran it over the two public Phase One packages, yours (8/29/2025) and Filevine's (2025-08-18), both Coalfire-assessed and both exported from Paramify, so you are the first to see the result before it goes anywhere else. The document is attached; the repository is public but nothing has been posted or cited.
>
> What it says, in one line: both packages read as 0 machine-validated methods on 38 KSIs, 0 inside their windows, 0 of the five owed artifacts, and the same three 2026 KSIs unreached (IAM-AAM, INR-RIR, MLA-LET) — because no Phase One indicator's subject lands on them. None of that is a mark against either assessment; it is what "assessed" meant under Phase One, put next to what the 2026 rules price. Three things in the document are mine to be wrong about and yours to correct: the Phase One → 2026 crosswalk (43 placed, 4 marked judgment, 8 retired to FRR families — you built the 25.04 → 25.05 comparison, so you will have opinions), the `monthly` cadence read from your trust-center page, and the choice not to sign your assessor's `True` as a verdict — the appliance signs only what it evaluated, and `validationRules` is empty on every evidence, so every one ingests as a collected, unevidenced, human-read method. (Related, and probably an export question rather than a finding: Filevine's file carries `assessmentStatus: "False"` on all 51 validations beside a signed validation letter.)
>
> The one question I would like answered, by either of you, in a sentence: **is a computed gap register of this kind the thing you are missing going into Class B/C, or is it the SDR?** Your answer decides the next six weeks of the roadmap. If you want the document held back from the community thread, or corrected first, say so and I will.

### 6.2 To Filevine (courtesy, same day)

> Subject: your 20x pilot package, read under the 2026 rules
>
> Your Phase One package (`Filevine/fedramp20x-low-submission`) is one of two public 20x machine-readable packages, so it is one of two an open-source gap engine I build was run over, read against the 2026.07.14.01 consolidated rules. Attached is the result, which I have also sent to Paramify and Coalfire; it will be posted to the FedRAMP community discussions in about a week unless you ask me to hold it. The short version: the register is structurally identical to Paramify's own — the finding is about the Phase One format under 2026 pricing, not about your assessment. One thing you may want to know about your file specifically: all 51 `assessmentStatus` fields read `"False"` beside the signed validation letter, which looks like an export artifact. Corrections welcome; the crosswalk and the cadence are the two things I declared rather than read.

### 6.3 Community thread, "20x Discussion"

> **A gap register computed over the two public Phase One packages, under the 2026 rules — and one question**
>
> I ingested the two public Phase One machine-readable packages (Paramify's 8/29/2025 and Filevine's 2025-08-18, both Coalfire-assessed) into an open-source appliance that computes the 2026.07.14.01 gap register per KSI: FRC-CSX-VVK method floors, VDR-TFR-MVX/NMV windows, FRC-CSX-MOT history, `default_artifacts.KSI`. Both CSPs had it a week before this post. Full document, method, and the reviewed Phase One → 2026 crosswalk: [link].
>
> The result is the same for both: 116 and 157 human-read methods on 38 KSIs, 0 machine-validated (`validationRules` is empty throughout — the appliance signs only what it evaluated, so the assessor's `True` is not a verdict it signs), 0 inside their windows, 0 of the five owed artifacts, and the same three KSIs with nothing at all — IAM-AAM, INR-RIR, MLA-LET — because no Phase One indicator's subject lands on them. 8 of the 51 Phase One validations address obligations that are FRR requirements now, not KSIs. This is not a finding about either CSP; it is what a Phase One validations set looks like under 2026 pricing, on the day #167's Class B/C form opened.
>
> Two things I declared rather than read, and would like corrected: the crosswalk (nothing upstream maps the 51 numbered indicators to the 46 mnemonics; 4 rows are marked judgment) and a `monthly` cadence taken from each trust-center page.
>
> The question, for pilot CSPs and 3PAOs especially, given #169's answer that the SDR is the provider's document with the assessor's summary inside: **is a computed, signed gap register of this kind the thing you are missing going into Class B/C, or is it the SDR?** One sentence is plenty.

## 7. What was checked and how

`gh api` against `FedRAMP/community` (discussion list by update, search for `paramify` and `filevine`, bodies of #32, #36, #58, #124, #147, #151, #153, #162, #166, #167, #169, #170, #172), `paramify/fedramp-20x-pilot` (issues, contributors, repo flags), `Filevine/fedramp20x-low-submission` (contents, README); the local pilot clone's `fedramp_20x_trust_center.md` for POCs; two web searches and the Coalfire case-study page. The Filevine YAML was fetched to the session scratchpad, measured with `grep -c`, and ingested with the command in §3.1 into a scratch ledger; the full `frontier` output (175 lines) is in the scratchpad as `filevine/frontier-b-alone.txt`. Nothing from either repository was copied into this one.
