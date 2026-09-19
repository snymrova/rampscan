# rampscan — implementation plan: R2, the Security Decision Record

**Written 2026-09-18 at `main` = `20fa47f`.** This file breaks R2 in `docs/PLAN-ARTIFACT-PLANE.md` §5 into buildable items. It covers issues #102, #103 and #104, and re-scopes #105. The parent plan still owns the argument for R2. This file owns the build.

---

## 0. Before any code: one owner decision

**Decided 2026-09-18: yes.** The owner lifted R2's pause. The text below is the argument as it was put.

The docs still say R2 is paused. `docs/WAY-AHEAD.md` §2 reads: "R2–R5 … resume at the S3 exit. Do not work them." S3 only exits when someone outside the project replies. S3-2 and #72 are parked, so that exit cannot happen, and R2 is blocked on something nobody is doing.

**Recommendation: decouple R2 from the S3 exit gate.** Reasons:

- The pause was put in place because rampscan signed false VEX. That was a soundness bug in the reachability gate, and S1 and S4 fixed it and closed. R2 does not touch that code.
- On 2026-09-17 the owner chose P1–P4 "ahead of R2/SDR". That ordering only makes sense if R2 comes next. P1–P4 merged on 2026-09-18.
- The SDR becomes mandatory on 2027-01-01, and `RootCawsLLC/ksi-harness` already claims SDR output.

If the owner agrees, R2.0 records the decision in `WAY-AHEAD.md`. Only the pause lifts: S3 keeps its own exit gate, and #72 keeps its 2026-10-09 deadline.

---

## 1. What R2 must produce, from the pinned text

### 1.1 The rules

| Rule | Force | What it demands |
|---|---|---|
| `SDR-CSO-FRR` | MUST | An SDR **"in both human-readable and JSON formats"**, with seven items for each applicable FedRAMP rule: how it is followed (or the reason and risk for not following it), verification, validation, independent verification, independent validation, responses to the assessor, and artifacts. |
| `SDR-CSO-MTD` | MUST | Metadata: version, date and time of last update, source of the update. |
| `SDR-CSX-KSI` | MUST | For each applicable KSI, short summaries of the five artifacts: (1) the measures, or the reason and risk for having none, (2) the cycle, (3) verification that the measures demonstrate the KSI, (4) verification that the automation is accurate and sufficient, (5) validation that the measures work as intended. |
| `SDR-CSX-KMT` | MAY at class a; MUST at b and c; MUST (to be set in the Phase 4 pilot) at d | Historical metrics per KSI: a 30-day summary and a summary of up to one year. Class c also needs the daily series. **This is R3, not R2.** |
| `SDR-CSF-CTF` | MUST | Rev5 controls only. **Out of scope** for a 20x SDR. |

### 1.2 The schema (`fedramp-security-decision-record-schema-2026-06-24.json`, `$schemaVersion` 1.1.1, already vendored and dual-pinned by P2-1)

- **Top-level `required`:** only `certificationPackageOverviewUri` and `fedRampRequirements`. `keySecurityIndicators` is not required (defect 1, §2).
- **Each `keySecurityIndicators[]` item requires** `ksiId`, `ksiImplementation`, `ksiValidation`, `ksiAssessment`, `ksiTests` and `ksiEvidence`. `ksiImplementationStatus` is optional and takes one of `Implemented`, `Not Implemented` or `Partially Implemented`.
- **Each `fedRampRequirements[]` item requires** `frrID` and `frrImplementation` (an array of Markdown strings). `frrImplementationStatus`, `frrValidation` and `frrAssessment` are optional.
- **`$defs.evidence` requires none of its fields.**
  - `evidenceType` takes one of `Log`, `Report`, `Screenshot`, `Configuration`, `Policy`, `Procedure` or `Audit Record`.
  - `evidenceLocation` must be an absolute URI.
  - **`lastUpdated` must be a `date`, not a `date-time`.** It is the one field where the value the register already has (an ISO instant) fails validation if copied as-is.
- **`metadata`** requires `version`, `lastUpdated` (a date-time) and `updateSource`. The schema does not require the block, but `SDR-CSO-MTD` does, so we always emit it.
- **`certificationPackageOverviewUri`** must be an absolute URI (it is defined in the common schema). rampscan builds the Certification Package Overview (CPO) but does not host it, so this value has to be declared (§4, D5).
- **`portsAndProtocols` and `securityControls`** are omitted. Ports are a declared fact that no rule forces into R2 (YAGNI), and controls belong to Rev5.

---

## 2. What changed upstream since the parent plan (checked 2026-09-18)

1. **The pin is current.** `FedRAMP/schemas@main` still serves SDR 1.1.1. The last SDR commit is from 2026-09-01 and only reworded `evidenceLocation`. The upstream file and our vendored copy parse to the same JSON. They differ only in whitespace, because ours is minified. So the sha256 pin guards our bytes, not upstream's. R2.0 checked the source: the vendored bytes are fedramp.gov's (`www.fedramp.gov/schemas/`, which serves them minified), identical to a fresh download (sha256 `6a6d7dca…`). This is recorded in the schemas README. There is no semantic change to chase.
2. **Defect 2 has already been filed by someone else.** `FedRAMP/schemas#10` ("SDR-CSX-KMT requires KSI metric history in the SDR, but the SDR schema has no field for it", filed by `mikedizon` on 2026-07-27) is still open. So #105 no longer files it. At most it adds a comment with our evidence.
3. **Defect 1 has not been filed.** No open or closed issue covers `keySecurityIndicators` being missing from `required`. #105 files only this one.
4. **Declining a MAY rule is settled.** On #21, FedRAMP staff (`dan-fedramp`) answered that "Not Implemented" is the correct status for a MAY rule the provider chooses not to implement, and that it is not a shortfall. So a `ruleCoverage` declaration of `not-implemented` maps to `frrImplementationStatus: "Not Implemented"` with the reason in `frrImplementation`. That follows from the answer, and nobody needs to decide it.
5. **Per-method data outside the schema is sanctioned.** On #19 (closed), FedRAMP said it is "too early to mandate a specific solution" for per-method history and that vendors "should feel free to present the data" as additional schemas or optional arrays. That is the licence for the `x-rampscan` block below.
6. **#24 is open** and asks how CR26 schemas should cite signed action decisions. It is adjacent to our `evidenceLocation` choice, so watch it. It does not block R2.

---

## 3. What already exists (verified against the code)

| Need | Where it is | State |
|---|---|---|
| Pinned SDR schema and a validator that fails closed (`uri`, `date` and `date-time` formats implemented) | `packages/cli/src/fedramp-schemas.ts` (`SDR_SCHEMA`, `FEDRAMP_SCHEMA_PINS`) | built, P2-1 |
| SDR reader: coverage diff, refusal of KSI ids in the rule array, refusal of duplicates | `packages/cli/src/sdr.ts` (`readSdrCoverage`) | built, P2-1 |
| Pattern for exports split into declared and computed halves, with a `problems` channel and an `x-rampscan.fieldSources` block | `packages/cli/src/fedramp-exports.ts` (CPO, OCR) | built, Q5 |
| Pattern for writing, validating and stamping, then re-validating after the stamp | `packages/cli/src/fedramp-run.ts` | built |
| Conformance over files on disk | `packages/cli/src/fedramp-conformance.ts` (`KNOWN_ARTIFACTS`, `checkConformance`) | built; has no rule verdict |
| Method register per KSI: methods, automation, clock, live `bundleDigest`, `freshAsOf`, `evidenceClass`, `freshMet` | `MethodRegisterRow` / `MethodCell`, `packages/core/src/ports.ts:350–586` | built, Q2–Q4 |
| The five artifact cells per KSI, with body digest, source, anchor, `validFrom` and absence records | `ArtifactCell` / `ArtifactBodyInfo`, `ports.ts:434–502` | built, R1 |
| Artifact body bytes, read from the ledger | the R1.6 console view reads bodies from the ledger | built |
| Rules addressable per class (129 at b, 131 at c, 132 at d) | `addressableRules`, `effectiveForce`, `packages/dataset/src/catalog.ts:949–1013` | built, P2-0 |
| Provider rule declarations (`addressed` + citation, `not-implemented` + reason) | `offering.ruleCoverage`, `packages/schema/src/offering.ts:215` | built, P2-2 |
| Rules the appliance computes, with a drift guard | `COMPUTED_RULES`, `packages/cli/src/submission.ts:56` | built |
| KSIs obliged per class (41 of 46 at b) | `optionalKsis`, `KsiRegisterView.summary` | built, R0 |

**Nothing new is stored.** Like the CPO and OCR, the SDR is a rendering of the projection. It is not appended to the ledger and not signed. Running it twice at the same instant produces the same bytes.

---

## 4. Design decisions

Items marked **(owner)** need an answer before or during the build. The owner has asked that calls which can be grounded in the rule text be decided rather than asked, so the rest are decided here and cite their grounds.

**D1. A separate `rampscan sdr` command, not a flag on `exports`.** The issues and the parent plan name it, and `exports` keeps its CI step unchanged. Output lands beside the CPO and OCR as `out/exports/fedramp/fedramp-security-decision-record.json` and `…/fedramp-security-decision-record.md`. Flags: `--out`, `--ledger`, `--as-of`, `--class`.

**D2. No prose for artifacts 1 or 3, ever.** Ground rule 1 of the parent plan, and §7.3 there. When a KSI has no body for artifact 1, its `ksiImplementation` is an empty array. The document's `problems` and the rule verdict (R2.3) both say so. An empty array is schema-valid. A filled one would be a claim the provider never made.

**D3. The human-readable half is rendered from the built JSON object, not from the projection.** One computation feeds both formats, so they cannot disagree. The Markdown header carries the sha256 of the JSON bytes, and R2.3 checks that the pair still matches. Markdown suits a repository, and R5 owns an HTML or console rendering.

**D4. `fedRampRequirements[]` has one row where the provider declared, and no row otherwise.** *(Narrowed while building R2.1: the first draft also gave a row to every rule in `COMPUTED_RULES`. The schema permits an empty `frrImplementation`, but such a row carries no explanation of how the rule is followed, which is what `SDR-CSO-FRR` asks for. It would also read as answered to `submission --sdr` and to FedRAMP. That is §9.3's "computed excuses nothing" again. So an undeclared computed rule gets no row. It is listed in `unaddressedRules` with `computedBy`, and a declared one gets rampscan's validation line.)* This is the parent plan's "populated where the register speaks and declared where it does not".
- `ruleCoverage: addressed` → `frrImplementation` = the citation.
- `ruleCoverage: not-implemented` → status `Not Implemented` and `frrImplementation` = the reason (grounded in FedRAMP/schemas#21).
- A declared rule that is also in `COMPUTED_RULES` → `frrValidation` names the rampscan surface that computes it. The current result lives on that surface; the SDR does not re-run it.
- An undeclared, uncomputed rule gets **no row**, and is named in `x-rampscan.unaddressedRules` and in `problems`. A row with an empty implementation would be schema-valid and would hide the omission from `submission --sdr`. That check exists because FedRAMP rejects on the missing row (P2-1, research note §9).
- Small schema change: `addressed` gains an optional `implementationStatus` (`Implemented` | `Partially Implemented`). "Addressed" alone does not say which. When it is absent, `frrImplementationStatus` is omitted, which the schema permits.

**D5. `certificationPackageOverviewUri` reuses the declaration that already exists, `offering.report.certificationPackageOverviewUri`** (`packages/schema/src/offering.ts:98`). The OCR already reads it from there. One fact gets one declaration: a second key would let the SDR and the OCR name two different CPOs. If it is absent, no SDR JSON is written and the outcome says why. This is the OCR's incidents refusal again: a required field is never defaulted. rampscan's own config already declares a value (the README URL), so the exit gate needs no new configuration. There is one wrinkle. The key sits inside `report`, the OCR's block, so a provider who wants an SDR before their first OCR has to declare the `report` block. If that bites, hoisting the key to `offering` is a small, separate change. No owner call is needed.

**D6 (owner; decided 2026-09-18: compute it). `ksiImplementationStatus` is computed conservatively: it may understate, it may never overstate.**
- `Not Implemented`: no method holds live evidence that passed. As built (R2.1), this includes a KSI whose only live evidence is a violated check: a failed measurement shows the KSI is not met, so calling it partial would overstate it.
- `Implemented`: all of the following hold, and nothing less:
  - the floor is met (or the class owes no floor and at least one automated method is live),
  - `staleMethods == 0`,
  - no method is `violated`,
  - `historyMet !== false`,
  - all five artifacts are present.
- `Partially Implemented`: every other case.
- The inputs sit in `x-rampscan.ksis[id].statusBasis`, so a reader can re-derive the status.

The other option is to omit the field, since the schema makes it optional, and carry the computed status only in `x-rampscan`. That is safer, but gives up the one field a reviewer scans first. Recommendation: compute it. Owner call because it is the most public claim the document makes.

**D7. `evidenceLocation` is a digest address.**
- By default it is an RFC 6920 named-information URI over the signed bundle's ledger digest (`ni:///sha-256;<base64url>`). That is a real standard for hash-addressed URIs, and it passes the pinned `uri` check.
- If the offering declares `evidenceBaseUri`, it becomes `<base>/sha256/<hex>`, which resolves once published.
- In the default case, `problems` states that a reader without the ledger cannot resolve the location. The address points at the bundle, the signed statement, rather than at artifact bytes. `evidenceText` names the artifact digests, which J4's resolver serves.

**D8. One `ksiEvidence` entry per method cell that holds live evidence.** `lastUpdated` = the date of `freshAsOf` (`date`, see §1.2). `evidenceType` comes from a declared collector→type map with a drift test that fails when a collector has no entry:
- scanners → `Report`
- IaC and config checks → `Configuration`
- attestations → `Audit Record`
- ingested AWS or Prowler results → `Report`

**D9. `ksiTests` lists every derived method, not only the evidenced ones.** The field is "tests used to validate". A method with no evidence is a test the provider owes. The string form is `<methodId> — <source>, automated|not automated, <clock> clock`. Each method's state goes in `x-rampscan`, so the schema field stays stable across runs.

**D10. The artifacts map onto the schema's three narrative fields like this:**
- `ksiImplementation` ← artifacts **1** and **2**, each prefixed with its item label
- `ksiValidation` ← artifacts **3**, **4** and **5**
- `ksiAssessment` ← the `assessed` source (R4.5). Until R4.5 lands it is an empty array, and the rule verdict reports "awaiting the assessor (`IVV-IAS-SUM`)".

The schema has no *verification* slot, while `SDR-CSX-KSI` items 3–4 and `SDR-CSO-FRR` item 2 are verifications. That may be a third schema/rule divergence, or it may be intended to live in the `Validation` field. **It is noted as a candidate, not claimed.** R2.3 reports where the items went, and nobody files it until it has been read against the upstream definitions `FRD-VER` and `FRD-VAL`.

**D11. Which KSIs get a row:** every KSI the class obliges (41 at b), always. A KSI that is optional at the class gets a row only when it holds evidence. Otherwise it is listed under `x-rampscan.optionalKsis`. The rule-verdict denominator counts obliged KSIs only (SPEC §13.7, the same rule the board follows).

**D12. Metadata is always emitted.**
- `lastUpdated` = the fold's `projectedAt`, never the wall clock. That keeps the bytes deterministic.
- `version` = `sha256:<12 hex>` over the document without its metadata, so the version changes exactly when the content changes.
- `updateSource` = `rampscan <version> (automated, ledger head <digest>)`.

**D13. `x-rampscan` carries the provenance.** It holds:
- `fieldSources`, as the CPO has
- per-KSI register state, gaps, method states and `statusBasis`
- `unaddressedRules` and `optionalKsis`
- the conformance stamp

Historical metrics are **not** in R2. They land in R3.3 (#108) in this same block, with the divergence stated and FedRAMP/schemas#10 cited. *As built (2026-09-18): landed as `x-rampscan.metrics`; see `docs/PLAN-HISTORY.md`.*

### Field map

| SDR field | Source | Declared or computed |
|---|---|---|
| `certificationPackageOverviewUri` | `offering.certificationPackageOverviewUri` | declared |
| `metadata.*` | the fold's instant, content digest, tool version | computed |
| `fedRampRequirements[].frrID` | the declared `ruleCoverage` ids that name a rule at the pin (D4 as built) | declared |
| `…frrImplementationStatus` | `ruleCoverage` status | declared |
| `…frrImplementation` | citation or reason | declared |
| `…frrValidation` | the `COMPUTED_RULES` surface plus its current result | computed |
| `keySecurityIndicators[].ksiId` | register row key | computed |
| `…ksiImplementationStatus` | D6 | computed |
| `…ksiImplementation` | artifacts 1 and 2 | authored or attested / computed |
| `…ksiValidation` | artifacts 3, 4 and 5 | judged / computed |
| `…ksiAssessment` | `assessed` source (R4.5) | declared, empty today |
| `…ksiTests` | `MethodRegisterRow.methods` | computed |
| `…ksiEvidence` | live `bundleDigest` per method cell | computed |

---

## 5. The work, item by item

The house convention applies: one squash PR per item, subjects suffixed `(#NN)`, with `Closes #NN`. Items are stacked and coded straight through without waiting on merges. Each item writes its failing test first and runs it red at the base commit.

### R2.0: preparation (½ day, can ride with R2.1's PR)

- Record the decision in `WAY-AHEAD.md`: lift the pause in §2 and add R2 to the §3 list. Record the upstream facts from §2 in the parent plan's session log.
- Schema: `offering.evidenceBaseUri` (URL, optional) and `ruleCoverage[addressed].implementationStatus` (optional enum). Tests cover each key's acceptance and refusal. The CPO URI already exists (D5).
- `docs/context/fedramp-schemas/README.md`: record where the SDR bytes were vendored from and why they are minified (§2.1).

### R2.1 (#102): `rampscan sdr`, the JSON half (2 days)

**Files**
- `packages/cli/src/sdr-build.ts`: a pure builder, `buildSecurityDecisionRecord(input) → { document, problems }`. Its input mirrors `FedrampExportInput` plus the KSI register view, the rule register, artifact bodies read from the ledger, and `ruleCoverage`.
- `packages/cli/src/sdr-run.ts`: writes, validates against `SDR_SCHEMA`, stamps, then validates again, mirroring `fedramp-run.ts`.
- Wire the `sdr` command in `main.ts`.
- Add the filename to `KNOWN_ARTIFACTS` in `fedramp-conformance.ts`.
- `COMPUTED_RULES`:
  - add `SDR-CSO-MTD`
  - reword `SDR-CSO-FRR` and `SDR-CSX-KSI` to name `rampscan sdr`

  The drift guard in `submission.test.ts` forces the new entry. The README's computed-rule count moves through the numbers gate, regenerated from the command. *As built: 15 → 17.* `SDR-CSX-KMT` was added too, because the SDR names it in its problems. The drift guard requires every cited rule to be in the map, and the `CDS-CSO-UTC` entry already counts a verdict of unmet, reported by name, as an answer.

**Tests (failing first)**
- **Schema:** the fixture ledger's SDR validates against the pinned schema, and a deliberately broken `lastUpdated` (a date-time where a date belongs) is refused.
- **Field map:** one test per row of the table in §4. Includes: artifact 1 authored for KSI-SVC-SIN appears in `ksiImplementation`; an absent artifact 1 yields `[]` plus a problem; a violated method prevents `Implemented` (D6); a not-implemented declaration yields `Not Implemented` plus its reason; an undeclared rule gets no row and appears in `unaddressedRules`.
- **Determinism:** two runs at the same `--as-of` produce identical bytes. `metadata.version` changes when one artifact body changes, and does not change when only the wall clock does.
- **Agreement across surfaces:** `submission --sdr <generated file>` reports exactly the omissions that `x-rampscan.unaddressedRules` lists. One fact, two surfaces, one answer, which is §5's rule in the P2 note made executable.
- **The refusal:** without `offering.report.certificationPackageOverviewUri`, no file is written and the outcome names the key.
- **Collector map drift:** every collector id in `packages/collectors` has an `evidenceType`.

**Acceptance**
- On the fixture: a schema-valid SDR in which every obliged KSI has a row and KSI-SVC-SIN carries its authored body.
- On this repository: schema-valid, with problems stated loudly. This repo authors no artifacts and declares no `ruleCoverage`, so expect empty `ksiImplementation` on 41 rows and about 115 unaddressed rules. That is the honest reading, and it is the point.

### R2.2 (#103): the human-readable SDR (1 day)

**Files**
- `packages/cli/src/sdr-render.ts`: `renderSdrMarkdown(document) → string`, a pure function of the JSON object only (D3).

**The layout**
1. **Header:** offering, class, dataset pin, `projectedAt`, the JSON sha256, and a declared/computed legend.
2. **Summary:** KSIs by status, rules addressed / declined / unaddressed, and the problems, quoted in full.
3. **One section per KSI:** status with its basis, then the five `SDR-CSX-KSI` items under their own rule-text labels. Each item shows its body and source, or the rule's own "or the reason…" line marked as missing. Then tests, then evidence (type, date, address).
4. **One table for FedRAMP rules:** id, force at class, status, statement. Declined rules are shown with their reason.
5. **What this document does not contain:** assessor content, historical metrics (R3), and the verification-slot note (D10).

`sdr` writes both files. The JSON is always written first, and the Markdown is rendered from the bytes as written.

**Tests**
- A golden test on the fixture.
- Every KSI and rule row in the JSON appears in the Markdown, and nothing appears that the JSON lacks. The check is a structural walk, not a snapshot.
- The embedded digest equals the sha256 of the JSON file.
- A KSI with no body shows the rule's "or …" line as missing and never shows invented text.

### R2.3 (#104): `conformance` gains the rule-compliance verdict (1½ days)

**Files**
- `packages/cli/src/sdr-rules.ts`: `checkSdrRules(document, { catalog, class, companion? }) → RuleVerdict[]`.
- `fedramp-conformance.ts` calls it for SDR documents and prints two verdicts per document, schema and rules, never one merged verdict (ground rule 3).

**The checks, each reported by rule id**

| Rule | Check | Honest limit it prints |
|---|---|---|
| `SDR-CSO-FRR` (coverage) | one row per addressable rule at the class. This **reuses** the diff that `submission --sdr` runs, lifted into `sdr.ts` if it is not already shared, and is never recomputed | — |
| `SDR-CSO-FRR` (both formats) | the `.md` companion exists and its embedded digest matches the JSON | a lone JSON file prints `unmeasured: no companion supplied`, never a pass |
| `SDR-CSO-MTD` | metadata is present with its three fields | — |
| `SDR-CSX-KSI` | one row per obliged KSI; `ksiImplementation` and `ksiValidation` are non-empty | "present, not judged": prose is counted, never graded |
| `SDR-CSX-KSI` (divergence 1) | **reported by name** when the document omits `keySecurityIndicators` and still validates against the schema | cites the pinned `required` array |
| `SDR-CSX-KMT` (b, c) | **reported by name**: "cannot be met in-schema" | cites FedRAMP/schemas#10; once R3.3 lands, reports whether the `x-rampscan` carriage is present |
| assessor content | an empty `ksiAssessment` or `frrAssessment` → "awaiting the assessor (`IVV-IAS-SUM`)", counted | — |

**Exit codes.** Schema failure still exits 1, unchanged, so the existing CI step keeps its meaning. Rule failures print always and exit 1 only with `--require-rules`. The reason: an SDR for an offering with no assessor yet cannot be rule-complete, and a gate that is red from installation onward gets switched off. That is the same argument `artifacts check` made in R1.5.

**The class** comes from the config or `--class`, which means conformance now loads the catalog. If no class can be resolved, the SDR rule checks are `unmeasured` and never skipped quietly. *As built: `--class`, else the class a rampscan-written record names in `x-rampscan.offeringClass`. `conformance` reads files, not a checkout, so it has no config to read. A record from another tool needs `--class`.*

**Tests**
- The divergence-1 document (schema-valid, zero KSIs) is schema ✓, rules ✗ `SDR-CSX-KSI`.
- A companion with a mismatched digest fails.
- A lone file is unmeasured.
- The class-c KMT line appears. The class-a KMT line does not, because it is a MAY.
- `--require-rules` flips the exit code.

**CI** (`test.yml`, beside the Q5 step): `pnpm rampscan sdr --ledger "$RUNNER_TEMP/absent-ledger" --out "$RUNNER_TEMP/conformance"`, then the existing `conformance` call. The gated rule is schema-valid, with the rule verdict printed and not gated.

### #105 (re-scoped, stays in S3 and parked with the sends)

The work drops from two filings to one filing plus one comment:
- **File** defect 1 (`keySecurityIndicators` missing from `required`) in the shape FedRAMP/schemas#3 set: a diagnosis, not a PR, naming the tool that found it.
- **Comment** on #10 with the measured evidence from R2.3's KMT line.

Both are outreach, so both wait on the owner's go, the same as S3-2.

---

## 6. Gates before each PR

These come from this repo's recorded lessons:

- `pnpm typecheck` (that is `tsc --build`; if it shows phantom errors, run `--clean` first)
- `pnpm lint:changed`
- `pnpm test`, from the repo root
- the numbers gate: regenerate the README figures from the commands in the same change (test count; computed rules 14 → 15)
- export `~/.local/bin` onto `PATH` before any scan
- no AI attribution in commits or PR bodies

---

## 7. The exit gate (the parent plan's, updated)

1. `rampscan sdr` on this repository's own offering writes a **schema-valid** SDR and its Markdown companion. CI generates it and checks it beside the CPO and OCR.
2. `conformance` prints **schema ✓ and rules ✗** for it, naming each failed rule. Divergences 1 and 2 are reported by name.
3. `submission --sdr` over the generated file agrees with the file's own `unaddressedRules`.
4. #105 is ready to send, not sent (S3 owns the go).

---

## 8. Out of scope, and the risks

- **Not in R2:**
  - Historical metrics (R3, #106–#108).
  - The assessor inbound (R4.5, #113).
  - `portsAndProtocols`, `securityControls`, signing the SDR, and an HTML or console view (R5).
- **The schema is a draft.** On 2026-09-01 alone it took a description change and a version bump to 1.1.1. The dual pin is the mitigation. A re-publication fails the pin before it can fail silently.
- **The biggest reputational risk is D6's status field.** One `Implemented` that the evidence does not carry is the `SECURITY.md` class of bug. That is why the rule is one-directional and its basis is printed.
- **Risk of scope creep toward a document editor** (parent plan §7.2). The SDR must stay a rendering of signed state plus declared passthrough. No prose generation, no editing surface.

## 9. Size and sequence

R2.0 → R2.1 → R2.2 → R2.3, stacked, about **5 working days**. The parent plan said 4. The extra day is R2.3's catalog loading and the cross-surface test.

**Owner answers, given 2026-09-18:** §0 yes, R2 is unpaused. D6: compute the status.

---

## Build log

- **2026-09-18.** R2.0 → R2.3 were built in one stacked run on branches `r2-1-sdr-json` → `r2-2-sdr-markdown` → `r2-3-sdr-rules`. Exit gate §7: items 1–3 are met locally. On this repository's own offering, `rampscan sdr` is schema-valid, and `conformance` prints schema ✓ and rules ✗, naming each failed rule. Divergence 1 is reported by name when a record omits `keySecurityIndicators`. KMT is reported as impossible in-schema. The test `agrees with submission --sdr about what it omits` covers item 3. Item 4 (#105) stays parked with the S3 sends. Changes made during the build, each recorded where it was decided:
  - D4 narrowed: only declared rules get a row.
  - D6 tightened: a KSI whose only evidence is violated is `Not Implemented`.
  - `SDR-CSX-KMT` joined `COMPUTED_RULES`.
  - The companion is found by filename, and its digest is read from a fixed `JSON sha256:` line.
  - The class comes from the record when `--class` is absent.
