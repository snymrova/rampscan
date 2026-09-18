# P3 — ingesting Prowler's 20x KSI output as a client-run source

**Issue:** #212, under the milestone *P1–P4 — the crowded-field response*.
**Status:** research only. No code. Every number below came out of a command
over the pinned upstream file, and §9 lists what this note could not establish.

Prowler is the reason P3 exists: it runs where rampscan deliberately does not —
inside the client's cloud, with a credential — so its output is exactly the
shape S3-0 established the contract for, a client-run transcript the appliance
**judges rather than trusts**. The appliance boundary (`SECURITY.md`) is
unchanged by everything below: no AWS credential, no AWS call.

---

## 1. The source

`prowler-cloud/prowler`, **Apache-2.0** (verified against the repository's own
licence metadata, not the README). That licence covers the compliance framework
JSON along with the rest of the tree, so vendoring a pinned copy with
attribution is permitted — the constraint that blocked the Paramify material
does not apply here.

The framework arrived in **PR #11701**, *"feat(compliance): replace FedRAMP 20x
pilot KSI with Consolidated Rules 2026.06.24.01"*, merged **2026-09-14**. It
removed the Phase One pilot frameworks (`fedramp_20x_ksi_low_{aws,azure,gcp}`,
version `25.05C`) and added one KSI framework. Two things about that PR are
worth carrying into the design:

- **It shipped as a single cross-provider file, not the five the description
  promised.** The body announces `fedramp_20x_ksi_{aws,azure,gcp,kubernetes,m365}`;
  what is on `master` is one file, `prowler/compliance/fedramp_20x_ksi_2026.json`,
  carrying all five providers in a `checks` object. A design that keys off the
  advertised filenames breaks on the first look at the tree.
- **Its own test plan has the verification boxes unchecked.** Two remain open in
  the merged body: *"Optional: `prowler aws --compliance fedramp_20x_ksi_aws`
  with credentials; inspect compliance CSV/OCSF output"* and *"Confirm dashboard
  module loads"*. The framework was validated as a **parseable document** — the
  Pydantic model, the CLI listing it — and was merged without ever being run
  against a real account. That is not a criticism to publish; it is a statement
  about what the artifact has been tested to be, and it is the reason rampscan
  judges the output rather than accepting it.

A **second** framework has appeared on `master` since, not in that PR:
`prowler/compliance/fedramp_20x_frr_class_c_2026.json`, framework
`FedRAMP-20x-FRR-Class-C`. See §2e — it lands in P2's territory, not P3's.

## 2. What Prowler publishes — computed from the pinned framework

All figures in this section were computed over
`prowler/compliance/fedramp_20x_ksi_2026.json` at `master`, fetched
2026-09-18. They are reproducible; none is remembered.

### 2a. The shape

Top-level keys: `framework`, `name`, `version`, `description`, `icon`,
`attributes_metadata`, `outputs`, `requirements`.
`framework` = `FedRAMP-20x-KSI`; `version` = **`2026.07.14.01`**.

`requirements` holds **46** entries. One entry, verbatim:

```json
{
  "id": "KSI-CED-RAT",
  "name": "Reviewing All Training",
  "description": "The effectiveness of relevant cybersecurity education and training is persistently reviewed, ...",
  "attributes": {
    "Theme": "KSI-CED: Cybersecurity Education",
    "NISTControls": "CP-3, IR-2, PS-6, AT-2, AT-2.2, AT-2.3, AT-3.5, AT-4, IR-2.3, AT-3, SR-11.1",
    "ClassApplicability": "Required for Classes B and C"
  },
  "checks": { "aws": [], "azure": [], "gcp": [], "kubernetes": [], "m365": [] }
}
```

`ClassApplicability` has exactly two values across the 46: **41** *"Required for
Classes B and C"* and **5** *"Optional for Class B, required for Class C"*. The
framework's own description records the third case in prose rather than in a
field — *"Class A authorizations mandate a subset of seven KSIs via
FRC-CLA-MFR"* — so **class A is not derivable from the requirement rows**; a
reader that filtered on `ClassApplicability` alone would silently treat class A
as class B. This is the `varies_by_class` trap of P2-0's §2a, one file over.

### 2b. The mapping is KSI-level, and that is exactly rampscan's method grain

The issue asked whether Prowler reaches the individual validation method beneath
a KSI. **It does not** — `checks` maps a KSI id straight to a flat list of
Prowler check ids, per provider. There is no method, validation or
sub-indicator layer anywhere in the file.

That turns out not to be a problem, because rampscan's method identity is
`aws-ingested:<recipe_id>#<ksi>` (`packages/schema/src/method.ts:163-165`) and
`recipe_id` is documented as *"upstream's recipe id — their names, not ours"*
(`packages/schema/src/ingest.ts:84`). So **one Prowler check becomes one
method** for the KSI it is mapped to, and a check mapped to two KSIs derives two
methods — which is already the rule (`method.ts:4-29`: *"A recipe claiming two
KSIs derives two methods"*). The grain fits without inventing a layer.

On AWS the numbers are: **459 check-mappings over 443 distinct check ids**;
**11** checks are mapped to more than one KSI, the widest being
`config_recorder_all_regions_enabled` at **6**.

### 2c. Coverage, computed

| Provider | KSIs with ≥1 check | check-mappings |
|---|---|---|
| aws | **33 / 46** | 459 |
| azure | 23 / 46 | 137 |
| gcp | 19 / 46 | 94 |
| kubernetes | 16 / 46 | 87 |
| m365 | 15 / 46 | 70 |

**13 KSIs have no check on any provider**, and since AWS covers 33, the
AWS-uncovered set *is* that same 13 — AWS covers every KSI any provider covers.

```
KSI-CED-RAT  Reviewing All Training                    KSI-PIY-RES  Reviewing Executive Support
KSI-CMT-RVP  Reviewing Change Procedures               KSI-PIY-RIS  Reviewing Investments in Security
KSI-CMT-VTD  Validating Throughout Deployment          KSI-PIY-RSD  Reviewing Security in the SDLC
KSI-INR-AAR  Generating After Action Reports           KSI-PIY-RVD  Reviewing Vulnerability Disclosures
KSI-INR-RIR  Reviewing Incident Response Procedures    KSI-RPL-RRO  Reviewing Recovery Objectives
KSI-INR-RPI  Reviewing Past Incidents                  KSI-SVC-RUD  Removing Unwanted Data
KSI-MLA-RVL  Reviewing Logs
```

**10 of the 13 are named "Reviewing …"**; the other three are *Validating
Throughout Deployment*, *Generating After Action Reports* and *Removing Unwanted
Data*. (Counted from the list, not from the shape of it — a first pass through
this note said twelve, which is the rule-4 error in miniature: the pattern was
obvious and the count was wrong.) Twelve of the thirteen are *periodic human
activity*; the exception, `KSI-SVC-RUD`, is a data-lifecycle claim. A cloud
scanner cannot see any of them, and Prowler does not pretend to.

This is the single most useful fact in the note. **The gap Prowler leaves is the
gap rampscan exists to price**, and it is not a gap Prowler is hiding — see
§2d. All 13 are `Required for Classes B and C` or stricter, so none of them is
optional for a class B offering.

### 2d. The MANUAL row — Prowler declares its own non-coverage

The KSI framework carries `outputs.table_config`, which routes it to the
**universal** compliance writer rather than the legacy per-provider one
(`prowler/lib/outputs/compliance/compliance.py:169-170`, *"Universal path: if
the framework has TableConfig, use the universal renderer"*). That writer emits
one CSV row per (requirement × finding) — and then, for every requirement with
no checks **for the provider being scanned**, one synthetic row
(`universal_output.py:206-217`):

```
Status          = "MANUAL"
StatusExtended  = "Manual check"
CheckId         = "manual"
ResourceId      = "manual_check"
ResourceName    = "Manual check"
Muted           = False
AccountId/Region= ""            (blank for manual rows)
```

So a Prowler AWS scan of the 46 KSIs emits real findings for 33 of them and a
single `MANUAL` row for each of the other 13. **Prowler states its own
non-coverage in the output, in a machine-readable field.** That is a better
input than the tree adapter ever got, and it is the field the adapter must read
first.

The CSV's columns are **built dynamically from the framework's
`attributes_metadata`** (`universal_output.py:79-144`), so for this framework
the attribute columns are `Requirements_Attributes_Theme`,
`..._NISTControls` and `..._ClassApplicability` — not the
Section/SubSection/Service columns of the generic model. A parser written
against `GenericComplianceModel` would find none of the three. The fixed
columns are `Provider, Description, AccountId, Region, AssessmentDate,
Requirements_Id, Requirements_Description, Status, StatusExtended, ResourceId,
ResourceName, CheckId, Muted, Framework, Name`.

Output paths: `{output_directory}/compliance/{output_filename}_{compliance_name}.csv`,
with an **OCSF JSON sibling that is always generated regardless of the user's
`--output-formats` flag** (`compliance.py:45-47`). The adapter should read the
OCSF JSON, not the CSV: it is guaranteed present, it is typed, and it does not
require reconstructing a dynamic header.

### 2e. Two version labels, and why the pin is a non-event

The KSI framework says `version: 2026.07.14.01`. rampscan pins
`2026.09.13.02` (`packages/dataset/src/pins.ts:45`). The FRR framework Prowler
added later says `2026.09.13.02` — **Prowler's own two frameworks are pinned to
different dataset versions**, which is worth knowing before trusting either
label as a statement about the other.

It does not matter for the KSIs, and this is checkable rather than assumable.
The 46 ids in Prowler's file and the 46 in rampscan's pinned dataset are
**identical in both directions — nothing in Prowler that rampscan does not
have, nothing in rampscan that Prowler does not have.** P1 had already recorded
why: the 46 KSIs, their statements and their control mappings are byte-identical
between `2026.07.14.01` and `2026.09.13.02`, which is exactly what let the
crosswalk be re-pinned without re-reading an entry.

**So P3 needs no crosswalk.** The `--crosswalk` flag on `ingest` maps *Phase
One* indicators to the 2026 catalog; Prowler already emits 2026 ids. The
adapter resolves KSI ids against the pinned catalog directly, and a Prowler
framework whose ids stop resolving is a refusal, not a mapping problem.

The FRR framework is **P2's** territory, not P3's, and it is a live competitive
fact rather than a build item: 158 requirements at class C, of which **17 have
at least one check**. That is the same question `rampscan submission` answers,
and the two denominators do not agree with P2-0's (129 applicable at class b,
131 at c, 132 at d). Whether Prowler's 158 counts something P2-0 excludes, or
the reverse, is a real question and is **not** answered here. It belongs in a
P2 follow-up; it should not be guessed at in a P3 PR.

## 3. What already exists

The contract a fourth source must satisfy is mapped in full in the session
scratch notes; the load-bearing parts:

- **One command, no registry.** `rampscan ingest <path>`
  (`packages/cli/src/main.ts:390-413`) picks its adapter by **sniffing**
  (`ingest.ts:234-316`): `.yaml`/`.yml` → package; any other file → native
  JSON; a directory → tree. There is no discriminator on disk and no plugin
  table. A Prowler adapter must either extend that sniff or introduce the
  registry that does not exist.
- **Every adapter outputs native `IngestSubmission[]`** (`ingest.ts:36-37`), so
  the digest discipline is identical on every path.
- **Verdict is computed, never declared** (SPEC §12.8, `SPEC.md:437`): no
  assertion at all → `unevidenced`; *"`evidenced` is earned only by an assertion
  that passed over rows (#147; `[].every()` is true and is the one truth this
  function never signs)"*.
- **Exit 0 proves collection, not compliance** (`SPEC.md:448`).
- **Refusal before append** (`SPEC.md:452`): an unresolvable KSI or a duplicate
  `(recipe, KSI)` refuses the **whole batch** before anything is signed.
- **`MethodSource` is a closed union** (`method.ts:144-149`): *"a fourth source
  is a schema change with its own provenance block and its own `automated`
  decision, never a string somebody types."*
- The two precedents on `automated`: the package adapter signs nothing and takes
  `automated: false` (`SPEC.md:450`); the runner takes
  **`automated: ctx.assertions.length > 0`** (`runs-intake.ts:354`, *"a machine
  validated this only if an assertion was evaluated over it"*).

## 4. The design

### 4a. Which source — `aws-ingested`, and AWS only, for the first cut

**Decided 2026-09-18 (owner): no schema change. P3 scopes to Prowler's AWS
provider and mints `aws-ingested` methods.** A Prowler AWS scan *is* a client-run AWS
result; that is the source's definition, not a loophole. `recipe_id` carries
the Prowler check id, which the "upstream's names, not ours" convention already
asks for, and the fold leg, the verify rendering and the §12.10 composition row
all work unchanged.

The cost is honest and should be written down: `aws-ingested` is the wrong name
for an Azure, GCP, Kubernetes or M365 scan, and the day a second provider is
wanted, that is the schema change `method.ts:144-149` describes — a fourth
source with its own provenance block and its own `automated` decision. AWS is
also where the coverage is (33 of 46 against 23, 19, 16, 15), so nothing is
lost by starting there and the naming stays true.

### 4b. Who evaluates — the question the whole item turns on

Prowler's `PASS`/`FAIL` is **Prowler's** assertion, not one the appliance
evaluated. It sits between the two precedents: the package adapter refused to
sign a third party's reading; the runner evaluates rampscan's own pinned
assertions over raw bytes.

**Decided 2026-09-18 (owner): rampscan evaluates its own assertion over
Prowler's rows**,
exactly as the tree adapter does, using the existing row-wise evaluator
(`packages/core/src/assert.ts`) over the OCSF findings for one KSI. `automated`
then follows the runner's rule — `assertions.length > 0` — rather than being
typed. Signing `automated: true` over an unexamined third-party verdict is the
claim S3-1 specifically refused to make about the Paramify package, and it
would move the `FRC-CSX-VVK` numerator on someone else's say-so.

### 4c. The vacuous pass this input introduces — write this test first

The obvious assertion is *"no FAIL rows for this KSI"* — `count_eq 0` over rows
where `Status == "FAIL"`. **Over a KSI whose only row is `MANUAL`, that passes.**
Thirteen of the 46 are in exactly that state, and they are the thirteen no
scanner can see. A naive adapter would therefore sign `evidenced` for the
thirteen indicators it has the *least* evidence about — which is #147 arriving
through a new door, and `SECURITY.md`'s class.

Three defences, in order:

1. **A `MANUAL` row is never evidence.** Filter `Status == "MANUAL"` out
   *before* the evaluator sees the rows, and if nothing survives, the KSI is
   **skipped and named** the way a failed run is (`SkippedEntry`,
   `ingest.ts:66-71`) — never a bundle under any verdict. It then lands in
   **G1** (`gaps.ts:96-112`, *"no validation method derives — nothing to cite is
   the finding"*), which is the honest place, and the board is unchanged from
   having never run Prowler at all. That is the correct outcome: a scan that
   could not look at something has told you nothing about it.
2. **The assertion must state its own population.** `count_eq 0` over zero
   surviving rows must fail, not pass. The labeled evaluator already takes this
   position for its own ops (`assert-labeled.ts:287-290`, *"`every element` over
   nothing is the vacuous pass ground rule 7 forbids"*); the row evaluator
   passes an empty filtered set vacuously by design, so the adapter carries the
   non-emptiness check rather than changing a shared evaluator under other
   callers' feet.
3. **The exit code decides nothing.** Prowler exits **3** when unmuted failures
   exist, **1** on a critical error, **0** otherwise — and exit 3 is suppressed
   by `-z` / `--ignore-exit-code-3`, and is *not* emitted when every failure is
   muted (`prowler/__main__.py:1549-1554`). So a clean exit 0 is consistent with
   a scan that failed everything and muted it. Exit 0 here is weaker than the
   tree adapter's exit 0, and the #147 rule applies with more force, not less:
   non-zero is a failed run and is skipped; zero is a run that finished, and the
   verdict comes from the assertion.

**`Muted` is a column on every row.** A muted finding is a provider's decision
to stop counting something. It must not silently pass: either muted rows are
excluded from the population and named, or the submission refuses. Not decided
here — it is a build item.

### 4d. The reviewed artifact — and the labels.json lesson

The tempting artifact is a rampscan-owned check→KSI table. **That is the
`labels.json` mistake repeated.** P1 deleted `recipes/aws-actions/labels.json`
because it duplicated something upstream had begun publishing, and a row that
looked current was one upstream renumbering away from naming the wrong thing
(`packages/cli/src/aws-labels.ts:1-19`). Prowler publishes the mapping; rampscan
must not keep a second copy of it.

What *is* owed is a pin and a golden test, in the shape §6's four-part pattern
already uses: the framework file vendored at a `sha256` and its `version`, the
way the three FedRAMP schemas and the SDR schema are (the **fifth** pin), plus a
test asserting **both ways** that every KSI id in the pinned framework resolves
at rampscan's dataset pin and every KSI in the catalog appears in the framework
— the check that produced §2e's result, run in CI instead of once by hand. The
13 uncovered indicators are recorded with a `basis` per row, because *that* is a
judgement: "no automated check exists for this on any provider at this pin" is a
fact about the artifact and needs to be re-read when the pin moves, not
re-stamped.

## 5. Two answers that must not disagree

`rampscan submission`'s KSI half (P2-1, §9.6) already measures what a package
omits from its `keySecurityIndicators` rows, and the register's G1 section
already measures which KSIs derive no method. A Prowler ingest moves the second
and must not be allowed to quietly move the first: **what Prowler covers is a
statement about rampscan's evidence, not about the provider's submission.** A
KSI that Prowler evidences is still omitted from the SDR if the provider did not
write the row — that distinction is exactly the `computed`/`declared` versus
`answered`/`omitted` split P2-1 was re-scoped around (§9.3 of the rejection
note), and P3 is the first change that could re-conflate them.

Concretely: ingesting Prowler must change the **method** registers and the G1/G2
counts, and must change **nothing** in `rampscan submission`'s omission
arithmetic.

## 6. Build items

- **P3-0.** Vendor `fedramp_20x_ksi_2026.json` pinned on `version` + `sha256`
  (the fifth pin), with the both-ways golden test of §4d. Failing test first:
  the id-set comparison, and a planted framework with an id that does not
  resolve at the pin refusing rather than skipping.
- **P3-1.** The OCSF reader: parse a Prowler compliance OCSF file, group
  findings by `Requirements_Id`, and refuse a document that is not one
  (no framework header, a framework that is not `FedRAMP-20x-KSI`, a KSI id
  that does not resolve). `MANUAL` rows recognised and set aside here, not
  downstream.
- **P3-2.** **The soundness test, written before the adapter** — the §4c
  trio, as `ingest-soundness.test.ts` was written for #147: a KSI whose only
  row is `MANUAL` never reads `evidenced`; an assertion over zero surviving rows
  fails; exit 0 with `-z` does not outvote a FAIL row. `it.fails` until P3-3.
- **P3-3.** The adapter: sniff extension, `IngestSubmission` per (check, KSI),
  `evidence_class: "process-generated"`, `automated` from the runner's rule,
  `signer_identity` on the `runner:` convention, `reproduce` carrying the
  invocation. Uncovered KSIs skipped and named, never minted.
- **P3-4.** The `Muted` decision (§4c), and the `--provider` guard that refuses
  a non-AWS Prowler document until a fourth `MethodSource` exists.
- **P3-5.** The register e2e: ingesting raises a KSI's method count, removing it
  lowers it again, and `rampscan submission`'s numbers do not move (§5).

## 7. Estimate, with the P1 and P2 lessons applied

P1 was a week because the cost was set by how far the *overlays* had moved, not
by what FedRAMP published. P2's equivalent question was how much was new
declaration surface rather than new reading. Here it is: **how much of this is
reading a published mapping, and how much is judgement?**

Almost all of it is reading. The mapping is upstream's, the ids match the pin
exactly, the grain fits the method identity without a new layer, and the
`MANUAL` row means the hardest case announces itself. **P3-0 through P3-3 are
the shippable core** and are small — a reader, a pin, a sniff, and the soundness
test that is the actual work.

The judgement is concentrated in two places, and neither compresses: the
`Muted` decision, and the §5 guarantee that P3 does not move P2's arithmetic.
The risk is not effort, it is the vacuous pass — which is why P3-2 is written
before P3-3 rather than after.

## 8. What this is worth publicly

The crowded-field response was opened because Prowler arrived. **The honest
reading is that Prowler is a source, not a rival**, and P3 is the change that
says so in code.

The number worth publishing is §2c's: at the current pin Prowler's KSI framework
reaches **33 of 46** indicators on AWS and **none** of the thirteen that are
periodic human activity — and it says so itself, in a `MANUAL` field, on every
one of them. A provider who runs Prowler and reads the summary sees a scan that
completed. A provider who runs it through rampscan sees thirteen indicators that
nothing evidenced, priced against the class B catalog, with the reason attached.

That is the product argument in one sentence, and it is stronger for being made
*with* the best open-source scanner in the field rather than against it:
**Prowler answers what it can see, and rampscan is what counts the rest against
you.**

## 9. What this note did not establish

Marked unknowns, not guesses. Each needs answering before or during the item
that depends on it.

- **The OCSF compliance JSON's exact per-finding schema.** The CSV row model was
  read in full; the OCSF sibling (`universal/ocsf_compliance.py`) was not. P3-1
  depends on it.
- **Whether the scan's arguments are recoverable from the output alone** — in
  particular whether `-z`, `--status`, `--severity` or a mute configuration can
  be detected by a consumer. If they cannot, a filtered scan is
  indistinguishable from a full one and the adapter must say so rather than
  assume a full one. **This is the most important open question in the note.**
- **Any scan-level provenance** — a scan id, start/end timestamps, the Prowler
  version, the account id — beyond the per-row `AssessmentDate`, `AccountId` and
  `Region`. Nothing signs or checksums Prowler's output, so the appliance's own
  signature over the submitted bytes is the only integrity there is.
- **Which Prowler release first ships the framework.** The PR references SDK
  `5.32.0 UNRELEASED`; not confirmed against a published release.
- **Whether the framework file format is stable.** It has already changed shape
  once since the PR that introduced it (five files → one), which is itself the
  argument for pinning on `sha256` rather than tracking `master`.
- **The 158 vs 129/131/132 discrepancy** between Prowler's FRR class C framework
  and P2-0's rule register (§2e). A P2 question, deliberately left open.

---

## Session log

- **2026-09-18** — Written at `main` = `d4b372c`, after P2 closed (#216 merged,
  #211 closed). Coverage, id-set equality, check reuse and the class
  distribution computed over the pinned upstream file; the CSV row model, the
  `MANUAL` emission, the universal-writer routing and the exit codes read from
  Prowler's source at `master`. The owner took §4a (AWS-only inside
  `aws-ingested`, no schema change) and §4b (rampscan evaluates its own
  assertion) as recommended, both recorded in place. Next: P3-0, the pin and
  the both-ways golden test.
