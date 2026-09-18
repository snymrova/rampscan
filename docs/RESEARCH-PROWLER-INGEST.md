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
  (the fifth pin; the exact values are in §10f, and the pin records the source
  **commit** because no release carries the file), with the both-ways golden
  test of §4d. Failing test first: the id-set comparison, and a planted
  framework with an id that does not resolve at the pin refusing rather than
  skipping. The test compares **class applicability** as well as the id set
  (§10a) — the second place the two catalogs can diverge at a re-pin.
- **P3-1.** The OCSF reader, against §10a's field table — **not §2d's**, which
  names the CSV's columns: parse the JSON array of `ComplianceFinding` events,
  group by `compliance.requirements[0]`, and refuse a document that is not one
  (`compliance.standards[0]` not the KSI framework, a KSI id that does not
  resolve at the pin, a file that is not an array). **An absent or empty file
  is a refusal, not zero findings** (§10a: no findings means no file, and no
  `MANUAL` rows either). `MANUAL` rows recognised by all three of §10a's
  markers and set aside here, not downstream.
- **P3-2.** **The soundness test, written before the adapter** — the §4c
  trio, as `ingest-soundness.test.ts` was written for #147: a KSI whose only
  row is `MANUAL` never reads `evidenced`; an assertion over zero surviving rows
  fails; exit 0 with `-z` does not outvote a FAIL row. `it.fails` until P3-3.
- **P3-3.** The adapter: sniff on **content**, not filename (the labels.json
  lesson again — `compliance.standards[0]` is in every row);
  `IngestSubmission` per (check, KSI) grouping many rows, because one check over
  many resources is many rows and a per-row submission trips ingest's duplicate
  refusal on the whole batch (§10e); the assertion evaluated over **`status_code`,
  the effective status** (§10d), with the raw check status and any
  config-override marker carried in the transcript;
  `evidence_class: "process-generated"`, `automated` from the runner's rule,
  `signer_identity` on the `runner:` convention, `reproduce` carrying the
  invocation. Uncovered KSIs skipped and named, never minted.
- **P3-3a.** The **mapped-check coverage measure** (§10c), which §6 did not have
  before the arguments turned out to be unrecoverable: `reported / mapped` per
  KSI against the pinned framework's AWS list, recorded on the submission and
  printed. It is what lets the appliance state the population it evaluated
  instead of calling a filtered scan a scan.
- **P3-4.** The `Muted` decision (§4c) — the field is `status_id` /
  `status == "Suppressed"`, not a boolean (§10a) — and the `--provider` guard
  that refuses a non-AWS Prowler document until a fourth `MethodSource` exists.
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

One qualification, from §10f: **no published Prowler release ships the KSI
framework yet** — its only commit postdates 5.42.0. Until one does, the sentence
above is about Prowler at `master`, and saying so is the difference between the
claim being true and being the kind of thing this project exists to catch.

## 9. What this note did not establish

Marked unknowns, not guesses. Each needs answering before or during the item
that depends on it. **Four of the six were answered the same day, in §10**;
each is marked with where. Left as written, with the answers beside them,
rather than edited into hindsight.

- ~~**The OCSF compliance JSON's exact per-finding schema.**~~ **Answered, §10a.** The CSV row model was
  read in full; the OCSF sibling (`universal/ocsf_compliance.py`) was not. P3-1
  depends on it.
- ~~**Whether the scan's arguments are recoverable from the output alone**~~
  **Answered, §10b — no.** — in
  particular whether `-z`, `--status`, `--severity` or a mute configuration can
  be detected by a consumer. If they cannot, a filtered scan is
  indistinguishable from a full one and the adapter must say so rather than
  assume a full one. **This is the most important open question in the note.**
- ~~**Any scan-level provenance**~~ **Answered, §10a/§10b — none as a header;
  the Prowler version, account, region and timestamp are per-row.** — a scan id, start/end timestamps, the Prowler
  version, the account id — beyond the per-row `AssessmentDate`, `AccountId` and
  `Region`. Nothing signs or checksums Prowler's output, so the appliance's own
  signature over the submitted bytes is the only integrity there is.
- ~~**Which Prowler release first ships the framework.**~~ **Answered, §10f:
  none yet.** The PR references SDK `5.32.0 UNRELEASED`; the framework's only
  commit postdates the latest release, so it is `master`-only today.
- **Whether the framework file format is stable.** Still open — and §10f's
  release gap is a second reason to expect movement. It has already changed shape
  once since the PR that introduced it (five files → one), which is itself the
  argument for pinning on `sha256` rather than tracking `master`.
- **The 158 vs 129/131/132 discrepancy** between Prowler's FRR class C framework
  and P2-0's rule register (§2e). A P2 question, deliberately left open.

---

## 10. §9 answered — the OCSF row, and the arguments that are not in it

Read at `master` after §9 was written: `universal/ocsf_compliance.py` (477
lines), `compliance.py`, `prowler/__main__.py`, `lib/check/check.py`,
`lib/check/compliance_config_eval.py`, `lib/check/compliance_models.py` and the
framework file at its only commit. Four of §9's six items are closed below.
Two stay open: whether the file format is stable — §10f's release gap is a
second reason to expect it to move — and the 158-vs-129 discrepancy, which
stays P2's.

### 10a. The OCSF row — and §2d names fields the adapter will not see

§2d documented the **CSV** row, because that is what the universal writer's
table path emits. The adapter reads the **OCSF** sibling (§2d's own conclusion),
and the OCSF writer is a different function with different field names. A
reader written against `Status`, `CheckId`, `Muted`, `Requirements_Id` finds
**none of them**. Correcting that here rather than letting P3-1 discover it.

The file is a bare JSON **array** of OCSF `ComplianceFinding` events
(`class_uid` 2003), serialised `exclude_none=True` — so absent fields are
absent, not null. Per row, what P3 needs:

| Meaning | OCSF path | Note |
|---|---|---|
| KSI id | `compliance.requirements[0]` | an array; one row per (finding × requirement) |
| Framework + version | `compliance.standards[0]` | `"FedRAMP-20x-KSI-2026.07.14.01"` — `framework + "-" + version` |
| Effective status | `status_code` | `PASS` / `FAIL` / `MANUAL` |
| Raw check status | `compliance.checks[0].status` | the check's own verdict, **before** config override |
| Check id | `compliance.checks[0].uid`, `metadata.event_code` | both carry it |
| Muted | `status_id` / `status` | `Suppressed` when muted, else `New` — **not** a boolean |
| Prowler version | `metadata.product.version` | per row, on manual rows too |
| Account / region | `unmapped.cloud.account.uid`, `.region`; `resources[0].region` | |
| Timestamp | `time`, `time_dt` | manual rows carry the scan-start timestamp |
| Requirement attributes | `unmapped.requirement_attributes` | `theme`, `nist_controls`, `class_applicability` |

The attributes survive because `OutputFormats.ocsf` defaults to `True`
(`compliance_models.py:629`) and this framework declares no `output_formats` on
any of its three `attributes_metadata` entries. So **`ClassApplicability` is in
the output** — `"Required for Classes B and C"` or `"Optional for Class B,
required for Class C"` — and the both-ways golden test of §4d should compare it
against rampscan's own class applicability as well as the id set, since it is a
second place the two catalogs can silently diverge at a re-pin.

A **`MANUAL` row is a different constructor**
(`_build_manual_compliance_finding`, `ocsf_compliance.py:381-432`) and is
identifiable three independent ways: `status_code == "MANUAL"`,
`metadata.event_code == "manual"`, and `finding_info.uid` prefixed `manual-`.
It carries **no `compliance.checks` and no `resources` at all**, and no
`unmapped.cloud` — so a reader that reaches for the check id on every row throws
on exactly the thirteen indicators §4c is about.

**The file is absent, not empty, when a scan finds nothing.**
`OCSFComplianceOutput.__init__` guards `if findings:` before `_transform`
(`ocsf_compliance.py:148-156`), and the manual rows are emitted *inside*
`_transform` — so zero findings means no transform, no file descriptor, no
file, **and no thirteen MANUAL rows either**. A missing or empty compliance
output is therefore a refusal, never "the scan evidenced nothing".

### 10b. The arguments are not recoverable. This is the answer, and it is no.

§9 called this the most important open question. Prowler serialises its own
command line **exactly once in the entire codebase** — `prowler_args = " ".join(sys.argv[1:])`
at `__main__.py:646`, inside the Slack block, passed to `slack.send(stats, prowler_args)`
and written to a chat message. **No output file records it.** The OCSF
compliance array has no header object of any kind: no scan id, no arguments, no
mutelist path, no start/end pair. Everything in §10a's table is per-row.

And the filters are applied upstream of every writer, so their effect is
removal, not annotation:

- **`--status`** drops findings inside `execute_checks`
  (`check.py:754-760`, *"Exclude findings per status"*), before muting, before
  `Finding.generate_output`, before any output object exists. A
  `--status PASS` scan writes a compliance file containing PASS rows and the
  thirteen MANUAL rows and **nothing else**.
- **`--severity`**, `--check`, `--service`, `--excluded-check` narrow
  `checks_to_execute` (`__main__.py:362`) — the checks never run.
- **The mutelist** is the one that does annotate: muted findings keep their
  status and are flagged, reaching OCSF as `status = "Suppressed"` (§10a).

So a full scan and a filtered one are **indistinguishable from the document**,
and §4c's third defence generalises: the exit code is not the only thing about
this input that decides nothing. The adapter must **state the population it
evaluated** rather than describe what it read as a scan.

### 10c. What is recoverable — the mapped-check coverage measure

The constructive half. rampscan holds the pinned framework, so for each KSI it
knows the full set of AWS check ids upstream maps to it; the OCSF file names
which of them actually reported. **`reported / mapped` per KSI is computable**,
and it is the honest description of the population the assertion ran over.

It is also a real defence, and the exact size of it is worth stating rather
than overselling. Hiding a failure with `--status PASS` removes that check's
FAIL row — and if that check produced no other row for the KSI, it drops out of
the reported set and coverage falls below full. **A `--status PASS` scan cannot
manufacture full mapped-check coverage** unless the hidden check also passed on
some other resource, which is only possible for a check that returned mixed
results across resources. That residual is narrow, nameable, and does not
compress further; it is the reason coverage is *recorded and printed* rather
than treated as proof of a complete scan.

This is also a build item §6 did not have. It belongs to P3-3, beside the
submission's `reproduce`.

### 10d. A scan's own config can force FAIL — read the effective status

Not in §9 because the note had not found it. `apply_config_status`
(`compliance_config_eval.py`) lets a requirement declare `ConfigRequirements`
over the configurable checks it maps, and when the scan ran with a config too
loose to satisfy them the requirement is **forced to `FAIL` regardless of the
finding's own status**, with the reason prepended to the message. The module's
worked example is CIS AWS 6.0 §2.11: loosen `max_unused_access_keys_days` to
120 and `iam_user_accesskey_unused` passes while the requirement is not
satisfied.

Upstream made it machine-detectable on purpose — `CONFIG_NOT_VALID_PREFIX`
(*"Configuration not valid for this requirement."*) is documented as opening
every such message so it "doubles as a stable marker for detecting the case
programmatically". In OCSF the row then carries `status_code == "FAIL"` with
`compliance.checks[0].status == "PASS"`, and the marker at the head of
`message` / `status_detail`.

**rampscan evaluates over `status_code`, the effective status, not the nested
raw check status.** The nested one is the looser of the two readings, and
taking it would reintroduce exactly the hole upstream closed. The raw status
travels in the transcript, and a divergence between the two is recorded rather
than discarded — it is a fact about the scan's configuration, which is the one
piece of scan-level context this input does carry.

### 10e. One check is many rows — group before submitting

`finding_info.uid` is `f"{finding.uid}-{requirement.id}"`, unique per resource.
One check over forty IAM users emits forty rows for the same KSI, and one
finding whose check maps to two KSIs is emitted twice (§2b). So **`(check_id,
KSI)` is not unique in the file**, and rampscan's ingest refuses a duplicate
`(recipe, KSI)` by rejecting the *whole batch* before anything is signed
(`SPEC.md:452`). §6's P3-3 already says "`IngestSubmission` per (check, KSI)" and is
right; the reason it cannot be per row is recorded here, because the failure
mode is a refused batch rather than a wrong number.

### 10f. No published release ships this framework

`fedramp_20x_ksi_2026.json` has **one commit**, `1b228d59`, 2026-09-14. The
latest Prowler release is **5.42.0, published 2026-09-11**, and the file returns
404 at both `5.42.0` and `5.41.0`. §9's question is closed: **no published
release ships it** — not this framework, and not the pilot frameworks the PR
replaced. Today the input P3 ingests can only be produced from `master`.

That does not block P3: the artifact is pinned and the fixtures are written
against it either way. It does qualify §8's public argument, which should say
`master` until a release carries it, and it is one more reason the pin is on
`sha256` and the golden test runs both ways.

**The pin for P3-0**, computed:

| | |
|---|---|
| Path | `prowler/compliance/fedramp_20x_ksi_2026.json` |
| Commit | `1b228d590b5f`, 2026-09-14 |
| `framework` | `FedRAMP-20x-KSI` |
| `version` | `2026.07.14.01` |
| `sha256` | `cc1a5fa8c88ee4e327c84ae871b8e51553b4d0c614193a25a0d5490449a8e766` |
| Bytes | 89,892 |

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
- **2026-09-18 (§9 answered, §10)** — #217 merged; `main` = `6bf24d0`. The
  §9 unknowns taken before P3-0, because the one the note called most important
  could have forced a rewrite. It did not force a rewrite; it forced a build
  item. **The arguments are not recoverable** — Prowler serialises its own
  `sys.argv` exactly once in the codebase, into a Slack message, and no output
  file carries it — and `--status` drops findings inside `execute_checks`
  before any writer exists, so a `--status PASS` scan and a clean scan are the
  same document. The constructive answer is §10c's mapped-check coverage, now
  P3-3a: the pinned framework names the checks each KSI expects, the file names
  the ones that reported, and hiding a FAIL removes its check from the reported
  set unless that check also passed on another resource — a narrow, nameable
  residual instead of an assumption. Three things the note had wrong or missing:
  §2d documents the **CSV** row and the adapter reads **OCSF**, where none of
  those field names exist (§10a); a scan's own config can force a requirement to
  `FAIL` while the nested check still reads `PASS`, so the effective
  `status_code` is the one to evaluate (§10d); and no findings means **no file
  at all**, not an empty one, so a missing document is a refusal rather than
  thirteen `MANUAL` rows. Also computed: the pin (`1b228d59`, sha256
  `cc1a5fa8…`, 89,892 bytes) and the fact that **no published release ships the
  framework** — 5.42.0 predates its only commit by three days, which qualifies
  §8's public claim. Next: P3-0.
