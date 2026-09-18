# P2 — the rejection linter

> **Status.** Research and design, 2026-09-18. **P2-0 built 2026-09-18**; its
> numbers corrected §2a in the same change, because they did not reproduce.
> **P2-3 and P2-4 built 2026-09-18** — `rampscan submission` ships the six
> sections. **P2-2 built 2026-09-18**: `offering.ruleCoverage` is the
> declaration surface, so `declared` is now a reachable state and §4b's table
> is three-quarters live. `outside` still is not, which is P2-1 and is why the
> unaddressed count remains an upper bound rather than a finding. The build
> items are §6; the estimate and its caveat are §7.

## 1. The source

[FedRAMP/community#167](https://github.com/FedRAMP/community/discussions/167),
*"20x Class B/C Certification submissions now open!"* — `emu-gov`, 2026-08-31,
category *20x Discussion*. **Zero comments**, so the post body is the whole of
it; there is no thread to mine and nothing to keep watching but the post itself.

It announces the submission form going live at 0900 ET and then lists, in the
program's own words, "a few top reasons why your submission might get rejected":

1. **Trust Center gated.** "Your Trust Center requires acknowledgement and/or
   acceptance of a privacy policy, terms of service or non-disclosure
   agreement — *I am but a humble civil servant and cannot agree to such things
   on behalf of our agency*."
2. **Incomplete package.** "If you don't have your SDR ready, come back later
   when you do. Also be mindful we ask for both human-readable and
   machine-readable files and any rule that calls out a specific schema should
   have at least an example provided."
3. **Missing rules and/or KSIs.** "Remember that **ALL** *MUSTs* and *SHOULDs*
   applicable to your class need to be addressed. If you don't have something
   implemented, say so and tell us why, don't just omit the KSI or rule
   altogether."
4. **JSON not following the schema.** "our minimal structure and required
   fields should be present."
5. **Assessment content missing.** "Independent Assessment Service's content
   not included in CPO and SDR."

Two of those are worth reading twice, because they are not what a compliance
tool usually checks:

- **Reason 3 makes omission the failure, not non-implementation.** A package
  that says "not implemented, and here is why" passes; a package that is silent
  is rejected. That is ground rule 10 — agreement and disagreement are both
  declared, never silent — stated by the program itself as a submission
  criterion. rampscan has the vocabulary for this already and has never pointed
  it at the rule set.
- **Reason 1 is a property of a live URL**, not of a file. Nothing in a package
  reveals it. It is the one reason a local appliance cannot answer, and the
  linter's job there is to say so rather than to pass.

## 2. Where each reason is binding — computed from the pin

Every reason has an authority in the pinned register (`2026.09.13.02`), which
is what makes this a check rather than a checklist. Each row below was computed
from `docs/context/fedramp-rules/fedramp-consolidated-rules.json`, not typed.

| # | Reason | Authority |
|---|---|---|
| 1 | Trust Center gated | `CDS-TRC-USH` (MUST share "without interruption"), `CDS-TRC-PAC` (MUST provide "documented programmatic access to all FedRAMP Certification Data, including programmatic access to human-readable materials"), `CDS-TRC-HMR` (SHOULD, both formats) |
| 2 | Incomplete package | `FRC-CSO-PKG` (MUST supply a complete package), `CPO-CSO-OVR` (MUST supply the overview "in both human-readable and JSON formats"), and `schema.url` on each rule that names one |
| 3 | Missing rules / KSIs | `force` + `applicability` per rule, `varies_by_class` where the force is per class; `FRC-CSX-MAS` (SHOULD apply all KSIs across the assessment scope) |
| 4 | JSON invalid | `FRC-CSO-JSN` (MUST be valid against the corresponding schema when a rule names one) |
| 5 | Assessment content | `IVV-CSO-ICP` (MUST supply independent assessment results "without inappropriate modification"), named inside `CPO-CSO-OVR`'s own `following_information` list |

### 2a. The per-class denominator, and the trap in reading it

`force` is a per-rule field **except** for 29 rules that carry
`varies_by_class` instead, where the force is per class — `FRC-CSX-VVK` reads
`MAY / SHOULD / MUST / MUST` across a–d. Reading the top-level `force` alone
returns `None` for all 29 and makes every class look identical (the first pass
of this research reported 147 addressable rules for every class, which is the
shape of that mistake). Reading the effective force separates them:

| Class | MUST | SHOULD | Addressable FRR rules | Plus KSIs |
|---|---|---|---|---|
| B | 88 | 41 | **129** | 46 |
| C | 91 | 40 | **131** | 46 |
| D | 92 | 40 | **132** | 46 |

> **Corrected 2026-09-18, P2-0.** This table first read 84/37/**121**,
> 85/38/**123**, 86/38/**124**, and *those numbers do not reproduce* — not at
> this pin and not at `2026.07.14.01` either, under any filter that can be
> stated. The counts above are what `loadRuleRegister` + `addressableRules`
> compute, pinned in `packages/dataset/test/rule-register.test.ts`. The rule
> count was also wrong (29 class-varied rules, not 25). The first pass's real
> error was not arithmetic: it reported numbers it had not re-derived from the
> reader that would go on to produce them, which is the mistake CONTRIBUTING
> rule 4 exists to prevent and which this note itself claimed to have avoided.

Filter, and each clause matters: the rule's scope is not `rev5` (a 20x
certification does not owe the 12 Rev5-only rules — this is the clause the
first pass is likeliest to have been missing, since without it the counts are
141/143/144); the subset's `applicability.types` includes `20x` and its
`applicability.classes` includes the class, **when the subset declares any**
(§2b); the rule's own `affects` includes `Providers`; effective force `MUST` or
`SHOULD`.

Upstream's own `obligations.json` corroborates more than the shape, and this is
the check worth keeping: its `forceDistribution` reports `MUST` 136 / `MUST NOT`
11 / `SHOULD` 45 / `SHOULD NOT` 5 / `MAY` 20 by requirement, and 189 / 11 / 84 /
5 / 39 once class variants are expanded — and the register **reproduces both
arms exactly**, from the other leg of §12.4. A walk that agrees to the unit with
a distribution this repository did not derive is a walk that is reading the
file correctly, which is why that equality is asserted in the test rather than
admired in a document.

**That set is reason 3's denominator.** It is also the number nobody in this
field publishes, which is most of why P2 is worth building.

### 2b. A metadata gap that must not be read as "not applicable"

`FRR.SDR.info.subsets` declares one subset, `CSO`. The data carries two: the
`20x` slice holds a `CSX` subset with `SDR-CSX-KSI` and `SDR-CSX-KMT`. It is
not a one-off — **four subsets carry rules and no declared applicability**:
`CPO/CSX`, `FRC/CSX`, `IVV/CSX`, `SDR/CSX`. Every one of them is a `20x` subset,
which is to say the gap falls precisely on the rules specific to the programme
this tool serves.

Confirmed at the pin, with one thing added: those four are the subsets *a 20x
register can reach*. Across the whole file there are **nine** — `CDS/CSF`,
`CPO/CSF`, `FRC/CSF`, `IVV/CSF` and `SDR/CSF` carry the same gap under `rev5`
scope, which the filter above excludes. So the four is right and is a
consequence of the scope clause, not independent of it.

So a loader that reads missing applicability as "does not apply" would silently
drop `FRC-CSX-VVK` (the method floor), `FRC-CSX-MOT` (the history floor) and
`SDR-CSX-KSI` (the five owed artifacts) — the three rules this entire
repository is built on.

Undeclared applicability must therefore count as **applicable, and be
declared as undeclared**. `KsiRegisterView.summary.applicabilityUnstated`
already carries exactly this signal for KSIs; the rule side needs its twin.

### 2c. The schema-vendoring split

24 rules carry a `schema.url`. For provider rules at class B or C they resolve
to **eight distinct schema files**, of which this checkout vendors two; the
third vendored file, `common-definitions`, is named by no rule and is the
shared `$ref` target of the other two:

| Schema | Vendored | Rules (class B/C, provider) |
|---|---|---|
| `certification-package-overview` | **yes** | `CDS-CSO-PUB`, `CDS-CSO-SVC`, `CDS-CSO-UTC`, `CPO-CSO-OVR`, `FRC-CSO-PKG`, `MAS-CSO-TPR`, `SCG-CSO-RSC` |
| `ongoing-certification-report` | **yes** | `CCM-OCR-AVL` |
| `common-definitions` | **yes** | (`$ref` target for both) |
| `security-decision-record` | no | `SDR-CSO-FRR`, `SDR-CSX-KSI`, `SDR-CSX-KMT` |
| `incident-report` | no | `IEC-CSO-IIR`, `IEC-CSO-OIR`, `IEC-CSO-FIR`, `IEC-CSO-EFI` |
| `significant-change-notifications` | no | `SCN-CSO-EVA`, `SCN-CSO-INF`, `SCN-CSO-HRM` |
| `vulnerability-detail-report` | no | `VER-RPT-PER`, `VER-RPT-VDT` |
| `accepted-vulnerability-info` | no | `VER-RPT-AVI` |
| `historical-ver-activity` | no | `VER-TFR-MRH` |

`docs/context/fedramp-schemas/README.md` states the reason the other eight are
absent: *"a pinned file nothing validates against is a pin nobody is
checking."* That argument is sound and it is also exactly what P2 changes — for
the schemas the linter validates against, and for no others. The
`security-decision-record` schema is the pointed case, because the SDR is the
single most emphatic item in #167 ("if you don't have your SDR ready, come back
later when you do").

So P2 splits the two questions, and must never let them blur:

- **Naming** a schema-bearing rule with no supplied example is answerable for
  all eight, needs no new vendoring, and is reason 2's second clause.
- **Validating** against a schema is answerable for three, and the other five
  must print as unvalidatable rather than as clean.

## 3. What already exists

| Surface | What it does | Reason |
|---|---|---|
| `fedramp-conformance.ts` + `rampscan conformance` | validates documents on disk against the pinned schemas, and cross-checks each document's own `x-rampscan.conformance` stamp against a fresh validation, both directions | **4, built** |
| `fedramp-schemas.ts` | pins three schemas on `$schemaVersion` **and** sha256; hand-rolled validator over a closed keyword set that throws on anything outside it | 4 |
| `fedramp-exports.ts` | builds the two documents, and already carries a `problems: string[]` channel holding seven rejection-shaped findings — absent trust center (`CDS-CSO-UTC`), absent next-OCR date (`CCM-OCR-NRD`), absent assessor (`CDS-CSO-PUB`), application freshness (`FRC-APP-FCP`), and three on the OCR | 1, 2, 5 in part |
| `gaps.ts` + `rampscan gaps` | the gap register: sections keyed to a rule id **and its force**, rows of subject/detail/digest, and a first-class `unmeasured` channel | the structural template |
| `ksi-register.ts` + `rampscan frontier` | per-KSI floors, freshness, history, artifact counts; `null` never faked to `0`; class applicability read, never re-derived | 3, KSI half |
| `ingest-package.ts` | reads a real assessed package (YAML) into native submissions; signs no verdict, invents no digest | the input |
| `catalog.ts` | the one reader of rule text, already walking `FRR.<family>.<slice>.<subset>.<id>` and already unpacking `varies_by_class` for five rules | where the widening goes |

**What does not exist**, checked by grep rather than assumed:

- Nothing pairs a machine-readable file with a human-readable one. `fedramp-run.ts`
  writes JSON only; `checkConformance` globs `*.json` and cannot miss what
  isn't there. The human-readable renderings exist but go to the terminal and
  are never written. Reason 2's first clause is greenfield.
- Nothing asks "is every MUST/SHOULD applicable to class X addressed?". The
  codebase reasons against a hand-picked **~16 rule ids**, each hardcoded at
  the site that needs it. There is no enumeration of the rule set anywhere.
- Nothing fetches a trust center. `fedramp-exports.ts` scopes it out in a
  comment — "this document is designed to be what a trust center serves, not
  the trust center" — which is a deliberate boundary, not an oversight.
- The `CPO-*` rule ids have **zero** TypeScript references. The overview
  document is built and validated against the JSON *schema*; the `CPO-*` rules
  that say what must be in it are unread. `FRC-CSO-PKG.related[0]` is
  `CPO-CSO-OVR`, so the link from what is implemented to what is not sits in
  the data already.

One correction to a plausible-looking shortcut: **`obligations.json` is not the
feed for reason 3.** Its `deadlines` array carries `force` and `applicability`
per row, which looks like the whole rule set, but its 73 rows hold only **36
distinct rule ids** — the timeframe rules only, out of 246. The denominator has
to come from Path B, the
consolidated rules file, through `catalog.ts`.

## 4. The design

One new command, a sibling of `exports` and `conformance`, completing the
FedRAMP-package trio:

```
rampscan submission [path]        # the rejection register
  --class b|c        target certification class (default b)
  --package <file>   an assessed package to read (ingest-package.ts)
  --out <dir>        where the exports are, for the conformance arm
  --json
```

It prints a **rejection register**: one section per #167 reason, each carrying
the reason's own words as provenance, the rule ids that make it binding, and
rows. It exits 1 on any row that would be a rejection, per the house rule that
every gate command exits 1 on a finding.

`gaps.ts` is the shape to copy, not `fedramp-conformance.ts` — sections keyed
to rule id + force, with an `unmeasured` channel that distinguishes *nothing
found* from *never checked*.

### 4a. The six sections

| Section | Asks | State today |
|---|---|---|
| `trust-center-gate` | does the declared trust center serve certification data without an acknowledgement gate? | **`unmeasured`, always, until P4.** Prints the declared URL and `authenticationRequired`, names `CDS-TRC-USH` / `CDS-TRC-PAC`, and says plainly that this appliance does not fetch. |
| `unaddressed-rules` | is every applicable MUST/SHOULD addressed? | the new work — §4b |
| `unaddressed-ksis` | is every applicable KSI addressed? | reads `ksi-register.ts`; the register already knows |
| `missing-example` | does every applicable schema-bearing rule have a document supplied? | new, cheap, complete for all eight schemas |
| `schema-invalid` | are the supplied JSON documents valid? | **reads `checkConformance`, does not re-implement it.** Prints the five unvendored schemas as unvalidatable. |
| `assessment-content` | are the independent assessment results present in the overview and on the SDR plane? | `IVV-CSO-ICP`; wiring plus a cross-document presence check |

`trust-center-gate` printing as `unmeasured` rather than being omitted is the
most important line in the design. It is FedRAMP's **first** listed reason, it
is the one this appliance cannot answer, and a register that quietly left it out
would be a vacuous pass on the most likely rejection (ground rule 7).

### 4b. Reason 3, and the four states a rule can be in

The denominator is computable (129 at class b). The numerator is the hard part,
and getting it wrong in either direction is worse than not shipping it:

- rampscan **cannot see** whether a provider is listed in the FedRAMP
  Marketplace (`FRC-APP-MLF`) or completed the application form
  (`FRC-APP-AFC`). Reporting those as *unaddressed* would be a false accusation
  at scale — 129 rows of mostly noise, which is how a linter gets ignored.
- Reporting them as *fine* is the vacuous pass.

So every applicable rule resolves to exactly one of four states, and the
register prints the counts:

| State | Meaning |
|---|---|
| `computed` | rampscan itself evidences the rule (`FRC-CSX-VVK` via the method floor, `SDR-CSX-KSI` via the artifact plane, `VDR-TFR-MVX` via the window meter, …) |
| `declared` | the offering declaration addresses it — **including "not implemented, and here is why"**, which #167 says explicitly is acceptable |
| `outside` | structurally not visible to a local appliance, and named as such rather than counted against the package |
| `unaddressed` | applicable, not computed, not declared, not outside — **this is the rejection** |

`outside` is itself a reviewed set, written down with a reason per rule the way
`recipes/aws-actions/allowlist.json` records a refused action. A rule cannot
drift into `outside` silently; that would be the escape hatch the whole check
exists to close.

This is what needs new declaration surface: `OfferingConfig` (a `strictObject`,
so this is a deliberate change) gains a rule-coverage block where a provider
addresses a rule with a citation or declines it with a reason. The linter then
refuses silence — which is #167's reason 3 turned into a typed, tested
requirement, and is the part of P2 that no other tool in this field does.

> **Built 2026-09-18, P2-2.** `offering.ruleCoverage`, a discriminated union on
> `status`: `addressed` carries a `citation`, `not-implemented` carries a
> `reason`, and `strictObject` on each arm means the wrong field for the status
> refuses rather than declaring nothing. Two refusals were not in this design
> and were found while building it, both worth recording because both are the
> same mistake wearing different clothes:
>
> - **A KSI indicator is the same shape as a rule id** (`KSI-CNA-OFA` against
>   `FRC-CSX-VVK`), so the regex that was supposed to catch typos accepted one.
>   It is refused by name now. Reason 3 has two halves and the KSI half is the
>   one rampscan *measures*; accepting a KSI here would have let a declaration
>   talk its way past the artifact plane and the method floor, which is the
>   part of #167 this appliance is best at.
> - **A declaration cannot overwrite a computation.** A config declaring
>   `FRC-CSX-VVK` addressed does not move it out of `computed`; the overlap is
>   reported instead. Same refusal as SPEC §12.4 rule 3, arriving from the
>   config side rather than the overlay side.
>
> Not dogfooded in `rampscan.config.json`, deliberately: rampscan is not a
> cloud service offering pursuing certification, and per-rule coverage is a
> provider's judgement about a package that in this repository's case does not
> exist. The block is exercised by the suite, including a parse of all 246 rule
> ids at the pin, which is the guard that matters — a rule set numbering rules
> differently must fail our test rather than a provider's config.

## 5. Two answers that must not disagree

`fedramp-exports.ts`'s `problems` channel already emits findings the register
will also want to print — trust center, assessor, freshness. The house treats
one fact computed twice as a bug (`ksi-register.ts:44`, `catalog.ts:196`).

So the register **reads** those problems rather than recomputing them, exactly
as the `schema-invalid` section reads `checkConformance`. P2 adds one computation
of its own — the rule-coverage sweep — and otherwise reprojects computations
that already exist under the names #167 uses. That also means the register
stays honest for free when those computations change.

## 6. Build items

- **P2-0.** Widen `catalog.ts` to enumerate the FRR rule set: every rule with
  its family, subset, effective per-class force, `affects`, `applicability`,
  and `schema.url`. One reader, in the package where rule text is read.
  Undeclared applicability surfaces as a flag, never as "not applicable"
  (§2b). Failing test first: the class B/C/D counts of §2a, and
  `SDR-CSX-KSI` present at class b.
- **P2-1.** The `outside` set — a reviewed artifact, one reason per rule,
  reviewed against a dataset version the way the allowlist is.
- **P2-2.** `OfferingConfig` rule coverage: address with a citation, or decline
  with a reason. Silence is neither.
- **P2-3.** `buildRejectionRegister` + `renderRejectionRegister`, six sections,
  `unmeasured` on `trust-center-gate`, reading the existing `problems` and
  `checkConformance` rather than re-deriving them.
- **P2-4.** `rampscan submission` wired into `main.ts` — the switch after
  `conformance`, both `usage()` blocks, the `--class` reporting exemption, exit
  1 on a finding.
- **P2-5.** Reason 2's first clause: a human-readable sibling for each
  machine-readable document, written rather than printed, and the pairing check
  over both.
- **P2-6.** Vendor the `security-decision-record` schema **only if** P2 actually
  validates against it, pinned on `$schemaVersion` and sha256 like the other
  three. Otherwise it prints as unvalidatable and stays absent — the README's
  argument holds.

## 7. Estimate, with the P1 lesson applied

P1 was scoped at about a day and was a week, because the cost was set by how
far the overlays had moved and not by what FedRAMP published. The equivalent
question here is: **how much of reason 3's numerator is new declaration surface
rather than new reading?** P2-0 and P2-3 are reading and reprojection and are
small. P2-1 and P2-2 are reviewed judgement over 129 rules, and that is the
part that will not compress.

So: **P2-0 and P2-3 are the shippable core**, and they are worth shipping
alone — a register that prints "129 applicable at class b, N computed, the rest
undeclared, and the trust center unmeasured" is already the honest number
nobody publishes. P2-1 and P2-2 turn *undeclared* into *addressed or refused*,
one rule at a time, and are better done as a reviewed batch after the register
exists to show the queue.

## 8. What this is worth publicly

Prowler and `ksi-harness` check KSIs. #167 says KSIs are one of five reasons a
package gets rejected, and the other four are about the package: the rule set,
the schemas, the formats, the trust center. A tool that reports the rejection
register is answering the question a provider actually has the week before they
submit, and the numbers in §2a are the ones nobody is publishing.

The most quotable line the register can print is also the most honest one: the
reason FedRAMP listed **first** is the one a local appliance cannot check, and
saying so is the difference between a tool and a checkbox.
