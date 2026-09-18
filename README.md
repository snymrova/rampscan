# rampscan

[![test](https://github.com/snymrova/rampscan/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/snymrova/rampscan/actions/workflows/test.yml)
[![smoke](https://github.com/snymrova/rampscan/actions/workflows/smoke.yml/badge.svg?branch=main)](https://github.com/snymrova/rampscan/actions/workflows/smoke.yml)

The open-source **KSI gap engine** for FedRAMP 20x: an appliance deployed **inside the client's own boundary** that answers, per Key Security Indicator, what is owed, what is validated, and precisely which class of gap sits between them — with the commit plane as its first evidence source and [ramprules](https://ramprules.com) as its enrichment.

One row per KSI, always — the 41 that class b obliges, and the 5 it makes optional printed dimmed beneath their own label rather than dropped. Each carries automated methods against the class floor (`FRC-CSX-VVK`), evidence age against its owed window (MVX — Persistent Machine Verification and Validation: 7 days class b, 3 days class c), the five owed artifacts, and the worst gap class computed for that row. A KSI nothing validates is a `G1 coverage` row, never an absent one — the absence is the finding.

The evidence under those rows is signed and commit-anchored. `scan` produces it from a checkout; `ingest` accepts a client-run AWS result the appliance never executed, or an assessed package, signing what was handed over and no verdict it did not evaluate; an attestation covers what neither can reach. Out of scope, deliberately: executing ramprules' AWS evidence recipes (the client runs those directly — they're copy-pasteable by design), and any SaaS control plane that would move code or evidence out of the client's boundary.

## Status

**`v0.1.0-beta`.** The CLI (`pnpm rampscan --help`), the twenty recipes in [`recipes/commit/`](recipes/commit/), a signed append-only ledger, a projection you can rebuild and prove, and a console. 1,475 tests across 126 files; the ones that want a scan tool or the PocketBase binary skip by name where it is absent, and CI runs without either on purpose, because it installs nothing. `tsc --build` is clean at the root and in the console, and both the suite and both typechecks are gated in CI on every pull request. The two figures in this paragraph are checked against the run by the suite's own reporter, and this document fails CI when they drift — that is ground rule 4, and [`packages/cli/test/published-numbers.test.ts`](packages/cli/test/published-numbers.test.ts) is what enforces it for every number below that comes from a command.

It is a beta because of the number in the next section, not because the machinery is unfinished.

## How much of FedRAMP this actually answers

Ground rule: **every number here comes from a command.** These come from `rampscan frontier`, which probes nothing and writes nothing — it counts the rows it prints. This is the self-scan, so the tool is reporting on itself. The block is pasted from the output, with rows elided at the `…`; the summary lines in it are compared with a fresh run of the command on every pull request, and the README fails CI when they differ.

```
$ pnpm rampscan frontier

rampscan frontier — the KSI register
class b · dataset 2026.09.13.02 · frontier overlay 0.13.0 · evidence: .

  KSI              methods    freshest         artifacts   worst gap
  KSI-CED-RAT      0/1        —                0/5         G1 coverage
  KSI-CMT-RVP      1/1 ok     32d / 7d         0/5         G3 freshness
  KSI-CMT-VTD      4/1 ok     32d / 7d         0/5         G3 freshness
  KSI-CNA-EIS      0/1        —                0/5         G1 coverage  optional at class b
  …

  floor met on 13 of 41 KSIs · at least one automated method on 13 · no method on 28
  covering all 41 — a row that says "nothing evidences this from a pipeline" is a row
  5 optional at class b, outside every meter above — KSI-CNA-EIS, KSI-MLA-ALA, KSI-SVC-PRR, KSI-SVC-RUD, KSI-SVC-VCM (0 evidenced anyway)
  clocks: 0 of 41 KSIs hold every method inside its owed window — VDR-TFR-MVX (MUST)
  history: no floor at class b — FRC-CSX-MOT (SHOULD, unquantified)
  artifacts: 0 of 41 KSIs hold all five owed artifacts — default_artifacts.KSI (2, 5 computed · 1, 3, 4 two-key judged)
  evidence class: 0 of 41 KSIs hold point-in-time evidence, rejectable when standalone — FRR-PVA-AA-06 (pipeline mints assert process-generated)

  adjudication queue (G8): 71 unreviewed, sorted by leverage
    AC-07        AC  lev 8  KSI-IAM-JIT KSI-IAM-SUS
    …

  legacy view: --by-controls   (23 of 209 controls · 32 reachable at this pin)
```

**13 of 41 KSIs meet the class-b method floor, and 28 have no pipeline method at all.** Read cold that looks like an unfinished tool, so read it the other way: the second number is the honest statement of what a *repository* can never answer, and it is the more useful of the two. Most FedRAMP controls are about acts performed on or by people — training delivered, screening completed, an agreement signed — and the document a repository could hold is evidence *about* the act, not the act. A tool that claimed all 41 from a checkout would be claiming it can see things that leave no trace in one. That is what `ingest` and the attestation clock exist for: a method the appliance did not execute can still be counted, once something signed says so.

**Every zero above is a different gap, and the tool says which.** `0/1` methods is `G1 coverage`; a method past its window is `G3 freshness`; the clocks, history, artifact and evidence-class lines are `G3`, `G4`, `G5` and `G6` measured separately, each against the rule that owes it. `rampscan gaps` prints them as a register — every row a (KSI, gap class, rule ID, evidence digest) tuple. A single blended percentage would have hidden which one you can actually fix this week.

`frontier` also names what nobody has decided yet: **71 controls unreviewed**, printed as a question rather than as a gap. `--by-controls` keeps the pre-pivot denominator printable — 23 of 209 controls covered against a ceiling of 32 — because a project that changes how it counts should be able to show both numbers, not just the flattering one. Both of those moved on the 2026.09.13.02 re-pin and in the direction that costs this plane something: nine controls left upstream's frontier because upstream answered them, so the ceiling a commit can reach fell from 38 to 32, and the unreviewed queue grew because upstream also put five new controls onto it. The nine are retired in [`recipes/adjudications/`](recipes/adjudications/) with the concession written out rather than deleted.

## What it does

`rampscan scan <path>` runs the collectors over a checkout — repo-facts, gitleaks, graph, syft, osv-scanner, reachability, grype, semgrep, checkov, spectral, documents, contract — joins their output against the twenty recipes in [`recipes/commit/`](recipes/commit/), and records each evidenced/violated row as a signed, commit-anchored bundle in an append-only content-addressed ledger. Re-scans keep unchanged evidence alive under its original signature; when an anchoring file changes, the projector marks that evidence `dead(anchor-drift)` and names the killing commit.

The reachability tier is what separates a verdict from a count. The `graph` collector builds `graph.db` for the snapshot (TypeScript/JavaScript import + call graph, exact vs inferred marked per edge; entry points detected over every application root — package.json `main`/`bin`/`exports`, files named on `scripts` command lines, Next.js and PocketBase file conventions — overridable via `graph.entrypoints`, with what the override left out recorded beside it), and the `reachability` collector joins `osv-results.json × graph.db × sbom.cdx.json`: a reachable advisory is `violated` with the call path as the artifact, a provably unreachable one becomes a **signed not-affected OpenVEX** (justification `vulnerable_code_not_in_execute_path`, exported to `out/exports/openvex.json`, digest-pinned as a subject of the signed bundle). The SBOM's `dependsOn` edges continue the walk forward from any package the code graph reached, with those hops marked `sbom` — they can prove a transitive dependency present and never prove one absent, because the manifest graph is partial. No graph, or no detectable entry points, degrades to the honest posture — every advisory counts, marked `unknown`; so does a package with no graph node and no chain to it. And a not-affected claim is only signed at the width of the whole tree: every statement carries the entry-point set and the application roots the walk entered as structured fields, and where the tree declares a package root no entry point covers, or `graph.entrypoints` left out an entry point detection found and the walk never reached, `not_affected` is refused for that run and the reason is recorded — a negative scoped to half a repository is not a negative, and a config is honoured as an instruction, not as a proof.

`rampscan serve` is the visual loop: PocketBase as projection store and auth, a Next.js console with the coverage board (filterable by KSI theme, control family, repo), the clock view (bundle age against the MVX window, expiring first), the drift view (born / died / verdict-flipped / scoped, with cause and killing commit), and the two-key queue — any signed-in identity proposes a `notApplicable`, an approver's key turn signs a scoping event into the **ledger**, and the register flips only when the projector re-folds it. The projector is the only writer of projection collections, enforced by PocketBase rules rather than by discipline, and a ledger watcher re-projects on every append, so a scan in another terminal moves the board live.

`rampscan exports` writes the two FedRAMP schema-target documents into `out/exports/fedramp/` — a Certification Package Overview (`FRC-CSO-PKG`) and an Ongoing Certification Report (`CCM-OCR-AVL`) — as JSON validated against the [pinned FedRAMP schemas](docs/context/fedramp-schemas/) per `FRC-CSO-JSN`, and exits 1 on a violation. Each document is two halves with a published line between them: the offering identity is **declared** in `rampscan.config.json` and passed through untouched, and the validation record is **computed** from the fold, so `x-rampscan.fieldSources` labels every field declared or computed and an assessor can tell which half was measured. The appliance makes no attestation on a provider's behalf: with no `offering.report` block declared there is no Ongoing Certification Report, because an empty incident list in one *is* the attestation that none occurred.

The package overview also carries an `FRC-APP-FCP` freshness stamp — the rule wants a package showing status verified within the previous **7 days**, which is its own flat window and not the class one — computed from the register and unclaimable by declaration, since `rampscan.config.json` refuses any key that would let a provider type their own package fresh. rampscan's own package currently reads `fresh: false`, and that is the stamp working.

`rampscan sdr` writes the Security Decision Record beside them, in the two formats `SDR-CSO-FRR` requires. The JSON is validated against the pinned SDR schema. The Markdown is rendered from the JSON file as written and carries its sha256, so the two cannot disagree without it showing. Each KSI the class obliges gets a row with its signed artifact bodies, every derived method as a test, and each live bundle as evidence. An empty artifact slot is an empty array: rampscan never writes the provider's explanation for them. `ksiImplementationStatus` is computed and allowed to understate but never to overstate, and each row publishes the inputs that decided it. Only the rules the offering's `ruleCoverage` declares get a row. Each undeclared rule is named instead, even one rampscan computes, because a row with no explanation would read as answered. rampscan's own record is schema-valid and fails the rules loudly, because this repository has written none of its explanations. That is the honest reading.

`rampscan conformance [path]` is the check pointed at a *file*: certification JSON on disk validated against the pinned schemas, whether rampscan wrote it or another tool did. It also compares each document's own conformance stamp against a fresh validation, which is the one thing regenerating cannot do — a document claiming `valid: true` after the pins moved under it fails rather than passing quietly. It refuses what it cannot resolve rather than skipping it, and CI runs it over this repository's own declared offering on every pull request, so a nonconforming export fails our build and never a client's. A Security Decision Record gets a second verdict beside the first: whether it meets the SDR rules. It needs a row for every addressable rule and every obliged KSI, the Markdown half has to name the JSON's exact bytes, and the metadata has to be present. Assessor content is counted as awaited. Historical metrics are reported as impossible inside the pinned schema. The two verdicts are never merged. The rule verdict fails the run only with `--require-rules`, because no record can meet every rule before its assessor has written into it.

`rampscan submission` is the rejection register. On 2026-08-31 FedRAMP announced the Class B/C submission form going live and listed, in its own words, the top reasons a submission gets rejected ([community#167](https://github.com/FedRAMP/community/discussions/167)) — a gated trust center, an incomplete package, missing rules or KSIs, JSON that does not follow the schema, and absent assessment content. The register is one section per reason, each carrying FedRAMP's sentence, the rules that make it binding, and rows. **129 rules are addressable at class b — 88 MUST and 41 SHOULD — and rampscan itself answers 17.** That denominator is the number nobody in this field publishes, and computing it means reading the force *per class*: 29 rules carry no top-level force at all, so a reader that took the field at face value would return the same denominator for every class.

Point it at the document FedRAMP reads and the register stops guessing. `SDR-CSO-FRR` obliges a Security Decision Record carrying a row for every applicable rule, and the published schema makes `"Not Implemented"` a valid status — so declaring a rule unimplemented satisfies the rule, and saying nothing does not. `rampscan submission --sdr <security-decision-record.json>` diffs the record's rows against the rules the class obliges and reports what is missing, which is the defect reason 3 actually rejects on. Without `--sdr` that section reads `unmeasured`: a checkout is not a submission, and rampscan does not accuse a package it was never shown.

Two things in that register are deliberately uncomfortable. The trust-center section prints **unmeasured** unless it is handed a probe. Whether an NDA gate stands in front of a provider's trust center is a property of a live URL, so `rampscan probe <url> --document <url>` is the one command that fetches. It GETs only the URLs it is given, anonymously, and writes a transcript that `submission --trust-center-probe` reads offline. The probe reads **gated** only on positive evidence, and it tells a click-through (reason 1 itself) apart from a login, which FedRAMP permits when it is declared. It reads **open** only when a named certification document comes back and validates against a pinned FedRAMP schema. A clean 200 on a landing page stays unmeasured, because a page that loads says nothing about the data behind it. And the 112 rules rampscan does not answer itself are counted and named but are **not** called rejections: a rule no local appliance could ever see — a FedRAMP Marketplace listing is not a property of a git checkout — reads exactly like one a provider omitted, and 112 accusations is how a linter gets ignored. `rampscan submission` exits 1 on the rejections it can stand behind and prints the rest as the queue they are.

Reason 3 is the only one of the five that names its own remedy: *"if you don't have something implemented, say so and tell us why, don't just omit the KSI or rule altogether."* So declining a rule **with a reason** is a pass and omitting it is the rejection — and `rampscan.config.json` is where a provider says so, one entry per rule in `offering.ruleCoverage`, either `addressed` with a citation or `not-implemented` with a reason:

```json
{ "ruleId": "FRC-APP-MLF", "status": "not-implemented",
  "reason": "not yet listed in the FedRAMP Marketplace; the listing request is filed 2026-09-02" }
```

There is deliberately **no** `status: "not-applicable"`. Applicability is declared upstream on the rule's own subset and is read, never accepted, and the set of rules structurally invisible to a local appliance is rampscan's own reviewed artifact rather than a provider's claim about themselves — a config key that let a rule drift there would be the single escape hatch capable of emptying this whole check. `"n/a"` and `"TBD"` are refused as answers for the same reason: they are the omission in one word. So is a KSI id typed into the block, which is the likeliest mistake and the one that would matter — the KSI half of reason 3 is *measured*, from the method registers and the artifact plane, and a declaration must not be able to talk its way past the half this appliance is actually good at. A declaration is not a verification, either, and the register says which one it is: it checks that an answer exists, never that it is true.

`rampscan artifacts` is the artifact plane (SPEC §13). `SDR-CSX-KSI` (MUST) makes five artifacts the required content of the Security Decision Record — the document `FRD-SDR` defines as the SSP's replacement — so an artifact is a first-class signed object here with the same lifecycle as evidence: content-addressed, commit-anchored, superseded rather than edited, and on `VDR-TFR-NMV`'s three-month clock whatever its source. **Three of the five are computed** from the fold and carry their generator: the cycle (2) from the scheduler's contract and the ledger's record of how it actually ran, the automation's accuracy (4) from the signed exec journal — which tool resolved, at which version, through which image digest, exiting how, and every limit that reading has — and the validation standing (5) from the register, with the population on every line, because evidenced over 412 observations and evidenced over none are the same word for very different facts.

**The other two are yours, and rampscan refuses to write them.** Artifacts 1 and 3 are the provider's own claims, and `source: computed` is refused for them by the schema rather than by a convention somebody remembers. `rampscan artifacts scaffold <KSI>` writes a stub with everything the appliance measured filled in and the claim left conspicuously blank, offering the reason-for-absence path the rule explicitly permits as an equal rather than a failure. An LLM in the loop makes drafting them trivially easy, and that is exactly why the refusal is written into the schema: the moment this appliance emits plausible compliance narrative, `SDR-CSX-KSI` becomes a text-generation benchmark and every signature in the ledger is worth less. A declared artifact lives beside the code in the repository's `artifacts` block, is anchored to the commit that last touched it, and stops counting when a later scan signs the observation that its file is gone.

`rampscan rebuild` drops the projection, refills it from the ledger and proves byte equality. `rampscan verify <digest>` checks any bundle or scoping event offline. `rampscan check` is the dry run over the working tree — pure gates, nothing signed, nothing appended, exit 1 on a would-be violation.

## How it is run

**From a clone, with `pnpm rampscan …`.** Every workspace package is `private: true` with no `bin` and nothing is published to npm, so `npm i -g rampscan` will not work and is not meant to — the entry point is `tsx packages/cli/src/main.ts`, wrapped by the root `rampscan` script. That is a decision rather than an omission: no external user has asked for a binary yet, and shipping one before then means versioning a surface nobody is using. The tag is the only version surface.

## Quickstart

Walked from a clone into an empty directory, with no `node_modules`, no ledger, no keys and no PocketBase binary present. Node 22 is the only prerequisite; pnpm is pinned by the `packageManager` field, so Corepack fetches the right version itself.

```
git clone https://github.com/snymrova/rampscan && cd rampscan
pnpm install            # seconds; no build scripts run — see pnpm-workspace.yaml
pnpm test               # 1,475 tests across 126 files; the ones wanting a tool or PocketBase skip by name
pnpm run doctor         # how each scan tool resolves on THIS machine
pnpm rampscan scan .    # scan this repository with itself
pnpm rampscan board     # the projection: registers, live evidence, graveyard
```

Note `pnpm run doctor`, not `pnpm doctor` — pnpm has a built-in `doctor` command of its own that will shadow the script and cheerfully report that everything is fine about something else entirely.

**No scan tools and no Docker is a supported machine**, and it is worth seeing before you install anything, because the graceful skip is a feature rather than an apology:

```
$ pnpm run doctor
  absent   docker       no Docker — tools must be installed as binaries (https://docs.docker.com/engine/install/)
  MISSING  syft         SBOM (CycloneDX) — M1 collector
           install syft — or install Docker and nothing else is needed
  MISSING  gitleaks     secrets, full history — M1 collector
           install gitleaks — or install Docker and nothing else is needed
  ...
7 tool(s) cannot resolve. Their collectors will skip with the reason recorded,
and their recipes will read unevidenced.
```

Nothing crashes and nothing silently passes: the recipes those collectors feed report `unevidenced` with the reason attached, which is the whole posture — a control with no evidence is never a control that passed. Install Docker and the same command resolves every tool to a pinned image from [`packages/collectors/tools.json`](packages/collectors/tools.json), pulled on first use. A binary already on PATH is used as-is. **rampscan installs nothing on the host, ever.**

For the console, one extra step fetches and sha256-verifies the pinned PocketBase binary:

```
pnpm run fetch-pocketbase     # sha256 verified against console/pocketbase/version.json
pnpm rampscan serve           # PocketBase + the Next.js console on :3000
```

## The console

Three views, screenshotted from a real projection — the scans behind them are
`rampscan scan fixtures/vulnerable-app`, run twice with one fault fixed in between.

**The coverage board.** Every recipe against every repository, with the offender
pointer printed under the row that failed and `violating since … · first seen at
commit …` beside it. A verdict here is never a bare red dot: it names the file,
the rule and the commit that introduced it.

![The coverage board — 20 rows for one repository, 6 evidenced and 14 violated, each violation naming its offending file and the commit it was first seen at](docs/images/board.png)

**An evidence bundle.** What a signed bundle actually contains, and the reason
the plain-English block is authored per recipe rather than generated: it explains
the *check* and says nothing about your repository, so it stays true when the
verdict changes. This one is marked `dead` because the second scan superseded it
— the ledger keeps it and names the commit that killed it.

![An evidence detail page for arch-boundaries-hold — plain-English checks, what a violation means and how to fix it, above the commit anchor, KSIs, controls, cadence, dataset pin, and the note that this bundle was superseded and killed by commit b51feb542f3f](docs/images/evidence.png)

**Drift.** Every movement the ledger records, with its cause. The `VERDICT
FLIPPED` row is the second scan finding the `CODEOWNERS` file that the first scan
reported missing — `violated → evidenced (anchor-drift)`, attributed to the
commit that did it. Nothing on this page is typed; it is folded from the bundle
chain.

![The drift view — evidence born, died and verdict-flipped, including codeowners-defined flipping from violated to evidenced by a named commit](docs/images/drift.png)

## It scans itself

The clearest demonstration is the one you can reproduce in the clone you just made. `rampscan scan .` on this repository, at `c0d1c73`:

```
11 evidenced · 3 violated · 6 unevidenced · 8 findings
```

All three violations are real and all three are left standing on purpose. The third is new, and it is the one this repository is proudest of.

`no-critical-reachable-advisories` counts every CRITICAL or HIGH advisory that is reachable from an entry point, or whose reachability is unknown. Six count. Two are in `next@15.5.23` and are reachable by an exact one-hop path — `console/web/app/api/artifact/route.ts » next/server` — because the console is a Next.js app and every one of its routes imports the framework. Two are `HIGH` advisories in `postcss@8.4.31`, reachable through the SBOM's `next → postcss` edge, with that hop marked `sbom` so a reader can see where the parsed call sites stop and the manifest's word begins. Two are in `sharp@0.34.5`, which no first-party file imports and no dependency chain from a reached package names: unknown, and unknown counts. **Until 2026-09-14 this row read `evidenced`,** on the strength of five signed `not_affected` statements about `postcss` and `sharp`. They were false. The walk had never entered the console — the config named one entry point in the CLI and the detector took it as the whole tree — so "not reachable from the entry points" was true and meant nothing, and the code that emitted the statements treated a package with no node in the graph as proven absent. That is the finding in [`docs/FINDING-VACUOUS-NOT-AFFECTED.md`](docs/FINDING-VACUOUS-NOT-AFFECTED.md), published as [GHSA-7jff-6v53-r56x](https://github.com/snymrova/rampscan/security/advisories/GHSA-7jff-6v53-r56x), and phases S0–S1 of [`docs/PLAN-SOUNDNESS.md`](docs/PLAN-SOUNDNESS.md) are what it took to make the row go red: absence became `unknown`, the SBOM joined the walk as a presence-prover, every negative now states its width and is refused at less than the whole tree, detection stopped being something the config could switch off, and the config's override was deleted. A third standing violation, explained, is worth more than the suppression it replaces — and the temptation to make it green again by narrowing an entry point or accepting a risk is the exact pressure this product exists to resist.

The same run signs exactly one `not_affected`: `vitest@4.1.10`, against a MODERATE advisory that did not exist in August. It is the earned kind. `vitest` has a node in the graph — the test files import it — and a walk that started from all 57 detected entry points, entered all 12 application roots the tree declares, and excluded nothing, never arrived at it. The statement carries that scope as structured fields (`rampscan:scope`), so the sentence "not in the execute path" comes with the entry points, the roots and the commit it was checked against. It is the only shape a negative is allowed to take now.

`ci-provenance-present` wants a workflow step that attests a build. This repository **publishes no artifact** — every package is private, the CLI runs from a clone — so a provenance step here would attest nothing and the recipe would pass on it. Passing a control you cannot prove is not a wrong answer, it is a false attestation, and it is the one thing [`SECURITY.md`](SECURITY.md) asks you to report as a vulnerability. It flips when there is something to attest.

`iac-baseline-clean` is checkov flagging the deliberately faulty workflow inside the generated test fixture — which raises a genuine scope question, whether a checkout scan should read paths the repository gitignores, that is open rather than answered.

## It gates its own pull requests

Every pull request against this repository runs [`.github/workflows/check.yml`](.github/workflows/check.yml), which is [`rampscan check`](.github/actions/rampscan-check/action.yml) over the branch's working tree. When a change breaks a boundary this repository declared in [`rampscan.config.json`](rampscan.config.json), the run leaves a comment naming the file, the import chain that reaches across the boundary, and the recipe's own authored fix sentence — then fails the job.

```
#### `arch-boundaries-hold`

**This tree would move the row: `evidenced` → `violated` (newly-violated).**

- `assert` No file outside a declared boundary's allow-list imports the guarded module (…).
  - `packages/projector/src/breach-demo.ts` — packages/projector/src/breach-demo.ts » packages/signer/src/index.ts

**Fix.** Route the access through an allowed importer, move the offending code inside the boundary, or — if the design genuinely changed — widen the allow-list in rampscan.config.json, where the change is reviewed like any other.
```

That excerpt is trimmed for width; the [comment it came from](https://github.com/snymrova/rampscan/pull/18#issuecomment-5353906519) is on a real pull request against this repository. [#18](https://github.com/snymrova/rampscan/pull/18) is a branch written to be failed — `packages/projector/src/breach-demo.ts` reaches into `packages/signer`, which [`rampscan.config.json`](rampscan.config.json) reserves to the CLI on the grounds that the CLI is the only surface holding a key. The dependency and the project reference are wired the way a developer breaching a boundary for real would wire them, so `tsc --build` has nothing to say and the suite passes: on that pull request `test` and `console-smoke` are green and `check` is red, which is the contract objecting and nothing else.

Three properties are worth more than the comment itself. **A comment is not a failure.** A pull request with nothing violated at all gets no comment, and a run that finds a breach fixed deletes the one its predecessor left — but a row that was already violated before the branch existed is still reported, described as **inherited**, with the commit its streak started at. It does not fail the job, because a gate that goes red for debt the pull request never created is a gate people learn to ignore; it is not suppressed either, because silence about known debt would read as a pass. [The pull request that added this paragraph](https://github.com/snymrova/rampscan/pull/21#issuecomment-5354653003) is the worked example — `introduced=0 inherited=1`, a comment and a green tick. And nothing in the run is evidence: the dry run reads a working tree no commit can name, so it signs nothing, appends nothing, and leaves the ledger byte-identical. The comment says so in its own body.

The action installs no tool binaries and pulls no images, because the dry run refuses every collector that spawns one.

## Documentation

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — components, the scan pipeline end to end, stores, trust boundaries, evidence lifecycle, invariants.
- [`docs/SPEC.md`](docs/SPEC.md) — the working spec: tech, architecture, dataflow, primitives, UI.
- [`docs/RECIPE-PREPARATION.md`](docs/RECIPE-PREPARATION.md) — how recipes are prepared (adjudicate → draft → validate → CI-gate) and how scan tools resolve at run time.
- [`docs/CONTROLS-TO-REPORTS.md`](docs/CONTROLS-TO-REPORTS.md) — how control IDs travel from the pinned crosswalk through recipes — the single join point — into every report.
- [`docs/COMPLIANCE-SCAN-HARNESS.md`](docs/COMPLIANCE-SCAN-HARNESS.md) — the founding brainstorm, including the decisions log (§11–§13).
- [`docs/FRONTIER-PIPELINE.md`](docs/FRONTIER-PIPELINE.md) — generated by `rampscan report` from the last scan.
- [`docs/context/`](docs/context/README.md) — snapshots of the ramprules dataset and the harnessarch brainstorms, for agent context. Read its README before trusting a number.
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — the ten ground rules, and for each one that has a gate, the test that is the gate.
- [`SECURITY.md`](SECURITY.md) — reporting path, and what rampscan does and does not send anywhere.

## Licence

Apache-2.0 — see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
