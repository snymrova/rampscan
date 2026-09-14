# rampscan

[![test](https://github.com/snymrova/rampscan/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/snymrova/rampscan/actions/workflows/test.yml)
[![smoke](https://github.com/snymrova/rampscan/actions/workflows/smoke.yml/badge.svg?branch=main)](https://github.com/snymrova/rampscan/actions/workflows/smoke.yml)

The open-source **KSI gap engine** for FedRAMP 20x: an appliance deployed **inside the client's own boundary** that answers, per Key Security Indicator, what is owed, what is validated, and precisely which class of gap sits between them — with the commit plane as its first evidence source and [ramprules](https://ramprules.com) as its enrichment.

One row per KSI, forty-six of them, always. Each carries automated methods against the class floor (`FRC-CSX-VVK`), evidence age against its owed window (MVX — Persistent Machine Verification and Validation: 7 days class b, 3 days class c), the five owed artifacts, and the worst gap class computed for that row. A KSI nothing validates is a `G1 coverage` row, never an absent one — the absence is the finding.

The evidence under those rows is signed and commit-anchored. `scan` produces it from a checkout; `ingest` accepts a client-run AWS result the appliance never executed; an attestation covers what neither can reach. Out of scope, deliberately: executing ramprules' AWS evidence recipes (the client runs those directly — they're copy-pasteable by design), and any SaaS control plane that would move code or evidence out of the client's boundary.

## Status

**`v0.1.0-beta`.** Sixteen CLI commands, twenty recipes, a signed append-only ledger, a projection you can rebuild and prove, and a console. 1,001 tests across 81 files — 996 pass on a fresh clone and 5 skip until `pnpm run fetch-pocketbase` supplies the binary they need, after which all 1,001 pass. `tsc --build` is clean at the root and in the console, and both the suite and both typechecks are gated in CI on every pull request.

It is a beta because of the number in the next section, not because the machinery is unfinished.

## How much of FedRAMP this actually answers

Ground rule: **every number here comes from a command.** These come from `rampscan frontier`, which probes nothing and writes nothing — it counts the rows it prints. This is the self-scan, so the tool is reporting on itself.

```
$ pnpm rampscan frontier

rampscan frontier — the KSI register
class b · dataset 2026.07.14.01 · frontier overlay 0.7.5 · evidence: .

  KSI              methods    freshest         artifacts   worst gap
  KSI-CED-RAT      0/1        —                0/5         G1 coverage
  KSI-CMT-RVP      1/1 ok     30d / 7d         2/5         G3 freshness
  KSI-CMT-VTD      4/1 ok     30d / 7d         2/5         G3 freshness
  …                                                        (46 rows, always)

  floor met on 13 of 46 KSIs · at least one automated method on 13 · no method on 33
  covering all 46 — a row that says "nothing evidences this from a pipeline" is a row
  clocks: 0 of 46 KSIs hold every method inside its owed window — VDR-TFR-MVX (MUST)
  history: no floor at class b — FRC-CSX-MOT (SHOULD, unquantified)
  artifacts: 0 of 46 KSIs hold all five owed artifacts — default_artifacts.KSI
  evidence class: 0 of 46 KSIs hold point-in-time evidence, rejectable when standalone

  adjudication queue (G8): 68 unreviewed, sorted by leverage

  legacy view: --by-controls   (23 of 209 controls · 38 reachable at this pin)
```

**13 of 46 KSIs meet the class-b method floor, and 33 have no pipeline method at all.** Read cold that looks like an unfinished tool, so read it the other way: the second number is the honest statement of what a *repository* can never answer, and it is the more useful of the two. Most FedRAMP controls are about acts performed on or by people — training delivered, screening completed, an agreement signed — and the document a repository could hold is evidence *about* the act, not the act. A tool that claimed all 46 from a checkout would be claiming it can see things that leave no trace in one. That is what `ingest` and the attestation clock exist for: a method the appliance did not execute can still be counted, once something signed says so.

**Every zero above is a different gap, and the tool says which.** `0/1` methods is `G1 coverage`; a method past its window is `G3 freshness`; the clocks, history, artifact and evidence-class lines are `G3`, `G4`, `G5` and `G6` measured separately, each against the rule that owes it. `rampscan gaps` prints them as a register — every row a (KSI, gap class, rule ID, evidence digest) tuple. A single blended percentage would have hidden which one you can actually fix this week.

`frontier` also names what nobody has decided yet: **68 controls unreviewed**, printed as a question rather than as a gap. `--by-controls` keeps the pre-pivot denominator printable — 23 of 209 controls covered against a ceiling of 38 — because a project that changes how it counts should be able to show both numbers, not just the flattering one.

## What it does

`rampscan scan <path>` runs the collectors over a checkout — repo-facts, gitleaks, graph, syft, osv-scanner, reachability, grype, semgrep, checkov, spectral, documents, contract — joins their output against the twenty recipes in [`recipes/commit/`](recipes/commit/), and records each evidenced/violated row as a signed, commit-anchored bundle in an append-only content-addressed ledger. Re-scans keep unchanged evidence alive under its original signature; when an anchoring file changes, the projector marks that evidence `dead(anchor-drift)` and names the killing commit.

The reachability tier is what separates a verdict from a count. The `graph` collector builds `graph.db` for the snapshot (TypeScript/JavaScript import + call graph, exact vs inferred marked per edge; entry points from package.json bins/exports, overridable via `graph.entrypoints`), and the `reachability` collector joins `osv-results.json × graph.db × sbom.cdx.json`: a reachable advisory is `violated` with the call path as the artifact, a provably unreachable one becomes a **signed not-affected OpenVEX** (justification `vulnerable_code_not_in_execute_path`, exported to `out/exports/openvex.json`, digest-pinned as a subject of the signed bundle). The SBOM's `dependsOn` edges continue the walk forward from any package the code graph reached, with those hops marked `sbom` — they can prove a transitive dependency present and never prove one absent, because the manifest graph is partial. No graph, or no detectable entry points, degrades to the honest posture — every advisory counts, marked `unknown`; so does a package with no graph node and no chain to it.

`rampscan serve` is the visual loop: PocketBase as projection store and auth, a Next.js console with the coverage board (filterable by KSI theme, control family, repo), the clock view (bundle age against the MVX window, expiring first), the drift view (born / died / verdict-flipped / scoped, with cause and killing commit), and the two-key queue — any signed-in identity proposes a `notApplicable`, an approver's key turn signs a scoping event into the **ledger**, and the register flips only when the projector re-folds it. The projector is the only writer of projection collections, enforced by PocketBase rules rather than by discipline, and a ledger watcher re-projects on every append, so a scan in another terminal moves the board live.

`rampscan exports` writes the two FedRAMP schema-target documents into `out/exports/fedramp/` — a Certification Package Overview (`FRC-CSO-PKG`) and an Ongoing Certification Report (`CCM-OCR-AVL`) — as JSON validated against the [pinned FedRAMP schemas](docs/context/fedramp-schemas/) per `FRC-CSO-JSN`, and exits 1 on a violation. Each document is two halves with a published line between them: the offering identity is **declared** in `rampscan.config.json` and passed through untouched, and the validation record is **computed** from the fold, so `x-rampscan.fieldSources` labels every field declared or computed and an assessor can tell which half was measured. The appliance makes no attestation on a provider's behalf: with no `offering.report` block declared there is no Ongoing Certification Report, because an empty incident list in one *is* the attestation that none occurred.

The package overview also carries an `FRC-APP-FCP` freshness stamp — the rule wants a package showing status verified within the previous **7 days**, which is its own flat window and not the class one — computed from the register and unclaimable by declaration, since `rampscan.config.json` refuses any key that would let a provider type their own package fresh. rampscan's own package currently reads `fresh: false`, and that is the stamp working.

`rampscan conformance [path]` is the check pointed at a *file*: certification JSON on disk validated against the pinned schemas, whether rampscan wrote it or another tool did. It also compares each document's own conformance stamp against a fresh validation, which is the one thing regenerating cannot do — a document claiming `valid: true` after the pins moved under it fails rather than passing quietly. It refuses what it cannot resolve rather than skipping it, and CI runs it over this repository's own declared offering on every pull request, so a nonconforming export fails our build and never a client's.

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
pnpm test               # 720 passed | 3 skipped (723) — the 3 want PocketBase, see below
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

The clearest demonstration is the one you can reproduce in the clone you just made. `rampscan scan .` on this repository:

```
12 evidenced · 2 violated · 6 unevidenced · 2 findings
```

Both violations are real and both are left standing on purpose.

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
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — the ten ground rules, each named with the test that enforces it.
- [`SECURITY.md`](SECURITY.md) — reporting path, and what rampscan does and does not send anywhere.

## Licence

Apache-2.0 — see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
