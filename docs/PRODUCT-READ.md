# rampscan: a product read from the code

**Method:** this is a reading of the source only — no document in `docs/` was opened, no
plan, no spec, no README. Everything below is grounded in what the code, the recipe
catalog, the tests and the git history actually do. Where I state a number I computed it
from the repo. Where the code and a document disagree, this file is the one that is
wrong; it is deliberately a second opinion, not a summary.

Date of reading: 2026-08-16, at `main` (42 commits, `5d98766`).

---

## 1. What this is

**rampscan turns a git commit into signed, independently-verifiable compliance evidence,
and keeps a board of what is currently proven, what is broken, and what nobody has
looked at.**

The shape of one pass:

```
checkout ─→ collectors ─→ observation rows ─→ recipe assertions ─→ verdict
                                                                    │
                                            in-toto statement ──────┘
                                                    │
                                       DSSE envelope (ECDSA P-256)
                                                    │
                              content-addressed append-only ledger
                                                    │
                                    pure fold ──→ projection
                                                    │
                                    ┌───────────────┴───────────────┐
                              CLI (`board`)                  console (Next.js)
```

Concretely, the pieces as they exist in the tree:

| Layer | Where | What it is |
|---|---|---|
| Recipe catalog | [recipes/commit/](../recipes/commit/) | 17 declarative JSON checks, each carrying KSI ids, NIST control ids, assertions, cadence, and authored plain-language prose |
| Collectors | [packages/collectors/src/](../packages/collectors/src/) | 12 collectors wrapping 7 pinned external tools + 5 pure ones |
| Code graph | [packages/graph/src/](../packages/graph/src/) | TS-compiler-based nodes/edges/routes with per-edge `exact`\|`inferred` resolution |
| Join | [packages/core/src/assert.ts](../packages/core/src/assert.ts) | assertion evaluation over observation rows → verdict + offender pointers |
| Ledger + signer | [packages/ledger/](../packages/ledger/), [packages/signer/](../packages/signer/) | content-addressed object store; DSSE over canonical in-toto JSON |
| Projector | [packages/projector/src/fold.ts](../packages/projector/src/fold.ts) | pure ledger → projection fold (registers, rollups, drift, gaps, runs) |
| CLI | [packages/cli/src/main.ts](../packages/cli/src/main.ts) | `scan check verify board rebuild serve daemon report tools model` |
| Console | [console/web/](../console/web/) | 9 pages + 7 API routes over a PocketBase projection |

### The five properties that make it a different thing from a scanner

These are not marketing claims; each is enforced somewhere specific.

**1. The output is evidence, not a report.**
A bundle is addressed by sha256 of its canonical JSON and signed with a DSSE envelope in
cosign's own format ([packages/signer/src/local.ts](../packages/signer/src/local.ts)). The
console will hand you the envelope and the public key and invite you to verify it with
`node:crypto` and nothing else — and the smoke test at
[e2e/console.smoke.spec.ts:92](../e2e/console.smoke.spec.ts#L92) actually does that, with
zero rampscan code in the check. The board is a *pure fold* of the ledger, and
`rampscan rebuild` exists to prove projection ≡ ledger.

**2. Evidence dies honestly.**
Every bundle anchors to the content hashes of the files it was about. When those files
change, the evidence is marked dead with cause `anchor-drift`, not quietly aged out
([packages/core/src/ports.ts:190](../packages/core/src/ports.ts#L190)). Re-verification on
cadence marks the prior bundle `superseded`. The graveyard is a view, not a cleanup job.

**3. "Nobody looked" is a first-class state.**
`unevidenced` sits in the register beside evidenced and violated, and the join that
produces it comes from the *catalog*, not from the ledger — so a recipe nobody ran is
visible rather than absent ([ports.ts:210](../packages/core/src/ports.ts#L210)). The
console then explains *why* a row is empty
([console/web/lib/emptystate.ts](../console/web/lib/emptystate.ts)), and distinguishes a
fixable skip ("semgrep not installed") from an honest one ("no IaC in the committed tree")
so only the first reaches the action queue.

**4. Reachability gating — this is the technical differentiator.**
The graph answers `reaches(entrypoint, target)`, and both the advisory gate and the SAST
gate are joins against it. An advisory is `not_affected` only when an *over-approximate*
walk — every edge kind, from every entry point and declared route — still cannot reach the
package; proven-unreachable advisories are emitted as OpenVEX with justification
`vulnerable_code_not_in_execute_path`. The direction of the approximation is signed into
every bundle as a sentence
([sast-gate.ts:44](../packages/collectors/src/sast-gate.ts#L44)): unknowns count *against*
you. A file the graph never saw, a missing graph, or no detectable entry point all make
the finding count.

**5. Marking something N/A costs two keys and a signature.**
Scoping a recipe out is a *proposal* in the console plus a separate *approver*, recorded
as a signed ledger event with both identities and the justification in the predicate
([packages/cli/src/scoping.ts](../packages/cli/src/scoping.ts)). The register cell does not
move until the projector re-folds that event. PocketBase never holds a fact the ledger
doesn't.

### Two more things the code does that I did not expect

**`rampscan check` — a dry run that is structurally incapable of being evidence.**
It walks the *working tree*, so it reads bytes no commit can name; therefore the output
type has no `verdict` field anywhere — rows carry `would_be`
([packages/cli/src/check.ts](../packages/cli/src/check.ts)). Which gates may run is
*computed*, not listed: pure collectors whose inputs come from other pure collectors. The
two gates it refuses (`sast-reachability`, the advisory gate) are refused with a per-gate
reason, because joining a fresh graph against a stale finding set would answer about
neither tree. It exits 1 on a would-be violation — a pre-commit hook or CI gate.

**Architecture as a compliance control.**
[rampscan.config.json](../rampscan.config.json) declares module boundaries; the `contract`
collector walks import edges and fails the `arch-boundaries-hold` recipe when anyone
outside the allow-list imports into a guarded module — mapped to `cm-2`/`cm-6`. A rule
whose module path matches *nothing* also fails, so a typo can't pass. That is an unusual
and genuinely valuable move: it puts "the design is still the design" in the same signed
register as "no secrets in history."

### Engineering posture, since it bears on the strategy

The repo holds a standard it mostly meets. Twin tests keep the console's
re-implementations honest against the engine. Numbers on screen are computed from rows,
never typed. There's a test that walks collector/projector/ledger sources asserting they
don't import things they must not. `plain.test.ts` guards authored prose. Tool resolution
is binary-on-PATH → pinned Docker image → honest skip, and *nothing installs on the host*.
601 unit tests, 18 Playwright smoke tests against a real scan behind a real `serve`.

The clearest evidence of the standard is negative: the most recent commit **cancels** a
local-LLM drafting feature after a live test showed a 0.5B model inventing a passing
verdict from a context that told it nothing was recorded. The reasoning was kept, the code
was deleted. A codebase that will delete two planned phases on evidence is one whose
claims you can price.

---

## 2. Where the value is, and for whom

The expensive part of compliance is not finding the problem. It is **proving to a third
party that you looked, when, at what, and that nothing was edited afterwards.** That is
the cost rampscan attacks, and the DSSE-signed content-addressed ledger is the whole
answer to it.

The second expensive part is triage: an advisory scanner hands you 400 rows and you spend
a week discovering that 388 are in code you never call. The reachability gate attacks
*that*, and hands you the call path as the artifact.

### Buyers and users, ranked by how well the current code serves them

**1. The engineering team at a small-to-mid SaaS pursuing FedRAMP 20x.** — *served today.*
The recipes are keyed to KSI indicators, which is the 20x vocabulary. The pitch is
"continuous machine-readable evidence instead of a screenshot binder," and this produces
exactly that artifact shape. This is the sharpest fit and everything else should be
sequenced behind it.

**2. The assessor / 3PAO.** — *served today, and it is the strongest wedge.*
They get an offline-verifiable artifact rather than a vendor's word: standard DSSE, standard
in-toto, cosign-compatible, `--as-of` replay of any past board from the append-only record.
This is the part competitors structurally cannot copy without rebuilding their data model.

**3. The developer.** — *built but not delivered.* `rampscan check` exists, works, exits
nonzero, and nothing in the world calls it. See §4.

**4. Adjacent non-FedRAMP buyers.** — *incidental today.* SOC 2 evidence, supply-chain
attestation, and architecture-boundary enforcement all fall out of the same machinery.
Worth knowing the door exists; not worth walking through it yet.

### The honest ceiling, computed from the catalog

I counted the coverage rather than trusting anything:

- **17 recipes → 12 of 46 KSI indicators → 22 of 209 controls.**
- By theme: `SVC` 3/8 · `CNA` 2/8 · `SCR` 2/2 · `CMT` 2/4 · `PIY` 2/5 · `IAM` 1/6.
- **Zero coverage** in `MLA` (monitoring/logging/audit, 5 indicators), `RPL` (recovery, 4),
  `INR` (incident response, 3), `CED` (education, 1).

That gap is not an oversight, it is the shape of the thing: those themes are runtime and
organizational facts, and this is a repo-static scanner. It matters strategically because
it means **rampscan cannot be the whole compliance story for its own primary buyer**, and
should be positioned as the evidence *engine* — the part that is automatable, continuous
and provable — rather than as the binder.

---

## 3. Deep or wide?

**Go deep. Specifically: deep on the reachability gate and on delivery, not wide on
languages.**

### The language-lock, measured

I classified all 17 recipes by what they actually depend on:

| Class | Count | Recipes |
|---|---|---|
| Fully language-agnostic | 6 | secrets-in-history, sbom, container-base-image-patched, iac-baseline-clean, api-spec-lint-clean, container-runs-nonroot |
| Agnostic in practice (repo/CI facts) | 6 | ci-actions-pinned, ci-provenance-present, codeowners-defined, tests-in-ci, dependency-update-automation, + advisory rows in the degraded posture |
| **JS-only by a one-line list** | 1 | `lockfile-pinned-deps` — `LOCKFILES` in [repo-facts.ts:15](../packages/collectors/src/repo-facts.ts#L15) knows npm/pnpm/yarn/bun and nothing else |
| **TS/JS-only by the graph** | 4 | route-auth-coverage, arch-boundaries-hold, arch-route-auth-declared, no-reachable-dangerous-code |
| **TS/JS-only by degradation** | 1 | no-critical-reachable-advisories still runs elsewhere, but falls back to "every advisory counts, marked unknown" — i.e. it becomes an ordinary advisory list |

So on a Python or Go repo today you get roughly 12 of 17 recipes — and you lose **exactly
the five that are differentiated**. That looks like an argument for going wide. It is the
opposite, for three reasons.

**A second language done at 40% fidelity attacks the property the product is sold on.**
The graph's edges are already labelled `exact` vs `inferred`, and `inferred` means "unique
name match across the project." A hand-rolled Python or Go extractor would produce a much
higher inferred ratio, and because the gate is deliberately over-approximate, more
inference means more `unknown`, which means more findings counting against you, which
means a noisier board. The current product's entire credibility rests on "when this says
not_affected, it means it." Shipping a second language that says `unknown` half the time
makes the first language's claims look like luck.

**The graph substrate is not finished in its first language.** Three vendored semgrep
rules ([packages/collectors/semgrep-rules.yaml](../packages/collectors/semgrep-rules.yaml)),
all `[javascript, typescript]`. Auth detection is a case-insensitive name heuristic
defaulting to `/auth/i` ([graph/src/config.ts:12](../packages/graph/src/config.ts#L12)).
`extract.ts` says in its own comments that scip-typescript slots in later behind the same
node/edge schema — that seam is designed and unused. Every hour spent there raises the
fidelity of five recipes on the language you already have.

**"Wide" is the wrong axis anyway.** The larger coverage gap is 34 uncovered KSI
indicators, not uncovered languages — and closing MLA/RPL/INR needs *runtime and cloud*
collectors, not parsers. The ports layer (`Runner`, `RepoSource`, `Scheduler`,
`LedgerStore`) is explicitly built for an AWS adapter. That's a real future direction; it
is not the next one.

---

## 4. UI or more languages?

**Neither, as posed. The highest-value work in this repo is closing the loop from a
violation to a merged fix — and that is mostly delivery work sitting on top of code that
already exists.**

### The UI is not the bottleneck

The console is not a prototype. Nine pages, seven API routes, real auth, 431 lines of
deliberate hand-written CSS (dark, dense, monospace where identity matters), deep-linked
control↔recipe↔bundle navigation in both directions, as-of time travel, since-baseline
diffing, CSV export whose row count is asserted against the screen, a download-and-verify
block, and an 18-test Playwright suite against a real scan. Marginal polish here returns
very little.

There is **one** UI-shaped gap worth doing, and it is an artifact rather than a screen:
*the thing you hand an assessor.* Today the export path is a CSV per view. A single signed,
printable coverage package — board + rollups + the envelopes + the public key + the
as-of instant — is the difference between "our tool" and "our submission," and it lands
squarely on the buyer identified as the strongest wedge.

### The actual gap: `rampscan check` has no consumer

`check` is finished, correct, carefully reasoned about, exits 1 on a would-be violation,
and **nothing in the world calls it.** There is one GitHub Actions workflow in the repo and
it is rampscan's own Playwright smoke.

Meanwhile the PR-comment payload is *already built and unused*:
`RegisterDiff` / `RegisterChangeKind` classify every transition including `newly-violated`
([ports.ts:349](../packages/core/src/ports.ts#L349)); `OffenderPointer` carries file, line
and call path; `introducedAt`/`introducingCommit` walk the violated streak back through the
bundle chain; and every recipe carries an authored `plain.fix` sentence written for a human.
That is a PR comment. It has never been rendered as one.

This is the single largest leverage-to-effort ratio in the repository, and it changes who
the product touches: from a compliance officer once a quarter to **every engineer on every
pull request**, which is also the only path by which this kind of tool ever gets adopted
bottom-up.

---

## 5. Recommended sequence

1. **Ship the PR gate.** A GitHub Action wrapping `rampscan check`, plus a PR comment
   rendered from the existing diff + pointers + `plain.fix`. Small work, large surface,
   and it puts the product in the developer's daily path.
2. **The assessor package.** One signed, printable, self-verifying export of the board at
   an instant. Directly serves the strongest wedge; mostly assembly of existing parts.
3. **Cheap polyglot wins that never touch the graph.** Extend `LOCKFILES` to
   `poetry.lock`, `Cargo.lock`, `go.sum`, `Gemfile.lock`, `composer.lock`. One array —
   and syft already SBOMs every one of those ecosystems, so the advisory chain follows for
   free. This is ~90% of the *perceived* "wide" for ~1% of the cost, and it dilutes
   nothing. Note `tests-in-ci` is already polyglot — its regex knows pytest, `go test`,
   `cargo test`, maven and gradle.
4. **Deepen the TS/JS gate.** Grow the semgrep ruleset past three rules; drive down the
   `inferred` edge ratio (this is where scip-typescript slots into the seam that is already
   designed for it); surface path-resolution confidence on the board where a claim rests
   on inference.
5. **Multi-repo / hosted.** The data model is already multi-repo — `repo` is a key on
   every row — but `serve` is one machine, one PocketBase, one key on disk. This is the
   commercial step and it should follow 1–2, not precede them.
6. **Then, and only then, pick one:** a second graph language (Python first — FastAPI and
   Django route registration maps cleanly onto the existing `route` node kind and `handles`
   edge, so the schema needs no change), *or* runtime/cloud collectors for the MLA/RPL/INR
   themes via the AWS adapters the ports were built for.

### The one thing not to do

Do not add a second language *and* a broader recipe set at the same time. Every new
(recipe × language) pair multiplies the `unknown` surface, and the product's credibility is
entirely a function of that surface staying small. The most recent commit in this repo
deleted two planned phases rather than ship something that would state a claim it could not
support. That instinct is the asset. Sequence the roadmap so it never has to be overruled.
