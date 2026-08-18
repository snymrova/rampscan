# Contributing to rampscan

This file is not a template. It is the set of rules that actually decide whether a
change merges here, and for most of them the enforcement is a test that fails CI
rather than a reviewer who remembers. Where that is true, the test is named — read
it before arguing with the rule, because the test is the rule and this document is
a description of it.

The short version: **rampscan's product is evidence, so the standard a change is
held to is the standard the product claims.** A number that no command produced, a
pass that came from finding nothing to check, or a disposition asserted instead of
argued — each of those is the exact failure the tool exists to detect in other
people's repositories, and none of them merges into this one.

---

## Getting set up

```
pnpm install          # Node 22, pnpm
pnpm test             # the whole suite — unit and e2e
pnpm typecheck        # tsc --build, root and console
pnpm doctor           # how each scan tool resolves on this machine
```

`pnpm doctor` is worth running first. Scan tools resolve Docker-first: a binary on
`PATH` is used as-is, otherwise the pinned image from
[`packages/collectors/tools.json`](packages/collectors/tools.json) runs. rampscan
never installs anything on the host. With neither binary nor Docker, a collector
skips gracefully and its recipes report `unevidenced` with the reason recorded —
that path is a feature, and tests cover it.

The CLI runs from the clone: `pnpm rampscan <command>`. No package is published and
none declares a `bin`, by decision.

Before opening a pull request, run `pnpm test` and `pnpm typecheck`. CI runs both,
and a change that breaks either will be caught there; running them locally just
makes it cheaper.

### Scanning this repository with a secret scanner

There is no `.gitleaksignore` here, deliberately. rampscan's own history is clean —
`gitleaks git --redact .` reports no leaks across every commit, and the fixture's
planted credentials are assembled at build time so no shaped literal exists in any
blob. That is the command the `gitleaks` collector runs, so the self-scan sees the
same thing.

A *working-tree* scan (`gitleaks dir .`) is a different matter and will report
findings — the local signing key under `rampscan-keys/`, the PocketBase superuser
record, and pattern hits inside `console/web/.next/` build output. All of it is
gitignored and none of it is tracked. It is not allowlisted because those are
precisely the paths where an accidental commit would matter most, and an allowlist
that quiets a scan you are not running is a detection hole you are.

---

## The ten ground rules

Six have been active since the first commit. Four more arrived later, with the
coverage push, and exist because a coverage push is the easiest way to destroy
this product's credibility.

**1. Ports and adapters, or it does not merge.** Any code touching storage,
signing, execution, scheduling or repo access goes through an interface in
`packages/core`. No direct `fs` or `child_process` calls from business logic.
*Enforced by:* this repository declares its own architecture contract in
`rampscan.config.json` and scans itself — `pnpm rampscan check .` is the live gate,
and `packages/cli/test/self-contract.test.ts` catches the way it rots quietly (a
rule whose module path no longer matches anything still parses, and a rule that
guards nothing is a rule that has stopped working).

**2. The `dataset_version` pin is enforced at load.** The dataset client refuses to
run on a mismatch. Dev mode reads `docs/context/ramprules/derived/`; those copies
are a snapshot and never the source of truth. Do not edit them to make something
pass.

**3. Append-only is enforced by the adapter and tested by a cheat.** The ledger
suite includes tests that *try* to tamper and must fail —
`packages/ledger/test/ledger.test.ts`. A change to the ledger that does not keep
those tests failing-to-cheat has removed the property, whatever else it did.

**4. Computed, never typed.** Any number that appears in a generated document, the
README, a release note or a comment comes from a run, not from a keyboard. This is
inherited from ramprules and it is the house rule most often broken by accident,
usually by copying a figure that was true last month.

**5. Tool versions ride in every cache key and every bundle's provenance.** A
result cached under a key that does not name the tool version is a result that will
be served after the tool changes.

**6. Tests ride with the change.** Not as a cleanup task afterwards.

**7. No vacuous passes — ever.** A recipe may not report `evidenced` from the
*absence* of something to check. A repository with no detected routes stays
honestly `unevidenced`; a boundary rule whose module path matches nothing fails,
because a module path that matches nothing is guarding nothing. *Enforced by:*
`packages/cli/test/catalog.test.ts` statically and
`packages/cli/test/catalog-bare.e2e.test.ts` dynamically, over a real scan of a
barren fixture. See "Adding a recipe" below — this rule is most of what that
checklist is.

**8. A disposition is reasoning, not a label.** Every adjudication record carries
an authored paragraph in the frontier's own voice, of the length and specificity
the existing records use. An adjudication without reasoning is an opinion, and this
repository does not ship opinions as evidence.

**9. Coverage is computed, never typed.** Rule 4 pointed at the one number this
project has an incentive to round up. `rampscan frontier` owns coverage. No
coverage figure enters a document unless a command emitted it, and the ceiling —
what the repository *cannot* answer — is published beside it.

**10. An adjudication upstream has already written is read before it is
re-written.** Where we agree with a published disposition, the record cites it and
adds only what a *commit* answers that an *API* does not. Where we disagree, the
record says so and argues. A silent disagreement between two overlays makes both
worthless.

---

## Adding a recipe

Recipes live in [`recipes/commit/`](recipes/commit/) as JSON, validated by
`PipelineRecipe` in `packages/schema`. Read an existing one first —
`recipes/commit/security-disclosure-published.json` is a good short example of
every obligation below in one file.

A recipe merges when all of this is true:

- [ ] **It parses.** `PipelineRecipe` is the shape gate. Shape is the schema's job.
- [ ] **Its `control_ids` and `ksi_ids` resolve** against the pinned dataset.
- [ ] **It declares `empty_means`.** What does an empty observation set mean for
      *this* recipe? The assertion layer passes an empty filtered set vacuously by
      design, and that is correct for "every active key is rotated" and
      catastrophic for "the repository has a security policy". The difference is
      not in the assertion or the collector — it is in what the recipe is asking,
      so the recipe has to say.
- [ ] **Its `notes` name the empty-set pattern**, in the sentence form the catalog
      uses: `Empty-set discipline — <Pattern>: …`, where the pattern is one of
      **Guard · Skip · Witness · Counter · Negative witness**. A recipe that cannot
      say which pattern it uses has not decided how it behaves on a repository
      lacking the thing it checks, and undecided is what a vacuous pass looks like
      in production.
- [ ] **It carries all three `plain` paragraphs**, authored, not copied out of the
      auditor-facing `evidence` line:
      - `checks` — what the collector actually looked at;
      - `violation` — what it means for the reader that this failed, in the
        reader's terms and consequences, not the control's;
      - `fix` — what to do, and honestly where the fix stops.
      `plain` is optional in the schema (the recipe shape mirrors the upstream AWS
      dataset's, which has no such field, so an imported recipe must still parse)
      and **required in this catalog**. *Enforced by:*
      `packages/cli/test/plain.test.ts`, which also refuses a stub, a paragraph
      recycled from the auditor-facing `evidence` line, any paragraph that states a
      verdict or a count or a condition of some particular repository, and any
      rampscan term used in the prose that the console's glossary does not define —
      the last one is what stops jargon being explained with more jargon.
- [ ] **Its `caveats` state the remainder.** What the recipe does not reach. A
      recipe that reads a file's existence does not claim the file is adequate, and
      saying so is not a weakness — it is the property that makes the rows that do
      pass believable.
- [ ] **If `empty_means` is `clean`, the `notes` say what domain was searched
      exhaustively** — in words that read as a totalizing quantifier (*every*,
      *all*, *entire*). "Nothing was found" is only good news when the search
      covered everything it claimed to, and a `clean` declaration is precisely the
      claim that it did.

## Adding or changing an adjudication

Adjudications live in [`recipes/adjudications/`](recipes/adjudications/), one file
per control, and they are how this project records what a repository can and cannot
answer. Ground rules 8 and 10 are the whole job:

- [ ] **`rationale` is an argument**, in the register the existing records use —
      what the control asks, which limb a checkout can reach, which it cannot, and
      why the line falls where it does rather than one control over.
- [ ] **`remainder` names what is left**, split into the control's own unreached
      limbs and the boundary limitation. Everything the disposition does not claim
      goes here, specifically enough that a reader can tell whether it matters to
      them.
- [ ] **`citesUpstream` is filled where upstream has spoken** — their disposition,
      whether this record `agrees` or `diverges`, and a note that argues the
      divergence narrowly. *Enforced by:* `packages/cli/test/frontier.test.ts`,
      which checks that dispositions are filed by the source that wrote them, that
      a record whose control leaves the frontier is retired rather than deleted,
      that a refusal points somewhere, and that where upstream has spoken the
      record says whether it agrees.
- [ ] **A `partial` disposition does not add to the coverage figure.** It adds to
      the authoring backlog. Do not let a record's disposition drift upward because
      a recipe is nearly written.

---

## Pull requests

- **One concern per pull request.** The commit history here is long-form on
  purpose: a message says what landed *and why the decision went that way*,
  including what was tried and rejected. Match that. A message that only restates
  the diff has thrown away the part a reader six months out actually needs.
- **Say what you verified, and with which command.** Ground rule 4 applies to pull
  request descriptions as much as to documents. "Tests pass" is weaker than the
  command and its output.
- **A correction to a plan is part of the change.** When execution shows a planned
  item was wrong or under-scoped, amend the plan document in the same commit and
  record what was learned. Several of the plan documents carry exactly these
  corrections inline; they are the most useful paragraphs in them.
- **Do not weaken a fixture to make a scan quiet.** `fixtures/vulnerable-app` has
  planted faults deliberately, and its determinism (fixed timestamps and identity,
  stable SHAs) is load-bearing for tests elsewhere. If a scanner flags it, the
  resolution is an allowlist with a stated reason, never a quieter fixture.

## Reporting a vulnerability

Not through an issue or a pull request. See [`SECURITY.md`](SECURITY.md).
