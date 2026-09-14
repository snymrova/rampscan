# Finding — `not_affected` is signed from an absent graph node

**Status:** recorded, not yet fixed. This is the reproduction record required by `docs/PLAN-SOUNDNESS.md` §5, phase **S0** (S0-4), and it is the body of the security advisory filed under `SECURITY.md` (S0-1).
**Date:** 2026-09-13
**Affects:** `main` at `2801f8c` and every commit back to the introduction of the reachability gate. Only `main` is supported.
**Class:** *a check that reports `evidenced` without the evidence being there* — the one threat `SECURITY.md` names as specific to what this tool is, and calls "a security report, not a bug report, and the most valuable one this project can receive." Found internally, and routed through the project's own policy on purpose: a security policy that binds strangers only is not a policy.
**Ground rule:** **7 — no vacuous passes, ever.**
**Reporter:** the maintainer. **Fix:** phase S1 (#128–#132).

---

## 1. Summary

`packages/collectors/src/reachability.ts:142` treats *the absence of a package from the code graph* as a proof that the package is unreachable, and emits a signed OpenVEX `not_affected` statement from it. Dependency nodes exist only where first-party source names them in an `import`, so **any advisory in a package your own source does not import directly is suppressed** — which on a typical Node service is the overwhelming majority of advisories, because transitive depth is where advisories live.

The suppression is not merely displayed. It is written to `openvex.json`, digest-pinned as a subject of a signed bundle, and it is the reason `no-critical-reachable-advisories` reports `evidenced`: that recipe's assertion is `count_eq 0` over rows where `severity in (CRITICAL, HIGH)` **and `not_affected == false`**.

## 2. Blast radius, stated plainly

**No false document has reached anyone.** `rampscan-out/` is gitignored (`.gitignore:9`) and **no file under it is tracked** — the `openvex.json` described below exists in the maintainer's working tree and has never been published, and the repository has 0 stars, 0 forks and 2 views in fourteen days. There is no adopter holding a false VEX document from this tool today, and therefore no embargo argument; the advisory is public and the fix happens in the open.

That bounds the impact. It does not change the class: the defect is in the load-bearing claim of the product, and the first person who runs `rampscan scan` against a real repository gets a signed false negative on their `HIGH` advisories.

> **Correction to `docs/PLAN-SOUNDNESS.md` §2.1 and §2.7.** That document calls the artifact "committed" and "published, reachable on GitHub". It is neither — verified by `git ls-files rampscan-out` returning nothing, below. The mechanism, the five statements, the graph and the SBOM edge are all exactly as §2 describes; only the publication status was wrong, and it was wrong in the direction that overstated severity. Recorded here rather than quietly edited.

## 3. The mechanism

`packages/collectors/src/reachability.ts:142`:

```ts
const notAffected = gated && (dep === undefined || !dep.reachable);
```

`dep === undefined` means the package has **no node in the code graph**. It is given standing equal to a completed walk that failed to arrive.

Dependency nodes come from one place — `packages/graph/src/extract.ts:324` creates `kind: "dependency"` from an import specifier — and `dependencyReachability` (`packages/graph/src/query.ts:151-155`) builds its whole map from `SELECT id, package FROM nodes WHERE kind = 'dependency'`. **There is no package→package edge anywhere in `graph.db`.**

### 3.1 The code's own safety argument does not hold

`packages/graph/src/query.ts:11-14` states the contract:

> dependency reachability walks EVERY edge kind (over-approximate): a not-affected VEX claim is only made when even the loose walk cannot reach the package.

The walk is over-approximate *within the edges the graph has*. The graph has no package-dependency subgraph at all, so the over-approximation the argument rests on is not present in the data. `recipes/commit/no-critical-reachable-advisories.json` publishes the same contract to users — "An advisory is `not_affected` only when the code graph PROVES the package is beyond every entry point and declared route" — and the implementation does not meet it.

### 3.2 Why this is ground rule 7 and not an ordinary bug

> **7. No vacuous passes — ever.** A recipe may not report `evidenced` from the *absence* of something to check. […] a boundary rule whose module path matches nothing fails, because a module path that matches nothing is guarding nothing.

A `not_affected` derived from a package having no node is structurally identical: the check found nothing to check and reported success. Rule 7 is enforced by `catalog.test.ts` and `catalog-bare.e2e.test.ts` over recipe **verdicts**; it was never extended to the reachability collector's **gating**, which is where the same failure mode moved.

### 3.3 A second, independent hole in the same claim

`rampscan.config.json` declares `graph.entrypoints: ["packages/cli/src/main.ts"]`, and `detectEntrypoints` (`packages/graph/src/entrypoints.ts:44-53`) returns **only** the configured entries when any are configured — package.json detection is skipped entirely. This repository holds two applications: the CLI, and `console/web`, a Next.js app. The console's entry points are not declared, so nothing it imports is on any walk. `basis.entrypoints` records the narrowing and the `impact_statement` names the file, which is honest as far as it goes — but an assessor reading `status: not_affected` will not read "(packages/cli/src/main.ts)" as *we walked one of your two applications*. **A negative claim must state the scope it is negative over, or refuse to be made.**

> **Closed, 2026-09-14 (S1-3).** The gate now measures the width of its own walk. Every directory with its own `package.json` that owns source files is an application root; `graph.db` records them (extractor 0.3.0) and the reachability collector counts how many of each root's files the walk from the entry points and declared routes reached. While any root reads zero — or the graph predates the record — `not_affected` is refused for the run: the row reads `unknown` with the refusal as its `gate_note`, the OpenVEX statement reads `under_investigation` with the same sentence, and `basis.degraded` carries it beside `basis.application_roots`. Every statement of a gated run carries `rampscan:scope` — commit, entry points, their source, and each root with `walked: true|false` — so the assessor in the paragraph above reads the width in fields, not in a parenthesis. On this repository's own graph there are **twelve** roots and **two** never entered: `console/web` (41 files) and the workspace root itself (28 files — PocketBase hooks and migrations, scripts, e2e, the two config files), a third application this document had not counted. Under S1-3 the self-scan signs no negative until S1-4 brings both into the walk.
>
> The coverage table also surfaced what the entry-point set alone could not: `extract.ts` emits no edge for `export … from "x"`, so the walk enters each `@rampscan/*` package at its `index.ts` barrel and stops — `packages/core` 1 of 13 files reached, `packages/schema` 1 of 14. That is §3.1's shape (a node the walk never arrives at) produced by the extractor rather than by the config, and it is recorded under the plan's S4-1 with a recommendation to fix the edge before S1-5.
>
> **Closed, 2026-09-14 (extractor 0.4.0).** The edge is emitted: an `export … from "x"` declaration now produces the same `exact` `imports` edge an import does, for `export *`, `export { a as b }`, `export * as ns`, and `export type { T }`. Re-measured from the configured entry point: files reached 60 → 109 of 285, every `@rampscan/*` package's `src/` entered in full except one file in `collectors` and seven in `cli`. Dependency packages reached: 12 → 12 — on this tree no package sat *only* behind a barrel, so the board does not move; the shape is closed regardless. What still keeps the walk out of `console/web` and the workspace root is the entry-point set, which is S1-4.

## 4. Reproduction

Every number below came from the command beside it, run against this working tree on 2026-09-13 at `2801f8c`.

### 4.1 Five advisories, three of them HIGH

```console
$ python3 -c "
import json
d=json.load(open('rampscan-out/artifacts/osv-scanner/osv-results.json'))
for res in d['results']:
    for p in res['packages']:
        for v in p['vulnerabilities']:
            print(p['package']['name'], p['package']['version'], v['id'], v['database_specific']['severity'])"
postcss 8.4.31 GHSA-6g55-p6wh-862q HIGH
postcss 8.4.31 GHSA-fxqj-rqcc-2cmp MODERATE
postcss 8.4.31 GHSA-qx2v-qp2m-jg93 MODERATE
postcss 8.4.31 GHSA-r28c-9q8g-f849 HIGH
sharp   0.34.5 GHSA-f88m-g3jw-g9cj HIGH
```

### 4.2 All five suppressed, and the suppression signed

```console
$ python3 -c "
import json
d=json.load(open('rampscan-out/exports/openvex.json'))
print('statements:', len(d['statements']))
for s in d['statements']:
    print(' ', s['status'], s['justification'], [p['@id'] for p in s['products']])"
statements: 5
  not_affected vulnerable_code_not_in_execute_path ['pkg:npm/postcss@8.4.31']
  not_affected vulnerable_code_not_in_execute_path ['pkg:npm/postcss@8.4.31']
  not_affected vulnerable_code_not_in_execute_path ['pkg:npm/postcss@8.4.31']
  not_affected vulnerable_code_not_in_execute_path ['pkg:npm/postcss@8.4.31']
  not_affected vulnerable_code_not_in_execute_path ['pkg:npm/sharp@0.34.5']
```

**Every advisory this repository has is suppressed.**

### 4.3 Neither package has a node, and no package→package edge exists

```console
$ python3 -c "
import sqlite3
c=sqlite3.connect('rampscan-out/artifacts/graph/graph.db')
d=sorted({r[0] for r in c.execute(\"select package from nodes where kind='dependency'\")})
print(len(d), d)
print('postcss:', 'postcss' in d, '| sharp:', 'sharp' in d)
print('edge kinds:', list(c.execute('select kind, count(*) from edges group by kind')))"
17 ['@playwright/test', 'next', 'node:async_hooks', 'node:child_process', 'node:crypto',
    'node:fs', 'node:os', 'node:path', 'node:sqlite', 'node:url', 'node:util',
    'pocketbase', 'react', 'typescript', 'vitest', 'yaml', 'zod']
postcss: False | sharp: False
edge kinds: [('calls', 1732), ('declares', 609), ('exports', 224), ('imports', 1019)]
```

17 dependency packages, every one of them a direct first-party import. No `depends_on` edge kind exists.

### 4.4 The data that disproves the claim is in the same output directory

```console
$ python3 -c "
import json
s=json.load(open('rampscan-out/artifacts/syft/sbom.cdx.json'))
ref2name={c['bom-ref']: c['name']+'@'+c['version'] for c in s['components'] if 'bom-ref' in c}
print('components', len(s['components']), '| dependency entries', len(s['dependencies']))
for d in s['dependencies']:
    if ref2name.get(d['ref'],'').startswith('next@'):
        print('next ->', [ref2name.get(x,x) for x in d['dependsOn'] if 'postcss' in ref2name.get(x,x)])"
components 173 | dependency entries 34
next -> ['postcss@8.4.31', 'postcss@8.5.26']
```

- **`postcss`** — the edge `next@15.5.23 → postcss@8.4.31` is in the SBOM, and `next` is a dependency node that ~~*is* reachable from the declared entry point~~ **is not reached from the declared entry point — see the correction below.** `postcss` is provably **reachable** from data rampscan collected, wrote to disk, and signed a contradicting statement about in the same run — *provably present below `next`*; whether `next` itself is in the execute path is exactly the §3.3 question.
- **`sharp`** — no path from `next` in the SBOM's `dependsOn`. The SBOM graph is partial (34 of 173 components carry outgoing edges), so `sharp` is genuinely **unknown**: not provably reachable, and not provably unreachable either.

Those two packages are the two halves of the correct, three-valued answer.

> **Correction, 2026-09-14 (S1-2).** The sentence struck above was wrong on the graph this section cites. Measured on `rampscan-out/artifacts/graph/graph.db` (commit `306ca638910b`, extractor `0.2.0+ts5.9.3`, entry points `["packages/cli/src/main.ts"]` from config): `reachableSet(db, entryRoots(db)).has("dep:next")` is **`false`**. The only importer of `next` is `console/web/app/layout.tsx`, which no configured entry point covers — so `next` has a node and the walk never arrives at it, which is §3.3's hole, not §3.1's. Two consequences, both recorded rather than smoothed over: (1) S1-2's SBOM join changes **nothing** on this repository's own artifacts, because the manifest walk can only start from a package the code walk reached and `next` is not one; `postcss` flips when S1-4 brings the console's root into the walk. (2) Under the gate as it stands, an advisory against `next` itself would be signed `not_affected` — the plan's S1-3 and S1-4 exist for precisely this, and this measurement is their concrete case. The `next → postcss` edge is as real as §4.4 says; what it proves is presence below `next`, and the claim that `next` was reached was never checked against the graph. It has been now.

### 4.5 Nothing under `rampscan-out/` is published

```console
$ git ls-files rampscan-out | wc -l
0
$ grep -n "rampscan-out" .gitignore
9:rampscan-out/
```

### 4.6 The defect has a passing test asserting it is correct

`packages/collectors/test/reachability.test.ts:110` — "proves the difference: lodash reachable with a path, minimist not_affected". `minimist` is declared in `fixtures/vulnerable-app/package.json:8` and imported by nothing, so it has no node, so it is `not_affected` by the very mechanism above. The test is green today and it is asserting the bug. **S1-1 must change this test, not preserve it.**

### 4.7 The failing test that gates the fix (S0-3)

`packages/collectors/test/reachability-soundness.test.ts` builds the same shape deliberately — `minimist` absent from the graph, present in a CycloneDX SBOM as a dependency of the reachable `lodash` — and asserts no `not_affected` may follow. Against `2801f8c`:

```console
$ npx vitest run packages/collectors/test/reachability-soundness.test.ts

 FAIL  packages/collectors/test/reachability-soundness.test.ts > S0-3 — a package absent from
       the graph is not proof of unreachability > does not sign not_affected for a package the
       walk never had a node for
AssertionError: expected true to be false // Object.is equality

- Expected
+ Received

- false
+ true

 ❯ packages/collectors/test/reachability-soundness.test.ts:125:38
    125|     expect(minimist["not_affected"]).toBe(false);
       |                                      ^
```

The committed form of that test is wrapped in `it.fails`, so `main` stays green while the finding is recorded rather than fixed, and the wrapper starts failing the moment S1-1 corrects the behaviour — which is what forces it to be unwrapped.

## 5. The fix, in one rule

**`not_affected` requires a node.** Three-valued, and everything else follows:

| claim | condition |
|---|---|
| `reachable: true` | a walk arrived — source graph or SBOM `dependsOn`; the path is the artifact |
| `not_affected` | a walk completed over a graph that **contains** the node, and missed; the scope is stated in the document |
| `unknown` | the walk was not possible, or the node was never in the graph |

Absence of a node yields `unknown`, never `not_affected`. The SBOM graph joins the walk as a **presence-prover only** — it is partial by measurement (§4.4), so it may upgrade `unknown` to `true` and may never justify a negative. Any later change that lets it do so reintroduces this finding in a new place.

Full remediation is `docs/PLAN-SOUNDNESS.md` phase S1 (#128–#132). Expected outcome on this repository: `postcss` reads `reachable: true` through `next`, `sharp` reads `unknown`, `openvex.json` carries zero `not_affected` statements, and `no-critical-reachable-advisories` flips `evidenced` → `violated` because two `HIGH` advisories are in fact reachable. **The self-scan gets worse — `12 evidenced · 2 violated` becomes `11 evidenced · 3 violated` — and that is the fix working.**

## 6. Timeline

| | |
|---|---|
| 2026-09-13 | Found during a full read of the repository for the S plan; `docs/PLAN-SOUNDNESS.md` §2 written |
| 2026-09-13 | Plan adopted (`2801f8c`, PR #123); S0 opened |
| 2026-09-13 | S0-3 failing test committed; this record written; advisory filed publicly, no embargo (S0-1) |
| 2026-09-14 | S0 merged (`c35b390`, PR #144); advisory published as [GHSA-7jff-6v53-r56x](https://github.com/snymrova/rampscan/security/advisories/GHSA-7jff-6v53-r56x) |
| 2026-09-14 | S1 closed at `c0d1c73`: the self-scan's `no-critical-reachable-advisories` row reads `violated` — six CRITICAL/HIGH advisories reachable or unknown (`next` ×2 exact, `postcss` ×2 via `sbom`, `sharp` ×2 unknown) — and `openvex.json` carries no statement resting on an absent node; its one `not_affected` (`vitest`) names 57 entry points, 12 roots walked, nothing excluded |
| 2026-09-14 | S1-1 (#128): the `dep === undefined` disjunct removed — a package with no graph node is `reachable: unknown`, counts, and is stated `under_investigation` in OpenVEX; S0-3 unwrapped from `it.fails` and passing. On the fixture the flagship recipe's offenders go from 2 to 3 (`GHSA-xvch-5gv4-984h`, minimist, joins them) |
| 2026-09-14 | S1-2 (#129): the SBOM's `dependsOn` edges join the walk as a presence-prover — hops marked `sbom`, the join written so it can only add to the reachable set, an invariant test guarding the direction. On the fixture, `minimist` becomes `affected` through `lodash ⇒ minimist`. On this repository's own graph, nothing moves: §4.4's claim that `next` was reached was wrong (corrected in place) — `next` is a node the walk never arrives at because `console/web` is outside the configured entry point, so `postcss` waits on S1-4 |
| 2026-09-14 | S1-3 (#130): a negative claim states its width and refuses to be made at less than the whole tree — application roots recorded in `graph.db`, coverage measured per root, `not_affected` refused while any root is never entered, `rampscan:scope` on every VEX statement. Measured: twelve roots on this repository, `console/web` and the workspace root never entered; and `export … from` barrels stop the walk at every package's `index.ts` (§3.3 addendum) |
| — | Remaining S1 (#131–#132), and `openvex.json` regenerated rather than deleted (S0-2) |
