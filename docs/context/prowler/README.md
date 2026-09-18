# Prowler's FedRAMP 20x KSI framework — pinned, not snapshotted

Most of `docs/context/` is a snapshot that is allowed to rot (see
[`../README.md`](../README.md)). **This directory is not**, for the same reason
[`../fedramp-schemas/`](../fedramp-schemas/README.md) is not: the file here is
read by code. It is the join table `rampscan ingest` resolves a Prowler scan
against, so a copy drifting here would not go stale quietly — it would change
which check counts as evidence for which Key Security Indicator.

| | |
|---|---|
| File | `fedramp_20x_ksi_2026.json` |
| Source | [`prowler-cloud/prowler`](https://github.com/prowler-cloud/prowler), `prowler/compliance/fedramp_20x_ksi_2026.json` |
| Commit | `1b228d590b5faa92d9e0bbbab7d6c2c38d3cfeda`, 2026-09-14 |
| `framework` / `version` | `FedRAMP-20x-KSI` / `2026.07.14.01` |
| sha256 | `cc1a5fa8c88ee4e327c84ae871b8e51553b4d0c614193a25a0d5490449a8e766` (89,892 bytes) |
| Licence | Apache-2.0, with the upstream project — see [`../../../NOTICE`](../../../NOTICE) |
| Pinned in | `packages/cli/src/prowler-framework.ts` |
| Checked by | `packages/cli/test/prowler-framework.test.ts` |

## Why a commit and a sha256, and not a version

Three labels point at three different things here, and none of them is a
release:

- the file's `version` says **2026.07.14.01**;
- the commit that added it says **2026.06.24.01** in its subject;
- rampscan pins the FedRAMP dataset at **2026.09.13.02**.

**No published Prowler release ships this file at all** — 5.42.0 predates its
only commit by three days — so the artifact is a branch, and a branch can be
rewritten under an unchanged `version`. That is precisely the class of move
[`packages/dataset/src/pins.ts`](../../../packages/dataset/src/pins.ts) exists
to complain about: a version we reason against that nothing was checking. The
bytes are what is pinned; the commit is what a reader diffs against.

The dataset gap is a non-event, and it is checked rather than assumed. P1
established that the 46 indicators, their statements and their control mappings
are byte-identical between `2026.07.14.01` and `2026.09.13.02`, which is what
let rampscan's own crosswalk be re-pinned without re-reading an entry. The
golden test re-derives that agreement on every run, three ways: the id sets
match in **both** directions, the five indicators optional at class b match, and
all **373** KSI→control edges match. So no crosswalk is needed on this path, and
if that ever stops being true it stops in CI rather than in a bundle.

## What is NOT kept here

A rampscan-owned copy of the check→KSI mapping. Prowler publishes that mapping
and owns it; keeping a second copy is the `labels.json` mistake P1 deleted —
a hand-kept table that looks current and is one upstream renumbering away from
naming the wrong thing.

What rampscan does keep beside the file is a judgement upstream does not
publish: [`recipes/prowler/uncovered.json`](../../../recipes/prowler/uncovered.json),
one line per indicator that no check on any provider reaches, saying why a scan
of cloud resource state cannot see it. The **set** is computed from this file
on every test run; only the reasons are written by hand.

## Re-pinning

A bump is a reviewed change, never a refresh. Fetch the file at the new commit,
run the suite, and read what the failures say:

```
curl -sSL -o docs/context/prowler/fedramp_20x_ksi_2026.json \
  https://raw.githubusercontent.com/prowler-cloud/prowler/<commit>/prowler/compliance/fedramp_20x_ksi_2026.json
pnpm vitest run packages/cli/test/prowler-framework.test.ts
```

The reader refuses a key it has never read, so a new field arrives as a named
refusal rather than as a silently dropped one. Update the pin in
`prowler-framework.ts`, then re-read `recipes/prowler/uncovered.json` against
the new mapping — if upstream authored a check for one of those thirteen, the
row goes, and the test fails until it does.
