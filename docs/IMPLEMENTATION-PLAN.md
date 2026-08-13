# rampscan — local prototype implementation plan

**Status:** committed plan for the first build. MVP discipline throughout: every milestone ends with something runnable, and anything that doesn't serve the core demo is deferred by name.
**Date:** 2026-08-13
**Reads against:** `docs/SPEC.md` (the target architecture — this plan builds a local-first subset of it), `docs/COMPLIANCE-SCAN-HARNESS.md` §11–13 (decisions).

---

## 1. What the prototype must prove

One loop, end to end, on a laptop:

> Point rampscan at a real repository → it scans → produces **evidence bundles keyed to ramprules recipe/KSI/control IDs**, signed and commit-anchored → a board shows **evidenced / violated / unevidenced** with a freshness clock → change the code → re-scan → the affected evidence **dies automatically** and the board shows the drift.

That loop is the entire thesis in miniature: the join (scanner ↔ catalog), the honest default (unevidenced visible), the anchor (evidence dies with its code), and the clock (MVX cadence). If the local prototype demonstrates those four, the AWS appliance is an infrastructure exercise. If it can't, no amount of Terraform saves it.

**Dogfood target:** `~/Projects/ramprules.com/fedramp-rules-hub` — a real TypeScript repo with a lockfile, CI, and the pleasant recursion that rampscan's first scanned repo is the project that defines its catalog. Secondary fixture: a deliberately broken toy repo (planted secret, vulnerable dep, unpinned action) so violations are demonstrable on demand.

### Not in the prototype, by name

Terraform/Fargate/Step Functions (local runner instead) · KMS + Object Lock (local cosign keypair + append-only dir) · Bedrock tier 3 (no model anywhere in the MVP) · the full 121-control adjudication (a starter set of ~12 recipes instead) · the semgrep, checkov, and spectral collector families (M1's five collectors instead) · multi-repo joins · GovCloud anything · the React Flow canvas (registers only) · webhooks (CLI + local cron).

---

## 2. The architectural insurance: ports and adapters

The one rule that keeps prototype code alive into the appliance: **every AWS dependency in the spec is an interface in the prototype**, with the local implementation written now and the AWS one later. Concretely, `packages/core` defines:

```ts
LedgerStore     // append(bundle), get(digest), list(query)      → local: content-addressed dir   → later: S3 + Object Lock
Signer          // sign(statement), verify(envelope)             → local: cosign keypair on disk  → later: cosign + KMS
Runner          // run(collectorManifest, workspace)             → local: child process / Docker  → later: Fargate task
Scheduler       // ensureCadence(class, target)                  → local: node-cron + CLI         → later: EventBridge
RepoSource      // fetch(ref) → workspace                        → local: path or git clone       → later: GitHub App
Projector       // fold(ledger) → projection                     // pure — identical in both worlds
```

Collector manifests, the finding schema, recipe schema, bundle format, and the projector are **identical** in prototype and appliance. What swaps is plumbing. This is the difference between "prototype" and "throwaway."

---

## 3. Milestones

Ordered so each one is demoable, and each de-risks the next. Estimates are focused-work days, honest but rough.

### M0 — Scaffold and contracts (1–2 days)

pnpm monorepo per the spec's §9 layout (only the packages M1 needs), Node 22, vitest, Zod.

- `packages/schema`: the **Finding** type (code-graph doc §5 + `ksi_ids`/`control_ids`), the **PipelineRecipe** type mirroring `aws-evidence.json`'s recipe shape (`collection.kind: "pipeline"`, assertions, cadence, `automatable`), the **EvidenceBundle** (in-toto statement shape).
- `packages/dataset`: loads ramprules slices from `docs/context/ramprules/derived/` (dev mode) or ramprules' `/api/*` (pinned mode); exposes `recipe(id)`, `controlsFor(ksi)`, `ksisFor(control)`; refuses to run if `dataset_version` mismatches the pin.
- `packages/core`: the port interfaces above, local adapters stubbed.
- `fixtures/vulnerable-app`: the planted-fault toy repo.

**Done when:** `pnpm test` green; schema round-trips a hand-written recipe; dataset client answers `ksisFor("ac-2.1")` correctly against the snapshot.

### M1 — First vertical slice: scan → joined findings (3–4 days)

The CLI exists: `rampscan scan <path>`.

- Five collectors — four wrapped (installed binaries; Docker images as fallback): **syft** (SBOM/CycloneDX), **osv-scanner** (advisories against the SBOM), **grype** (container: the image the repo's Dockerfile builds — OS-level packages the repo manifest never declares; skipped gracefully when there is no Dockerfile), **gitleaks** (secrets, full history) — plus one hand-rolled: **repo-facts** (plain file checks, no external tool: lockfile pinning, CI workflow presence and provenance configuration — the collector that evidences `lockfile-pinned-deps` and `CI-provenance-present`). Each wrapper: spawn → parse JSON → emit Findings in the shared schema → declare which recipe IDs it can evidence, via a collector **manifest**.
- **The starter recipe set** (`recipes/pipeline/*.json`): ~12 hand-authored pipeline recipes covering what these collectors plus M4 can prove — SBOM-exists-and-fresh, no-critical-reachable-advisories (assertion arrives in M4; until then non-reachability-gated), container-base-image-patched, no-secrets-in-history, lockfile-pinned-deps, CI-provenance-present, route-auth-coverage (assertion arrives in M4 with the graph), and the like. Each maps to real KSI/control IDs from the dataset (KSI-SVC/SCR/CNA/vulnerability clusters — SCR, not FedRAMP's public `TPR` naming, is this dataset's supply-chain theme). This is Phase 0's schema shakedown with a tenth of Phase 0's volume — MVP-first; the 121-control adjudication resumes after the prototype proves the shape.
- **The join**: collector output × recipe assertions → per-recipe verdict (`evidenced | violated | unevidenced`), each with artifacts and the commit hash.
- Output: `rampscan scan` prints the three-register summary to the terminal and writes `scan-result.json`.

**Done when:** scanning `fedramp-rules-hub` yields real evidence rows and real unevidenced rows; scanning `fixtures/vulnerable-app` yields violations with artifacts; every verdict cites recipe + KSI + control IDs that resolve against the dataset.

### M2 — Ledger, signing, and honest death (2–3 days)

The run's output stops being a JSON file and becomes a record.

- `packages/ledger` (local adapter): content-addressed append-only directory (`ledger/objects/<sha256>`, `ledger/index.jsonl`). No deletes, no rewrites — enforced by the adapter, not by discipline.
- `packages/signer` (local adapter): in-toto statement per bundle, signed with a local cosign keypair; `rampscan verify <digest>` checks any bundle offline.
- **Anchor death**: the projector computes, for every live evidence edge, whether its anchoring content hash still exists at the scanned commit; changed anchor → edge marked `dead(anchor-drift)` with the killing commit. Nothing "expires" by human memory.
- `packages/projector` v1: folds the ledger into a queryable projection (plain SQLite this milestone — PocketBase arrives with the console): current coverage, verdict history, freshness per bundle.

**Done when:** two successive scans of the same repo with a touched file in between → the touched-path evidence dies, untouched evidence survives with its original signature, and `verify` passes on both old and new bundles. The append-only property has a test that tries to cheat and fails.

### M3 — The console: registers and the clock (3–4 days)

`rampscan serve` starts PocketBase + the Next.js console locally.

- PocketBase as projection store + auth (roles: viewer / approver), populated only by the projector — the spec §6 rules apply from day one (ledger wins; projection rebuildable; a `rampscan rebuild` command proves it).
- **Coverage board**: the three registers, filterable by KSI theme / control family / repo; row → evidence detail (artifacts, assertions, commit, signature, reproduce command).
- **Clock view**: bundle age vs the target class's MVX window (class picked in config: b=7d, c=3d); expiring-first sort; stale = visually loud.
- **Drift view**: what changed between the last two scans — died, born, verdict-flipped — with the cause (anchor drift / assertion flip / tool version).
- **The first two-key write**: `notApplicable` proposal → approver signs (their PocketBase identity recorded in a signed ledger event) → register updates via projection. One flow, but it lands the pattern.

**Done when:** the M2 demo runs visually — scan, board fills, touch a file, re-scan, watch the row die and drift explain why. A `notApplicable` survives a projection rebuild because it lives in the ledger.

### M4 — The graph and the flagship join: reachability VEX (4–6 days)

The tier-2 move that nothing off-the-shelf does — and the hardest milestone; scoped tightly.

- `packages/graph`: tree-sitter + `scip-typescript` over the target repo → `graph.db` (SQLite): symbols, imports, calls, plus dependency nodes joined from the SBOM. Exact vs inferred marked per edge. **TypeScript/JavaScript only** in the prototype.
- `reaches(entrypoints, vulnerableSymbol)` via recursive CTE; entry points = package.json bins/exports + declared server routes, config-assisted where detection falls short (honesty over magic: an `entrypoints` override in config beats a silently wrong graph).
- Advisory findings from M1 get gated: reachable → `violated` with the call path *as the artifact*; unreachable → `evidenced` for the not-affected recipe, emitted as **OpenVEX** with the justification.
- **Route-auth coverage**, the first graph-native recipe: route nodes extracted from the code, and "every route reaches an auth check in its call path" answered by recursive CTE — the API-specific check that costs nothing extra once the graph exists, and turns the M1 `route-auth-coverage` recipe's assertion live.
- Console: advisory rows show the path; the VEX export lands in `exports/`.

**Done when:** `fixtures/vulnerable-app` contains one reachable and one unreachable vulnerable dependency, and rampscan proves the difference — path shown for the first, signed not-affected VEX for the second. That single demo is the product's sharpest sentence.

### M5 — The clock runs itself + self-scan (2–3 days)

- `packages/scheduler` (local adapter): `rampscan daemon` — node-cron drives re-scans on the class cadence; nearing-expiry warnings print/notify before the window closes, not after.
- **Cache verification**: incremental scans (dirty-set by content hash) with a scheduled full scan that diffs against the incremental result and alerts on divergence — the spec's "the cache verifies itself," proven locally.
- **Dogfood closure**: rampscan scans **itself**, and `docs/FRONTIER-PIPELINE.md` v0 is generated from real runs — which recipes the prototype covers, against which KSIs/controls, with live numbers. The founding doc's closing test, executed: pointed at its own repo, does the board come back worth reading?

**Done when:** the daemon has run unattended across a multi-day window on a laptop, produced fresh evidence on cadence, flagged one near-expiry, and the self-scan report renders numbers that are computed, never typed (the ramprules house rule, inherited).

---

## 4. Sequencing logic, stated once

- **M1 before any storage**: the join is the thesis; if collector-output × recipe-assertions doesn't produce honest verdicts on a real repo, the rest is furniture.
- **Ledger before console**: the board must be a projection from day one, or it will quietly become the record and the architecture's spine is gone.
- **Graph after console**: reachability is the deepest work and the best demo, but the registers are what a compliance reader trusts first — same ordering as the spec's frontend argument (§8).
- **Daemon last**: cadence only matters once there is evidence worth keeping fresh.

Total: roughly **15–22 focused days** to a prototype that runs the full loop unattended on real repos.

---

## 5. Local environment

- Node 22 + pnpm; PocketBase binary vendored in `console/pocketbase/` (checked against a pinned version); collector binaries via a `rampscan doctor` command that checks/installs syft, osv-scanner, gitleaks, cosign (brew/apt or direct release download), Docker optional as the fallback runner.
- No network needed after setup except OSV queries and (pinned mode) ramprules' API — mirroring the appliance's allowlist shape from the start.
- Tests: vitest unit per package; one end-to-end test that runs the whole M1–M2 loop against `fixtures/vulnerable-app` in CI.

## 6. Risks worth naming now

| Risk | Mitigation in this plan |
|---|---|
| Recipe authoring stalls the build (Phase 0's 121 controls is weeks of judgment) | Starter set of ~12 recipes in M1; full adjudication resumes post-prototype with a proven schema. |
| SCIP/tree-sitter rabbit hole | M4 is TS-only, entry points config-overridable, and the milestone's demo is one reachable + one unreachable dep — not graph completeness. |
| The projector quietly becomes writable | Append-only enforced in the adapter with a cheating test; `rampscan rebuild` in CI proves projection ≡ ledger. |
| Collector version drift breaks verdict comparability | Tool version in every cache key and every bundle's provenance from M1 — same rule as the appliance. |
| Prototype conventions diverge from ramprules' data discipline | `dataset_version` pin enforced at load; generated docs computed-not-typed; recipe shape mirrored field-for-field from `aws-evidence.json` (sole rename: `govcloud` → `caveats`, per the spec §10.1). |
