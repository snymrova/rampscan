# rampscan — plan of action (local development)

**Status:** working checklist — the executable layer over `docs/IMPLEMENTATION-PLAN.md`. That plan owns scope and milestone definitions; this document owns task order, exit tests, and current status, and gets updated as work lands. On any scope dispute, the implementation plan wins; on any architecture dispute, `docs/SPEC.md` wins.
**Date started:** 2026-08-13
**Mode:** everything local — no AWS, no Terraform, no Bedrock. Every AWS dependency enters only as a port interface with a local adapter (plan §2).

---

## 0. Ground rules, active from the first commit

1. **Ports and adapters or it doesn't merge.** Any code touching storage, signing, execution, scheduling, or repo access goes through a `packages/core` interface. No direct `fs`/`child_process` calls from business logic.
2. **`dataset_version` pin enforced at load.** The dataset client refuses to run on a mismatch. Dev mode reads `docs/context/ramprules/derived/`; never treat those copies as the source of truth.
3. **Append-only is enforced by the adapter, tested by a cheat.** The ledger test suite includes a test that *tries* to rewrite/delete and must fail.
4. **Computed, never typed.** Any number that appears in generated docs (`FRONTIER-PIPELINE.md`) comes from a run, not a keyboard — the ramprules house rule, inherited.
5. **Tool versions in every cache key and every bundle's provenance** from M1, exactly as the appliance will do it.
6. **Tests ride with the milestone.** vitest unit tests per package as it's built; the M1–M2 end-to-end test against `fixtures/vulnerable-app` is part of M2's exit, not a cleanup task.

---

## Phase A — environment and scaffold (before M0 counts)

- [x] A1. `git init` + first commit of the docs tree. Commit anchoring is the product's spine; the repo itself needs history from day one (M5 self-scan and gitleaks history scanning both need real commits).
- [x] A2. Toolchain check: Node 22, pnpm. Record exact versions in the session log below.
- [x] A3. pnpm workspace scaffold — only what M0 needs: `packages/schema`, `packages/dataset`, `packages/core`, `fixtures/vulnerable-app`. Shared `tsconfig`, vitest, Zod. No console/, no infra/, no empty placeholder packages.
- [x] A4. `rampscan doctor` (can be a stub script first): checks for syft, osv-scanner, grype, gitleaks, cosign; prints install hints (brew/apt/release download). Docker optional, as fallback runner only.

**Exit test:** `pnpm install && pnpm test` runs green on an empty-but-wired workspace; `git log` shows history.

---

## Phase B — M0: contracts (plan: 1–2 days)

Build order inside the milestone — schema first, because everything else imports it:

- [x] B1. `packages/schema` — **Finding** (code-graph shared schema + `ksi_ids`/`control_ids`), **PipelineRecipe** (field-for-field mirror of `aws-evidence.json`'s recipe shape: `ksi_ids`, `control_ids`, `evidence`, `collection` with `kind: "pipeline"`, `expected_output`, `assertions`, `cadence`, `automatable`, `notes`, `caveats` — sole rename `govcloud` → `caveats` — plus `anchor: commit`), **EvidenceBundle** (in-toto statement shape). All Zod, with round-trip tests.
- [x] B2. `packages/dataset` — loader over `docs/context/ramprules/derived/` (dev mode) with the `/api/*` pinned mode stubbed behind the same interface; `recipe(id)`, `controlsFor(ksi)`, `ksisFor(control)`; hard failure on `dataset_version` mismatch.
- [x] B3. `packages/core` — the six ports (`LedgerStore`, `Signer`, `Runner`, `Scheduler`, `RepoSource`, `Projector`) as interfaces; local adapters stubbed, not implemented.
- [x] B4. `fixtures/vulnerable-app` — the planted-fault toy repo: a planted secret (in history, not just HEAD), a vulnerable dependency, an unpinned CI action. Committed with its own git history inside the fixture. *Deviation: a nested `.git` cannot be committed, so the fixture is generated deterministically (fixed timestamps/identity → stable SHAs) by the committed `fixtures/build-vulnerable-app.mjs`; the generated repo is gitignored.*

**Exit test (plan §M0):** `pnpm test` green; a hand-written recipe round-trips through the schema; `ksisFor("ac-2.1")` answers correctly against the snapshot.

---

## Phase C — M1: scan → joined findings (plan: 3–4 days)

The thesis milestone — if the join doesn't produce honest verdicts here, stop and rethink before building storage.

- [ ] C1. Collector manifest format + the `Runner` local adapter (spawn → parse JSON → Findings), Zod-enforced at the wrapper boundary.
- [ ] C2. Collectors, in this order (cheapest first, each demoable alone):
  - [ ] `repo-facts` (hand-rolled, no external tool — lockfile pinning, CI workflow presence/provenance) — proves the manifest shape without dependency risk
  - [ ] `gitleaks` (secrets, full history)
  - [ ] `syft` (SBOM/CycloneDX)
  - [ ] `osv-scanner` (advisories against the SBOM)
  - [ ] `grype` (container image from the repo's Dockerfile; graceful skip when absent)
- [ ] C3. `recipes/pipeline/` starter set — ~12 hand-authored recipes covering what these collectors plus M4 can prove (SBOM-exists-and-fresh, no-secrets-in-history, lockfile-pinned-deps, CI-provenance-present, container-base-image-patched, no-critical-reachable-advisories, route-auth-coverage, …), each resolving to real KSI/control IDs (KSI-SVC/SCR/CNA clusters).
- [ ] C4. The join: collector output × recipe assertions → per-recipe verdict (`evidenced | violated | unevidenced`) with artifacts + commit hash.
- [ ] C5. CLI: `rampscan scan <path>` → three-register terminal summary + `scan-result.json`.

**Exit test (plan §M1):** scanning `~/Projects/ramprules.com/fedramp-rules-hub` yields real evidence rows *and* real unevidenced rows; scanning the fixture yields violations with artifacts; every verdict cites recipe/KSI/control IDs that resolve against the dataset.

---

## Phase D — M2: ledger, signing, honest death (plan: 2–3 days)

- [ ] D1. `packages/ledger` local adapter: `ledger/objects/<sha256>` + `index.jsonl`; the cheating test (rule 3) lands with it.
- [ ] D2. `packages/signer` local adapter: in-toto statement per bundle, local cosign keypair; `rampscan verify <digest>` works offline.
- [ ] D3. Anchor death in the projector: anchoring content hash changed at the scanned commit → edge marked `dead(anchor-drift)` with the killing commit.
- [ ] D4. `packages/projector` v1: ledger → plain SQLite projection (coverage, verdict history, freshness per bundle). PocketBase waits for M3.
- [ ] D5. The end-to-end test: full M1–M2 loop against the fixture, in CI.

**Exit test (plan §M2):** two scans with a touched file in between → touched-path evidence dies, untouched evidence survives with its original signature, `verify` passes on old and new bundles, and the append-only cheat test fails to cheat.

---

## Phase E — M3: console (plan: 3–4 days)

- [ ] E1. Vendor PocketBase (pinned version) under `console/pocketbase/`; projector becomes its only writer; `rampscan rebuild` proves projection ≡ ledger.
- [ ] E2. `rampscan serve`: PocketBase + Next.js locally. Coverage board (three registers, filterable), row → evidence detail (artifacts, assertions, commit, signature, reproduce command).
- [ ] E3. Clock view (bundle age vs class window from config, b=7d / c=3d; expiring-first) and drift view (died / born / verdict-flipped, with cause).
- [ ] E4. First two-key write: `notApplicable` proposal → approver signs → ledger event → register updates via projection.

**Exit test (plan §M3):** the M2 demo runs visually end to end, and a `notApplicable` survives `rampscan rebuild` because it lives in the ledger.

---

## Phase F — M4: graph + reachability VEX (plan: 4–6 days, hardest)

Scope guard: TypeScript/JavaScript only; entry points config-overridable; the demo is one reachable + one unreachable vulnerable dep — not graph completeness.

- [ ] F1. `packages/graph`: tree-sitter + scip-typescript → `graph.db` (symbols, imports, calls; dependency nodes joined from the SBOM; exact vs inferred per edge).
- [ ] F2. `reaches(entrypoints, vulnerableSymbol)` recursive CTE; entry points from package.json bins/exports + declared routes, with `entrypoints` config override.
- [ ] F3. Advisory gating: reachable → `violated` with the call path as the artifact; unreachable → `evidenced` (not-affected), emitted as OpenVEX with justification.
- [ ] F4. Route-auth coverage: route nodes + "every route reaches an auth check" CTE; turns the M1 recipe's assertion live.
- [ ] F5. Fixture upgrade: one reachable and one unreachable vulnerable dependency, provably different. Console shows the path; VEX lands in `exports/`.

**Exit test (plan §M4):** rampscan proves the reachable/unreachable difference on the fixture — path shown for one, signed not-affected VEX for the other.

---

## Phase G — M5: the clock + self-scan (plan: 2–3 days)

- [ ] G1. `packages/scheduler` local adapter: `rampscan daemon` (node-cron on the class cadence), nearing-expiry warnings *before* the window closes.
- [ ] G2. Incremental scans by content-hash dirty set + scheduled full scan that diffs against the incremental result and alerts on divergence.
- [ ] G3. Self-scan: rampscan scans its own repo; `docs/FRONTIER-PIPELINE.md` v0 generated from real runs, numbers computed never typed.

**Exit test (plan §M5):** daemon runs unattended across a multi-day window, produces fresh evidence on cadence, flags one near-expiry, and the self-scan board is worth reading.

---

## Deferred by name (do not build these locally)

Terraform / Fargate / Step Functions · KMS + Object Lock · Bedrock / any model · the 121-control adjudication (starter ~12 only) · semgrep / checkov / spectral collector families · multi-repo joins · GovCloud · React Flow canvas · webhooks.

---

## Session log

Update this table as work lands — newest first. "Phase" refers to this document's phases.

| Date | Phase | What landed | Notes / deviations |
|---|---|---|---|
| 2026-08-13 | A + B (M0) | git history started; pnpm workspace (Node v22.22.2, pnpm 9.6.0, git 2.43.0); `packages/schema` (Finding / PipelineRecipe / EvidenceBundle / CollectorManifest, Zod, round-trip tests); `packages/dataset` (dev loader over `derived/`, pinned-mode stub, version pin hard-fails, `ksisFor("ac-2.1") → [KSI-IAM-JIT, KSI-IAM-SUS]` verified); `packages/core` (six ports + stubbed local adapters that reject loudly); `fixtures/build-vulnerable-app.mjs`; `scripts/doctor.mjs`. `pnpm test`: 17/17 green; `pnpm typecheck` clean. | Fixture is generated, not committed (nested `.git` can't be committed) — deterministic script committed instead, SHAs stable (HEAD `9352d78`). Doctor: syft/osv-scanner/grype/gitleaks/cosign absent on this machine, Docker present — install before C2. M0 exit tests pass. Next action: C1 (collector manifest + Runner local adapter). |
| 2026-08-13 | — | Docs phase: spec, implementation plan, architecture reference, this plan | No code yet. Next action: A1 (`git init`). |
