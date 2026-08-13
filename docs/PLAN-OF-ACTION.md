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

- [x] C1. Collector manifest format + the `Runner` local adapter (spawn → parse JSON → Findings), Zod-enforced at the wrapper boundary.
- [x] C2. Collectors, in this order (cheapest first, each demoable alone):
  - [x] `repo-facts` (hand-rolled, no external tool — lockfile pinning, CI workflow presence/provenance) — proves the manifest shape without dependency risk
  - [x] `gitleaks` (secrets, full history)
  - [x] `syft` (SBOM/CycloneDX)
  - [x] `osv-scanner` (advisories against the SBOM)
  - [x] `grype` (container image from the repo's Dockerfile; graceful skip when absent)
- [x] C3. `recipes/pipeline/` starter set — ~12 hand-authored recipes covering what these collectors plus M4 can prove (SBOM-exists-and-fresh, no-secrets-in-history, lockfile-pinned-deps, CI-provenance-present, container-base-image-patched, no-critical-reachable-advisories, route-auth-coverage, …), each resolving to real KSI/control IDs (KSI-SVC/SCR/CNA clusters).
- [x] C4. The join: collector output × recipe assertions → per-recipe verdict (`evidenced | violated | unevidenced`) with artifacts + commit hash.
- [x] C5. CLI: `rampscan scan <path>` → three-register terminal summary + `scan-result.json`. (No installable bin yet: `pnpm rampscan scan <path>` via tsx.)

**Exit test (plan §M1):** scanning `~/Projects/ramprules.com/fedramp-rules-hub` yields real evidence rows *and* real unevidenced rows; scanning the fixture yields violations with artifacts; every verdict cites recipe/KSI/control IDs that resolve against the dataset.

---

## Phase D — M2: ledger, signing, honest death (plan: 2–3 days)

- [x] D1. `packages/ledger` local adapter: `ledger/objects/<sha256>` + `index.jsonl`; the cheating test (rule 3) lands with it.
- [x] D2. `packages/signer` local adapter: in-toto statement per bundle, DSSE/ECDSA-P256 keypair (cosign envelope format, node:crypto implementation); `rampscan verify <digest>` works offline.
- [x] D3. Anchor death in the projector: anchoring content hash changed at the scanned commit → edge marked `dead(anchor-drift)` with the killing commit.
- [x] D4. `packages/projector` v1: ledger → plain SQLite projection (coverage, verdict history, freshness per bundle). PocketBase waits for M3.
- [x] D5. The end-to-end test: full M1–M2 loop (two scans, touched file, anchor death, surviving signatures) in CI.

**Exit test (plan §M2):** two scans with a touched file in between → touched-path evidence dies, untouched evidence survives with its original signature, `verify` passes on old and new bundles, and the append-only cheat test fails to cheat.

---

## Phase E — M3: console (plan: 3–4 days)

- [x] E1. Vendor PocketBase (pinned version) under `console/pocketbase/`; projector becomes its only writer; `rampscan rebuild` proves projection ≡ ledger.
- [x] E2. `rampscan serve`: PocketBase + Next.js locally. Coverage board (three registers, filterable), row → evidence detail (artifacts, assertions, commit, signature, reproduce command).
- [x] E3. Clock view (bundle age vs class window from config, b=7d / c=3d; expiring-first) and drift view (died / born / verdict-flipped, with cause).
- [x] E4. First two-key write: `notApplicable` proposal → approver signs → ledger event → register updates via projection.

**Exit test (plan §M3):** the M2 demo runs visually end to end, and a `notApplicable` survives `rampscan rebuild` because it lives in the ledger.

---

## Phase F — M4: graph + reachability VEX (plan: 4–6 days, hardest)

Scope guard: TypeScript/JavaScript only; entry points config-overridable; the demo is one reachable + one unreachable vulnerable dep — not graph completeness.

- [x] F1. `packages/graph`: TypeScript compiler API (deviation from tree-sitter + scip-typescript — see session log) → `graph.db` (symbols, imports, calls, routes, dependency nodes; exact vs inferred per edge).
- [x] F2. `reaches(entrypoints, vulnerableSymbol)` recursive CTE; entry points from package.json bins/exports + declared routes, with `graph.entrypoints` override in `rampscan.config.json`.
- [x] F3. Advisory gating: reachable → `violated` with the call path as the artifact; unreachable → `evidenced` (not-affected), emitted as OpenVEX with justification.
- [x] F4. Route-auth coverage: route nodes + "every route reaches an auth check" CTE; turns the M1 recipe's assertion live.
- [x] F5. Fixture upgrade: one reachable and one unreachable vulnerable dependency, provably different. Console shows the path; VEX lands in `exports/`.

**Exit test (plan §M4):** rampscan proves the reachable/unreachable difference on the fixture — path shown for one, signed not-affected VEX for the other.

---

## Phase G — M5: the clock + self-scan (plan: 2–3 days)

- [x] G1. `packages/scheduler` local adapter: `rampscan daemon` (tick loop on the class cadence — deliberate deviation from node-cron, see session log), nearing-expiry warnings *before* the window closes.
- [x] G2. Incremental scans by content-hash dirty set + scheduled full scan that diffs against the incremental result and alerts on divergence.
- [x] G3. Self-scan: rampscan scans its own repo; `docs/FRONTIER-PIPELINE.md` v0 generated from real runs, numbers computed never typed.

**Exit test (plan §M5):** daemon runs unattended across a multi-day window, produces fresh evidence on cadence, flags one near-expiry, and the self-scan board is worth reading.

---

## Deferred by name (do not build these locally)

Terraform / Fargate / Step Functions · KMS + Object Lock · Bedrock / any model · the 121-control adjudication (starter ~12 only) · semgrep / checkov / spectral collector families · multi-repo joins · GovCloud · React Flow canvas · webhooks.

---

## Session log

Update this table as work lands — newest first. "Phase" refers to this document's phases.

| 2026-08-13 | G (M5) | The clock runs itself. `packages/scheduler` — the sixth and last port's real local adapter: pure cadence math (`assessCadence`: scan due at 0.5 of the MVX window or on a moved HEAD or on no evidence; warn at 0.75, the console's "expiring" threshold; expired past 1.0) + a **setTimeout tick chain, not node-cron** — deliberate deviation, same house style as DSSE-without-cosign: cron expressions add nothing when the schedule is "check every N minutes, act on the clock math"; node-cron slots in behind the same port. Warnings emit BEFORE the scan decision each tick (a daemon that slept past 0.75 warns and then refreshes — never silence after the fact), once per bundle digest; a refresh mints a new digest and a new warning slot. **The freshness/identity tension resolved**: M2's evidence identity means unchanged evidence survives with its original timestamp — so continuously re-verified evidence would "expire" on the MVX clock. `scan()` gained `refreshOlderThanMs` (daemon sets window×0.5): identical evidence past it is **re-signed with a fresh timestamp** (prior dies `superseded` — an honest record of each re-verification); plain `rampscan scan` unchanged. **G2, the cache verifies itself**: `createCachingRunner` in core (a Runner decorator — collectors untouched), dirty-set by content hash read from `git ls-tree` blob hashes (no file I/O); per-collector `cacheScope` in the manifest — globs (repo-facts: exactly the files its checks read; grype: Dockerfiles; graph: ts/js+config), `@commit` (gitleaks, full history), `@tree` (syft), `@inputs` (osv-scanner, reachability — keyed on consumed artifact hashes). Key = collector + toolVersion + resolved scope + tools.json content hash salt (ground rule 5); skipped runs never cached (environmental); full mode bypasses reads but refreshes entries. Every `--full-every`th daemon scan runs full and `diffScanResults` (verdicts + assertion outcomes, tool-version changes as context) against the last incremental at the same commit → `divergence-report.json` + loud alert; this is also the designed corrective for what the cache cannot see (advisories published to OSV/grype's DB since the cached run, PATH tool upgraded in place). CLI: `rampscan daemon <path>` (`--cache`, `--check-interval`, `--full-every`; events logged + appended to `daemon-events.jsonl`), `rampscan report` (G3: `docs/FRONTIER-PIPELINE.md` from scan-result.json — registers, KSI/control coverage counts, theme rollup, tool provenance, skipped collectors; the generator recounts from rows, trusts nothing it can recompute). `packages/scheduler/src/mvx.ts` is the server-side twin of `console/web/lib/mvx.ts` (client bundle keeps its copy; thresholds agree by test). Core's Scheduler stub + its loud-stub test retired. `pnpm test`: 186/186. | Daemon e2e compresses the multi-day window to a fake clock (window=10s, injected `clock`): startup scan → quiet tick → cadence refresh with cache hits → quiet (clock reset by refresh) → scheduled full scan verifies clean cache → slept-past-0.75 tick warns BEFORE refreshing (remainingMs > 0) → poisoned cache entry rides one incremental scan and the next full scan catches exactly `lockfile-pinned-deps` diverging, report written → moved HEAD re-scans → `daemon-events.jsonl` holds every event. The wall-clock "unattended across a multi-day window" run is operational, not code: start `pnpm rampscan daemon <path>` and leave it. Self-scan: see FRONTIER-PIPELINE.md commit. **M5 exit test passes** in compressed form; prototype loop complete — all six ports real, all five milestones landed. |
| 2026-08-13 | F (M4) | The graph and the flagship join. `packages/graph`: extraction via the **TypeScript compiler API, not tree-sitter + scip-typescript** — deliberate deviation, taken to dodge the plan's own named risk (the SCIP rabbit hole: native bindings + an indexer install for what the prototype needs lexically). Same layering as the code-graph doc §3.2, honesty preserved per edge: `exact` = lexical fact (local decl, import binding, resolved relative path), `inferred` = unique name-match across the project (ambiguous names produce NO edge); scip-typescript slots in later behind the same node/edge schema. `graph.db` (node:sqlite): nodes (file/symbol/dependency/route), edges (imports/declares/exports/calls/handles), routes, meta (extractor version, commit, entry points, auth patterns). `reaches()` is a recursive CTE for the SET (the verdict); display paths are BFS (presentation). Two traversals, two deliberate approximation directions: advisory reachability walks every edge kind (over-approximate — `not_affected` only when even the loose walk can't reach the package); route→auth walks calls/handles only (under-approximate — a positive evidence claim needs an actual call chain, and rows say when it rests on an inferred edge). Entry points: `graph.entrypoints` config → package.json main/bin/exports → fallback; routes are always roots. Collectors: `graph` (graph.db artifact + route-auth observations + a finding per unauthed route; no routes → honestly unevidenced, never vacuously evidenced), `reachability` (osv-results.json × graph.db → gated rows; reachable CRITICAL/HIGH → finding with the call path as trace evidence; proven-unreachable → OpenVEX `not_affected` / `vulnerable_code_not_in_execute_path`; no graph or no entry points → M1 posture, rows marked `unknown`, VEX `under_investigation`); osv-scanner demoted to pure producer. Recipes: `no-critical-reachable-advisories` re-pointed at reachability (`count_eq 0 where severity in [CRITICAL,HIGH] and not_affected eq false` — unknown counts against you), `route-auth-coverage` assertion live. Fixture: minimist 1.2.5 (GHSA-xvch-5gv4-984h, CRITICAL) declared but never imported + hand-rolled express-shaped router (`/settings` behind requireAuth, `/health` bare — no real framework, so the lockfile carries only the two planted vulns). CLI copies openvex.json to `out/exports/`; console evidence page surfaces call paths from assertion details. `pnpm test`: 140/140. | **M4 exit test passes** live and in CI shape: fixture scan → `no-critical-reachable-advisories` violated citing lodash with path `src/index.js » lodash/merge`, minimist absent from findings, VEX statement `not_affected` with the entry-point impact statement, openvex.json a digest-pinned subject of the signed bundle (`rampscan verify` green on it); `route-auth-coverage` violated by exactly `GET /health`. Shortest-path note: the module-scope require IS the path (import = execution), so the flagship path runs through the import edge, not handleRequest. Next action: G1 (`packages/scheduler`, `rampscan daemon`). |
| 2026-08-13 | E (M3) | The board became visual and the two-key write landed. `packages/schema`: **ScopingEvent** (`https://rampscan.dev/scoping/v1` — subject = justification hash, predicate carries proposer + approver identities) and the **LedgerStatement** union; ledger/signer/verify widened to statements (one ledger, two statement kinds). `packages/projector` v2: fold now emits **registers** (projection × recipe set — unevidenced finally visible outside scan output; live scoping → `notApplicable`; live evidence outranks scoping), **drift events** (born / died / verdict-flipped / scoped, computed from chains), and gained a **PocketBase writer** (fetch-based admin client, v0.23+ collections API; drop-and-refill; projection collections created with `createRule/updateRule/deleteRule: null` so the projector's superuser is the ONLY writer — enforced by rules, tested by an anonymous-write-rejected test). PocketBase 0.39.10 pinned in `console/pocketbase/version.json` (sha256 per platform from the release's checksums.txt); `pnpm fetch-pocketbase` downloads + verifies, binary gitignored. CLI: **`rampscan rebuild`** (fold → SQLite → read back → require byte equality; exits nonzero on mismatch), **`rampscan serve`** (PB bootstrap: generated superuser 0600, users.role viewer/approver, demo accounts, proposals collection; fold → PB; fs.watch on `index.jsonl` re-projects on every ledger append; spawns Next.js dev with env-passed dirs), `recordScoping` (recipe resolved against catalog, dataset pin enforced, DSSE-signed, appended). `console/web`: Next.js 15 + PocketBase JS SDK, login (PB auth), **board** (4 register tabs, repo/KSI-theme/control-family filters, realtime), **evidence detail** (assertions, subjects with anchor-vs-artifact marking, signature, reproduce commands, raw statement), **clock** (age vs class window, expiring-first, b=7d/c=3d), **drift** (grouped by day with cause), **approvals** (propose from any account; approve/reject is approver-only via `/api/scoping/decide`, which verifies the PB token, signs the scoping with the approver identity in the predicate, appends to the LEDGER, then stamps the proposal). `pnpm test`: 114/114. | Next needed `resolve.extensionAlias` (workspace packages import NodeNext-style `./x.js` → x.ts). Proposals are console-writable by design (not projection); approved facts live only in the ledger. **M3 exit test passes** twice over: `packages/cli/test/scoping.e2e.test.ts` (scoping survives two rebuilds, register stays `notApplicable`, other 11 recipes stay visible unevidenced) and live in the browser — scan → board fills → propose → approve → register flips via watcher re-projection → touch Dockerfile → re-scan → exactly `container-runs-nonroot` + `container-base-image-patched` die with the killing commit named in drift. Next action: F1 (`packages/graph`: tree-sitter + scip-typescript → graph.db). |
| 2026-08-13 | tooling | Docker-first tool resolution: wrappers no longer spawn tools directly — `packages/collectors/src/tools.ts` resolves binary-on-PATH → pinned Docker image (`packages/collectors/tools.json`: syft 1.51.0, grype 0.117.0, gitleaks 8.24.3, osv-scanner 2.5.0) → skip with reason. **rampscan never installs anything on the host** (user decision: no install when Docker is possible; hence no binary downloader was built — doctor hints remain for the no-Docker case). Docker runs are path-mapped via `tool.mount(hostPath)` bind mounts, `-u uid:gid` so artifacts land user-owned, `HOME=/tmp` so git-in-container (gitleaks) behaves; grype under Docker mounts a persistent DB cache (`~/.cache/rampscan/grype-db` via `GRYPE_DB_CACHE_DIR`) so the ~700MB DB isn't re-pulled per scan. Docker tools report the bare pinned version — same string shape the binary reports — so evidence identity doesn't re-key across runtimes. doctor rewritten around resolution (binary / docker-image / MISSING). `pnpm test`: 97/97. | Live smoke with binaries hidden from PATH: gitleaks/syft/osv-scanner ran via pulled pinned images, identical verdicts (2/9/1) and identical `tool_versions` strings as the binary run; zero skipped collectors. Image-digest pinning (vs tags) deferred as appliance-level hardening, noted in tools.json. |
| 2026-08-13 | D (M2) | The output became a record: `packages/ledger` (content-addressed append-only dir — objects written `wx` + chmod 0444, `index.jsonl` append-only, `get()` re-hashes so out-of-band tampering throws; the cheat test chmods an object back and rewrites it, and is caught), `packages/signer` (DSSE envelope over the canonical in-toto statement, ECDSA P-256/SHA-256 via node:crypto — cosign's envelope format without the cosign binary; keys auto-generate at `--keys`, private key 0600), `packages/projector` (pure fold: per-recipe chains → predecessor dead as `superseded` or `anchor-drift` with killing commit; cross-recipe anchor death when another recipe's later bundle saw the same path change; SQLite writer via node:sqlite, drop-and-refill because the ledger is the record), `canonicalJson` in schema (one byte sequence per statement, shared by digest + signature). CLI: scan signs + appends each evidenced/violated row unless identical evidence already exists (**evidence identity = verdict + anchors + assertion outcomes + tool/dataset version, deliberately not artifact hashes** — collector artifacts aggregate every recipe, keying on them would kill everything on any change); `rampscan verify <digest>` (content + signature + payload-covers-this-bundle, offline); `rampscan board` (live/dead registers + `--db` SQLite). `pnpm test`: 90/90 green; typecheck clean. | Unevidenced rows never reach the ledger (no artifacts, nothing to attest) — the board's third register stays in scan output until M3 joins projection × recipe set. Live demo on the fixture: touching the Dockerfile killed exactly `container-runs-nonroot` + `container-base-image-patched` (anchor-drift, killing commit named), 9 bundles survived with original signatures, verify green on dead and live bundles. cosign now optional in doctor (independent envelope verification only). **M2 exit test passes** (`packages/cli/test/ledger.e2e.test.ts`). Next action: E1 (vendor PocketBase, projector as sole writer, `rampscan rebuild`). |

| Date | Phase | What landed | Notes / deviations |
|---|---|---|---|
| 2026-08-13 | C (M1) | Full vertical slice: `packages/collectors` (repo-facts, gitleaks, syft, osv-scanner, grype — each a `Collector` with manifest + Zod-parsed tool output), real `Runner`/`RepoSource` local adapters in core (runner is the Zod boundary; hashes + relativizes artifacts; feeds an inputs map so osv-scanner consumes syft's SBOM), assertion evaluator + the join in `packages/core` (aws-evidence semantics: row-wise ops vacuous on empty filtered sets, count ops over `where`-filtered rows), 12 recipes in `recipes/pipeline/` (KSI/control IDs validated against the dataset at scan time and in tests), `packages/cli` (`pnpm rampscan scan <path>` → three-register summary + `scan-result.json`; per-recipe rows carry assertions/artifacts/anchor_paths so M2 bundles are a re-keying). `pnpm test`: 66/66 green; typecheck clean. | Tools installed to `~/.local/bin` (gitleaks 8.24.3, syft 1.51.0, grype 0.117.0, osv-scanner 2.5.0). Fixture's planted secret changed: gitleaks allowlists AWS's documented example key (`AKIAIOSFODNN7EXAMPLE`), so the fixture now plants a non-allowlisted fake key — fixture SHAs moved. Fixture is built once per test run by vitest globalSetup (parallel per-file rebuilds raced). syft excludes uncommitted trees (`node_modules`, `.next`, `.git`, …): they aren't commit-anchored, and unexcluded the hub scan blew the 600s timeout. grype scans the final FROM's base image, not a locally built app image. **M1 exit tests pass**: fixture → 2 evidenced / 9 violated / 1 unevidenced (all four planted faults caught: 2 history secrets, lodash HIGH advisories, 2 unpinned actions + no provenance, node:16-alpine CRITICALs via grype); fedramp-rules-hub → 4 evidenced / 5 violated / 3 unevidenced — real evidence rows, real unevidenced rows, every verdict citing dataset-resolvable IDs. Next action: D1 (ledger local adapter + the cheating test). |
| 2026-08-13 | A + B (M0) | git history started; pnpm workspace (Node v22.22.2, pnpm 9.6.0, git 2.43.0); `packages/schema` (Finding / PipelineRecipe / EvidenceBundle / CollectorManifest, Zod, round-trip tests); `packages/dataset` (dev loader over `derived/`, pinned-mode stub, version pin hard-fails, `ksisFor("ac-2.1") → [KSI-IAM-JIT, KSI-IAM-SUS]` verified); `packages/core` (six ports + stubbed local adapters that reject loudly); `fixtures/build-vulnerable-app.mjs`; `scripts/doctor.mjs`. `pnpm test`: 17/17 green; `pnpm typecheck` clean. | Fixture is generated, not committed (nested `.git` can't be committed) — deterministic script committed instead, SHAs stable (HEAD `9352d78`). Doctor: syft/osv-scanner/grype/gitleaks/cosign absent on this machine, Docker present — install before C2. M0 exit tests pass. Next action: C1 (collector manifest + Runner local adapter). |
| 2026-08-13 | — | Docs phase: spec, implementation plan, architecture reference, this plan | No code yet. Next action: A1 (`git init`). |
