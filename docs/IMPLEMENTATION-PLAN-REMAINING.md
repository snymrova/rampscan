# rampscan — implementation plan: what remains

**Status:** committed plan for the work after Phase H (engine expansion, complete) and Phase I3d (auditor lens, in progress). This document owns **scope and task breakdown** for everything not yet built; `docs/PLAN-OF-ACTION.md` and `docs/PLAN-OF-ACTION-CONSOLE.md` own **task status** and get ticked as work lands. On any scope dispute this document wins over the checklists; on any architecture dispute `docs/SPEC.md` wins over this document.
**Date:** 2026-08-15
**Reads against:** all of `docs/` — SPEC (target architecture), IMPLEMENTATION-PLAN (M0–M5, complete), COMPLIANCE-SCAN-HARNESS (founding doc §11–13 decisions), ARCHITECTURE (invariants), BRAINSTORM-DAST-OBSERVABILITY-AI-HELPER (the options analysis this plan promotes from), FRONTIER-PIPELINE (the generated self-scan record).

---

## 1. The inventory: everything the docs still owe, in three tiers

Walked across all eight documents. Nothing below is invented here; each line names where it came from.

### Tier 1 — committed, ordered, built next

| # | Item | Source | State |
|---|---|---|---|
| I3e | Export: register CSV · per-control evidence package (zip) · print-friendly evidence page | CONSOLE I3, SPEC §8.5 | not started |
| I3f | Not-affected claims show their work (entry-point provenance, over-approximation statement, exact-vs-inferred edges) | CONSOLE I3 | not started |
| J1 | The run record, ledger-first: `scan-run` statement kind + capture | PLAN J, BRAINSTORM §2.2/§5 | not started |
| J2 | `/runs` console page: scan timeline → per-collector table | PLAN J, BRAINSTORM §2.3 | not started |
| J3 | Board hop: "how was this produced?" on every row | PLAN J | not started |
| J4 | Artifact viewers: normalized artifacts as tables + raw download | PLAN J | not started |
| J5 | Provenance chain end-to-end · tooling-health card · `rampscan tools` | PLAN J | not started |
| K1 | Plain-language layer, no AI: `plain` on every recipe · glossary · guided empty states | PLAN K, BRAINSTORM §3.1 | not started |

### Tier 2 — held at an explicit go/no-go, analysis already written

| Item | Source | The decision that gates it |
|---|---|---|
| K2 — BYOK AI helper (T1 "Explain this" first) | BRAINSTORM §3 | Does the comprehension pain survive K1? Decide after K1 ships, on evidence, not appetite. |
| Phase L — DAST / ZAP, Mode A only | BRAINSTORM §1 | Runtime evidence is a second anchor class. Its own milestone; parked 2026-08-15. |
| Cheap-win collectors: `zizmor`/`actionlint`, `dockle`, license recipe over syft data, `trivy config` | BRAINSTORM §1.7 | Each is an H-phase-shaped single-collector move. Ride along any phase; none is on the critical path. |
| Engine-track CI wiring for the Phase H collector families | PLAN H, CONSOLE deferred list | Deferred by user decision (engine-first). `.github/workflows/smoke.yml` is the console smoke, not this. |

### Tier 3 — deferred by name, out of the local prototype entirely

Unchanged from IMPLEMENTATION-PLAN §1 and the two checklists' deferral lists, restated here so "remaining" is honest about its own boundary: Terraform/Fargate/Step Functions/EventBridge and the AWS adapters behind the six ports · KMS + S3 Object Lock · GitHub App repo access · Bedrock tier 3 and the micro-LLM cascade · the **121-control adjudication** (`recipes/adjudications/`, SPEC §10.2 — the starter 15 recipes stand in) · OSCAL assessment-results emission · multi-repo joins · GovCloud · the React Flow graph canvas (SPEC §8.6, Phase 4) · webhooks · auditor SSO / external assessor accounts · console access audit log · acknowledge-as-ledger-event · PDF rendering service · languages beyond TS/JS in the graph.

Two of these deserve a note rather than silence, because a reader of SPEC will expect them sooner:

- **The 121-control adjudication is the single largest piece of undone *product* scope in the docs** (SPEC §10.2, founding doc §12: "the first deliverable is pipeline recipes for the 121-control uncovered set"). The prototype deliberately inverted that order and proved the machine first. It stays deferred here — but it is data work, not engineering work, and it is what turns a 15-recipe demo into a product. Name it in any roadmap conversation; do not let it hide inside "deferred".
- **Class d has no MVX window** (SPEC §11 q6, ARCHITECTURE §8): config refuses it. Still open, still correctly refused.

---

## 2. Sequencing, and the one real fork

The plan of record says J1 next. The fork is whether I3e/I3f — the last two auditor-lens items, unfinished since 2026-08-14 — jump the queue.

**Decision: finish I3e/I3f first, then J1.** Three reasons, all mechanical rather than aesthetic:

1. **I3's exit test currently cannot pass.** It reads: "traverse to an evidence bundle → download the evidence package → `rampscan verify` passes offline on the downloaded bundle · exported CSV row count equals the on-screen register · print view contains digest, commit, dataset pin, tool versions." Every clause is I3e. Phase I is 4/6 landed and 0/1 exit tests passed; starting J leaves a phase open behind us with a written test we know fails.
2. **I3e is small and its dependencies are all built.** `/api/verify/bundle` and `/api/verify/key` (I3b) already stream exactly the bytes the zip needs; the register views (I3a) already hold exactly the rows the CSV needs. This is assembly, not architecture.
3. **J changes what I3e would have to export.** Once `scan_runs` exists, the honest per-control evidence package includes the run record for each bundle. Shipping the zip *before* J1 means one small additive change later; shipping J1 first means I3e is designed around a moving target. The additive direction is cheaper.

I3f is the exception worth reordering: it renders entry-point provenance and exact-vs-inferred edge marking, which is **the same information J5's provenance chain renders**. Build I3f *after* J5, folded into it, rather than twice.

Resulting order:

```
I3e  →  J1  →  J2  →  J3  →  J4  →  J5 (+I3f folded in)  →  K1  →  [go/no-go: K2, L]
```

Estimates, focused-work days, honest but rough: I3e 1–1.5 · J1 2.5–3 · J2 1.5 · J3 0.25 · J4 1.5 · J5+I3f 2 · K1 1.5. **Total ≈ 10–11 days** to the end of K1.

---

## 3. I3e — export

**What lands.** Three export surfaces, all read-only, all in the auditor lens's existing posture.

- **Register CSV.** Any register view (board, controls, KSIs, scoping, and the as-of fold of each) exports the rows *currently rendered* — filters and as-of instant included, or the row count will not match the screen and the exit test fails by design. Computed console-side from the same records the table renders; no new route needed, no new fold. Header row names the view, the repo, the dataset pin, and the `projected_at` (or as-of instant) the rows were folded at — a CSV that does not say when it was true is a screenshot with commas.
- **Per-control evidence package (zip).** For one control (or KSI) rollup: every mapped recipe's live bundle envelope byte-for-byte from `/api/verify/bundle`, the artifacts each bundle's subjects name, `rampscan.pub` from `/api/verify/key`, and a generated `VERIFY.md` carrying the stamped `verifyCommand` (I3b's `ProjectionSettings.verifyCommand`, the serve's real `--ledger`/`--keys` dirs) plus a manifest listing digest → recipe → verdict → commit. Assembled in a new `GET /api/export/control?reg=…&id=…` in the diff route's exact posture (auth-refresh gate, `runtime: nodejs`, structurally unable to write) — server-side because it needs ledger object-store reads the browser cannot do.
- **Print CSS on the evidence page.** `@media print`: nav/buttons/realtime chrome hidden, digest + commit + dataset pin + tool versions + assertions + offenders forced visible and un-truncated, URL footer. CSS only — no PDF service (deferred by name).

**Decisions to make while building.**
- *Zip mechanics:* Node's stdlib has no zip writer. Either add one small dependency (`archiver`/`jszip` — first runtime dep added for a console feature, against the standard-library bias in PRINCIPLES) or emit an uncompressed `.tar` via a hand-rolled writer (~60 lines, no dependency, and `tar` is at least as assessor-legible as `zip`). **Recommend: hand-rolled uncompressed tar**, consistent with DSSE-without-cosign and setTimeout-without-node-cron — this codebase's standing habit of declining a dependency for a bounded, testable job.
- *Artifact inclusion:* bundles name artifacts by digest, and artifacts live in `rampscan-out/artifacts/`, not the ledger object store. A package that ships bundle + key but not artifacts is honest and smaller; one that ships artifacts must say what it did when an artifact from an older run is no longer on disk. **Recommend: include artifacts when present, list them as `missing (artifact not retained)` in the manifest when absent** — never silently omit.

**Files.** `console/web/lib/export.ts` (CSV serialization, pure, tested) · `console/web/app/api/export/control/route.ts` · `console/web/app/globals.css` (print block) · export buttons on `/controls`, `/`, `/scoping`, `/evidence/[digest]` · `packages/cli/src/export.ts` if the tar writer is shared with a future CLI export (build it in `@rampscan/cli` and import it, matching the `computeBoardAsOf` one-hand pattern).

**Exit test.** Phase I3's written exit test, verbatim, as smoke test 9: control register → evidence bundle → download package → extract → `rampscan verify` passes offline on a bundle from the downloaded package (node:crypto path already proven in smoke 6) → exported CSV row count equals the on-screen register row count → print stylesheet applied, page contains digest/commit/dataset pin/tool versions.

---

## 4. J1 — the run record, ledger-first

The load-bearing item. Everything J2–J5 does is render what J1 records.

### 4.1 What the capture point actually is

The plan says "captured at the Runner boundary (single choke point, collectors untouched)". **That is half true, and the half it misses is the half auditors want.** Verified against the code:

- [`packages/core/src/local.ts:42`](../packages/core/src/local.ts#L42) — the runner sees the collector call, so **duration, exit code, artifacts (already hashed at line 61), findings count, and skip reason** are free here. Collectors untouched, exactly as written.
- [`packages/collectors/src/tools.ts:60`](../packages/collectors/src/tools.ts#L60) — but `kind: "binary" | "docker"`, the image ref, and the **argv** live inside `ResolvedTool.exec`, one layer below the runner. The runner never sees a command line.

So J1 needs **two capture points, not one**: the runner records the collector-level envelope, and `tools.ts` records the tool-level invocations. Recommended seam: an **exec journal** — an optional `record?: (entry: ToolExecRecord) => void` threaded through `resolveTool`/`createDockerTool`/`createBinaryTool`, defaulting to a no-op so nothing changes for callers that don't ask. The runner installs a per-collector recorder and drains it after `collect()` returns. Collectors still untouched — the journal rides the tool handle they already hold.

**Do not** route this through `CollectOutput`: that type is the collectors' contract, and adding run telemetry to it makes every collector responsible for reporting its own provenance — precisely the arrangement where one collector quietly under-reports.

### 4.2 The statement

New predicate type `https://rampscan.dev/scan-run/v1`, third member of the `LedgerStatement` union at [`packages/schema/src/scoping.ts:42`](../packages/schema/src/scoping.ts#L42), with `isScanRun()` beside the two existing guards.

```
subject:    the run's artifacts (name + sha256) — the same subject discipline every bundle uses
predicate:  run_id, repo, commit, trigger (manual | daemon·incremental | daemon·full | serve),
            started_at, duration_ms, dataset_version,
            collectors: [{
              collector, tool, tool_version,
              runtime: { kind: "binary", path } | { kind: "docker", image, digest } | { kind: "absent" },
              invocations: [{ argv (redacted), duration_ms, exit_code }],
              duration_ms, exit_code,
              artifacts: [{ name, sha256, bytes }],
              cache: { state: "hit" | "miss" | "not-cacheable", key, scope },
              skip_reason?
            }]
```

Four decisions this forces, with recommendations:

1. **Always-append, no dedup.** Evidence bundles dedupe on evidence identity; a run record is unique by construction (durations, timestamps) and appending one per scan means the daemon adds one per cadence refresh. That is correct — the record of *what ran* should not be deduplicated away — but it should be stated: ledger growth becomes per-tick, and the projector's drop-and-refill cost grows with it. **Recommend: accept, and cap the projected `scan_runs` collection to the newest N runs while the ledger keeps all** (the projection is rebuildable; the ledger is the record).
2. **Do bundles reference the run digest?** BRAINSTORM §2.2 floats it; J1's text does not commit. Adding `run_digest` to the evidence predicate would re-key **every** bundle — the I2c precedent explicitly kept new pointers *out* of evidence identity so existing bundles survive. **Recommend: no back-reference in the bundle. Join the other way** — the run record names the run_id, the bundle predicate already carries the run_id, and the projector joins on it. Zero re-keying, same navigation.
3. **Docker image digest.** `tools.json` pins tags, not digests (noted in the H-phase log as appliance-level hardening deferred). The run record promises `docker(image, digest)`. **Recommend: resolve the digest once per image per scan via `docker image inspect --format '{{index .RepoDigests 0}}'`, record it when available, record `digest: null` with a reason when not** — never quote a tag as a digest. This also delivers, as a side effect, the digest-pinning fact the H phase deferred.
4. **argv redaction.** Signed statements are permanent; a leaked secret in a permanent record is worse than no record. **Recommend: an allowlist, not a denylist** — argv entries are emitted verbatim only when they match known-safe shapes (flags, paths under the workspace/artifact dir, pinned versions); anything else renders `<redacted:N bytes>`. Test it against the fixture's planted secret and against `--token`-shaped arguments. A gitleaks-pattern denylist is the tempting version and it is the one that eventually leaks.

### 4.3 Projection, rebuild, verify

`Projection` gains `scanRuns: ScanRunRow[]` beside `rows/registers/drift/controls/ksis/gaps` ([`packages/core/src/ports.ts:316`](../packages/core/src/ports.ts#L316)); `foldEntries` folds the new statement kind; SQLite table + PocketBase collection `scan_runs` in the same drop-and-refill, projector-only-writer posture ([`fold.ts`](../packages/projector/src/fold.ts), [`sqlite.ts`](../packages/projector/src/sqlite.ts), [`pocketbase.ts`](../packages/projector/src/pocketbase.ts)); `rampscan rebuild`'s byte-equality check extends to it for free once it is in `Projection`; `rampscan verify <digest>` must accept the new kind rather than reject it as unknown.

**Files.** `packages/schema/src/scan-run.ts` (+ `scoping.ts` union, `index.ts` exports) · `packages/collectors/src/tools.ts` (exec journal) · `packages/core/src/{ports.ts,local.ts}` (recorder threading, `RunResult` telemetry field) · `packages/core/src/cache.ts` (cache state + key already computed here — surface it) · `packages/cli/src/scan.ts` (assemble → sign → append, beside the existing bundle loop at lines 241–247) · `packages/cli/src/daemon.ts` (trigger label) · `packages/projector/src/{fold.ts,sqlite.ts,pocketbase.ts}` · `packages/cli/src/verify.ts`.

**Exit test.** Fixture scan → exactly one `scan-run` statement appended → `rampscan verify <run-digest>` green offline → every collector that ran appears with a version, a runtime, a duration, an exit code, and its artifacts' digests matching the bundles' subjects → a scan with one tool hidden from PATH and Docker disabled records `runtime: absent` + the skip reason → `rampscan rebuild` reproduces `scan_runs` byte-for-byte → redaction test: a planted secret passed as an argument never appears in the signed payload.

---

## 5. J2 / J3 — `/runs` and the board hop

**J2.** New page `console/web/app/runs/page.tsx`, read from the `scan_runs` collection (realtime like every other projection view; no new server route — the projection is already console-readable). Timeline row per scan: timestamp, commit, trigger, duration, and the counts `N collectors: X ran · Y cache-hit · Z skipped ⚠` with the skip count **loud** (BRAINSTORM §2.3 — a silently-absent tool quietly turning a column unevidenced is the most confusing failure mode this system currently has). Expanding a row renders the per-collector table: runtime pill (binary / docker / cache-hit / skipped), tool@version, duration, exit code, artifact list. Deep-linkable: `/runs?scan=<run_id>&collector=<name>` arrives expanded and highlighted — reuse the `?reg=…&id=…` pattern from I3a (`useSearchParams` under a Suspense boundary for the static prerender).

**J3.** One link per board row — "how was this produced?" → `/runs?scan=…&collector=…`, resolved from the row's live bundle's `run_id`, or from the newest run when the cell is unevidenced (which is exactly the case that needs it most). `stopPropagation` so the row's evidence click survives, same as I3a's cell links. Ship the moment J2 renders; it is an afternoon and it is the highest-leverage piece in the phase.

**Exit test.** Fixture scan → `/runs` lists the run with correct counts recomputed from the rows (never typed) → expand → every collector present with runtime/version/duration/exit/artifacts → hide one tool → the timeline row counts the skip loudly → an unevidenced board cell's hop lands on that collector's row with the named reason visible. Smoke test 10.

---

## 6. J4 — artifact viewers

Normalized artifacts rendered as tables instead of raw JSON dumps: semgrep results (check id · file:line · severity · message), osv results (package · advisory · severity · fixed-in), gitleaks (rule · file:line · commit — **secret value never rendered**), checkov (check · resource · file), spectral (rule · path · severity), graph route rows (method · path · authed · call path). Raw download beside each table in the authorized-fetch posture I3b established (blob via authorized fetch, not a bare `<a href>` — a plain link carries no PB token).

One decision: **artifacts are not in the ledger** — they live in `rampscan-out/artifacts/`, addressed by the digest the bundle's subject names. The viewer needs a `GET /api/artifact?digest=` route in the diff-route posture that resolves digest → path and **re-hashes before serving**, refusing on mismatch. Serving an artifact by path without re-hashing would let a modified file on disk render under a signed bundle's digest — the exact confusion the whole architecture exists to prevent.

**Exit test.** Flagship violated bundle → artifact table renders the same offender count the assertion reports → raw download's sha256 equals the subject digest → a tampered artifact on disk yields a loud refusal, not a rendered table.

---

## 7. J5 (+I3f) — the provenance chain, tooling health, `rampscan tools`

Three pieces, one theme: make the whole causal line visible in both directions.

- **The chain, rendered and clickable both ways:** `recipe → collector → tool@version(runtime) → artifact digest → bundle digest`, on evidence pages and run rows. Every hop already exists in data after J1; the page draws the line.
- **I3f folded in here:** on rows whose verdict rests on reachability (`no-critical-reachable-advisories`, `no-reachable-dangerous-code`), the chain extends into the graph and must show its work — the entry-point set with its provenance (`rampscan.config.json` override vs `package.json` inference vs fallback, from `packages/graph/src/entrypoints.ts`), the over-approximation statement rendered inline ("not-affected only when even the loose walk cannot reach the package; unknowns count against us"), and exact-vs-inferred marking on every displayed edge. This is the same rendering problem as the chain, on the same pages, for the same reader — build once.
- **Tooling-health card on `/runs`:** doctor's live resolution per tool, plus the historical per-run resolution from `scan_runs`, so "when did semgrep stop resolving as a binary?" has a date.
- **`rampscan tools` CLI:** the static map — recipe ↔ collector ↔ tool ↔ pinned image. Doctor answers "can it run", `tools` answers "who feeds whom", `/runs` answers "what happened". Pure derivation over the recipe catalog + collector manifests + `tools.json`; no new data.

**Exit test.** From `no-reachable-dangerous-code`'s board row, every hop of the chain reaches the next in one click and returns; the not-affected claim on the fixture's unreachable eval renders its entry-point set, its provenance, and the over-approximation statement; `rampscan tools` output agrees with `doctor` on which tools exist and with `/runs` on which ran. Phase J exit test (as written in PLAN-OF-ACTION) passes end to end.

---

## 8. K1 — the plain-language layer, no AI

- **`plain` on every recipe** — one operator-English paragraph per recipe in `recipes/pipeline/*.json`: what this checks, what a violation means in practice, what fixing it looks like. Schema addition in `packages/schema` (optional field, so no recipe breaks); rendered on board rows (collapsed), evidence pages (expanded), and the queue's tier detail. **Authored prose, not computed** — the computed-never-typed rule governs *verdicts and numbers*; explanation is exactly what should be written by a human. 15 recipes × one paragraph.
- **Glossary-on-hover** for the jargon layer: KSI, control, recipe, DSSE, anchor, anchor-drift, the three verdicts, `notApplicable`, MVX window, `not_affected`, two-key write, projection, ledger. One `lib/glossary.ts` map + a `<Term>` component; a term with no entry renders plain, never a broken tooltip.
- **Guided empty states**, wired to J1's skip reasons: "this row is unevidenced because grype did not resolve — no binary on PATH, no Docker. Run `pnpm doctor`." The reason comes from the run record, not from a console-side guess.

**Exit test.** Every recipe in the catalog has a `plain` paragraph (test asserts completeness — a new recipe without one fails CI). Every unevidenced row on the fixture board explains itself in a sentence that names the actual cause from the run record. Smoke asserts the flagship row renders its plain text and one glossary term resolves.

---

## 9. Decisions to settle before code starts

Carried from BRAINSTORM §4's open questions plus what this walk surfaced. Recommendations attached; none is blocking except the first.

| # | Question | Recommendation |
|---|---|---|
| 1 | I3e/I3f before J1, as §2 argues? | **Yes** — I3e first (closes Phase I's exit test), I3f folded into J5. |
| 2 | Sign the run record, or leave it unsigned in `out/`? | **Sign it.** Ledger-first is already the plan of record; unsigned-in-`out/` creates the only operator-facing record that cannot be verified or rebuilt. |
| 3 | Bundle → run back-reference? | **No.** Join on the `run_id` the predicate already carries; re-keying every bundle to gain a link is a bad trade (I2c precedent). |
| 4 | Zip dependency for I3e? | **No dependency** — hand-rolled uncompressed tar, house style. |
| 5 | Docker image digests? | **Resolve and record**, `null` with a reason when unavailable. Delivers the H-phase's deferred digest pinning as a side effect. |
| 6 | Cap the projected `scan_runs`? | **Yes**, newest N runs projected, all runs kept in the ledger. |
| 7 | Which cheap-win collector, if any, rides with J? | **None during J.** J is a rendering phase; a new collector adds a column to render mid-build. Reconsider between K1 and the K2/L go/no-go. |
| 8 | DAST Mode B/C anchor class — ever, or never? | **Not now**, and not decided by this plan. It is the gating question for Phase L and belongs to that go/no-go. |

---

## 10. Risks worth naming

| Risk | Mitigation in this plan |
|---|---|
| Signed argv leaks a secret into a permanent record | Allowlist redaction (§4.2 d4), tested against the fixture's planted secret before J1 lands. A denylist is the version that eventually leaks. |
| Ledger growth from per-tick run records | Accepted deliberately; projection capped, ledger uncapped. Watch the daemon's steady-state rate on the first multi-day run. |
| `/runs` becomes a second source of truth about verdicts | It renders *runs*, never states. No verdict, register state, or coverage number may be computed on this page — it reads `scan_runs` only. |
| J4's artifact route serves unverified bytes | Re-hash before serving; refuse on mismatch (§6). |
| Phase J is four rendering items and could sprawl | Each of J2–J5 has its own smoke test and ships alone. J3 is deliberately a one-afternoon item wedged between two larger ones to keep momentum visible. |
| K1's `plain` prose rots as recipes change | Completeness test in CI; the paragraph lives in the recipe JSON, so it moves with the thing it describes. |
| The 121-control adjudication keeps sliding | Named in Tier 3 explicitly as product scope, not engineering scope, so it is refused deliberately each time rather than forgotten. |

---

## 11. What "done" looks like at the end of K1

A scan of the fixture produces, in one loop: signed commit-anchored evidence for 15 recipes across the three registers; a signed run record naming every tool, version, runtime, argv, duration, exit code, cache state, and artifact digest behind it; a console where an auditor can pick a control, traverse to a bundle, read its plain-English meaning, see the exact chain that produced it, verify it offline with no rampscan code, and take the whole package away as a file; and where an operator staring at an unevidenced cell is one click from the named reason a tool did not run. Every number on every page computed, nothing typed. That is the prototype's honest ceiling before either of the two held decisions — the AI docent and runtime evidence — gets made on its own merits.
