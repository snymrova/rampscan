# rampscan — implementation plan: what remains

**Status:** committed plan for the work after Phase H (engine expansion, complete) and Phase I3 (auditor lens, complete — I3e landed 2026-08-15, I3f folded into and landed with J5). **Phases J and K1 are complete**: J1–J5 and K1 all landed 2026-08-15. Everything committed in this plan is built; what remains are the two held go/no-gos (K2, L), each decided on its own merits. This document owns **scope and task breakdown** for everything not yet built; `docs/PLAN-OF-ACTION.md` and `docs/PLAN-OF-ACTION-CONSOLE.md` own **task status** and get ticked as work lands. On any scope dispute this document wins over the checklists; on any architecture dispute `docs/SPEC.md` wins over this document.
**Date:** 2026-08-15
**Reads against:** all of `docs/` — SPEC (target architecture), IMPLEMENTATION-PLAN (M0–M5, complete), COMPLIANCE-SCAN-HARNESS (founding doc §11–13 decisions), ARCHITECTURE (invariants), BRAINSTORM-DAST-OBSERVABILITY-AI-HELPER (the options analysis this plan promotes from), FRONTIER-PIPELINE (the generated self-scan record).

---

## 1. The inventory: everything the docs still owe, in three tiers

Walked across all eight documents. Nothing below is invented here; each line names where it came from.

### Tier 1 — committed, ordered, built next

| # | Item | Source | State |
|---|---|---|---|
| I3e | Export: register CSV · per-control evidence package (tar) · print-friendly evidence page | CONSOLE I3, SPEC §8.5 | **landed 2026-08-15** |
| I3f | Not-affected claims show their work (entry-point provenance, over-approximation statement, exact-vs-inferred edges) | CONSOLE I3 | **landed 2026-08-15** (folded into J5) |
| J1 | The run record, ledger-first: `scan-run` statement kind + capture | PLAN J, BRAINSTORM §2.2/§5 | **landed 2026-08-15** |
| J2 | `/runs` console page: scan timeline → per-collector table | PLAN J, BRAINSTORM §2.3 | **landed 2026-08-15** |
| J3 | Board hop: "how was this produced?" on every row | PLAN J | **landed 2026-08-15** |
| J4 | Artifact viewers: normalized artifacts as tables + raw download | PLAN J | **landed 2026-08-15** |
| J5 | Provenance chain end-to-end · tooling-health card · `rampscan tools` | PLAN J | **landed 2026-08-15** |
| K1 | Plain-language layer, no AI: `plain` on every recipe · glossary · guided empty states | PLAN K, BRAINSTORM §3.1 | **landed 2026-08-15** |

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
 ✓      ✓      ✓      ✓      ✓             ✓                 ✓         ←here
```

Phase J is complete; Phase I closed with it, since I3f was the last unlanded item of the auditor lens. K1 closed Phase K's committed half — the AI docent (would-be K2) was never part of it and stays held.

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

### 4.4 As built (2026-08-15) — where the shipped J1 differs from §4.1–4.3

Three deviations, each taken for a stated reason. Read these before J2 builds on top of it.

1. **One capture point, not two.** §4.1 called for the runner *plus* `tools.ts`. In fact every process a collector starts goes through `exec()` in `packages/collectors/src/support.ts` — the tool wrappers call it, and so do the collectors that shell out to `git` directly. Journaling there is structurally complete rather than merely thorough: there is no other door, so no collector can under-report by taking a shortcut, and the direct `git ls-files` calls land in the record for free. `resolveTool()` records the *resolution* (binary path / image / absent + reason) separately, so a tool that never ran still says why.
2. **The journal is an `AsyncLocalStorage`, not a threaded parameter.** `createJournaledRunner` opens one per collector and drains it after `collect()` returns. This keeps §4.1's rule — nothing enters the collector contract — while removing the need for collectors to cooperate at all.
3. **`tools` is an array in the predicate**, not the flat `tool / tool_version / runtime` triple §4.2 sketched. A collector resolves zero external tools (`repo-facts`, `graph`, `reachability`, `sast-reachability`) or several; a flat triple would have had to invent one for the pure collectors. Per-collector `tool_version` is still flat — it is the version the bundle already carries.

Also as built: telemetry rides `RunResult`, so the scan cache persists and restores it. On a `cache: { state: "hit" }` the invocations shown are the ones of the run that *produced* the cached result — the record never claims a spawn that did not happen, and the state field is what says so.

**Deferred out of J1 on purpose:** `scanInstants` ([`diff.ts:23`](../packages/projector/src/diff.ts#L23)) still enumerates **evidence** timestamps only. Folding run-record instants into it would make `--since previous` and I3d's as-of quick-picks mean "since the previous scan" rather than "since the previous scan that moved evidence" — a real improvement, and a silent redefinition of two shipped features. It belongs to J2, which renders the scan timeline anyway and can change both surfaces in one deliberate move.

---

## 5. J2 / J3 — `/runs` and the board hop

**J2.** New page `console/web/app/runs/page.tsx`, read from the `scan_runs` collection (realtime like every other projection view; no new server route — the projection is already console-readable). Timeline row per scan: timestamp, commit, trigger, duration, and the counts `N collectors: X ran · Y cache-hit · Z skipped ⚠` with the skip count **loud** (BRAINSTORM §2.3 — a silently-absent tool quietly turning a column unevidenced is the most confusing failure mode this system currently has). Expanding a row renders the per-collector table: runtime pill (binary / docker / cache-hit / skipped), tool@version, duration, exit code, artifact list. Deep-linkable: `/runs?scan=<run_id>&collector=<name>` arrives expanded and highlighted — reuse the `?reg=…&id=…` pattern from I3a (`useSearchParams` under a Suspense boundary for the static prerender).

**J3.** One link per board row — "how was this produced?" → `/runs?scan=…&collector=…`, resolved from the row's live bundle's `run_id`, or from the newest run when the cell is unevidenced (which is exactly the case that needs it most). `stopPropagation` so the row's evidence click survives, same as I3a's cell links. Ship the moment J2 renders; it is an afternoon and it is the highest-leverage piece in the phase.

**Exit test.** Fixture scan → `/runs` lists the run with correct counts recomputed from the rows (never typed) → expand → every collector present with runtime/version/duration/exit/artifacts → hide one tool → the timeline row counts the skip loudly → an unevidenced board cell's hop lands on that collector's row with the named reason visible. Smoke test 10.

### 5.1 As built (2026-08-15) — J2

- **The counts partition, and that is the whole point.** `ran + cacheHit + skipped === dispatched`, always: a cache hit is not counted as having run, because nothing was spawned. The timeline row's summary is therefore reproducible by recounting the table it expands into — which is exactly what smoke 10 does, parsing the row's own claim and then counting collector rows and runtime pills against it. The evidence page's run-record summary (shipped in J1 with overlapping buckets) now calls the same `runCounts`, so the two surfaces cannot disagree about one run.
- **`scanInstants` folds run-record instants** ([`diff.ts`](../packages/projector/src/diff.ts)) — the redefinition J1 deferred to here. A run record carries the same clock as the bundles it produced, so an evidence-moving scan is untouched; what changes is the scan that moved *nothing*, which used to leave no trace at all. `--since previous` and I3d's as-of quick-picks now mean the literal thing they say.
- **Deliberately NOT on this page:** no verdict, no register state, no coverage number. `lib/runs.ts` has no way to compute one, which is the enforcement — /runs renders runs, and the board stays folded from evidence and scoping alone.
- **Deferred to J3, by its own plan:** the board hop. The deep link `/runs?scan=…&collector=…` is built and pinned by smoke 10 (arrives expanded, the named collector highlighted, its argv open); J3 is the one link on the board row that points at it.

### 5.2 As built (2026-08-15) — J3

The plan's sketch said "resolved from the row's live bundle's `run_id`". Reading the code first found that **neither** field the hop needs was on the board: `RegisterRow` carried `bundleDigest` but no run id (that lives in the bundle predicate), and **nothing console-side mapped recipe → collector** at all (`recipe.collection.collector` is catalog-only, and a bundle names *tools*, not the collector that ran them). The unevidenced hop — the case the plan calls the one that needs it most — has no bundle to read either field from, so it could not have been built the sketched way.

- **Both fields become part of the fold's existing catalog join**, not a second lookup: `collector` comes from the catalog exactly as `ksiIds`/`controlIds`/`cadence` do, and `runId` is lifted off the live predicate beside `commit` and `freshAsOf`. Two columns through `registers` in sqlite and PocketBase; `rampscan rebuild` on the live ledger folds 63 statements → 75 cells and reads back byte-identical. No new route, no per-row bundle fetch, and **the board still fetches no run data** — a board that queried the run log to draw itself would be partly a function of it, which is the J1 rule this had to stay clear of.
- **A guessed collector was the tempting shortcut and is refused:** a recipe missing from the catalog gets *no* collector rather than one inferred from the bundle's tool names, and its row simply hops without the `&collector=` half. A wrong collector name on the one link an operator follows to find out why a cell is empty is worse than no name.
- **Two shapes, because a row has two honest answers.** Evidenced/violated → `?scan=<run_id>&collector=…`, "how was this produced?". Unevidenced → `?repo=…&collector=…`, "why is this empty?" — *no run produced that cell*, so `/runs` substitutes the newest recorded scan of the repo and **says so in a notice** rather than letting the substitution read as the real thing. `notApplicable` gets **no hop at all**: a scoped-out cell was not produced by a run and is not missing because of one, and its provenance is the signed scoping event already on the row.
- **Three honesty cases the sketch did not name, all found by running it:** a named scan that is not in the capped projection says which fact applies — older than the cap, or (the live ledger's actual state) *no scan has appended a run record here yet*, since run records began at J1 and 9 of the board's cited runs predate them; and a collector the target run never dispatched says "never dispatched" instead of promising a highlight it will not draw — a different fact from "it ran and skipped".
- **`stopPropagation`, and the row click still works** (smoke re-walks recipe-cell → evidence page after using the hop). The link rides the control register's recipe sub-rows too, and is suppressed under a historical fold — `/runs` reads the live projection, so a hop from an as-of board would leave the chosen instant silently (I3d's propose-N/A precedent).
- vitest 381/381 (13 new: 6 fold tests over the two joined fields — per-row collector, catalog-miss naming none, `runId` following the *live* bundle and never a superseded one, unevidenced and scoped-out carrying none, run records still introducing no cell — plus the sqlite round trip re-pinned with a distinct collector per row, and 7 `runHop` twin tests in the export-csv/mvx-twin posture covering both shapes, both null cases, and URL encoding of a repo name with a slash). Smoke 11/11 cold (2.7m), test 11 walking the real fixture: the flagship's hop resolving to `reachability`, landing on the run the board named with that collector highlighted and no missing-run notice, **every** evidenced/violated row carrying a hop (not just the flagship), the row click surviving, and both unevidenced-arrival notices against the real run record. Root + console typecheck clean.

---

## 6. J4 — artifact viewers

Normalized artifacts rendered as tables instead of raw JSON dumps: semgrep results (check id · file:line · severity · message), osv results (package · advisory · severity · fixed-in), gitleaks (rule · file:line · commit — **secret value never rendered**), checkov (check · resource · file), spectral (rule · path · severity), graph route rows (method · path · authed · call path). Raw download beside each table in the authorized-fetch posture I3b established (blob via authorized fetch, not a bare `<a href>` — a plain link carries no PB token).

One decision: **artifacts are not in the ledger** — they live in `rampscan-out/artifacts/`, addressed by the digest the bundle's subject names. The viewer needs a `GET /api/artifact?digest=` route in the diff-route posture that resolves digest → path and **re-hashes before serving**, refusing on mismatch. Serving an artifact by path without re-hashing would let a modified file on disk render under a signed bundle's digest — the exact confusion the whole architecture exists to prevent.

**Exit test.** Flagship violated bundle → artifact table renders the same offender count the assertion reports → raw download's sha256 equals the subject digest → a tampered artifact on disk yields a loud refusal, not a rendered table.

### 6.1 As built (2026-08-15) — J4

**The refusal is not the edge case; on any machine that has scanned since, it is the ORDINARY case.** Counted before writing a line: of the nine artifacts in this repo's own scan output, only three still hash to a digest the ledger attests — the other six were overwritten by later runs. A viewer built around the happy path and bolted on a mismatch branch would have had the proportions exactly backwards, so the resolver was written refusal-first and every reason is a distinct sentence.

- **Three refusals to serve, and they are different facts.** *Not attested at all* → 404, "this system serves attested artifacts, not files": a digest no signed statement names is a request to read an arbitrary file and is refused as one, which is also what keeps the route from becoming a file-read primitive. *Attested, but the bytes on disk are from a later run* → 409 naming that fact, and never conflated with *attested, but no file of that name was retained*. *An anchor* → never served at all: it is the client's own source at the scanned commit, so the evidence page renders the `git show <commit>:<path>` line in place of a button that would only ever refuse (I3e's rule, same reason, now with a UI consequence).
- **Two hashes, and the second one is the point.** The route re-hashes before serving — serving by path would let a modified file render under a signed bundle's digest — and then the *browser* re-hashes the received bytes with SubtleCrypto against the digest the statement attests, before a single row is drawn. The evidence page's standing line is "don't trust this page — it renders a projection"; a table drawn from bytes the page merely received is exactly the thing that warns about. After the check, the table is a rendering of bytes **the reader's own browser confirmed**.
- **The family comes from the attested NAME, never from sniffing the content.** The subject name is part of what was signed; the shape of the bytes is not. A viewer that guessed the family from content could be steered by the bytes into rendering them as something they are not — pinned by a test that feeds semgrep-shaped JSON under another name and gets no table.
- **A secret is absent, not masked.** The gitleaks table is rule · file:line · commit · date; `Secret` and `Match` have no column, and the test greps the *whole rendered table* rather than the column list, because a column list can be right while a message field quietly carries the value. The table says out loud that it withheld it.
- **Nine families ship** (semgrep, checkov, spectral, gitleaks, osv-scanner, grype, openvex, repo-facts, cyclonedx) — more than §6 listed, because the fixture's real evidence attests grype/openvex/repo-facts/sbom too and "raw JSON dump" is what J4 exists to remove. Each table states what it does *not* show: checkov names the passed count it is not listing, semgrep names the run's own error count, openvex carries the over-approximation statement, and every capped table states the true total (I2c's offender-count precedent).
- **`graph.db` gets no table, deliberately.** §6 sketched "graph route rows (method · path · authed · call path)"; the actual schema is `routes(id, method, route_path, file, line)` with **no `authed` column**, and it is a binary SQLite file the browser cannot parse — a table would require deriving rows server-side, which breaks the property that the table renders bytes the reader verified. It downloads byte-exact with the reason stated, and the graph's rendering belongs to **J5 (+I3f)**, which already owns entry-point provenance and exact-vs-inferred edges over the same file for the same reader.
- **One hand, and I3e now shares it.** `indexArtifacts` + `matchByDigest` moved into `packages/cli/src/artifact.ts` and the evidence package calls them, so the package and the viewer cannot come to different conclusions about the same file on disk.
- vitest 412/412 (31 new: 8 resolver tests over a real scanned world — the tamper refusal restoring cleanly afterwards, `not retained` vs no-out-dir, the anchor's `git show` line, an unattested digest, and `../../etc/passwd` and friends refused before any lookup; plus 23 twin tests over the console's own `lib/artifacts.ts`, including the secret-absence grep, the content-sniffing refusal, an OSV advisory found only by alias still reporting its fixed version, grype's `not-fixed` stated rather than blank, the row cap naming its true total, and every shipped family re-rendered against this repo's real artifacts with every row as wide as its header). Smoke 12/12 cold (2.9m). Root + console typecheck clean.

---

## 7. J5 (+I3f) — the provenance chain, tooling health, `rampscan tools`

Three pieces, one theme: make the whole causal line visible in both directions.

- **The chain, rendered and clickable both ways:** `recipe → collector → tool@version(runtime) → artifact digest → bundle digest`, on evidence pages and run rows. Every hop already exists in data after J1; the page draws the line.
- **I3f folded in here:** on rows whose verdict rests on reachability (`no-critical-reachable-advisories`, `no-reachable-dangerous-code`), the chain extends into the graph and must show its work — the entry-point set with its provenance (`rampscan.config.json` override vs `package.json` inference vs fallback, from `packages/graph/src/entrypoints.ts`), the over-approximation statement rendered inline ("not-affected only when even the loose walk cannot reach the package; unknowns count against us"), and exact-vs-inferred marking on every displayed edge. This is the same rendering problem as the chain, on the same pages, for the same reader — build once.
- **Tooling-health card on `/runs`:** doctor's live resolution per tool, plus the historical per-run resolution from `scan_runs`, so "when did semgrep stop resolving as a binary?" has a date.
- **`rampscan tools` CLI:** the static map — recipe ↔ collector ↔ tool ↔ pinned image. Doctor answers "can it run", `tools` answers "who feeds whom", `/runs` answers "what happened". Pure derivation over the recipe catalog + collector manifests + `tools.json`; no new data.

**Exit test.** From `no-reachable-dangerous-code`'s board row, every hop of the chain reaches the next in one click and returns; the not-affected claim on the fixture's unreachable eval renders its entry-point set, its provenance, and the over-approximation statement; `rampscan tools` output agrees with `doctor` on which tools exist and with `/runs` on which ran. Phase J exit test (as written in PLAN-OF-ACTION) passes end to end.

### 7.1 As built (2026-08-15) — J5 (+I3f)

**The plan's first line was wrong, and the flagship is exactly where it breaks.** "Every hop already exists in data after J1; the page draws the line." Two hops did not exist. A bundle named its recipe and its tool *versions* but never the **collector** that produced it — recipe→collector was catalog-only, which J3 had already discovered from the other side. And the run record listed what each collector *produced*, never what it **consumed** — so for `sast-reachability`, which spawns no process at all, a chain assembled from the run record's `tools` would have rendered **"no external tool"** over a verdict that is entirely semgrep's output judged against the graph. That is not a rough chain, it is a false one. So two fields were signed rather than inferred: `collector` on the evidence predicate, `consumes` on each run record's collector row.

- **The basis is signed with the claim, because it is recoverable from nowhere else.** `graph.db` is a binary artifact the browser cannot parse (J4 refused to table it for exactly that reason) and it is **not even a subject of the SAST bundle** — that bundle's subjects are anchor files. A console that fetched the entry-point set from somewhere beside the claim would be describing a different walk than the one that produced the verdict above it. So `ClaimBasis` rides the predicate: the entry-point set, its provenance (`config` | `package.json` | `fallback` | `none` | `unavailable`, each rendered as a sentence naming what the reader can do about it), any declared entry that **resolved to no file** (a dropped root silently widens every not-affected claim), the route roots, the graph's own shape (nodes, edges, and how many edges are only name-inferred), and a `degraded` reason when the gate ran without a graph or without roots. Three recipes carry one, and the two gates' `approximation: "over"` sits opposite `route-auth-coverage`'s `"under"` — a positive "this route reaches auth" may only rest on a real chain, and the two walks must not read alike.
- **`collector` and `basis` are KEYED into evidence identity, and the hole that decided it is concrete.** I2c's additions were deliberately excluded because they restate what `detail` already witnesses; these do not — they are claims about what the evidence *rests on*. `sast-reachability` anchors the flagged files and `rampscan.config.json`, **not `package.json`**: with the basis outside identity, editing `package.json` so entry-point inference lands on a different set leaves every "not affected" bundle alive, still claiming unreachability from a set that no longer exists. Keyed on the basis, that scan re-keys and the stale claim dies. The cost is taken openly: a bundle predating J5 does **not** match its re-scan, so every live bundle supersedes once, with no back-compat exemption — "absent means whatever is there now" is how an identity rule stops being one.
- **Every displayed edge is marked, or none of them are.** `shortestPath` already knew each hop's resolution and threw it away in an OR; it now returns `resolutions[]`, one per hop, and the marks ride the **offender pointer** (I2c's slot, already outside identity) rather than being reconstructed console-side. `offenderPointer` accepts them only when the array length matches the path it claims to describe — a short array would shift every mark onto the wrong edge, and a wrong mark on a call path is worse than no mark, so a mismatch renders every hop `unmarked`. Pre-I3f evidence renders unmarked too, never assumed exact.
- **Gaps are drawn as gaps.** The chain emits five hop kinds always; a hop it cannot draw carries the *reason* in its own slot. Three of them are load-bearing and two predate this commit: the run older than the projection cap, the run that was never written down (J3's two facts, one hand — `missingRunReason`), the collector the run never dispatched, and a pre-J5 bundle whose producer cannot be named — where the chain **refuses to fall back to the catalog**, because the catalog says what would produce it *today*, not what did.
- **`rampscan tools` prints the transitive truth, not the local one.** The first version rendered `no-reachable-dangerous-code` as "pure — no external tool" and that was the same lie the chain nearly told, caught by reading the real output. The map now closes over the input graph: the flagship names `semgrep (via semgrep)`, the advisory recipe names `osv-scanner` and `syft` two artifacts upstream. It probes nothing — same three inputs, same bytes on any machine — and exits nonzero on a broken link: a recipe naming an unregistered collector, a one-way recipe↔collector link, a declared recipe the catalog lacks, an input nothing produces, a tool with no pin. `tools: []` is a new manifest field and therefore a *declaration*, so a test greps every collector's source for its `resolveTool("…")` calls and fails on drift — verified by breaking one on purpose.
- **The `/runs` back edge stays on the right side of J2's rule.** Each collector row now names the statements it produced, by recipe id and digest **only**; no verdict is read and none rendered, so the page still computes nothing about the board. A bundle with no `collector` is dropped rather than attached to a guessed one (J3's refusal, same reason).
- **Tooling health is history and says so.** The card walks the run records: current resolution, the collectors that asked for it, absent-run count, and a change dated at the **oldest run that already showed the current answer** — as precisely as a record of discrete runs can date something that happened between two of them, which is why it reads "since" and not "at". The live half is left to `doctor` by name: a console inferring present-tense tool health from the last recorded run would be reporting a probe it never ran.
- vitest **476/476** (64 new: 25 twin tests over the console's own `lib/provenance.ts` — the two-level upstream walk, cycle and diamond termination, both run-absence reasons, the collector never dispatched, marks that do not fit their path, every entry-point source sentence, and `toolHealth`'s dating rule; 15 over `buildToolMap` — the real catalog's wiring green, plus six synthetic breakages proving the checker actually notices; 10 in a J5/I3f exit test over a real signed ledger built with the real gate and graph and no external tool; 8 over per-hop resolutions and graph shape; 5 over the new identity rules; 3 on manifest-vs-source drift). Root + console typecheck clean. `rampscan rebuild` on the live ledger: 63 statements → 75 cells, sqlite byte-identical.

---

## 8. K1 — the plain-language layer, no AI

- **`plain` on every recipe** — one operator-English paragraph per recipe in `recipes/pipeline/*.json`: what this checks, what a violation means in practice, what fixing it looks like. Schema addition in `packages/schema` (optional field, so no recipe breaks); rendered on board rows (collapsed), evidence pages (expanded), and the queue's tier detail. **Authored prose, not computed** — the computed-never-typed rule governs *verdicts and numbers*; explanation is exactly what should be written by a human. 15 recipes × one paragraph.
- **Glossary-on-hover** for the jargon layer: KSI, control, recipe, DSSE, anchor, anchor-drift, the three verdicts, `notApplicable`, MVX window, `not_affected`, two-key write, projection, ledger. One `lib/glossary.ts` map + a `<Term>` component; a term with no entry renders plain, never a broken tooltip.
- **Guided empty states**, wired to J1's skip reasons: "this row is unevidenced because grype did not resolve — no binary on PATH, no Docker. Run `pnpm doctor`." The reason comes from the run record, not from a console-side guess.

**Exit test.** Every recipe in the catalog has a `plain` paragraph (test asserts completeness — a new recipe without one fails CI). Every unevidenced row on the fixture board explains itself in a sentence that names the actual cause from the run record. Smoke asserts the flagship row renders its plain text and one glossary term resolves.

### 8.1 As built (2026-08-15) — K1

**The exit test could not run on the fixture that existed, and that is the finding, not a footnote.** "Every unevidenced row on the fixture board explains itself" — `vulnerable-app` is fully tooled, so all fifteen of its rows come back evidenced or violated and the board has **no empty cell at all**. J3 had already hit this from the other side and recorded it ("this fixture is fully tooled so its board has no unevidenced row to click"), then routed around it. Twice is a fixture problem, so the smoke world gained a **second repository**, `bare-app`: a library with a lockfile and nothing else — no Dockerfile, no CI, no IaC, no API description — whose collectors skip honestly and say why. Six of its rows come back empty, which is the first time the empty-cell half of this console has been exercised end to end.

- **`plain` is a TRIPLE, not the one paragraph the plan sketched** — `{ checks, violation, fix }`, because each surface needs a different one: the board answers "what is this row", the queue answers "what do I do about it", and only the evidence page wants all three. One blob would force every surface to print the other two, and would let a recipe answer one question and call itself documented; three slots make a half-written explanation fail the completeness test instead. Optional in the schema (the recipe shape mirrors the AWS dataset's, which carries no such field) and **required in this repository's catalog** by `plain.test.ts` — shape is the schema's job, completeness is policy's.
- **The prose rides the fold's existing catalog join**, exactly as `cadence` and `collector` do (J3's precedent), and carries J3's refusal with it: a recipe that fell out of the catalog gets **no prose**, because the only alternatives are prose about a different check or prose invented at render time. It is deliberately **not signed** into any bundle — it is a definition maintained in the catalog, not a fact about a scan, and signing it would re-key every bundle each time a sentence got clearer (J5 already spent that once, on purpose).
- **J1's standing rule needed SHARPENING, not obeying as written.** The rule: the board is folded from evidence and scoping alone, and J3 honoured it by having the board fetch no run data whatsoever. K1's guided empty states need run data on the board, so the rule is restated in its precise form — *which cells exist and what state each is in* is a function of evidence and scoping only; *why an already-drawn empty cell is empty* is a function of the run log only, because it is recorded nowhere else. `lib/emptystate.ts` is structurally incapable of returning anything but sentences, and a test greps its every output for all four state words (J1's own precedent).
- **Five absences, five sentences**, kept apart because the fixes differ: the collector that skipped (its reason quoted, never paraphrased), the collector the run never dispatched, no run record for this repo (J3's two facts again — none ever written vs aged past the cap), a recipe with no collector at all, and — **the one the plan never named** — a collector that RAN and still left the cell empty. That last one is a third of `bare-app`'s empty rows in practice, and the honest text says exactly that rather than inventing "no findings", which would be guessing at a verdict.
- **The queue's skip-reason tier stopped needing a daemon.** It read `scan-recorded` daemon events only, so an operator running `rampscan scan` by hand got an empty queue while their toolchain was broken. It now falls back to the run record through the *same* hand the board's empty states use — the daemon event still wins where both exist, so a daemon-driven queue does not change shape underneath its operator. Honest skips remain not-tasks on both paths. Conditions with no instant (no run on file, recipe gone from the catalog) stay off the queue entirely: a queue row states when it became actionable, and inventing that time would be worse than leaving the fact on the board, where nothing has to pretend to have happened at a time.
- **The glossary's load-bearing behaviour is the negative one**: a term with no entry renders as bare text — no wrapper, no dotted underline, no popover that opens onto nothing. `lookupTerm` normalizes camelCase (`notApplicable` off a record key), case, underscores and slashes, refuses to stem (`controller` is not `control`), and the definitions are held to the same rule as the recipes' prose: they describe the system and may not state a count or a condition of any repository.
- **Two real bugs the second repository exposed, both fixed here.** The filter chips lied: every count above the board and the control register was computed over the whole projection while the table and the CSV honoured the filters, so "All 30" sat above 15 rows — invisible for as long as there was one repo. And the J5 basis panel was located in the smoke by the prose inside it, which K1's plain-language block (also mentioning "entry points") silently became a better match for; the panel now carries a class.
- vitest **523/523** (47 new: 8 catalog-completeness tests including the computed-never-typed grep and the jargon↔glossary tie, 13 glossary twin tests, 14 empty-state twin tests pinned against the collectors' real `absentReason` wording, 7 queue tests for the run-record fallback, and 5 fold tests for the prose join and its sqlite round trip). Smoke **14/14 cold (5.0m)**; root + console typecheck clean.

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
