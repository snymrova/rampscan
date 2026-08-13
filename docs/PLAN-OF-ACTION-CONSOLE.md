# rampscan — plan of action: console personas (operator + auditor)

**Status:** working checklist — the executable layer for the post-H console track. `docs/PLAN-OF-ACTION.md` owns the prototype's history (Phases A–H, complete); this document owns the console persona work: task order, exit tests, current status. On any architecture dispute, `docs/SPEC.md` wins.
**Date started:** 2026-08-14
**Decision of record (2026-08-14):** one console, two lenses — not two products. The operator lens answers "what do I act on today"; the auditor lens answers "prove it, trace it, let me take it with me." Both are projections over the same ledger, role-gated in the existing console (`users.role`), never forked.

---

## 0. Ground rules, active from the first commit

1. **One console, two lenses.** Auditor and operator views are role-gated pages over the same projections. No second app, no second data path — two renderings that drift apart would violate the honesty principle at the UI layer.
2. **Registers stay the record.** Workflow state (queue triage, assignments, acknowledgments) lives in console-writable PocketBase collections — the same posture as proposals — never in the projection collections. Nothing an operator clicks may mute, hide, or reorder a register row's verdict.
3. **The auditor lens is strictly read-only and export-heavy.** Every rendered claim carries its bundle digest and an offline verification path. The console asks to be distrusted: "verify this yourself" is a feature, not an apology.
4. **Computed, never typed** (inherited). Coverage percentages, gap durations, queue rankings — every number on a page comes from a fold or a query, not a keyboard.
5. **Console tests ride with the first UI slice.** The console currently has zero automated tests; the first Playwright smoke is part of I2's exit, not a cleanup task. Every later phase extends it.
6. **New views are projections.** No new ledger statement kinds in this track — the ledger already holds everything these pages need. (If a phase discovers otherwise, that's a spec conversation first.)

---

## Phase I1 — substrate: projections both lenses need

- [x] I1a. **Control register projection** in `packages/projector` (`fold.ts`): control → mapped recipes → rolled-up verdict (`violated` beats `unevidenced` beats `evidenced`; scoping honored per existing precedence) + coverage counts ("2 of 3 mapped recipes evidenced"). Same for a KSI register. SQLite + PocketBase writers, same drop-and-refill posture.
- [x] I1b. **As-of fold**: `fold(ledger, { asOf })` — deterministic point-in-time projection from the append-only record. CLI surface first: `rampscan board --as-of <iso>` (cheapest honest demo of the capability).
- [x] I1c. **mvx twin test** — closes the drift gap found 2026-08-14: one test imports both `packages/scheduler/src/mvx.ts` and `console/web/lib/mvx.ts` and asserts the thresholds agree (fresh < 0.75 ≤ expiring < 1.0 ≤ expired). The comment "thresholds agree by test" becomes true.
- [x] I1d. **Cadence-adherence history**: per-recipe freshness gaps derived from bundle chains × MVX windows — every interval where live evidence sat past 1.0, with start/end/duration. Exposed in the projection; the clock view and the auditor's gap timeline both read it.

**Exit test:** e2e — two scans with a touched file between them; folding as-of a timestamp between the scans reproduces byte-for-byte the projection the first scan produced. Control-register counts match an independent recount from rows (report-test posture). mvx twin test green. `pnpm test` green throughout.

---

## Phase I2 — operator lens: from status display to work queue

- [ ] I2a. **Action queue page**: one ranked list merging cache-divergence alerts, evidence entering the expiring band before its next cadence refresh, new violations (born/verdict-flipped drift events), and actionable unevidenced rows (collector skipped for a fixable reason, e.g. tool missing → doctor hint). Ranking: divergence > expiring-before-next-cadence > new violation > actionable unevidenced. Pure re-projection + daemon events; no new writes.
- [ ] I2b. **Daemon status strip** on the board header: last scan (commit + time), daemon alive/stale (no tick past the check interval → say so loudly), next expected cadence action, divergence-report presence. Source: `daemon-events.jsonl` (`serve` tails it into a console-readable collection). An operator who cannot see the daemon died owns a silently rotting board.
- [ ] I2c. **Fix pointers on violation rows**: failing file/line where the artifact carries it (semgrep, reachability `call_path`), reproduce command, killing/introducing commit — on the row or one click deep, never a context switch away.
- [ ] I2d. **"Since baseline" drift toggle**: diff the board against a chosen prior scan (default: previous), not only the by-day grouping.
- [ ] I2e. **First Playwright smoke** (ground rule 5): `rampscan serve` → login → board renders rows from a real fixture scan → evidence detail shows assertions + call path → action queue renders ranked. Runs in CI against the fixture.

**Exit test:** with the daemon stopped, the console visibly says so. The daemon e2e's poisoned-cache divergence scenario surfaces at the top of the queue. Playwright smoke green in CI.

---

## Phase I3 — auditor lens: verify, trace, take away

- [ ] I3a. **Control register page**: the auditor's landing view — control ID → mapped recipes → verdicts → evidence bundles, every hop clickable in both directions (bundle → recipe → KSI → control and back).
- [ ] I3b. **Verify-this-yourself block** on every evidence page: download raw DSSE bundle + public key, copy-paste offline `rampscan verify <digest>` invocation. Page header surfaces what the bundle already carries: dataset pin, tool versions, extractor version, scanned commit.
- [ ] I3c. **Scoping register**: every scoping decision — approved *and rejected* proposals — with full justification text, proposer + approver identities, timestamps, signature verification status, and the recipe/controls removed from scope. N/A is where auditors sample hardest; the honest record of a rejected scope-out is a strength.
- [ ] I3d. **As-of selector** on board + control register (UI over I1b) and the **cadence-gap timeline** in the clock view (UI over I1d): "did evidence lapse during the assessment period, and for how long?"
- [ ] I3e. **Export**: CSV of any register view; per-control evidence package (bundles + artifacts + public key + verify instructions, zipped); print-friendly evidence page (CSS, not a PDF service).
- [ ] I3f. **Not-affected claims show their work**: entry-point set and its provenance (config override vs package.json inference), the over-approximation statement rendered inline ("not-affected only when even the loose walk cannot reach the package; unknowns count against us"), exact-vs-inferred edge marking on displayed paths.

**Exit test:** an assessor-shaped Playwright walkthrough — pick a control on the control register → traverse to an evidence bundle → download the evidence package → `rampscan verify` passes offline on the downloaded bundle. Scoping register shows one approved and one rejected proposal with verifiable signatures. Exported CSV row count equals the on-screen register. Print view of an evidence page contains digest, commit, dataset pin, tool versions.

---

## Deferred by name (do not build in this track)

Auditor SSO / external assessor accounts · console access audit log · acknowledge-as-ledger-event (workflow state stays console-local until a real need names it) · PDF rendering service (print CSS only) · multi-repo joins · React Flow canvas · webhooks · CI wiring for the Phase H collector families (still the next *engine* track, deliberately not this one).

---

## Session log

Update as work lands — newest first.

| Date | Phase | What landed | Notes / deviations |
|---|---|---|---|
| 2026-08-14 | I1 | Full substrate: `Projection` gains `controls`/`ksis` (`RollupRow`: rolled-up verdict + attributable counts, computed from register rows so a recount always agrees), `gaps` (`CadenceGap`: chain × MVX window, ongoing tail ends at `projectedAt` — never a wall clock), and `FoldOptions.asOf`/`windowMs`. SQLite tables + PocketBase collections (`controls`, `ksis`, `gaps`) with drop-and-refill and lossless read-back — `rampscan rebuild` proves it over the real ledger. CLI: `rampscan board --as-of <iso>`; serve/daemon/rebuild folds now carry `windowMs` so persisted projections include the gap history. Tests: `projector/test/substrate.test.ts` (10), `scheduler/test/mvx-twin.test.ts` (3, loads the console copy by path — a workspace import would break `tsc --build`), Phase I1 exit block in `cli/test/ledger.e2e.test.ts` (as-of between two real scans reproduces scan 1's projection byte-for-byte via `canonicalJson`; control recount from rows). `pnpm test` 219/219, `pnpm typecheck` clean. | PocketBase rollup field is `rollup_id` ("id" collides with PB's record id); SQLite gap columns `gap_start`/`gap_end` ("end" is a keyword). Exit-test determinism: `asOf` filters on predicate timestamps and `projectedAt` is caller-supplied, so the projection object itself never carries a wall-clock read. Next action: I2a (action queue page). |
| 2026-08-14 | — | Track created: this document. Decisions from the persona review: one console two lenses; registers stay the record (workflow state console-writable, never projected); auditor lens read-only + export-heavy; sequencing substrate → operator quick wins → auditor lens (auditor-only postpones daemon visibility and would demo beautiful stale evidence; operator-only postpones the differentiator). Known debts this track inherits: console has zero automated tests; `cadence.test.ts` asserts re-stated mvx thresholds without importing the console copy. | No code yet. Next action: I1a (control register projection in `packages/projector`). |
