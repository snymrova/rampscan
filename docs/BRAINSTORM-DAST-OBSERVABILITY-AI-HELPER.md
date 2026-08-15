# Brainstorm: DAST (ZAP), tool-run observability, and a BYOK AI helper

*2026-08-14. Working brainstorm for the next horizon after Phase H (engine expansion) and Phase I (console personas). Nothing here is committed scope — this is the options-and-tradeoffs document. Decisions get promoted into PLAN-OF-ACTION.md when made.*

**Decision 2026-08-15: ZAP/DAST is parked.** §1 stays as the record of the analysis, but the runtime-evidence anchor class, the self-launch machinery, and the fixture work are a milestone of their own, not a rider. Next focus: **observability + UI (§2), then the comprehension layer (§3.1)** — see §5 for the recommended phase plan.

Three asks on the table:

1. **Add ZAP** (or DAST generally) — can rampscan produce runtime evidence, not just committed-tree evidence?
2. **Tool-run observability** — today it is hard to see *which* tools ran, *how* they resolved, and *what* they actually produced. Doctor answers "could it run"; nothing answers "what did it do last scan".
3. **Operator comprehension** — the console's board / reports / evidence pages assume the reader already speaks recipe/KSI/DSSE. Operators don't. Idea: an AI helper on a **BYOK** (bring-your-own-key) model, so the boundary promise survives.

Every idea below is tested against the standing invariants before anything else: the ledger is append-only and only ever holds signed, deterministic evidence; verdicts are **computed, never typed**; tools resolve binary-on-PATH → pinned Docker image → honest skip; no SaaS control plane, nothing leaves the client's boundary by rampscan's hand.

---

## 1. ZAP and the DAST question

### 1.1 Why ZAP is unlike every collector we have

All eleven current collectors share one property: they read a **committed tree** (or an image named by it) and are anchored to a commit. ZAP needs a **running application**. That breaks two assumptions at once:

- **Anchoring.** A URL is not a commit. If we scan `https://staging.example.com`, what commit did we just produce evidence about? The deployed artifact may be three commits behind the checkout we scanned.
- **Determinism.** DAST output varies run-to-run (timing, session state, response ordering). Our evidence identity and byte-stable-artifact discipline (semgrep's `semgrep-results.json` is sorted and path-normalized precisely so two runtimes agree) doesn't transfer for free.

Neither is fatal. Both need a deliberate answer, or the honest answer is "unknown", which is worse than not shipping.

### 1.2 What fits the existing model with zero friction

The mechanics are the easy part. ZAP ships an official image and scripted scan modes that fit `tools.json` exactly:

```json
"zap": { "version": "2.16.x", "image": "zaproxy/zap-stable:2.16.x", "entrypoint": "zap-baseline.py" }
```

- `zap-baseline.py` — passive spider + passive rules only. No attack traffic, safe against anything, bounded runtime (~1–5 min). This is the right first mode: it finds missing security headers, cookie flags, exposed debug/error pages, mixed content — exactly the class of finding operators expect from "we ran a DAST".
- `zap-api-scan.py` — takes an OpenAPI document and scans the API surface it declares. **Synergy with spectral**: the spectral collector already locates OpenAPI documents in the committed tree. The same detection can feed ZAP the spec, and the recipe becomes "the API the spec declares is the API the runtime serves, and it's clean".
- `zap-full-scan.py` — active attack rules. **Out of scope for now**: active scanning against anything but a fixture we own raises authorization questions rampscan should not silently answer for the operator.

Resolution order, doctor reporting, honest skip on no-Docker-no-binary — all unchanged.

### 1.3 The anchoring problem: three target modes, in order of honesty

**Mode A — self-launched target (strongest, build first).** rampscan builds/starts the app *from the scanned commit* and scans `localhost`. Config in the scanned repo's `rampscan.config.json`:

```json
"dast": { "start": "docker compose up -d", "url": "http://localhost:3000", "readyPath": "/health", "stop": "docker compose down" }
```

Evidence is genuinely commit-anchored: the thing scanned *is* the commit. This is the only mode where DAST evidence gets the same anchor class as everything else in the ledger. Honest skip when there is no `dast` block or the app fails to become ready (skip reason recorded, recipes report unevidenced — exactly the checkov posture on a repo with no IaC).

**Mode B — configured URL + commit attestation.** Scan a deployed URL, but require the target to expose a build-info endpoint (or header) naming its commit. rampscan records the claimed commit and marks the anchor `runtime(url, claimed-commit, scanned-at)`. If claimed commit ≠ scanned commit, that mismatch is itself a finding ("deployed artifact does not match scanned commit"), not something to paper over.

**Mode C — bare configured URL.** Anchor is honestly `runtime(url, scanned-at)` — a timestamped statement about a URL, nothing more. The bundle predicate must say so loudly, and the console must render it as a different anchor class (a distinct pill, not the commit pill). Tempting to skip Mode C entirely; keeping it is defensible only because "we scanned prod on the cadence" is a real assessor ask. Decide at build time.

Recommendation: **ship Mode A only** in the first cut. It keeps every ledger invariant intact and the fixture can prove it end-to-end. B and C introduce a second anchor class into the ledger schema — do that as its own deliberate move with its own projector/console/verify treatment, not as a rider.

**Mode A lifecycle, spelled out** (the "self-launched target" in one breath — DAST scans a URL, and self-launch is rampscan answering "which URL?" by starting the app itself from the exact checkout being scanned, so the running app *is* the commit by construction):

```
checkout commit → dast.start (compose up / node server.js)
→ poll dast.readyPath until 200 (bounded; two failures → honest skip, never violated)
→ zap-baseline against dast.url (localhost)
→ dast.stop → normalize alerts → zap-results.json (commit-anchored like any artifact)
```

**Localhost honesty caveat**: a self-launched app is not production config. Perimeter-added headers (HSTS from an ALB/CDN, WAF behavior, TLS) don't exist in front of localhost — so Mode A recipes must assert only what the *app itself* owns (framework-set CSP, cookie flags, no debug endpoints, no stack traces in error pages), with the recipe notes saying why perimeter headers are out of scope. Perimeter checks are precisely the Mode B/C ask, deferred with the anchor-class question.

### 1.4 Determinism and cadence

- **Normalization**: sort alerts by (rule id, url path, evidence string), strip timestamps/scan ids/durations, relativize URLs against the target base → `zap-results.json`, byte-stable across runs *of the same app build*. Same discipline as semgrep's artifact.
- **Cache**: DAST must **never** be served from the content-hash cache in the way static collectors are. For Mode A the honest cache key is the built image/app digest, and even then the scheduled full scan should re-run it (rules update). Simplest correct posture: `cacheScope: []` — always run, let the cadence be the cost control.
- **Flake policy**: a target that fails readiness twice is a skip with reason, never a violated. DAST flake must not be able to flip a register.

### 1.5 Candidate recipes

| id | assertion sketch | notes |
|---|---|---|
| `dast-baseline-clean` | count of alerts at risk ≥ High == 0 | the headline recipe; Medium rides along as observations |
| `security-headers-present` | required header set present on the root + one authed route | CSP, HSTS, X-Content-Type-Options, frame-ancestors; ZAP's passive rules already emit these individually |
| `no-exposed-debug-surface` | zero hits for error-disclosure / stack-trace / directory-listing rules | maps to the "no debug in prod" ask |
| `api-surface-matches-spec` | zap-api-scan over the spectral-detected OpenAPI doc, zero High | the spectral × ZAP join; stretch |

KSI/control mapping must be validated against the dataset like every other recipe (scan-time + test-time) — candidates look like the SVC/CNA families plus si-10/sc-8-adjacent controls, but **the dataset decides, not this doc**.

### 1.6 The fixture

`fixtures/vulnerable-app` has an express-*shaped* hand-rolled router but doesn't actually listen. Make it genuinely runnable (a `listen` entry + trivial Dockerfile target or `node src/server.js`), then plant DAST faults with the same every-fault-is-deliberate discipline: missing CSP/HSTS, a `/debug` route that dumps env-shaped data, verbose error page. Exit test: fixture scan → `dast-baseline-clean` violated citing the planted alerts; a repo with no `dast` block → honest skip; self-scan (rampscan has no web app) → honest skip.

### 1.7 Cheaper wins in the same breath (candidates, not commitments)

If the goal is "more tools", these fit the *existing* static model with far less machinery than ZAP — worth weighing before or alongside:

- **`zizmor` or `actionlint`** — GitHub Actions security/lint; deepens the existing ci-actions story; static, deterministic, tiny.
- **`dockle`** — container config lint (complements grype's CVE view with CIS-style config checks); scans the same final-FROM image grype already resolves.
- **license recipe over syft data** — syft already extracts license data; a `dependency-licenses-declared` recipe is join-only, zero new tools.
- **`trivy config`** — overlaps checkov; probably skip, noted for completeness.

ZAP is the *distinctive* move (it opens the runtime evidence class the frontier doc can brag about); zizmor/dockle are the *cheap* moves. Both can be true.

---

## 2. Tool-run observability: "what ran, and what did it produce?"

### 2.1 What exists today, and the gap

- `pnpm doctor` — *can* each tool run, and how would it resolve. Point-in-time, terminal-only, not per-scan.
- `CollectOutput` already carries `toolVersion`, `exitCode`, `skipped.reason` per collector — but it's consumed by the join and mostly discarded from the record.
- `rampscan-out/` holds `scan-result.json` + `artifacts/`, `daemon-events.jsonl` holds daemon ticks — none of it surfaced in the console, none of it answers "show me the exact argv and image digest behind Tuesday's scan".

The gap in one sentence: **evidence says what was concluded; nothing durable says how the run that concluded it actually went.** Auditors ask exactly this ("what version of what scanner, invoked how, producing what"), and it's also the debugging surface we keep reconstructing by hand (see the PATH/unevidenced trap already recorded in memory).

### 2.2 Proposal: the scan-run manifest

The Runner (already the single choke point every collector passes through) records, per collector, per scan:

```
collector, tool, resolved version,
runtime: binary(path) | docker(image, digest) | absent,
argv (redacted of any secret-shaped values), cwd, duration_ms, exit_code,
artifacts produced: [{ name, sha256, bytes }],
cache: hit | miss | not-cacheable, cache key inputs,
skip reason (when skipped)
```

→ written as `run-manifest.json` in `rampscan-out/` per scan, one entry per scan instant. It is *about* the run, not itself evidence — but it's the "how" behind every bundle, so the medium-term move is to sign it and reference its digest from the bundles it produced (auditor question answered offline via `rampscan verify`). Short-term, unsigned in `out/` is already a big step.

### 2.3 Surfaces

- **Console `/runs`**: scan timeline (the as-of work already enumerates scan instants) → expand a scan → per-collector rows with runtime pill (binary/docker/skipped), version, duration, exit code, artifact list → click an artifact → rendered view of the normalized JSON (semgrep/osv/zap results as tables, not raw dumps) + raw download in the evidence-page posture. This *is* the operator's answer to "what tools are being used and what are they outputting."
- **Provenance chain rendered end-to-end**: recipe → collector → tool+version → artifact digest → bundle digest. Every hop already exists in data; the page just draws the line. This chain is also precisely the grounding an AI helper needs (§3).
- **Board hop — "how was this produced?"**: one small link on every board row deep-linking to `/runs?scan=…&collector=…`. Probably the single highest-leverage piece: an operator staring at a confusing `unevidenced` cell lands one click from "grype skipped: no binary, no Docker" instead of guessing.
- **CLI `rampscan tools`**: the static map (recipe ↔ collector ↔ tool ↔ pinned image) — doctor answers "can it run", `tools` answers "who feeds whom", `/runs` answers "what happened".
- **Doctor into the console**: a tooling-health card on `/runs` (last resolution per tool, historical per-run), so a silently-absent tool is loud *before* it produces a mysterious column of unevidenced — and "when did semgrep stop resolving as a binary?" has an answer with a date.

**Page sketch** (`/runs`):

```
┌──────────────────────────────────────────────────────────────────────┐
│ Scan runs                          [Tooling health: 9 ok · 2 docker] │
├──────────────────────────────────────────────────────────────────────┤
│ ▸ 2026-08-14 09:12Z  commit a19af63  daemon·incremental  4m 02s      │
│      11 collectors: 8 ran · 2 cache-hit · 1 skipped ⚠                │
│ ▸ 2026-08-13 09:00Z  commit 2f0165e  daemon·full         11m 40s     │
└──────────────────────────────────────────────────────────────────────┘

expanded run → per-collector table:

│ collector   tool·version      runtime                  time  exit  artifacts │
│ gitleaks    gitleaks 8.24.3   ⬡ docker ghcr.io/…@sha…  18s   1     gitleaks-report.json │
│ semgrep     semgrep 1.173.0   ▸ binary ~/.local/bin    41s   0     semgrep-results.json │
│ osv-scanner —                 ↻ cache-hit (lockfile unchanged)     osv-results.json     │
│ grype       —                 ⊘ skipped: no binary, no Docker — recipes unevidenced     │

collector row / evidence page → provenance chain, clickable both ways:

recipe no-reachable-dangerous-code → collector sast-reachability
  → semgrep 1.173.0 (docker @sha256:…) → semgrep-results.json #f3a1…
  → bundle #8c2e… (violated)
```

The `1 skipped ⚠` count on the timeline row is loud by design — a silently-absent tool quietly turning a column unevidenced is today's most confusing failure mode.

### 2.4 Why this phase goes first

It's the smallest lift (the data mostly exists at the Runner boundary), it de-mystifies the system for exactly the operator who is currently lost, it's the debugging surface ZAP integration will need on day one, and it's the context substrate the AI helper grounds in. Everything downstream gets cheaper.

---

## 3. The BYOK AI helper: a docent, never a judge

### 3.1 The comprehension problem, and the non-AI first aid

The operator's stated pain: the console, the reports, the evidence pages are hard to understand. Before any model is involved, three cheap moves attack the same pain and improve the AI's grounding as a side effect:

1. **`plain` field on every recipe** — one paragraph, written for the operator, of what this recipe checks and what a violation means in practice. Rendered on board rows and evidence pages. (Computed-never-typed applies to *verdicts*; explanatory prose is exactly what should be authored.)
2. **Glossary-on-hover** for the jargon layer: KSI, DSSE, anchor, verdict classes, MVX window, not_affected, two-key.
3. **Guided empty/first-run states** — "this column is unevidenced because gitleaks did not resolve; here's the doctor line" (feeds directly off §2's manifest).

Ship these regardless of the AI decision. They're an afternoon each and they lower the floor the AI has to explain from.

### 3.2 Why BYOK is the only shape that fits

The founding constraint: no SaaS control plane, evidence and code never leave the client's boundary by rampscan's hand. An AI helper survives that constraint only if:

- the **key belongs to the operator** (their Anthropic/OpenAI key, or — the strongest fit — **their AWS account's Bedrock**, where the inference call never leaves the boundary at all; for a harness already deployed inside the client's AWS account, BYO-Bedrock-role is arguably the flagship configuration);
- calls go **direct from the client's environment to their chosen provider** — rampscan proxies nothing through any rampscan-operated service (there is none);
- the feature is **opt-in, off by default**, with a consent screen that states exactly what leaves the boundary when a provider outside AWS is chosen.

Note the deferral log says "Bedrock / any model" is deferred-by-name. This proposal is a different animal from what was deferred (rampscan running a model as part of the *evidence pipeline*): here the model is operator-invoked, operator-keyed, and structurally incapable of touching evidence. The deferral stands for the pipeline; the docent is new scope and should be decided on its own merits.

### 3.3 Hard rules (the two-key discipline, applied to AI)

1. **Explain-only, read-only.** The helper's server route (if any) gets the diff-route posture: auth-refresh gate, runtime nodejs, structurally unable to write. The model can never append to the ledger, flip a verdict, file a scoping proposal, or press any button an operator can press.
2. **Unsigned narrative, loudly labeled.** Every AI output renders under an "AI-generated explanation — not evidence, not signed, verify against the bundle" banner. Same honesty posture as the as-of strip.
3. **Deterministic context assembly.** What the model sees is built by code — recipe JSON + `plain` text, dataset control text, the bundle's signed predicate, the run-manifest entry — never a free grab over the filesystem. The context builder is testable and its output loggable.
4. **Redaction before egress.** Findings can embed secret-shaped strings (gitleaks' whole job). A redaction pass (reuse gitleaks-style patterns) scrubs the assembled context before any non-Bedrock provider. Plus a per-conversation "show what was sent" affordance — the prompt audit is part of the trust story, not a debug feature.
5. **Prompt audit trail** in daemon-events/console storage (not the ledger — it isn't evidence): who asked, what context was assembled, which provider. 

### 3.4 Feature tiers

- **T1 — "Explain this."** A button on any board row / evidence page / drift entry / clock lapse. One-shot: assembled context → streamed explanation ("what this recipe checks, why this row is violated, what the artifact shows, what fixing it looks like"). No conversation state. This alone probably kills 80% of the comprehension pain.
- **T2 — "Ask the board."** Chat with tool-use where the tools are exactly the console's existing read-only GET routes (board, as-of, diff, scoping register, verify). The model composes reads; it cannot write because the tools can't. "Why did coverage drop since last Tuesday?" → it calls the diff route and narrates.
- **T3 — Remediation drafts.** "Draft the fix" → suggested steps or a PR-description skeleton for a violated row, grounded in the artifact (the semgrep hit, the unpinned action, the CVE). Clearly a draft; rampscan never opens PRs.
- **T4 — Narrative for the auditor package.** Summarize a register or an as-of snapshot into assessor-facing prose, every claim linked to a bundle digest. Highest value, highest risk of the model over-claiming — gate it on T1/T2 confidence and keep the every-sentence-cites-a-digest rule mechanical.

Build T1 first; it's stateless, cheapest to guard, and the fastest test of whether the operator pain actually yields to explanation.

### 3.5 Architecture sketch

- **Provider adapter** (`console/web/lib/ai/`): one interface, three implementations — Anthropic, OpenAI-compatible, Bedrock (SigV4/IAM role, no key material at all). Model name is operator-chosen; stream everything.
- **Key custody**: per-user record in PocketBase (console-only collection, PB rules: owner-read-write, projector/ledger untouched), encrypted at rest with a serve-held secret; or session-only (paste per session, held in memory) as the paranoid default. Offer both; default to session-only.
- **One route**: `POST /api/ai/explain` (and later `/api/ai/chat`) — assembles context server-side (it needs projection + ledger reads the browser can't do), calls the provider with the operator's credential, streams back. Read-only posture enforced structurally.
- **Cost/latency**: T1 contexts are small (a recipe + a predicate + a manifest entry ≈ a few KB); cache assembled context by bundle digest so repeat explains are near-free on providers with prompt caching.

---

## 4. Sequencing recommendation

Order chosen so each phase feeds the next:

- **Phase J — observability substrate.** Run manifest at the Runner boundary → `/runs` page with per-collector rows + rendered artifacts + provenance chain → `rampscan tools` → doctor card. *Exit test: after a fixture scan, `/runs` shows every collector's runtime/version/duration/artifacts; a deliberately-absent tool shows the skip loudly; the provenance chain from `no-reachable-dangerous-code` to its bundle digest renders end-to-end.*
- **Phase K — comprehension layer.** `plain` on all recipes + glossary + guided empty states (K1, no AI); then BYOK helper T1 with the hard rules of §3.3, Bedrock + Anthropic adapters first (K2). *Exit test: with a session-only key, "Explain this" on the flagship violated row streams a grounded explanation that cites the bundle digest and renders under the not-evidence banner; the redaction pass provably scrubs the planted fixture secret from an assembled context; with no key configured the button explains BYOK instead of erroring.*
- **Phase L — DAST.** Mode A only (self-launched target), `zap-baseline` via pinned image, `dast-baseline-clean` + `security-headers-present`, runnable fixture with planted DAST faults. *Exit test: fixture scan launches the app, ZAP finds the planted faults, the bundle is commit-anchored like any other, no-`dast`-block repos and the self-scan skip honestly; `/runs` (Phase J) shows the ZAP run's image digest and duration.*

Cheap parallel candidates (zizmor/dockle/license-recipe) can ride along any phase as single-collector moves in the H-phase mold.

Open questions to settle before promoting to the plan: Mode B/C anchor class — build ever, or never? Sign the run manifest in Phase J or defer? Key custody default (session-only vs stored)? Does T2 ship with tool-use or wait for T1 telemetry? Which cheap-win tool, if any, rides with Phase J?

---

## 5. Recommended plan of action (2026-08-15, ZAP parked)

The observability phase, ordered so each step ships something visible and the capture layer lands first (everything downstream only reads it):

- **J1. The run record, ledger-first.** A new statement kind — `scan-run` — signed and appended once per scan: per-collector tool + resolved version, runtime (binary path | docker image+digest | absent), redacted argv, duration, exit code, artifact names+digests, cache hit/miss with key inputs, skip reason. Projected by the projector into a `scan_runs` collection like everything else. Ledger-first rather than a console-side collection because the manifest is the *how* behind every bundle — auditors ask for exactly this — and going through the ledger buys rebuild byte-equality, as-of, and offline `verify` for free instead of as retrofits. (The lighter alternative — console-writes-it like proposals — saves schema work but creates the only operator-facing record that can't be verified or rebuilt; rejected.)
- **J2. `/runs` page**: scan timeline (from scan instants + `scan_runs`) → expanded per-collector table with runtime pills, loud skip counts. The §2.3 sketch.
- **J3. Board hop**: "how was this produced?" link on every board row → `/runs?scan=…&collector=…`. Smallest diff, highest leverage — ship the moment J2 renders.
- **J4. Artifact viewers**: rendered tables per artifact type (semgrep/osv/gitleaks/checkov/spectral results), raw download in the evidence-page authorized-fetch posture.
- **J5. Provenance chain** on evidence pages + run rows (recipe → collector → tool → artifact digest → bundle digest, clickable both ways); tooling-health card; `rampscan tools` CLI.

**Exit test (Phase J):** fixture scan → `/runs` shows every collector's runtime/version/duration/artifacts and the signed scan-run verifies offline via `rampscan verify`; with one tool deliberately absent, the timeline row counts the skip loudly and the board's unevidenced cell hops to the named reason; `rebuild` reproduces `scan_runs` byte-for-byte; provenance renders end-to-end for the flagship recipe.

- **K1 (next, no AI): the plain-language layer.** `plain` field on all recipes rendered on board rows + evidence pages, glossary-on-hover, guided empty states wired to J1's skip reasons. An afternoon each, attacks the operator-comprehension pain directly, and doubles as grounding if/when the BYOK helper (§3) gets its own go/no-go.

BYOK helper (K2) and DAST (§1) each remain their own decision after J+K1 land.
