# Implementation Plan — Architecture Contract, Agent Surface, On-Device LLM

*Written 2026-08-15. Derived from `docs/BRAINSTORM-PM-ROADMAP-ONTOLOGY-ONDEVICE-LLM.md`, revised by two decisions made after it:*

1. **Contract-first scope.** "Ontology" is retired as an internal term. The descriptive code graph is an internal evidence input, not a deliverable — `code-review-graph` (30k★, Tree-sitter, 30 MCP tools) owns the general navigation-graph space and rampscan will interop, not compete. What ships is the **normative layer**: declared architecture rules, checked by pure gates, signed as evidence — "rampscan attests architecture rules the same way it attests security rules."
2. **Phases reordered.** The brainstorm's L1 (unified ontology export) is demoted to a slim artifact in L2; the contract moves first because it is the shortest path to new signed value and every later phase leans on it.

Phase letters continue the repo's existing sequence (…J1–J5, K1) as **L0–L5**.

---

## Standing constraints (every phase is bound by these)

These are the invariants the codebase enforces today; nothing below may bend one.

- **I1 — computed, never typed.** New authored prose (contract rule descriptions, model drafts) must be structurally unable to state a verdict, count, or repo fact. Enforce by test the way `plain.test.ts` greps recipe prose today.
- **I4/I5 — the fold stays pure and board-only-from-evidence+scoping.** No model output and no contract *file* enters the fold; only signed bundles do.
- **I7 — claims carry their ground.** Every new gate emits a `ClaimBasis` with an explicit approximation direction; unknowns count against the repo.
- **I8 — offline evidence path.** No network in scan, gates, or model inference. The model runtime is local or honestly absent.
- **I15 — absence with a reason.** A repo with no contract, or a machine with no model runtime, produces a stated skip, never silence and never a vacuous pass.
- **Twin-test rule.** Any logic duplicated into `console/web/lib/` gets a twin test importing both copies (existing pattern: `mvx-twin`, `glossary-twin`, `provenance-twin`, `emptystate-twin`).
- **Fixture rule.** Every new behavior is exercised on real fixture output, extending `fixtures/build-vulnerable-app.mjs` (the violation case) and `fixtures/build-bare-app.mjs` (the honest-absence case) — never a typed fixture string.
- **Ledger compatibility.** New statement fields follow the J5 precedent: if a field joins evidence identity, existing bundles supersede once, openly — no back-compat exemption, and the plan says so before landing.

---

## L0 — Decisions to lock before code (½ day, no code)

Resolve the brainstorm's open questions with these defaults (change here, not mid-phase):

| Question | Default locked for this plan |
|---|---|
| Buyer | The existing compliance operator remains primary. The agent-guardrails story is framed as CM-family control coverage first, agent tooling second. |
| Identity keying | The **contract rule set** (normalized text of the rules a gate evaluated) is keyed into evidence identity via the gate's `basis` — editing the contract re-keys and kills stale evidence, same rationale as entry-point basis (`packages/core/src/bundle.ts:96-113`). The descriptive repo-model digest is **not** keyed (advisory, like `offenders`). |
| Second language | Deferred. TS/JS only until an external user asks. |
| Model pinning | Model weights are pinned by content hash in a manifest, resolved-or-honestly-skipped exactly like `tools.json` images. |
| Runtime | The model port is runtime-agnostic. Evaluate needle vs Ollama vs llama.cpp *against the port contract* in L4's first work item; do not choose earlier. |
| KSI/control mapping for contract recipes | Must resolve in the pinned crosswalk (`validateRecipeIds` throws otherwise). L0 deliverable: pick real CM-family control ids + KSI ids from dataset pin `2026.07.14.01` for the two L1 recipes. |

Exit: a short decision record appended to this file's changelog section.

---

## L1 — The Architecture Contract (config schema + pure gate + recipes)

**Goal:** a repo can declare two kinds of architecture intent in `rampscan.config.json`; rampscan checks them with a pure gate and signs the result; a broken rule is a `violated` board row with an offender pointer and a call path.

### Work items

1. **Schema** — extend the config schema (currently `packages/graph/src/config.ts`: `graph.entrypoints`, `graph.authPatterns`) with a `contract` block in `packages/schema` (Zod, like everything at a boundary):
   ```jsonc
   "contract": {
     "rules": [
       { "kind": "route-auth", "id": "admin-routes-authed",
         "routes": "/admin/*", "description": "…" },
       { "kind": "boundary",  "id": "billing-isolated",
         "module": "src/billing", "allowedImporters": ["src/api"],
         "description": "…" }
     ]
   }
   ```
   Exactly two rule kinds. `description` required (it is the rule's plain-language seed and is barred from stating verdicts — grep-tested). Rule ids unique; unknown kinds are a config *error*, not a skip (a typo must not silently waive a rule).
   - `route-auth` **promotes the existing heuristic**: today `route-auth-coverage` checks *every* route against default patterns `["auth"]`; a declared rule scopes which routes *must* pass, turning a heuristic observation into declared intent.

2. **Gate collector** — new `packages/collectors/src/contract.ts`, registered in the execution order after `graph` (`packages/collectors/src/index.ts:51-63`). Pure: consumes `graph.db` only, spawns nothing (`tools: []` in its manifest — the manifest-vs-source drift test already enforces this). Per rule kind:
   - `route-auth`: reuse `packages/graph/src/query.ts` auth walk (`calls|handles` edges only — under-approximate, positive claims need a real chain), filtered to the rule's route glob.
   - `boundary`: walk `imports` edges into the guarded module; any importer outside `allowedImporters` is an offender with the import chain as `call_path`. Over-approximate (any resolution, `exact` and `inferred` both count) — a violation may only be *waived* by the loose walk finding nothing.
   - `ClaimBasis` per recipe: approximation direction per rule kind, the normalized rule set (identity-keyed per L0), graph shape, `degraded` when the graph or entry points are absent.
   - **No config → no observation** (recipe stays honestly unevidenced with reason "no contract declared"), mirroring `graph.ts:150-153`'s no-routes refusal. Config present but zero rules of a kind → same.

3. **Recipes** — two new files in `recipes/pipeline/`: `arch-route-auth-declared.json`, `arch-boundaries-hold.json`. Full `plain` triple (checks/violation/fix), `cadence`, real KSI/control ids from L0, `automatable: "full"`, `anchor: "commit"` with `rampscan.config.json` + guarded module files as anchors (so editing the contract or the module drifts the anchor — the K-phase machinery kills stale evidence for free).

4. **Fixtures** — `vulnerable-app` gains `src/billing.js` imported directly from `src/render.js` in violation of a declared boundary, plus a declared `route-auth` rule that `GET /health` breaks (the route already exists unauthed). `bare-app` stays contract-less and must render the "no contract declared" empty state through the existing `emptystate` hand.

5. **Console** — no new surface. The rows ride the existing board/queue/evidence pages; verify the glossary needs (at most) one new term ("contract rule") and add it under the existing no-improvised-definitions rules.

### Tests / exit criteria
- Vitest: gate unit tests (both kinds, both verdicts, degraded, no-config refusal, offender call paths); fold test (contract rows join like any recipe); identity test (editing a rule re-keys, editing an unrelated file does not); `plain.test.ts` and `manifest-tools` pass unmodified.
- Smoke: one new Playwright test walking the boundary violation on `vulnerable-app` — board row violated, evidence page shows offender import chain and the basis naming the rule text; `bare-app` row explains its emptiness.
- `rampscan rebuild` byte-identical on the new ledger; root + console typecheck clean.

**Size:** the largest phase; comparable to a J-phase. **Risk:** crosswalk mapping (mitigated in L0); boundary-rule path semantics on `inferred` edges (decided above: count them).

---

## L2 — Repo Model export (slim, one artifact)

**Goal:** one canonical-JSON artifact, `repo-model.json`, that unifies what the fold already knows — for the L3 agent surface to serve and for auditors to download. Deliberately *not* a graph platform.

### Work items
1. `packages/cli/src/model.ts` — `buildRepoModel(projection, catalog, dataset, toolMap)`: typed nodes (repos, recipes, controls, KSIs, collectors, tools, contract rules, routes-summary) + typed links (crosswalk, provenance, consumes, rule→recipe). Pure derivation over existing structures (`buildToolMap`, fold output, dataset client) — no new extraction. *(Landed with the first argument changed: it takes the ledger ENTRIES and folds them itself — see the changelog.)*
2. Emit during `scan()` as a run artifact (recorded in the run record with its sha256, like every artifact); viewable via a new artifact-viewer family (the J4 pattern: family from attested name, states what it does not show). **Not** part of evidence identity (L0 decision).
3. `rampscan model` command prints it / writes it standalone from the ledger (no scan needed — it is a fold derivative, same posture as `rampscan tools`).

### Tests / exit criteria
- Vitest: determinism (same ledger → byte-identical model), completeness (every live register row appears; every contract rule appears), and the artifact-viewer twin test.
- Smoke: evidence page renders the model artifact table on the fixture scan.

**Size:** small — plumbing over existing joins. **Risk:** scope creep back toward "platform"; the guard is the node-type list above, closed.

---

## L3 — MCP Agent Surface (`rampscan mcp`)

**Goal:** a local, read-only MCP server any coding agent can use to stay on contract — plus one dry-run tool, `check_diff`, that answers "would my working-tree change break the contract?" before a commit. Interop stance: **no navigation tools** (impact radius, semantic search — that's code-review-graph's job); rampscan serves what only rampscan knows: the contract, the signed state, and the dry-run.

### Work items
1. New package `packages/mcp` (stdio MCP server; evaluate `@modelcontextprotocol/sdk` — first dependency decision of the phase, minimalism rules apply). Wired as `rampscan mcp [--ledger --db --recipes]`.
2. Tools (all read-only over the projection/ledger/catalog — the console's posture):
   - `get_contract` — declared rules + plain-language.
   - `get_board` / `get_violations` — register rows with verdicts, offender pointers, empty-state reasons.
   - `get_evidence <digest>` — the signed statement (what `/evidence/[digest]` shows, minus rendering).
   - `get_repo_model` — the L2 artifact.
   - `explain_term` — the glossary, same no-improvised-definitions rule.
   - `check_diff` — re-extract the graph over the **working tree** (uncommitted), run the pure gates only (`contract`, `route-auth-coverage`, optionally `sast-reachability` sans semgrep re-run), return would-be verdicts clearly labeled `dry-run — not evidence, nothing signed, nothing appended`. Never touches the ledger; never writes an artifact into `out/`.
3. Trust boundary, stated in code the way the console states its own: the MCP process opens the ledger read-only and possesses no signer. There is no write tool, and `check_diff` output carries the dry-run label structurally (a distinct response type), not as prose.
4. Dogfood: commit a `rampscan.config.json` contract for **rampscan's own repo** (e.g., `packages/*` may not import from `console/`, collectors are the only spawners) and run the surface against it.

### Tests / exit criteria
- Vitest: each tool handler over a real fixture ledger; `check_diff` on a working tree with the planted boundary break — verdict flips in dry-run while `rampscan board` is unmoved; ledger byte-count identical before/after a full MCP session.
- Smoke: script an MCP client (stdio) against the fixture: agent asks `get_contract` → edits the fixture to break it → `check_diff` reports the breach → real `rampscan scan` confirms with a signed violated bundle. This end-to-end is **the demo** of the whole direction.

**Size:** medium. **Risk:** MCP SDK churn (pin it); temptation to add navigation tools (refused above).

---

## L4 — ModelRunner port + two advisory uses

**Goal:** a local model can *draft* text a human signs and *annotate* the queue — with zero standing in the verdict path.

### Work items
1. **Runtime evaluation (first item, timeboxed):** needle vs Ollama vs llama.cpp server, scored only against the port contract: local resolve/version-report, offline inference, temperature-0 generation, pinned-weights support, uid-safe execution. Pick one as the reference adapter; the port keeps the others possible.
2. **Port** — `ModelRunner` beside the six ports in `packages/core/src/ports.ts`: `resolve() → available|absent{reason}`, `draft(task, context) → {text, model_id, weights_sha256, costTokens}`. Adapter in a new `packages/model`. Resolution mirrors `tools.ts:9-21`: runtime on PATH/socket → pinned weights present → else honest skip. `pnpm doctor` and `rampscan tools` report the model row like any tool.
3. **Use (b) — scoping-justification drafting.** In the console proposal drawer: "Draft with local model" fills the justification textarea from row context (recipe `plain`, empty-state reason, repo facts). The human edits; the approver's key turn signs — the signed subject remains the human-approved text (`core/src/scoping.ts:7-10` unchanged). Absent model → button absent with reason, not disabled mystery. Served via one new console API route that shells to the local runtime — the evidence path never touches it.
4. **Use (c) — queue triage advisory.** An optional `advisory` field on queue items: model-drafted "what probably happened / what to try", typed `PLAUSIBLE`, rendered in a visually distinct slot (the `gate_note` treatment), never in computed columns, never persisted to the ledger or projection — computed at render time or cached in a sidecar file, so I5 is untouched by construction.
5. **Prose guard:** the grep-based test pattern from `plain.test.ts` applied to drafting prompts' system instructions (the model is *instructed* not to state verdicts) **and** a structural test: advisory text renders only in advisory slots.

### Tests / exit criteria
- Vitest: port resolution/skip; deterministic plumbing (given a canned runtime response, byte-stable output); fold untouched by advisory presence (projection byte-identical with and without model).
- Smoke: with no runtime installed (CI reality), every surface degrades honestly — drafting affordance absent with reason, queue renders without advisories, doctor says why.
- A manual-run smoke (skipped when runtime absent) exercising a real local draft end-to-end.

**Size:** medium. **Risk:** runtime instability (contained to the adapter); CI has no model (designed for — absence is a first-class tested path).

---

## L5 — Narrative evidence tier

**Goal:** `automatable: "narrative"` recipes exist end-to-end: model drafts a narrative from signed facts → two-key human approval → the approved text becomes signed evidence. The compliance-market payoff; last because it needs a schema decision.

### Work items (design-first)
1. **Design record before code:** narrative evidence as a new predicate type (`https://rampscan.dev/narrative/v1`) vs. reuse of the scoping-event shape (text-as-subject). Leaning: new predicate joining the statement union (`scoping.ts:43-47`), because the fold must treat a narrative differently from a scope-out — but the two-key *flow* (proposals collection → approver key turn → ledger append → refold) is reused verbatim.
2. First narrative recipe(s) from the dataset's `narrative`-tier obligations; `plain` triple; fold + board render a narrative-evidenced state honestly distinct from machine-evidenced (the glossary gains the distinction).
3. Drafting context assembled only from signed facts (bundles, run records, contract) — the model paraphrases the ledger, and the human owns the result.
4. Cadence/MVX: narratives age like any bundle; the daemon's expiry warnings apply unchanged.

### Exit criteria
- Full loop on fixtures: draft → approve → signed narrative bundle → board row → `rampscan verify` passes offline on the narrative statement → rebuild byte-identical.
- A rejected draft never touches the ledger (the scoping-register precedent, re-pinned for narratives).

**Size:** large; do not start until L4's drafting loop has real usage. **Risk:** highest — this is where "computed, never typed" meets authored evidence; the mitigation is that the *human key turn*, not the model, is the recorded author, and the board state names the tier.

---

## Sequencing, dependencies, and what is deliberately out

```
L0 ─▶ L1 (contract + gate) ─▶ L2 (repo-model artifact) ─▶ L3 (MCP + check_diff)
                                                            │
                              L4 (model port + advisory) ◀──┘  (independent of L2/L3; needs only L0)
                                       │
                              L5 (narrative tier)
```

- L1 is pure product value with zero new trust assumptions — ship it even if everything after slips.
- L4 can start in parallel with L2/L3 if capacity exists; L5 must not.
- **Out of scope, on purpose:** multi-language extraction; graph navigation/visualization tooling; editable ontology UI; cloud model endpoints; any model output in the fold, the board's computed columns, or a signed bundle (except L5's human-approved text); competing with code-review-graph on the descriptive layer.

## Changelog

- 2026-08-15 — initial plan drawn from the brainstorm + the code-review-graph interop decision and the contract-first scope decision.
- 2026-08-15 — **L0 decision record.** All table defaults confirmed against the code as written; the two open deliverables resolved:
  - **KSI/control ids for the L1 recipes**, picked from pin `2026.07.14.01` and validated the way `validateRecipeIds` validates (every control reachable from the recipe's KSIs in the crosswalk):
    - `arch-route-auth-declared` → `ksi_ids: ["KSI-IAM-ELP"]` (Ensuring Least Privilege), `control_ids: ["ac-3", "cm-2.7"]` — ac-3 is the access-enforcement substance; cm-2.7 (baseline configuration for high-risk areas) is the declared-contract angle, and both are in KSI-IAM-ELP's control reach.
    - `arch-boundaries-hold` → `ksi_ids: ["KSI-CNA-DFP", "KSI-SVC-ACM"]` (Defining Functionality and Privileges; Automating Configuration Management), `control_ids: ["cm-2", "cm-6"]` — cm-2 (baseline configuration) is reachable from both KSIs, cm-6 (configuration settings) from KSI-SVC-ACM.
  - **Identity keying mechanics**: `ClaimBasis` gains an optional `contract_rules` field — the normalized (canonical-JSON) text of exactly the rules the gate evaluated for that recipe, per rule kind, so editing a boundary rule re-keys the boundary evidence and not the route evidence. It rides the basis, which `sameEvidence` already compares whole, so no identity-function change is needed; a pre-L1 contract bundle cannot exist, so nothing supersedes on landing.
  - Two L1 shape decisions taken here rather than mid-phase, both forced by reading the code the plan cites: (1) **no config at all → a collector-level skip** with a stated reason, because a skip reason is the one absence the run record can quote and K1's empty states already render it — config present but zero rules of a kind stays the plan's per-recipe no-observation; (2) **a declared rule that matches nothing in the graph is a violation, not a silent pass** — a typo'd route glob or module path must not waive the rule it mistyped, so each rule emits a matched/unmatched observation row and an assertion fails on `matched = false`.
- 2026-08-15 — **L1 landed.** Built as planned above, with four notes worth carrying into L2–L5:
  1. **The identity decision needed no new identity rule.** `contract_rules` rides `ClaimBasis`, which `sameEvidence` already compares whole — so the L0 keying decision cost zero changes to the identity function, and no bundle supersedes (no pre-L1 contract bundle can exist). Keeping the rules *per kind* is what earns it: the gate anchors the whole config file, so a shared blob would have re-keyed both recipes on any edit while telling neither which rules it was checked against.
  2. **The `description` verdict-ban is structural, not a CI grep.** K1's prose lives in this repository, so a test can police it; a contract description is authored by the repo being scanned, so the refusal has to live in the schema.
  3. **A mistyped rule fails three ways on purpose** — refuses to parse (unknown kind, misspelled field), or parses and then *violates* on `matched: false`. There is no path where a typo reads as a pass.
  4. **The console needed no new surface**, exactly as the plan predicted — but the basis panel did need to render the new field, because "the basis names the rule text" is an L1 exit criterion and an unrendered signed field is one an auditor cannot check.
- 2026-08-16 — **L2 landed.** Built as planned above, with five notes worth carrying into L3–L5:
  1. **The signature in work item 1 was wrong in a load-bearing way, and fixing it produced the phase's best property.** `buildRepoModel(projection, …)` cannot work: a `Projection` carries bundle *digests*, not predicates, and the two things this artifact most needs — the declared contract rules and the shape of the graph a gated verdict was walked over — live only inside the SIGNED `ClaimBasis`. So the function takes the ledger **entries** and folds them itself. Taking both an entries list and a projection would have let the two describe different ledgers; folding inside makes that unrepresentable.
  2. **The contract is read from the signed basis, never from `rampscan.config.json`** — which is the honest reading rather than merely a convenient one: the model states the contract the evidence was *checked against*, so a model built from today's file would describe a contract no verdict on the board ever saw. It also means `rampscan model` needs no checkout, only a ledger — the `rampscan tools` posture the plan asked for. Pinned by a test that rewrites the fixture's config *after* the scan and asserts the model's rule text does not move, and by a second test asserting the rendered declarations are byte-equal to the set of `contract_rules` strings in the ledger.
  3. **The artifact carries no clock, deliberately** — there is no `generated_at`, and the fold instant is taken from the ledger's own newest statement rather than `Date.now()`. That is what makes "same ledger → byte-identical bytes" true, and therefore what makes `rampscan model --json` reproduce the artifact a scan attested. The artifact is timeless; its *attestation* is dated, by the run record whose subject names it. Guarded by a grep of the serialized bytes for any ISO instant, so a future field that reads a clock breaks a test instead of quietly breaking reproducibility.
  4. **A REAL BUG THIS PHASE EXPOSED, in J4's resolver.** `resolveArtifact` classified a subject as a scoping `justification` whenever its statement was not an evidence bundle. That had never been wrong out loud because, before L2, every artifact was *also* some evidence bundle's subject — `repo-model.json` is the first artifact a **run record alone** attests, and under the old shortcut it refused to serve, with a sentence about a scoping event that does not exist. Subjects are now classified by STATEMENT KIND (scoping → justification, evidence + named in `anchor_paths` → anchor, otherwise artifact), which also corrects `scan-result.json`'s answer to the honest "not retained — no file of that name under the scan output dir".
  5. **No new console surface again**, and this time for a reason worth naming: the evidence page already renders every subject of every statement with the J4 viewer, so the model needed exactly one artifact *family*. The table shows nodes AND links — each link on the row of the node it leaves, with a `state` link carrying its verdict into the label — because a table of nodes alone would render half a model while looking like a whole one; and it computes **no coverage number**, because the board owns the counts and a second one here would be a different answer that merely looks like the same one.
  Scope guards held: node kinds closed at eight, link kinds closed at nine, `ksi-control` links restricted to controls the model already holds (a KSI reaches controls no recipe here touches, and pulling them in would grow the artifact without telling the reader anything about this world), and every link's endpoints are asserted to be nodes — a recipe naming an unregistered collector becomes a STATED problem rather than a dangling link.
