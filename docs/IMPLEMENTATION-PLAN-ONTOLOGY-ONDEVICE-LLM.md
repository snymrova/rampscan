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

## L3 — The pre-commit gate (revised 2026-08-16: L3a–L3c ship, L3d deferred)

> **Revision of record, taken before code.** The phase below was written as one item — an MCP server whose tool list happened to include a dry run. Read against what shipped, six of its seven tools are re-exports of things already readable (`get_contract` and `get_repo_model` are `rampscan model --json`; `get_board`/`get_violations` are the projection; `get_evidence` is the ledger; `explain_term` is `console/web/lib/glossary.ts`), and exactly one — `check_diff` — is a capability this system does not have. A protocol is not what that capability needs.
>
> So L3 splits, and the split is a build ORDER as much as a scope: with a JSON CLI first, an MCP server is a ~150-line adapter with no logic of its own; with MCP first, the CLI surface either duplicates the handlers or never exists.
>
> - **L3a — `rampscan check`**, the working-tree dry run. The whole of the new capability, serving three callers a protocol cannot: a human before committing, a git pre-commit hook, and a CI pull-request job. ✅ **landed 2026-08-16**
> - **L3b — dogfood the contract on rampscan's own repository.** Independent of any agent surface, and the item that tests whether L1's schema survives contact with a real monorepo. ✅ **landed 2026-08-16**
> - **L3c — `board --json`.** Whatever is readable should be scriptable. ✅ **landed 2026-08-16**
> - **L3d — `rampscan mcp`. DEFERRED**, not cancelled, and deferred on the plan's own two rules: L0 put the compliance operator first and agent tooling second, and the minimalism rule governs the first dependency of a phase — `@modelcontextprotocol/sdk` would be this engine's fourth external runtime dependency (after `zod`, `yaml`, `typescript`) and its first *wire protocol*, on a spec that revs several times a year, for a surface with no users yet. It also becomes a third copy of read logic beside the engine and `console/web/lib/`, which the twin-test rule then has to police. Un-defer when an external user asks — the same trigger the second language waits on.
>
> What is NOT deferred with it: the interop stance (no navigation tools) and the trust boundary (read-only, no signer) are decisions this revision keeps, because L3a inherits both — `check` opens the ledger read-only, constructs no signer, and adds no navigation surface.

### L3a — `rampscan check` (landed)

**Goal:** answer "would my change break the contract?" over the working tree, before anything is committed, and be structurally incapable of producing evidence while doing it.

- **Reuse, not a parallel pipeline.** The real `Runner`, the real collectors and the real `joinRecipeResults` — so a dry run and a scan cannot disagree about a recipe for any reason except the tree they read.
- **The tree is the one difference.** `Workspace` gains `tree?: "committed" | "worktree"`; the graph walk honours it (index + untracked-not-ignored, minus files deleted from disk). Every other caller stays committed-tree by default, and the field's doc comment says why: a signed claim is about a commit.
- **The gate set is COMPUTED from the manifests**, not listed: pure (`tools: []`) and fed only by other such collectors. Today that is `repo-facts`, `graph`, `contract` — and `repo-facts` falls out of the rule rather than being invited. The two pure-but-fed gates (`sast-reachability`, `no-critical-reachable-advisories`) are refused for a stated reason: their producer's artifact is from a different tree, and a fresh graph joined against a stale finding set answers about neither.
- **Not evidence, structurally.** No field named `verdict` anywhere (rows carry `wouldBe`), `dryRun: true` in the envelope, the scratch graph in a temp dir deleted in a `finally`, nothing appended, no artifact in `out/`.
- **Exit 1 on a would-be violation** — the one place in this CLI where a violation is a nonzero exit, and the difference from `scan` is deliberate: a scan RECORDS a fact, so a violation there is a result and not a failure, while `check` is a question the caller asked, so its exit code is the answer.

### L3d — MCP Agent Surface (`rampscan mcp`) — deferred, kept for when it is asked for

**Goal:** a local, read-only MCP server any coding agent can use to stay on contract — plus one dry-run tool, `check_diff`, that answers "would my working-tree change break the contract?" before a commit. Interop stance: **no navigation tools** (impact radius, semantic search — that's code-review-graph's job); rampscan serves what only rampscan knows: the contract, the signed state, and the dry-run.

*(Superseded in part by L3a: `check_diff` exists as `rampscan check`, so this phase is now an adapter over L3a–L3c rather than the home of any logic.)*

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

## L4 — ModelRunner port + two advisory uses (revised 2026-08-16: L4a–L4b ship, L4c deferred)

> **Revision of record, taken before code.** The question that produced this revision was whether L4 should be deferred wholesale on L3d's rules. It should not, but applying those rules honestly narrows it, and the narrowing is not where the question implied.
>
> L3d's deferral rested on three tests. L4 **passes** the re-export test — nothing in this system drafts prose today, so the port is genuine new capability rather than a wire protocol over existing reads. It **fails** the no-users test on the evidence: the live ledger holds ONE scoping event across 126 statements, so drafting scoping justifications automates a workflow that has fired approximately once. And it **inverts** the build-order test, which is decisive: L3d was a LEAF — nothing depended on MCP, so deferring it cost nothing downstream — while L4 is a TRUNK. `Automatable` already admits `"narrative"` (`packages/schema/src/recipe.ts:52`) and L5's entire loop is draft → human edit → two-key approval → signed. Deferring L4 does not postpone L5; it cancels it.
>
> - **L4a — the `ModelRunner` port + one reference adapter.** The interface, the resolution ladder, the honest-absence path, the doctor/`rampscan tools` row.
> - **L4b — use (b), scoping-justification drafting.** Kept *despite* the no-users test, for a reason that must be stated rather than dressed up as labor saved: the port needs one real consumer or it is an unvalidated interface, i.e. a guess — and this flow IS L5 in miniature (model drafts, human edits, key turn signs). It is built as L5's rehearsal, and the decision record says so.
> - **L4c — use (c), queue triage advisory. DEFERRED**, on this repository's own precedent rather than by analogy. `console/web/lib/queue.ts:190` already puts the recipe's authored `plain.fix` on every queue item, and that prose is specific ("Route the access through an allowed importer, move the offending code inside the boundary, or — if the design genuinely changed — widen the allow-list…"). A `PLAUSIBLE`-typed model paragraph answering "what to try" would render directly beside a deterministic, human-written answer to nearly the same question. L2 refused a second coverage number on exactly this ground — the board owns the counts, and a second one here would be a different answer that merely looks like the same one. Un-defer when a queue row exists whose authored `fix` is demonstrably not enough, which is a condition the queue itself can show.
>
> Deferring L4c also dissolves an open question rather than answering it: where a per-row advisory is computed and cached (render-time vs sidecar) only mattered for L4c, and I5 stays untouched by construction instead of by discipline.

### Work items
1. **Runtime evaluation (first item, timeboxed): ✅ done 2026-08-16 — Ollama is the reference adapter, needle is NOT A CANDIDATE, and the evaluation changed the port's signature.** Scored against the port contract: local resolve/version-report, offline inference, temperature-0 generation, pinned-weights support, uid-safe execution. Findings, all from running the thing rather than reading about it:
   - **`needle` is a MODEL, not a runtime — the plan carried a category error out of the brainstorm.** Cactus Compute's Needle is a 26M-parameter (Needle 2: 45M/14MB) specialist distilled for **function calling**, and its own documentation says you must bring your own inference runtime to ship it. It therefore cannot be a `ModelRunner` adapter — and it is wrong for L4b on the merits anyway, because a tool-calling specialist does not draft a scoping justification in operator English. "Should needle be deferred too?" resolves to *not applicable*, not *later*.
   - **Ollama is the reference adapter**, on this machine's evidence: `0.3.12` on PATH, daemon active on `127.0.0.1:11434`, sha256-addressed blob store, per-request `temperature`/`seed`, and nothing installed onto the host by rampscan. llama.cpp's `llama-server` stays possible through the port and has the *better pinning story* (a GGUF file the port can hash itself, no daemon) — it is simply not present here, and the port exists so that stays a swap rather than a rewrite.
   - **`resolve()` needs THREE states, not the plan's two.** This machine right now is the state the plan cannot express: runtime present, **zero weights pulled**. "No runtime" and "runtime but no pinned weights" are different operator fixes (install it vs pull the pin), so `absent{reason}` splits into `absent` and `unprovisioned`, and I15's stated skip says which.
   - **Resolution is an HTTP probe, not a PATH `which` — a real divergence from the `tools.ts` ladder the plan assumed.** The binary on PATH answers almost nothing: the thing that serves is a *daemon* that may be stopped, may run as another user, or may be remote via `OLLAMA_HOST`. `tools.ts`'s binary→Docker→skip order does not transfer; the model ladder is probe→pinned-weights-present→skip.
   - **The weights store is not readable by the calling uid**, which is a trust-boundary difference worth naming before L5: `/usr/share/ollama/.ollama/models` is owned `ollama:ollama` and the daemon runs as `User=ollama`. So the port **cannot verify a weights hash by reading bytes** — it asks the daemon what it is running and believes the answer. Docker pinning is enforced by Docker; this is a reported digest. Acceptable for L4's advisory path; **must be re-taken at L5**, where drafted text can survive into a signed subject (the D5 re-take, now with a second reason).
   - **The adapter must never call `/api/pull`.** Pulling weights is a network operation, so a port that fetches on demand would breach I8. Absent weights are a stated skip, never a download.
   - **D4 is vindicated by cause, not convenience.** Temperature 0 fixes only the token *selection rule*; it does not make the logits identical run to run. CPU inference is mostly deterministic with a fixed seed, GPU kernels reorder float ops and are not — and "mostly" is not byte-stable. So byte-stability tests drive the exported test double, exactly as locked, and no test asserts bytes out of a live runtime.
2. **Port** — `ModelRunner` beside the six ports in `packages/core/src/ports.ts`: `resolve() → ready | unprovisioned{reason} | absent{reason}` (three states — see the evaluation above; the plan's original two could not express "runtime up, no weights", which is this machine's actual state), `draft(task, context) → {text, model_id, weights_digest, costTokens}`. Adapter in a new `packages/model`. Resolution does **not** mirror `tools.ts:9-21`'s binary→Docker ladder: it is probe the daemon → pinned weights present → else honest skip, and the divergence is documented at the port because a reader who assumes the tool ladder will assume a `which` decides it. `weights_digest` is the digest the runtime **reports**, named so it cannot be mistaken for one rampscan verified. `pnpm doctor` reports the model row with the unprovisioned state distinct from absent — but **`rampscan tools` does NOT**, and the plan's "like any tool" was wrong twice: that command's own comment says it is a *pure derivation, nothing probed*, so a daemon probe would make its output depend on whether a process is up; and its map is recipe ↔ collector ↔ tool, in which the model has no row by construction because it answers no recipe and feeds no collector. Doctor probes and is the honest home. In doctor the states map 1:1 onto the port's — ready → `ok`, unprovisioned → `no-model`, absent → `absent` — and the middle one needed its own word because printing `absent` beside "0.3.12 running" would have the status column contradict the sentence next to it. The model row can never read `MISSING`, the word that counts toward doctor's failure total: a missing model changes nothing about a scan, and a doctor that exited nonzero over it would say otherwise.
3. **Use (b) — scoping-justification drafting.** In the console proposal drawer: "Draft with local model" fills the justification textarea from row context (recipe `plain`, empty-state reason, repo facts). The human edits; the approver's key turn signs — the signed subject remains the human-approved text (`core/src/scoping.ts:7-10` unchanged). Absent model → button absent with reason, not disabled mystery. Served via one new console API route that shells to the local runtime — the evidence path never touches it.
4. **Use (c) — queue triage advisory. DEFERRED** (see the revision above). Kept here for when it is asked for: an optional `advisory` field on queue items, model-drafted "what probably happened / what to try", typed `PLAUSIBLE`, rendered in a visually distinct slot (the `gate_note` treatment), never in computed columns, never persisted to the ledger or projection.
5. **Prose guard:** the grep-based test pattern from `plain.test.ts` (`packages/cli/test/plain.test.ts`) applied to drafting prompts' system instructions (the model is *instructed* not to state verdicts) **and** a structural test: drafted text reaches only the textarea a human edits, never a rendered surface of its own.

### Tests / exit criteria
- Vitest: port resolution/skip; deterministic plumbing (given a canned runtime response, byte-stable output) driven through the port's **exported test double**, not a mock invented in the test file — see D4; fold untouched by the model's existence (projection byte-identical with and without a runtime present).
- Smoke: with no runtime installed (CI reality), every surface degrades honestly — drafting affordance absent *with its reason*, doctor says why.
- A manual-run smoke (skipped when runtime absent) exercising a real local draft end-to-end.
- The ledger is byte-identical across a drafting session that ends in no approval, the scoping-register precedent re-pinned for drafts.

**Size:** medium, smaller after the L4c deferral. **Risk:** runtime instability (contained to the adapter); and the asymmetry named in D6 — CI never has a model, so the *absent* path is tested continuously while the *present* path is exercised only by the manual smoke. "Absence is a first-class tested path" is true and is not the same claim as presence being well tested.

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
L0 ─▶ L1 (contract + gate) ─▶ L2 (repo-model artifact) ─▶ L3a/b/c (check · dogfood · board --json)
                                                            │
                                                            ├─▶ L3d (MCP) — DEFERRED until asked
                                                            │
                          L4a (ModelRunner port) ◀──────────┘  (independent of L2/L3; needs only L0)
                                       │
                          L4b (draft a justification — L5's rehearsal)
                                       │        └──▶ L4c (queue advisory) — DEFERRED until a row shows the need
                                       ▼
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
- 2026-08-16 — **L3 revised, then L3a–L3c landed; L3d deferred.** The revision is recorded in §L3 above; these are the findings from building it, all of which came out of running the thing rather than reading the plan:
  1. **DOGFOODING THE CONTRACT CRASHED THE L1 GATE, and that is the whole value of L3b.** `arch-boundaries-hold` threw `Cannot read properties of null (reading 'startsWith')` on this repository: file nodes include PHANTOMS — an import the extractor cannot resolve to a walked file still gets a `file:` node, with no `path` — and the boundary walk read `path` unguarded. Neither fixture had an unresolvable import, so no test could have found it; the gate simply reported both contract recipes unevidenced with a stack trace for a reason. The fix reads `path ?? id`, and it is not a null guard for its own sake: this walk is OVER-approximate by declaration and its signed statement says unknowns count against the repo, so an import that NAMES the guarded module must count even when nobody can say which file it lands on. Dropping the row would have waived the rule on exactly the imports the graph understands least.
  2. **A BOUNDARY IN A MONOREPO NAMES THE PACKAGE, NOT ITS `src/`.** The first draft of this repo's own contract declared `module: "packages/signer/src"` and immediately flagged `packages/signer/test/signer.test.ts` — the module's OWN test — as an outside importer, because a package's tests live beside `src/` and not inside it. `module: "packages/signer"` with `allowedImporters: ["packages/cli"]` states the invariant that was actually meant: only the CLI holds a signing key, and no other surface imports the signer. L1's schema needed no change; the lesson belongs in the docs a customer reads.
  3. **NO ROUTE-AUTH RULE IN THIS REPO'S OWN CONTRACT, and the absence is a decision rather than an oversight.** rampscan's HTTP surface is the console's Next.js route handlers, which the extractor does not detect as route nodes (it detects express-style `app.get(…)`). L1 makes a rule that matches nothing VIOLATE — correctly — so declaring one here would buy a permanent red row that says nothing about this repository's architecture. `self-contract.test.ts` is where that is written down, next to the assertion that every declared module still exists (a stale rule parses fine and then violates, which would otherwise read as a code problem nobody can fix by editing code).
  4. **THE FIRST VERSION PUT OFFENDER POINTERS ON THE WRONG ROWS**, caught by reading real output rather than by a test: pointers were read from the collector's FINDINGS and grouped by collector, but the contract gate answers two recipes, so the boundary row showed the route-auth offender and vice versa. They now come off the failing ASSERTION (I2c's `offenders`), which is per-recipe by construction and is the same pointer the board and the queue render. A second reading found the neighbouring lie: "… and 1 more" printed over an EMPTY offender list, promising a pointer that was not being withheld but did not exist — a failing row with nothing to point at now says exactly that.
  5. **`check` EXITS NONZERO ON A VIOLATION AND `scan` DOES NOT**, deliberately: a scan records a fact, so a violation there is a true result and not a failure, while `check` is a question the caller asked before committing — its exit code IS the answer, which is what makes it usable as a pre-commit hook or a CI gate without parsing anything.
  6. **The two pure-but-fed gates are refused, not included.** Purity alone would admit `sast-reachability` and the advisory gate, and the plan even floated reusing an earlier run's semgrep output. Refused: the only such artifact available at dry-run time is from a DIFFERENT tree, and a fresh graph joined against a stale finding set answers about neither — the mixed-tree read that H6's false `not_affected` already cost once. The dry-run gate set is therefore computed from the manifests (pure, and fed only by other members), which also means `repo-facts` falls out of the rule rather than being invited — unpinning a CI action is exactly what a developer wants caught before the commit.
  7. **A dynamic import by computed path is invisible to this walk**, and the twin tests are why anyone noticed: `console-twins-stay-in-the-console` holds on this repo partly because the twin tests load the console's copy through `await import(pathString)` rather than a static import — a posture I3e adopted for an unrelated reason (a static import would emit compiled duplicates into `console/web/lib`). The boundary claim is honest about this already through its approximation statement and the graph shape it signs, but the limit is worth naming rather than discovering later: the over-approximate read is over the imports the extractor can SEE.
  8. vitest 601/601 (23 new: 19 in an L3a exit test over a real scanned world — the computed gate set and every refusal reason, the untracked breach the committed walk cannot see asserted against git's own `ls-tree`, the index-but-deleted file dropped, the worktree FIX flipping a row to would-pass while the signed board stays violated, the ledger byte-identical across a dry run, the scratch dir gone, and a walk of the serialized output proving no field named `verdict` exists; 1 phantom-import regression test in the L1 gate suite; 3 self-contract tests); smoke 17/17 cold, test 17 walking the whole line: `board --json` agreeing with the browser's board, the dry run over the committed tree exiting 1 with its refusals stated, then an untracked file planted mid-test whose breach the dry run names with the import path while the projection the console renders never mentions it, and the answer returning to the committed one when the plant is removed; root + console typecheck clean.
- 2026-08-16 — **L4 decision record, taken before code** (the L0 posture: resolve here, not mid-phase). The prompting question was whether L4 should be deferred wholesale the way L3d was. Applying L3d's own three rules rather than the analogy: L4 **passes** the re-export test, **fails** the no-users test, and **inverts** the build-order test — L3d was a leaf and L4 is a trunk, so deferring it cancels L5 rather than postponing it. The narrowing that follows is recorded in §L4 above; these are the decisions it locks.
  - **D1 — scope.** L4a (port + one reference adapter) and L4b (drafting a scoping justification) ship; **L4c (queue triage advisory) is deferred**, on this repository's own precedent rather than on taste: `console/web/lib/queue.ts:190` already puts the recipe's authored `plain.fix` on every queue item, so a `PLAUSIBLE`-typed model paragraph answering "what to try" would land beside a deterministic, human-written answer to nearly the same question — which is L2's refusal of a second coverage number, restated. Un-defer condition, stated so it is checkable: a queue row whose authored `fix` is demonstrably not enough.
  - **D2 — L4b is built as L5's rehearsal, and the record says so.** The live ledger holds ONE scoping event across 126 statements, so the honest justification for use (b) is NOT the typing it saves. It is that a port with no consumer is an unvalidated interface, and this flow is L5's loop in miniature — model drafts, human edits, key turn signs. Any later argument for L4b that leans on operator labor is arguing from a workflow that has fired approximately once.
  - **D3 — weights are pinned in their own `models.json`, not inside `tools.json`.** Same resolve-or-honestly-skip posture as `packages/collectors/tools.json`, and a separate file because a tool spec's `image`/`entrypoint` fields mean nothing for a weights blob; overloading the shape would make the manifest-vs-source drift test police a field that cannot drift while saying nothing about the one that can.
  - **D4 — the port exports its own test double.** "Deterministic plumbing given a canned runtime response" is an exit criterion, and CI has no model, so the canned response is the ONLY path CI ever walks. A mock invented inside a test file would make that path a property of the test rather than of the port; the double ships beside the adapter and is the thing the byte-stability test drives.
  - **D5 — the draft is not recorded, and no provenance note says a model touched it.** `toScopingEvent` (`packages/core/src/scoping.ts:22-49`) hashes the justification text as the statement's subject: the approver signs the reasoning, and the reasoning is whatever the human left in the textarea. A "drafted by model X" field would be a claim about text the human may have rewritten entirely — unverifiable by construction, and the ledger does not carry unverifiable claims. `scoping.ts` is unchanged by L4, exactly as the plan predicted. L5 is where this gets harder and the decision must be re-taken, not inherited: there the model's text may survive to become the signed subject.
  - **D6 — the runtime choice is a reference adapter, not a commitment.** L0 already decided the port is runtime-agnostic, so needle vs Ollama vs llama.cpp is cheap and reversible; the timebox picks whichever resolves offline with pinned weights most simply. What is NOT cheap and is named here rather than discovered later: CI will never have a model, so the absent path is tested continuously and the present path only by a manual smoke. "Absence is a first-class tested path" was true when the plan wrote it and is not the same claim as presence being well tested.
  - Dissolved rather than answered: where a per-row advisory is computed and cached (render-time vs sidecar) was an open L4 question that mattered only to L4c. With L4c deferred, I5 stays untouched by construction instead of by discipline.
- 2026-08-16 — **L4a work item 1 (runtime evaluation) done; recorded in §L4 above.** Two findings changed the plan rather than confirming it. **`needle` is not a runtime** — it is Cactus Compute's 26M-parameter function-calling model, which its own documentation says needs a separate inference runtime to ship, so it was never a `ModelRunner` candidate and is doubly wrong for L4b, where the task is drafting operator English and not calling a tool. The L0 table's "needle vs Ollama vs llama.cpp" compared a model against two runtimes; that line is a category error inherited from the brainstorm, and it is corrected here rather than carried. **Ollama is the reference adapter** on this machine's evidence (0.3.12, daemon active, sha256 blob store, per-request temperature/seed), with llama.cpp kept possible by the port and holding the better pinning story for whenever it is present. **The evaluation changed the port's signature**: `resolve()` needs three states because "runtime up, zero weights pulled" is this machine's literal state and is a different operator fix from "no runtime"; resolution is an HTTP probe rather than the `tools.ts` PATH→Docker ladder, because the daemon may be stopped, owned by another user, or remote; and the weights store is unreadable by the calling uid, so the port reports the digest the runtime claims instead of one it verified — tolerable while drafts are advisory, and the second reason D5's decision must be re-taken at L5. Determinism research supplied a cause for D4 rather than a convenience: temperature 0 fixes the selection rule, not the logits, so no test asserts bytes out of a live runtime.
- 2026-08-16 — **L4a and L4b landed** (L4c stays deferred). Built as revised above, with six notes worth carrying into L5:
  1. **The three-state resolution earned itself on the first real probe, not in a test.** Run against this machine's live daemon the adapter returns `unprovisioned` with `runtimeVersion: "0.3.12"` and "`ollama pull llama3.2:3b` provisions it". Under the plan's original `available|absent{reason}` that machine would have reported ABSENT and sent its operator to install software already running. Two absences, because the fix differs.
  2. **The plan's "`pnpm doctor` and `rampscan tools` report the model row like any tool" was wrong about half of it.** `rampscan tools` says in its own comment that it is a pure derivation, nothing probed — and its map is recipe ↔ collector ↔ tool, in which a drafting model has no row *by construction*, because it answers no recipe and feeds no collector. The absence of a `tools` row is the correct output, not a gap. Doctor probes and is the honest home; its status words map 1:1 onto the port's, and `unprovisioned` needed its own word (`no-model`) because the first version printed "absent" beside "0.3.12 running" — a status column contradicting the sentence next to it.
  3. **The manifest pins a `name:tag`, not a content hash — which corrects L0's own table against what `tools.json` actually does.** That file pins image *tags* and its comment calls digests appliance-level hardening. Here a digest pin would be closer to theatre: the daemon's blob store is owned by its service user and unreadable by the calling uid, so rampscan RELAYS the digest the runtime reports. Hence `weightsDigest` and not `weights_sha256`, with a test asserting the second name is absent. **This is the second reason D5 must be re-taken at L5**, and the sharper one: at L5 an unverifiable weights claim would sit behind text that became a signed subject.
  4. **I4/I5 are asserted structurally instead of promised.** The exit criterion asked for a projection byte-identical with and without a runtime; a package that cannot IMPORT the model cannot vary with it, which is stronger and cheaper. A test walks eight packages' sources for `@rampscan/model`, asserts core declares the port but imports no adapter, asserts the CLI does not draft at all, and asserts EXACTLY ONE console route reaches the model by path — so a second door is a failing test and a conversation.
  5. **A model that is not ready produces no button, only its reason.** The affordance fetches resolution on mount and renders either the control or the sentence, never a greyed-out promise; the POST re-checks resolution rather than trusting the GET, because a daemon can stop between page load and click. The route reads no repo, no ledger and no network — context comes from the client, which sends only catalog and board facts, so what a draft can be about stays auditable at the call site.
  6. **K1's fixture fact resurfaced from the other side, in the smoke.** `propose N/A` renders only on an *unevidenced* row, and `vulnerable-app` is fully tooled — so the drafting smoke had to run against `bare-app`, the same collision K1 hit when its exit test needed an empty row and the flagship fixture had none. Worth stating as a standing property of the fixture pair rather than rediscovering a third time: **anything reachable only from an empty row is testable only on `bare-app`.**
  7. vitest 629/629 (28 new in `packages/model`: 11 evidence-path guards, 13 port/prompt/double tests including the real adapter returning absent rather than throwing against a port nothing listens on, 4 doctor-row tests); smoke 18/18 cold (9.4m), test 18 walking the honest-degradation path on `bare-app`; root + console typecheck clean, the root build catching a `costTokens: undefined` that the tests let through (exactOptionalPropertyTypes — fixed by omitting the key, because "reported no count" and "reported zero" are different facts).
