# PM Brainstorm — Way Ahead: Repo Ontologies & On-Device LLM

*Written 2026-08-15. Grounded in the code only (packages/, console/web/, fixtures/, e2e/) — no prior docs consulted. Every claim about the current product cites a source file.*

---

## 1. Where the product actually stands (read off the code)

One sentence: **rampscan scans a git checkout with pinned tools, joins results against a catalog of FedRAMP-mapped recipes, signs every verdict as DSSE/in-toto evidence into an append-only content-addressed ledger, and folds that ledger into a coverage board, control register, clock, drift view, and provenance chain in a local console.**

What matters for this brainstorm is not the feature list but the **invariants the code enforces**, because any new direction lives or dies by whether it respects them:

| # | Invariant (enforced, not documented) | Where |
|---|---|---|
| I1 | Verdicts, states, counts are **computed, never typed**. The only authored prose (recipe `plain`, glossary) is structurally barred from claiming anything about a repo. | `packages/schema/src/recipe.ts:61-73`, `console/web/lib/glossary.ts:5-16` |
| I2 | The ledger is the record; every store is disposable. `rampscan rebuild` *proves* fold ≡ read-back by byte equality. | `packages/cli/src/rebuild.ts:44-46` |
| I4 | The fold is pure: same ledger + same asOf → same projection. No wall clock. | `packages/projector/src/fold.ts:107-111` |
| I7 | `not_affected` must carry its ground: over-approximate walks for waivers, under-approximate for positive claims; unknowns count *against* the repo. The `ClaimBasis` is signed into evidence identity. | `packages/core/src/bundle.ts:96-113`, `packages/graph/src/query.ts:11-18` |
| I8 | Local-first, offline-first. No network in the evidence path, no telemetry, tools pinned or honestly skipped. | `packages/collectors/src/tools.ts:9-21`, `semgrep.ts:137`, `checkov.ts:128-132` |
| I15 | Absence is reported with a reason, never swallowed. | run records, empty states, provenance hop reasons |

And one **load-bearing discovery**: the schema already reserved seats for a model tier, and nothing sits in them:

- `packages/schema/src/finding.ts:3-5` — "Every collector — a file check, a wrapped scanner, **later a model** — emits this shape."
- `finding.ts:32` — `verdict: CONFIRMED | PLAUSIBLE` marked *"tier 3 only; absent = deterministic"*
- `finding.ts:30` — `confidence: 0..1` (*"tier 1 is 1.0 and says so"*)
- `finding.ts:45` — `provenance.costTokens?`
- `recipe.ts` — `automatable: full | partial | narrative` — the `narrative` tier has **zero recipes** in `recipes/pipeline/` today; every shipped recipe is machine-checkable. The entire narrative half of the compliance surface is unaddressed.

So both user-suggested directions — ontology and on-device LLM — are not pivots. **The architecture pre-committed to both and then stopped at the door.**

---

## 2. The ontology question: "can rampscan create ontologies for repos?"

### 2.1 Short answer: it already builds ~70% of one. It just doesn't call it that, and doesn't serve it to anyone.

Palantir's ontology model is **object types + link types + action types**, versioned, permissioned, queryable, and used as the shared semantic layer that both humans and agents operate through. Map that onto what the code already produces:

| Ontology concept | rampscan already has | Where |
|---|---|---|
| Object types | files, symbols, dependencies, routes (`nodes.kind`), plus recipes, KSIs, controls, tools, collectors, artifacts, bundles, runs, repos | `packages/graph/src/db.ts:26-97`, catalog, crosswalk |
| Link types | `imports/declares/exports/calls/handles` edges with `exact|inferred` resolution; recipe↔KSI↔control crosswalk; recipe↔collector↔tool↔artifact provenance chain; `consumes` between collectors | `db.ts`, `packages/dataset/src/client.ts`, `console/web/lib/provenance.ts`, `packages/cli/src/tools.ts:85-182` |
| Actions (governed writes) | the two-key scoping flow: propose → approver's key turn → signed event appended to the ledger | `console/web/app/api/scoping/decide/route.ts:5-10` |
| Versioning | commit-anchored, content-addressed, dataset pinned, `GRAPH_VERSION` stamped | `packages/graph/src/index.ts:13-18` |
| Provenance on every assertion | DSSE-signed in-toto statements; `ClaimBasis` carrying entry-point provenance and graph shape | `packages/schema/src/bundle.ts:81-114` |
| Honest uncertainty | `inferred` edges counted, `entrypoints_unresolved` travel with the graph, `degraded` flag | `db.ts:16-22`, `query.ts:256-265` |

What's **missing** to call it an ontology rather than an internal artifact:

1. **It's siloed per concern.** `graph.db` (code structure), the catalog (compliance semantics), the crosswalk (framework semantics), the tool map, and the provenance chain are five separate structures joined ad hoc in the fold and the console. There is no single queryable "this repo, as objects and links."
2. **It's not consumable by anything outside rampscan.** `graph.db` is explicitly a binary artifact the browser can't parse (that's *why* ClaimBasis is signed, `bundle.ts:69-79`). No export format, no query API, no serving surface.
3. **It's TS/JS only** (`packages/graph/` uses the TypeScript compiler API; prototype scope stated in the code).
4. **It has no "intent" layer.** The graph knows what the code *is*; nothing records what the code is *supposed to be* — which routes must stay authed, which modules may not import which, which dependencies are sanctioned. Today the closest thing is `rampscan.config.json` (`graph.entrypoints`, `graph.authPatterns`) — a two-field embryo of exactly this.

### 2.2 The reframe that makes this a product, not a feature

The user's actual pain — *"keep up with AI coding agents, keep them on track"* — is the market's pain too. Coding agents today operate on raw text + grep. They hallucinate architecture, violate invariants nobody wrote down, and nobody can prove after the fact what they changed semantically.

rampscan's unfair advantage is not "we can build a graph" (many can: LSP, tree-sitter, Sourcegraph, Glean). It is:

> **rampscan is the only tool whose graph is signed, commit-anchored, honest about its own approximations, and already wired to a verdict/attestation pipeline.**

So the pitch is not "rampscan generates an ontology." It is:

> **The Repo Ontology is the signed contract between a codebase and the agents that work on it.** Agents read it to stay on track; rampscan re-extracts it after every change and *attests* whether the contract still holds — using the exact machinery (recipes, assertions, bundles, board, drift, provenance) that already exists.

This turns "keeping agents on track" into a fourth register state story the product already knows how to tell: an agent that broke an invariant produces a **violated** row with an offender pointer and a call path, exactly like the `eval()` reachability row does today.

### 2.3 Concrete shape — three layers

**Layer A — Descriptive ontology (extract & unify).** New artifact: `ontology.json` (or a served, queryable SQLite) that unifies what already exists:
- objects: routes, symbols, deps, files, entry points, recipes, controls, KSIs, tools, artifacts, bundles
- links: the existing edge kinds + provenance + crosswalk
- every object carries its provenance (which collector, which run, which commit) — the fold already knows all of this
- **format thought**: JSON-LD or a simple typed-node/typed-edge JSON keeps it framework-neutral; the schema lives in `packages/schema` like everything else; canonical-JSON hashing gives it a digest → it can be a **subject of a signed bundle** for free. The ontology becomes evidence.

**Layer B — Normative ontology (the contract).** Extend `rampscan.config.json` from `{entrypoints, authPatterns}` into a declared-intent file — effectively **architecture recipes**:
- `"every route under /admin/* must reach an auth symbol"` (route-auth-coverage already computes this; today the pattern is a heuristic default `["auth"]` — promote it to declared intent)
- `"module src/billing may only be imported by src/api"` (layering / boundary rules — a new pure gate over existing `imports` edges)
- `"no new dependency without a lockfile pin"` (repo-facts already adjacent)
- `"these symbols are the public surface; everything else is internal"`
- Each declared rule is checked by a **pure gate collector** (the `reachability` / `sast-reachability` pattern: consumes `graph.db`, spawns nothing, emits observations + ClaimBasis). Each becomes a recipe with assertions → a board row → signed evidence. **Zero new verdict machinery.** The contract violations get plain-language, provenance chains, queue entries, drift tracking — all inherited.

**Layer C — Agent surface (serve it).** An **MCP server** (`rampscan mcp` or part of `serve`) exposing read-only tools to any coding agent (Claude Code, Cursor, etc.):
- `get_ontology` / `query_graph` (routes, reachability, who-imports-whom)
- `get_contract` (the normative rules, with plain-language)
- `get_board` / `get_violations` (current signed state)
- `check_diff` (pre-commit: "here's my staged change — which contract rules would it break?") — this is the killer tool: the agent asks *before* committing, rampscan re-extracts the graph on the working tree and runs the pure gates. Fast, offline, deterministic.
- Trust boundary is clean: MCP surface is **read-only + dry-run-check only**, mirroring the console's posture (read everything, write nothing but proposals). An agent can never append to the ledger; only a real scan does.

### 2.4 Why this respects the invariants

- I1: contract rules are authored *intent*, but whether they **hold** is computed by gates. Same split as recipes/assertions today.
- I7: boundary/layering gates over-approximate (any edge kind) when waiving, exactly like SAST reachability.
- I8: everything local. An agent talking to local MCP adds no network to the evidence path.
- I14: the ontology is commit-anchored; agent-induced drift is just anchor drift, already computed.

### 2.5 What NOT to build

- **Not a general knowledge graph platform.** Palantir's ontology spans an enterprise; ours spans one repo × one compliance surface. Stay narrow: objects that gates can check.
- **Not editable ontology UI.** The contract is a file in the repo (reviewable, diffable, ownable by CODEOWNERS — which repo-facts already checks). No CRUD screens.
- **Not multi-language yet.** Prove the loop on TS/JS where the extractor exists; a second language (Python, via tree-sitter) is a fast-follow only after the agent surface has a user.

---

## 3. The on-device LLM question (cactus-compute/needle and friends)

### 3.1 Where a model must NOT go

The product's entire identity is I1: *computed, never typed*. A model that emits verdicts, or prose that claims facts about a repo, would dissolve the one property that differentiates rampscan from a screenshot folder. Also I4: the fold must stay deterministic — no model output may enter the fold.

So: **no LLM in the verdict path, no LLM output signed as evidence, no LLM text on the board's state columns. Ever.**

### 3.2 Where a model fits — and the schema already says so

The `Finding` schema drew the line years-in-code-time ago: `verdict: CONFIRMED | PLAUSIBLE`, `confidence < 1.0`, `provenance.costTokens` (`finding.ts:30-45`). The design is visibly: **tier 1 = deterministic (all of today), tier 3 = model-assisted, and model output is always labeled PLAUSIBLE until a deterministic check confirms it.** An on-device model (needle-style llama.cpp wrappers, Ollama, etc.) is the *only* kind that fits, because I8 forbids shipping repo contents to a cloud API from the evidence path. This is a genuine positioning win: **"the compliance scanner whose AI never phones home"** — the same sentence structure as `semgrep --metrics=off`.

Ranked candidate uses, most- to least-aligned:

**(a) The `narrative` recipe tier — the biggest hole in the product.** `automatable: narrative` exists in the schema with zero implementations. Real FedRAMP evidence includes policies, SSP narratives, justifications — things no scanner can check. A local model can **draft** a narrative from the signed facts ("this repo evidences KSI-X via recipes A, B; here is the residual gap...") into a *proposal* object. A human approves; the approved text is what gets signed — reusing the **two-key scoping flow verbatim** (`core/src/scoping.ts:7-10`: the justification text itself is the signed subject). The model drafts; the human's key turn is the fact. No invariant bends.

**(b) Scoping-justification drafting.** Same mechanism, smaller scope: when an operator proposes `notApplicable`, the model drafts the justification from the row's context (recipe plain-language, repo facts, empty-state reason). Approver still turns the key.

**(c) Triage/explanation on the queue.** The queue ranks actionable items; a model can attach "what probably happened and what to try" to a *skip* or a *violation* — clearly typed as `PLAUSIBLE`, rendered in a visually distinct advisory slot (like `gate_note`), never in the computed columns. Cheap, high daily value.

**(d) Natural-language query over the projection.** "Which controls regressed since the baseline?" → model translates to fold/diff queries, **answers are the computed rows themselves**, model only routes. Read-only, safe, demo-friendly.

**(e) Tier-3 confirm loop for `unknown` gate rows.** Today an `unknown` in the SAST gate (file not in graph) counts against the repo (I7, correctly). A model could *propose* "this hit is in dead template code" — but confirmation must come from a deterministic re-check (e.g., the human adds the file to entry-point config, or a gate re-runs). Model narrows the search; determinism closes it. This is the `PLAUSIBLE → CONFIRMED` promotion path the schema sketches.

**(f) Ontology enrichment (bridge to §2).** Descriptive graph edges are `exact|inferred`; a model could propose semantic labels ("this symbol is an auth middleware", "this module is billing") that flow into the **normative** layer only as *suggested* contract rules a human commits to the config file. The model suggests intent; the file in git *is* the intent.

### 3.3 Engineering shape

- A **model runtime port** beside the six existing ports (`ports.ts:16-18`): `ModelRunner` with resolve-or-honest-skip semantics identical to tools (`tools.ts:9-21`): local runtime present (needle/Ollama/llama.cpp binary on PATH, or a pinned container) → use it; absent → skip with reason, surface in `rampscan tools` / doctor. **The model is a tool**: pinned (model file hash in `tools.json`-style manifest), version-recorded in run records, argv/prompt-redaction rules apply, `costTokens` recorded. Deterministic-ish: temperature 0, pinned weights, and even then output is *never* identity-keyed.
- Model outputs live in **`proposals`-like collections or advisory fields**, never in bundles — except path (a)/(b) where the *human-approved text* is signed, which is already how scoping works.
- Choose runtime pragmatically: the specific repo (cactus-compute/needle) is one option; the port should be runtime-agnostic (needle, Ollama, llama.cpp server) exactly as collectors are binary-or-image agnostic. Don't marry a runtime; marry the port.

---

## 4. How the two tracks compound

The sleeper insight: **the ontology is what makes a small on-device model good enough.** A 3–8B local model free-reading a repo will hallucinate. The same model handed the ontology — typed objects, signed facts, plain-language definitions from the glossary, the contract rules — is doing constrained retrieval + phrasing, which small models do well. And in the other direction, the LLM makes the ontology **legible**: contract rules get drafted plain-language (then human-audited, same as `plain` today), violations get explanations.

And for the agent-guardrails story, the loop closes:

```
coding agent ──reads──▶ ontology + contract (MCP, read-only)
      │                          ▲
   edits code                    │ signed, commit-anchored
      ▼                          │
 rampscan re-extracts ──gates──▶ board row (violated? drift?)
      ▼
 queue + on-device model explains ──▶ human (or the agent) fixes
```

Every arrow except the model's is deterministic and attested. That is a story no agent-observability startup can tell, because none of them own a signed ledger.

---

## 5. Proposed roadmap (phases, in order)

**Phase L1 — Unify & export the descriptive ontology.** `rampscan ontology` command: fold graph.db + catalog + crosswalk + tool map + provenance into one typed, canonical-JSON, digestable `ontology.json`. Sign it as a bundle subject. Console gets a read surface (even just the evidence-page treatment). *Small; mostly plumbing over existing structures. Proves the noun exists.*

**Phase L2 — The contract + gate collectors.** Extend `rampscan.config.json` to declared intent (start with exactly two rule kinds: route-auth intent — promoting the existing heuristic — and module boundary rules). One new pure gate collector, N contract recipes with `plain`, fixtures: teach `vulnerable-app` a boundary violation; `bare-app` stays honestly contract-less. *This is where the board learns to say "an agent broke the architecture."*

**Phase L3 — MCP agent surface.** Read-only MCP server over projection + ontology + contract, plus `check_diff` dry-run. Dogfood it: point Claude Code at rampscan's own repo with rampscan's own contract. *This is the demo that sells the whole direction.*

**Phase L4 — On-device model port + first two uses.** `ModelRunner` port with skip-honesty; ship (b) scoping-justification drafting and (c) queue triage, both clearly advisory. *Smallest invariant-safe LLM footprint with daily value.*

**Phase L5 — Narrative tier.** `automatable: narrative` recipes end-to-end: model drafts → two-key approval → signed narrative evidence. *The compliance-market payoff; also the hardest to get right — last for a reason.*

Sequencing logic: L1→L2 make the product better with **zero** new trust assumptions; L3 monetizes the moment (agents need ground truth *now*); L4–L5 add the model only after there is a signed substrate for it to stand on.

## 6. Open questions to decide before L1

1. **Who is the buyer for the agent story** — the compliance operator (current persona) or the engineering lead running agent fleets? They meet at the same board, but the queue and plain-language would be tuned differently.
2. **Ontology stability vs. identity**: is `ontology.json` part of evidence identity (re-keying bundles when the graph changes shape) or advisory like `offenders`? Precedent cuts both ways (ClaimBasis is keyed; offenders are not). Leaning: the *contract* is keyed, the *descriptive graph digest* is not.
3. **Second language**: which one earns Python-via-tree-sitter — customer demand or fixture realism?
4. **Model distribution**: pin a specific small model hash for reproducible drafting, or accept whatever local runtime serves? (Pinning fits the product's soul; it also raises the setup bar. Doctor-style honesty can bridge: "model absent → drafting unavailable, reason stated.")
5. **needle specifically**: evaluate it against Ollama/llama.cpp on the actual port contract (resolve, version-report, offline, deterministic-ish generation) before committing; the port design makes this a swappable decision.
