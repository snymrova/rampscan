# The Code-Graph Harness — a brainstorm

**Status:** brainstorm, not committed work. No decision taken, nothing scheduled.
**Date:** 2026-08-12
**Reads against:** the eleven primitives (`src/lib/pillars.ts`), the Teardowns register, `docs/DOMAIN-HARNESSES.md` (§5.6 three-tier oracle, §5.2 two-key write), and the React Flow infrastructure already in `src/components/diagrams/flow/`.

---

## 1. The idea in one paragraph

A harness whose *product* is verification. Not "run the tests" as a step near the end, but a fleet of analyzers — each testing the code for a different variable — all writing their findings onto **one shared graph of the codebase**, which is simultaneously the context an agent reads, the ledger a human inspects, and the picture on the screen. One topology, many readings. The graph is the argument.

The claim worth testing: **most verification tooling is a set of silos with a dashboard each — types here, coverage there, bundle size somewhere else, security in a PDF — and the silo boundary is exactly where the useful questions live.** "Which untested symbol did this diff reach, and does anything downstream of it ship to the client bundle?" needs four silos to answer and no tool asks it, because no tool holds one model of the code that all four wrote to.

---

## 2. Why this is a harness problem and not a linter problem

Walk it down the eleven slots and it becomes obvious this is a harness, not a tool:

| Primitive | What it is here |
|---|---|
| **Instructions** | What "good" means in *this* repo — the thresholds, the exempt paths, the house rules that make a finding a finding. |
| **Context Delivery** | The graph query beats grep. `reaches(diff)` hands the model the actual blast radius instead of the top 20 fuzzy matches. |
| **Context Management** | Findings are ranked and budgeted into the window. 400 findings is not context, it is noise with line numbers. |
| **Tool Interfaces** | Every analyzer is a tool with one schema in and one finding schema out. That uniformity *is* the architecture. |
| **Execution Environment** | Analysis runs on untrusted code. Building a repo to get bundle stats executes its build scripts — this is a sandbox problem, immediately. |
| **Durable State** | The graph, the findings ledger, the baselines. Survives the run; that's what makes drift visible. |
| **Orchestration** | Fan-out across analyzers, incremental re-analysis, cache invalidation, the fix loop with its gate. |
| **Sub-agents** | One per variable, plus adversarial verifiers whose only job is to refute findings. |
| **Skills** | "How we investigate a flaky test." "How we retire a dead export." Named procedures per finding class. |
| **Verification** | The recursive part: the harness must verify *itself* — false-positive rate is its own metric. |
| **Evolution** | A confirmed finding becomes a rule. A false positive becomes a suppression with a stated reason. The board gets sharper without the model changing. |

That table is also the argument for building it: it is the site's own thesis applied to a real system, and every slot has a non-obvious answer.

---

## 3. The graph

### 3.1 What's a node

Not files. Files are too coarse to hang a finding on and too fine to draw. The useful grain is **the symbol**, with files and packages as containers you can zoom out to.

```
node  = { id, kind, name, path, span, contentHash, container }
kind  ∈ package | module | symbol | route | test | asset | dependency | config
```

`contentHash` is doing quiet, load-bearing work: it is what lets a finding survive a reformat, follow a rename, and **die honestly** when the code it described is genuinely gone. Anchor drift is why static-analysis dashboards rot into noise within two quarters — the findings outlive the code they were about, and nobody can tell which ones still mean anything.

### 3.2 What's an edge — and where each one comes from

Edges are the whole value, and they come from different extractors with very different reliability:

| Edge | Source | Reliability |
|---|---|---|
| `imports`, `exports` | AST (tree-sitter / TS compiler API) | exact |
| `calls`, `references` | type-resolved symbol index (SCIP-shaped) | exact for typed code |
| `covers` (test → symbol) | coverage trace from a test run | exact, but only for code the tests reached |
| `renders`, `serves` (route → module) | build graph / router manifest | exact |
| `bundles` (chunk → module, with bytes) | bundler stats | exact |
| `depends` (module → package) | lockfile + resolution | exact |
| `co-changes` (symbol ↔ symbol) | git history | statistical, and often the most interesting edge on the board |
| `owns` (person/team → path) | CODEOWNERS + blame | social, not technical |
| `dispatches` (dynamic) | runtime trace or model inference | **unreliable — must be marked as such** |

The last row is the honest one and should be visible in the UI, not hidden. A graph that silently mixes a resolved call edge with a guessed one is lying at exactly the moment you most need it to be careful.

### 3.3 Incremental by construction

Full re-analysis per commit is a non-starter above toy size. The design is: content-hash every node, cache each analyzer's output keyed by `(analyzer version, node hash, config hash)`, and on a new commit re-run only the **dirty set** — changed nodes plus their blast radius, at a depth each analyzer declares for itself (a type check needs dependents; a complexity metric needs nothing but the node).

The trap to write down now: **an incremental cache is a durable-state problem wearing a performance costume.** A stale cache produces a green board for broken code, which is worse than no board. Non-negotiable: analyzer version participates in the key, and there is a cheap full re-run on a schedule that diffs against the incremental result. The harness verifies its own cache.

---

## 4. The variables

The "various variables" the code gets tested for. Sorted the only way that matters — by **strength of oracle**, cheapest and most certain first. This is `DOMAIN-HARNESSES.md` §5.6 applied to code.

### Tier 1 — deterministic. No model. Exact answers, cheap, run always.

- **Type errors, unresolved references** — the compiler, wired in as a continuous signal (OpenCode's LSP-fleet move).
- **Dead code** — exports nobody imports, unreachable branches, orphan files, unused deps.
- **Cycles** — import cycles, package-level dependency cycles.
- **Coverage per symbol** — not the repo percentage, which is a vanity number. The useful artifact is the set of symbols with **zero covering tests**.
- **Complexity** — cyclomatic, cognitive, nesting depth, fan-in/fan-out, file length.
- **Churn** — commits touching this symbol over time, number of distinct authors.
- **Hotspot = churn × complexity** — the oldest and best composite metric in this space. High-churn, high-complexity, low-coverage is the definition of where the next incident comes from, and it needs three silos to compute.
- **Bundle bytes per module, and the delta vs baseline** — plus which route pulls it in.
- **Public API surface diff** — did this change break semver, on a package that claims not to?
- **Dependency health** — advisories, licence conflicts, version drift, unmaintained packages, duplicate versions of the same lib.
- **Secrets and entropy scan.**
- **Schema and migration compatibility** — is the migration backward-compatible with the code still running in production?
- **Accessibility and performance budgets** on rendered routes — this repo's own constraint (`prefers-reduced-motion`, diagram legibility) is exactly the kind of house rule that belongs in tier 1 rather than in a reviewer's memory.

### Tier 2 — generated and property-based. Semi-exact. Run on the dirty set.

- **Mutation testing.** The highest-value variable on this entire list and the one almost nobody runs. Coverage says a line executed; mutation testing says whether the test would have *noticed* if the line were wrong. It converts "92% covered" into "41% of introduced faults were caught," which is the number people think coverage already means.
- **Property-based tests / fuzzing** on pure functions, with a shrunk counterexample as the finding's evidence.
- **Differential testing** — old implementation vs new, same inputs, on a refactor that claims to change nothing.
- **Contract tests** replayed against recorded traffic.
- **Visual and snapshot diffs** for rendered output.

Tier 2 is where a verification harness earns its keep, because these are the checks teams skip for want of orchestration — they are slow, they need isolation, and they need somewhere to put the result. That is a harness's three jobs.

### Tier 3 — model-judged. Expensive, fuzzy, **must be adversarially verified before display.**

- Correctness against stated intent (the diff vs the ticket vs the doc).
- Logic-level security: the authorisation check that types cannot see, the second refund that is type-valid and business-invalid.
- Concurrency and ordering reasoning.
- Domain-rule violations — the **ontology gate**, checked against a formal model of the domain rather than an English rule in a prompt.
- Simplification, reuse, altitude — the taste tier.

**The design rule for tier 3:** a model finding is a *hypothesis*, and it does not reach the board until independent verifiers have tried to refute it and failed. Show `CONFIRMED` and `PLAUSIBLE` differently, and never mix a plausible tier-3 opinion into the same visual register as a type error. The moment the board's tier-1 credibility is spent on tier-3 guesses, the whole product is a dashboard nobody opens.

---

## 5. One finding schema, or none of this works

Every analyzer — a regex, a compiler, a fuzzer, a model — emits the same shape. This interface is the actual architecture; everything else is plumbing.

```ts
interface Finding {
  id: string;                 // stable across runs: hash(anchor + variable + signature)
  variable: string;           // "coverage" | "mutation" | "bundle-size" | "logic-security" | ...
  anchor: {
    node: string;             // graph node id
    span?: [number, number];  // line range
    contentHash: string;      // what it was about, so drift is detectable
  };
  severity: "blocker" | "high" | "medium" | "low" | "info";
  confidence: number;         // 0..1 — tier 1 is 1.0 and says so
  verdict?: "CONFIRMED" | "PLAUSIBLE";   // tier 3 only; absent means deterministic
  summary: string;            // one sentence, the defect itself
  failureScenario: string;    // concrete inputs/state → wrong output. No scenario, no finding.
  evidence: Evidence[];       // command + exit code + output, counterexample, trace, screenshot
  reproduce: string;          // the exact command a human can paste
  fix?: { patch: string; verifiedBy: string[] };
  provenance: { analyzer: string; version: string; runId: string; costTokens?: number };
  lifecycle: "new" | "persisting" | "fixed" | "suppressed";
  suppression?: { reason: string; by: string; until?: string };  // never a bare ignore
}
```

Three deliberate choices in there:

1. **`failureScenario` is required.** A finding that cannot say what breaks and when is an opinion. This single field kills most of what makes review tools tiresome.
2. **Suppression requires a reason and optionally an expiry.** A bare ignore is how a board becomes decorative. An expiring suppression is how it stays alive.
3. **`provenance.costTokens`** — because tier 3 has a bill, and the harness should be able to show which variables are worth their cost.

---

## 6. The UI — one graph, many overlays

The part the question was really about. The infrastructure is already here: `@xyflow/react` 12, `ArchCanvas`, four-sided handles in `nodes.tsx`, `InspectorPanel`, `MapShell`, nested drawings, deep-link-by-`#part=<id>`. What follows is that machinery pointed at a codebase instead of an architecture diagram.

### 6.1 Semantic zoom, or the picture is decoration

Non-negotiable at scale. A 4,000-node force-directed hairball is the genre's signature failure: it looks like intelligence and answers nothing.

```
repo  →  package  →  module  →  symbol
```

Each level is its own layout, and edges **aggregate** on the way up (47 symbol-level calls between two packages become one edge with weight 47, and its thickness is the weight). Zooming past a threshold expands a container in place rather than replacing the view, so context is never lost — the same move `nested.ts` already makes for drawings-inside-drawings.

This repo's own hard-won lesson applies directly: the comment in `OntologyGate.tsx` about node-link graphs needing 8px type on a phone is the right instinct, and it goes double here. **Every graph view needs an equivalent register view** — a sortable table of the same data — and the table, not the canvas, is the accessible primary. The graph is how you notice; the table is how you work. (PRODUCT.md's accessibility line already requires this: nothing essential may live only inside a pan-and-zoom canvas.)

### 6.2 The overlays

One topology, recoloured. The overlay switcher is the core interaction of the whole product.

| Overlay | Node encodes | Reads as |
|---|---|---|
| **Coverage** | % covered, uncovered in alarm colour | where the tests aren't |
| **Mutation score** | % of faults caught | where the tests are *theatre* |
| **Churn** | commits in window | what won't hold still |
| **Hotspot** | churn × complexity ÷ coverage | where the next incident is |
| **Bundle** | bytes shipped | what the user pays for |
| **Ownership** | team colour | where the handoffs are |
| **Age** | last-touched | what nobody understands anymore |
| **Findings** | count + max severity | the board itself |

The pairs are where insight lives — high churn on low coverage; large bundle contribution on a route nobody visits; a symbol with 400 fan-in and one owner. **Two overlays at once, one as colour and one as size**, is the whole "many variables" idea rendered in a single glance.

### 6.3 The views that answer a real question

Ranked by how often the question is actually asked:

1. **Blast radius of a diff.** Select a branch or PR → the changed nodes, everything reachable from them, and every test that covers any of it. Then the sharp bit: **the reached-but-untested set**, listed. This is the screen that justifies the build.
2. **The uncovered set.** Symbols with zero `covers` edges, sorted by churn. Actionable on day one, needs only tier 1.
3. **Drift over time.** The same graph across commits — coverage falling, a cycle appearing, a bundle creeping past budget. When there is no absolute standard, movement is the finding (the lesson `DOMAIN-HARNESSES.md` §4.8 draws from search).
4. **Path between two nodes.** "How does the auth module end up importing the PDF renderer?" — the shortest path, with each hop's evidence.
5. **Finding inspector.** Click a node, get its findings, each with evidence and a paste-ready reproduce command. `InspectorPanel` is already this component.
6. **The cut.** Select a package and see what would break if it were deleted. The refactoring-planning view.

### 6.4 Where it appears

A board nobody opens is a board that does not exist. Three surfaces, and the first two matter more than the third:

- **In the diff** — findings posted as inline PR comments, with the blast-radius view linked as an image or a permalink.
- **In the terminal / the agent** — the graph as a tool, queried mid-run.
- **The board itself** — for the questions the other two can't hold: drift, hotspots, planning a refactor.

---

## 7. The agent loop on top

The graph is a tool surface for agents, not just a human UI. This is what makes it a harness rather than a report generator.

**Context delivery.** `graph.reaches(diff)`, `graph.coveredBy(symbol)`, `graph.pathBetween(a, b)`, `graph.findings({variable, severity})`. A structured query returning the true dependency closure is categorically better context than twenty grep hits, and it is *smaller* — which is the context-management win, not just the accuracy one.

**The fix loop**, with the gate mechanical rather than social — `DOMAIN-HARNESSES.md` §5.2 (the two-key write) applied to code:

```
pick a CONFIRMED finding
  → agent proposes a patch in an isolated worktree
  → re-run only the analyzers whose dirty-set the patch touches
  → accept iff: this finding clears
                AND no new finding appears anywhere in the blast radius
                AND tier-1 stays green
  → otherwise discard, and record the failed attempt on the finding
```

That last clause is the interesting one. A failed fix attempt is **evidence about the finding**, not just a wasted run — three failed attempts on the same finding is a signal the finding is misstated, and the board should say so.

**Fan-out shape.** Analyzers pipeline, they do not barrier: each variable's findings should reach adversarial verification the moment that variable finishes, not after the slowest analyzer in the batch. A barrier is only correct where a stage genuinely needs the whole previous set — deduplicating findings across variables is the one real case (four analyzers reporting the same symbol is one problem, not four).

**Evolution.** The compounding loop, and the reason this is worth building rather than buying:
- a `CONFIRMED` finding that recurs → a tier-1 rule, so it is never a model's job again
- a `PLAUSIBLE` finding refuted twice → that analyzer's prompt or threshold is wrong; record it
- a suppression with a reason, repeated across the repo → a house rule that belongs in Instructions
- a fix pattern applied three times → a Skill

The harness gets sharper while the model stays frozen. That is the Evolution sheet's exact claim, running on a system where the evidence is countable.

---

## 8. Prior art, and the honest positioning risk

Nothing here is unprecedented, and the pieces are mostly available: tree-sitter and SCIP/LSIF for the symbol index, CodeQL and Semgrep for queryable static analysis, Stryker and mutmut for mutation, knip and dependency-cruiser and madge for dead code and cycles, Nx and Turborepo for the project graph, coverage tooling everywhere, Sonar and Codacy for the dashboard, Sourcegraph for cross-repo navigation.

**The bet is not a new analyzer. It is the shared substrate and the agent surface** — one graph every variable writes onto, one finding schema, and a query interface an agent can use mid-run. Sonar has a dashboard; it does not have a model of your bundle. Nx has a project graph; it does not know your mutation score. Nobody joins churn to coverage to bundle bytes to a logic finding on one symbol.

**And the risk, stated plainly:** that description also fits "an aggregator dashboard," a category with a long history of being built, admired once, and abandoned. Three things separate the useful version from that fate, and if the build cannot commit to all three it should not start:

1. It posts into the diff, where the decision is actually made.
2. Tier-3 findings are adversarially verified and visually separated, so tier-1 credibility is never spent on a guess.
3. Findings expire. Anchors are content-hashed, suppressions carry reasons, and the board can prove it is describing the code as it is now.

---

## 9. Where it runs out of road

- **The graph is a model, and the edges you most need are the ones you cannot statically see.** Dynamic imports, DI containers, reflection, string-keyed dispatch, anything crossing a network boundary. A confident-looking graph with a missing edge is more dangerous than no graph, which is why guessed edges must be marked as guessed on the canvas.
- **Tier 3 is opinions with good typography.** Adversarial verification lowers the rate; it does not change the kind.
- **Every finding costs attention, and attention is the budget being spent.** A harness that surfaces 300 true findings has not helped. Ranking is not a feature here — it is the product, and it is harder than any single analyzer.
- **The incremental cache is a correctness surface**, not a performance detail. See §3.3.
- **It measures what it can render.** Coupling to a team's understanding, the cost of a bad abstraction, whether the design is right — none of it has a node, so none of it appears, and a board that is entirely green is a claim it has no standing to make.
- **The build cost is real.** Tier 1 across a monorepo is weeks. Tier 2 needs isolation and a scheduler. Tier 3 needs an eval harness of its own before it can be trusted — you are building a verification system, so you inherit the obligation to verify it.

---

## 10. Build order, if it were built

The MVP question is: what is the smallest loop that is genuinely useful the day it lands?

**Not** the graph. The graph is the substrate, and a substrate with one overlay is a demo.

**The smallest useful loop is the blast-radius answer on a real diff:** symbol graph + coverage edges + `reaches(diff)` → *"this change reaches 34 symbols; 11 have no test covering them; here they are."* That needs a parser, a coverage trace, one query, and a table. No canvas, no findings ledger, no agent, no tier 3.

From there, in order of value per unit of work:

1. **Mutation testing on the reached-and-tested set** — turns coverage from a claim into a measurement, and it is the variable most likely to change someone's behaviour.
2. **Findings ledger + content-hashed anchors** — the moment there is more than one variable, the schema has to exist.
3. **The canvas**, with two overlays (coverage, hotspot) and the register view beside it.
4. **PR posting** — where the board meets the decision.
5. **Drift over commits** — only meaningful once there is history to draw.
6. **Tier 3 with adversarial verification** — last, deliberately. It is the most impressive demo and the most likely to poison the well if it arrives before tiers 1 and 2 have earned the board's credibility.

---

## 11. Open questions

1. **Scope: one repo or many?** Cross-repo call edges are where the real blast radius lives in a service architecture — and they are also where the build cost stops being linear.
2. **Is the graph the durable artifact, or a derived view?** If derived and rebuildable, drift-over-time needs snapshots anyway. Rebuildable-plus-snapshots is probably right, but it is two storage stories, not one.
3. **Who is the operator?** An engineer reading their own PR needs a different surface from a lead planning a quarter's refactor. Axis 5 from `DOMAIN-HARNESSES.md` applies to this harness too, and the answer changes the UI more than any technical decision here.
4. **Does this belong to harnessarch.com at all?** It is a strong worked example of the eleven primitives on a system with countable evidence — which is exactly what the site's evidence rules make hard to come by. Building it would generate the site's first honest, self-owned case study. That is either the best reason to build it or a bad reason to build the wrong thing.
5. **Would it survive its own board?** If the harness cannot be pointed at itself and come back green — or come back red with findings worth fixing — it does not deserve to be pointed at anything else.
