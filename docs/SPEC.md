# rampscan — working spec

**Status:** draft spec, brainstorm-grade. Decisions marked **DECIDED** are settled unless contradicted by building; everything else is a recommendation with the reasoning attached.
**Date:** 2026-08-13 · **amended 2026-09-11** (§12, the KSI pivot — the Q0 spec amendment of `docs/PLAN-KSI-PIVOT.md`) · **amended 2026-09-13** (§13, the artifact plane — the R0 spec amendment of `docs/PLAN-ARTIFACT-PLANE.md`)
**Reads against:** `docs/COMPLIANCE-SCAN-HARNESS.md` (the founding doc — its §11 decisions bind this spec), `docs/context/ramprules/` (dataset 2026.07.14.01), `docs/context/harnessarch/` (the code-graph and domain-harness arguments); §12 additionally reads against `docs/RESEARCH-KSI-GAP-ENGINE.md` and `docs/RESEARCH-PARAMIFY-PILOT.md`, and §13 against `docs/PLAN-ARTIFACT-PLANE.md`, `docs/RESEARCH-KSI-FULFILMENT.html` and `docs/RESEARCH-UPSTREAM-READINESS.html`.

---

## 1. What rampscan is, in three sentences

A single-tenant appliance, deployed by Terraform module into a client's AWS account, that fetches the client's repositories read-only, scans code / IaC / CI configuration inside an egress-restricted sandbox, and emits **signed, commit-anchored evidence bundles** keyed to ramprules recipe, KSI, and control IDs. A scheduler re-verifies every bundle inside the FedRAMP 20x MVX window for the client's class (7 days at class b, 3 at class c), and evidence whose code anchor changed **dies automatically** rather than lingering as a stale claim. A console shows three registers — evidenced, violated, unevidenced — and exports assessor-ready artifacts.

The one-line differentiation: ramprules' automation frontier counts 209 KSI-reached controls, 97 covered (88 by AWS API recipes, 9 by pipeline evidence), 112 uncovered. rampscan is the pipeline source.

---

## 2. Tech stack

**DECIDED unless noted.** The bias throughout: boring, single-tenant, client-ownable. Every component must be explainable to a 3PAO assessor in one sentence.

| Concern | Choice | Why |
|---|---|---|
| Language | TypeScript (Node 22), pnpm monorepo | Matches ramprules and harnessarch — one ecosystem across the family; best tree-sitter/SCIP bindings; the schema layer can import ramprules' `types.ts` conventions directly. |
| Infra as code | Terraform module (the deliverable itself) | Clients deploying into their own account expect a Terraform module they can read and pin. CDK would be fine too; Terraform wins because the *client's* platform team reviews it, and Terraform is the lingua franca of that review. |
| Compute | ECS Fargate tasks (collectors), one small ECS service (console + API) | No servers to patch inside a client's boundary; per-task IAM roles; per-task network config is how the sandbox is enforced (§5). Lambda rejected for collectors: 15-min ceiling and image-size limits fight real scans. |
| Orchestration | AWS Step Functions (scan pipeline DAG) + EventBridge Scheduler (the MVX clock) | State, retries, and timeouts without running an orchestrator; the execution history is itself evidence of the scan having run. A self-hosted queue would be one more thing to audit. |
| Evidence ledger | S3, content-addressed, **Object Lock (compliance mode)** + KMS | The source of truth is append-only signed bundles. Object Lock gives WORM semantics an assessor recognises; content-addressing makes tampering self-evident; the client owns bucket and keys. |
| Attestation format | in-toto statements, signed with **cosign + AWS KMS** | DECIDED over Sigstore keyless/Fulcio: no public transparency log dependency inside a client boundary, no external OIDC trust root to explain. This **supersedes the mechanism in the founding doc's §11.3** (Sigstore keyless via CI OIDC — chosen when signing was assumed to happen in a CI job; §13's in-account deployment removed that premise) while keeping its principle intact: two signature classes, never mixed. The KMS key *is* the harness identity; human approvals are signed separately via the console with the approver's identity. |
| Projection DB | **PocketBase** (SQLite) — see §6 for the full argument | Console backend: auth, roles, admin UI, realtime subscriptions, one Go binary in the console container. Holds only a **rebuildable projection** of the ledger, never the record. |
| Code graph store | SQLite file per repo-snapshot (`graph.db`), stored in S3 beside the bundles | Queried with recursive CTEs (`reaches`, `pathBetween`). A graph database (Neo4j etc.) is rejected: one more stateful service in the client's account for query patterns SQL handles at this scale. The graph is a *derived artifact*, rebuildable from the commit. |
| Graph extraction | tree-sitter (structure) + SCIP indexers (scip-typescript, scip-python) for resolved references | Same layering as the code-graph doc §3.2: exact edges labeled exact, inferred edges labeled inferred. MVP languages: TypeScript/JavaScript, Python, HCL. |
| Collectors (tier 0/1), wrapped not rewritten | syft (SBOM), osv-scanner + grype (advisories: repo deps and container images), gitleaks (secrets incl. history), semgrep (SAST query packs per control family), checkov (IaC posture), spectral (API spec linting) | Each is best-in-class OSS with a JSON output; rampscan's value is the **join to control IDs**, the graph, and the ledger — not re-implementing scanners. Every wrapper pins the tool version, and the version participates in the evidence cache key. Container scope: the image the repo's Dockerfile builds — pipeline-source; scanning a live registry is runtime and out of scope. |
| API-specific checks | spectral (spec ↔ config) + **graph route queries** (spec ↔ code) | The code graph extracts route nodes, so "every route reaches an auth check in its call path" and "code exposes no route the OpenAPI spec omits" are recursive-CTE queries, not new tools — the cheapest collector family this architecture unlocks. AC-family recipes. |
| Reachability / VEX | Internal: graph `reaches()` over the SCIP call graph, joined to syft's package→symbol mapping; output as OpenVEX | This is the flagship tier-2 join and the piece none of the wrapped tools can do alone. |
| Model tier | Amazon Bedrock, same account/region (GovCloud when the boundary requires): Haiku-class for routing/triage, frontier-class for tier-3 judgments | Founding doc §11.4. All Bedrock traffic via VPC endpoint; model IDs and prompts pinned and logged per finding (`provenance`). |
| Console frontend | Next.js, static-exported where possible, served by the console service; client SSO via their IdP (OIDC) in front | Matches the family's stack; the React Flow experience from harnessarch transfers directly when the graph view arrives (§8). |
| Repo access | GitHub App (or GitLab equivalent) with read-only contents scope; short-lived installation tokens; clone into ephemeral task storage | Least privilege, revocable by the client, and the App identity shows up in their audit log — the access is itself evidenced. |

---

## 3. Architecture

Single account, single tenant, two planes — and the "control plane" is deliberately almost nothing:

```
                        client's AWS account
  ┌──────────────────────────────────────────────────────────────────┐
  │                                                                  │
  │  EventBridge Scheduler ──┐        (the MVX clock, per class)     │
  │  webhook (push event) ───┤                                       │
  │  console "run now" ──────┴──► Step Functions: scan pipeline      │
  │                                    │                             │
  │        ┌───────────────────────────┼──────────────────────┐      │
  │        ▼                           ▼                      ▼      │
  │   fetch task              graph-build task          collector    │
  │   (GitHub App,            (tree-sitter+SCIP         tasks ×N     │
  │    ephemeral clone)        → graph.db)              (Fargate,    │
  │        │                           │                 sandboxed)  │
  │        └───────────► artifacts ◄───┴──────────────────────┘      │
  │                          │                                       │
  │                          ▼                                       │
  │              sign task (cosign + KMS)                            │
  │                          │                                       │
  │                          ▼                                       │
  │        S3 evidence ledger (Object Lock, content-addressed)       │
  │                          │            ▲                          │
  │                          ▼            │ two-key writes           │
  │              projector (rebuilds PocketBase)                     │
  │                          │            │                          │
  │                          ▼            │                          │
  │        console service: PocketBase + Next.js  ◄── client SSO     │
  │                          │                                       │
  │                          ▼                                       │
  │        exports: OpenVEX · evidence packages · frontier report    │
  │                                                                  │
  │  Bedrock (VPC endpoint) ◄── tier-3 verifier tasks (Phase 3)      │
  └──────────────────────────────────────────────────────────────────┘
        ▲ inbound only, versioned, public:
        ramprules dataset (/api/*, pinned dataset_version) · OSV · package metadata
```

Component notes, the non-obvious ones:

- **The scan pipeline is a DAG, not a barrier chain.** Fetch → graph-build fan out into collectors as each input becomes ready; collectors pipeline into signing individually. The only barrier is dedup/aggregation before projection (the one legitimate barrier, per the code-graph doc §7).
- **The projector is a pure function** `ledger → SQLite`. It runs after every write and can rebuild the entire PocketBase state from S3 at any time. This property is load-bearing (§6).
- **Two-key writes go *through* the console but *land* in the ledger.** A `notApplicable` scoping or a narrative approval is drafted in the console, signed by the approver (their SSO identity, recorded in the attestation), and appended to the ledger like any other evidence object. PocketBase never holds a fact the ledger doesn't.
- **Updates:** the appliance updates by Terraform module version bump, client-initiated. No auto-update channel into their boundary; an update is a change they review. Collector/tool versions are pinned per module release, so evidence provenance survives upgrades.

---

## 4. Dataflow — one scan, end to end

1. **Trigger.** EventBridge (clock: freshest evidence for class c must never exceed 3 days), a repo push webhook, or a console button. Trigger metadata enters the run record.
2. **Fetch.** Short-lived token → shallow clone at a pinned commit into task-local storage. The commit hash is the anchor for everything downstream.
3. **Graph build.** tree-sitter + SCIP → `graph.db` for this snapshot: symbols, imports, calls, routes, IaC resources, log sinks, crypto uses, dependency nodes. Exact vs inferred marked per edge.
4. **Dirty set.** Diff against the last scanned commit → changed nodes + blast radius per collector's declared depth. First scan is a full scan; steady state is incremental. Cache key: `(collector, toolVersion, nodeContentHash, configHash, dataset_version)`.
5. **Collect.** Fargate tasks fan out, one per collector family, sandboxed (§5). Each emits **findings** (the shared schema, code-graph doc §5, extended with `ksi_ids` and `control_ids`) and **evidence candidates** (artifact + assertion results per pipeline recipe).
6. **Join.** Findings and evidence are joined to the pinned ramprules dataset: recipe ID → KSI IDs → control IDs. Anything that can't resolve to a recipe is a finding only, never evidence — the ontology-gate rule.
7. **Sign.** Each bundle becomes an in-toto statement — subject: artifact digests; predicate: recipe ID, commit, dataset version, tool versions, assertions, run ID — signed via cosign with the harness KMS key.
8. **Append.** Bundles land in S3 content-addressed under Object Lock. Evidence edges from prior commits whose anchor hash changed are marked dead *by the projector computing it*, not by anyone remembering to.
9. **Project.** The projector folds the ledger into PocketBase: current coverage per control, the three registers, freshness clocks, drift deltas.
10. **Surface.** Console registers update (realtime via PocketBase subscriptions); expiring-evidence alerts go to the client's channel (SNS → their choice); exports regenerate.
11. **(Phase 3) Escalate.** The routing model flags diff hunks implicating KSIs with no deterministic collector; tier-3 tasks judge; adversarial verifiers refute or confirm; survivors enter the ledger as `PLAUSIBLE`, visually quarantined from deterministic evidence.

---

## 5. The sandbox, precisely

Scanning means executing untrusted repo content inside a client's account — resolvers and build scripts run code. This is the Execution Environment primitive at its sharpest, and it is a design commitment, not a hardening backlog:

- Collector tasks run with **no route to the internet** except a proxy allowlist: ramprules dataset, OSV, and the package registries a given collector legitimately needs. Everything else, including instance metadata beyond the task role, is denied.
- Task IAM: write to *one* artifact prefix, read the clone, nothing else. The signing key is **not** available to collector tasks — signing is a separate task that reads artifacts and never executes repo content. A compromised scan can therefore corrupt its own artifacts but cannot sign them.
- Ephemeral everything: clone and workspace die with the task; nothing untrusted touches durable storage except declared artifact outputs.
- Static-first bias: prefer lockfile resolution over `npm install`, manifest parsing over building. Where a build is unavoidable (some SBOM depth), it runs in the most restricted task class and its outputs are marked `built: true` in provenance — an assessor can discount them if they choose.

---

## 6. PocketBase — the answer, with the reasoning

**Yes to PocketBase, in a specific role; no to PocketBase as the database of record.**

The tempting mistake is to make the app DB the system of record. In this product the record must be append-only, tamper-evident, client-owned, and legible to an assessor in ten years — that is S3 + Object Lock + signed bundles, and no application database changes that.

Once the record lives in the ledger, the app DB is a **projection**: a rebuildable index whose total loss costs one projector run. For that role PocketBase is a genuinely good fit for this deployment shape:

- One Go binary inside the console container — nothing extra to operate in the client's account.
- Auth, roles, and admin UI out of the box, fronted by the client's own SSO; PocketBase users map to console roles (viewer / approver / admin), and **approver** is the identity that signs two-key writes.
- Realtime subscriptions give the registers live updates without building a websocket layer.
- SQLite is exactly the right weight for a single-tenant projection measured in tens of thousands of rows.

Rules that keep the choice safe, written down now:

1. **The projector is the only writer** of projection collections. Console writes go to the ledger first (signed), then appear via projection. If PocketBase state and ledger state ever disagree, the ledger wins and the projection is rebuilt.
2. **`graph.db` stays out of PocketBase.** Graph queries hit the snapshot SQLite artifact directly; the projection holds only rollups.
3. **Exit path acknowledged:** if the console outgrows PocketBase (multi-region, exotic query load), the projector's pure-function property means swapping the projection store is a rewrite of one component, not a migration of a record.

---

## 7. The eleven primitives, concretely

The founding doc's §7 mapped the slots conceptually. This is the implementation column.

| Primitive | rampscan implementation |
|---|---|
| **Instructions** | `rampscan.config.ts` in the client's config repo: target class (b or c — class d has no MVX window, open question 6), repos in scope, semgrep pack selection, suppression policy, alert channels. Versioned, reviewed by the client, hash-pinned into every run's provenance. |
| **Context Delivery** | For tier 3: graph traversal (`reaches(diff)` subgraph) + the implicated KSI/recipe slice from the pinned dataset, serialized compactly. Never embedding search. The dataset arrives by ID via ramprules' `/api/*`, cached locally, version-pinned. |
| **Context Management** | Finding ranking before any window: dirty-set first, severity × freshness-debt ordering; the console's registers are the same ranking made visible. Tier-3 prompts get budgeted subgraphs, not files. |
| **Tool Interfaces** | One schema for every collector output (code-graph doc §5 + `ksi_ids`/`control_ids`), enforced with Zod at the wrapper boundary. A collector is: container image + manifest declaring inputs, dirty-set depth, recipe IDs it can evidence, and tool version. Adding a collector is adding a manifest, not touching the pipeline. |
| **Execution Environment** | §5. Egress-allowlisted Fargate tasks, split signing, ephemeral workspaces, static-first. |
| **Durable State** | The S3 ledger (Object Lock, KMS, content-addressed) + `graph.db` snapshots + the incremental cache. Retention: audit-cycle years, client-configured, never shorter than their authorization timeline. |
| **Orchestration** | Step Functions DAG (pipeline, not barrier), EventBridge as the MVX clock, per-collector retries/timeouts, run records as first-class objects. Scheduled full re-scan diffs against incremental results — the cache verifies itself. |
| **Sub-agents** | Phase 3 only: adversarial verifiers per tier-3 hypothesis (refuters, majority kill), and independent second judgment on every `notApplicable` proposal before it reaches the human key — the clinical second-reader pattern. |
| **Skills** | One procedure file per control family / recipe cluster: how to evidence it, how to investigate a violation, how to adjudicate applicability. Stored in-repo, versioned; tier-3 prompts assemble from them. Confirmed fix patterns graduate into these files. |
| **Verification** | The ramprules catalog is the oracle; recipe assertions are the checks; the reasoner rule is mechanical: *no evidence without a recipe ID + artifact + passing assertions + live anchor*. The harness verifies itself: per-collector false-positive rate and cache-divergence rate are tracked variables with their own alerts. |
| **Evolution** | The demotion pipeline: tier-3 CONFIRMED pattern → semgrep rule or recipe assertion (tier 1); refuted-twice → prompt/threshold fix, recorded; recurring suppression-with-reason → config default proposal. Every demotion is a ledger event — the harness can show an assessor its own detection lineage. |

---

## 8. Frontend — and the code-graph question

**Do we visualize the code graph? Yes — but it is Phase 4, and it is never the primary surface.** The harnessarch lesson (code-graph doc §6.1) binds: every graph view ships beside a register view, and the register is the accessible primary. For this product that ordering is even stronger, because the person the console must convince is an assessor, and assessors work from tables and packages, not canvases.

Console surfaces, in build order:

1. **The coverage board** (MVP). Three registers — **evidenced** (with freshness clock per bundle), **violated**, **unevidenced** (the honest default, never hidden) — filterable by KSI theme, control family, repo, class. Each row opens the evidence: artifact, assertions, commit, signature, reproduce command.
2. **The clock view.** Every bundle's age against the class's MVX window; expiring-soon sorted first. This is the screen that exists because the regulation demands the loop.
3. **Drift.** What died since the last window and why — anchor changed, assertion failed, tool version bumped. Movement is the finding.
4. **Approvals.** The two-key queue: `notApplicable` proposals and narrative attachments, showing the *domain object* (control, justification, evidence gap), never the tool call — the non-technical console rule (domains doc §5.8).
5. **Exports.** OpenVEX, per-control evidence packages (bundle + verification instructions), and the pipeline-coverage report in ramprules' frontier vocabulary (covered / partial / narrative / unreviewed).
6. **(Phase 4) The graph canvas.** React Flow, reusing the harnessarch flow components' patterns: semantic zoom (repo → package → module → symbol), overlays for evidence coverage / findings / PII paths, inferred edges visually distinct from exact ones, and deep-links from any finding to its subgraph. It earns its place as the *explanation* surface — why is this control violated, what does this taint path traverse — after the registers have earned the product's credibility.

---

## 9. Repo layout (planned)

```
rampscan/
  docs/                      # this spec, founding doc, context snapshots
  fixtures/
    vulnerable-app/          # planted-fault toy repo (prototype demo fixture)
  packages/
    core/                    # port interfaces (LedgerStore, Signer, Runner, Scheduler, RepoSource, Projector) + adapters
    schema/                  # finding, recipe, bundle, attestation types (Zod)
    dataset/                 # ramprules client: fetch, pin, cache, verify version
    graph/                   # tree-sitter + SCIP extraction; graph.db builder + query lib
    collectors/
      sbom/  advisories/  container/  secrets/  semgrep-packs/  iac/  api/  provenance/  logging/
    reachability/            # graph × SBOM join → OpenVEX
    signer/                  # in-toto + cosign/KMS
    ledger/                  # S3 append + content addressing + anchor-death computation
    projector/               # ledger → PocketBase projection (pure)
    scheduler/               # MVX clock logic (class → cadence → EventBridge)
  console/
    pocketbase/              # projection collections, roles, hooks
    web/                     # Next.js registers + (later) graph canvas
  infra/
    terraform/               # the deployable module — the actual product artifact
  recipes/
    pipeline/                # the pipeline recipe overlay (Phase 0's deliverable)
    adjudications/           # per-control disposition for the 121, with reasoning
```

---

## 10. What Phase 0 produces, restated as acceptance criteria

Phase 0 is data work, no infrastructure, and it is done when:

1. `packages/schema` defines the **pipeline recipe** type mirroring `aws-evidence.json`'s recipe shape (`ksi_ids`, `control_ids`, `evidence`, `collection` with `kind: "pipeline"`, `expected_output`, `assertions`, `cadence`, `automatable`, `notes`, and `caveats` — the one deliberate rename, generalizing aws-evidence's partition-specific `govcloud` field) plus `anchor: commit`.
2. `recipes/adjudications/` holds a disposition for **each of the 112 uncovered controls** — `automatable | partial | narrative`, with one paragraph of reasoning each, in ramprules' frontier vocabulary so the overlay can be contributed upstream.
3. `recipes/commit/` holds drafted recipes for every control adjudicated `automatable` or `partial` — the honest pipeline ceiling, computed before any scanner exists.
4. A generated `docs/FRONTIER-PIPELINE.md` states the numbers: how many of 112 the pipeline source can cover, fully or partially, and what remains narrative forever.

That document is simultaneously rampscan's scope definition, its first marketing artifact, and a contribution ramprules' automation-frontier register is structured to receive.

---

## 11. Open questions

1. **GovCloud-first or commercial-first?** The Terraform module should be partition-clean either way (ramprules' own recipes carry `arn:aws-us-gov` caveats as a model), but the first reference deployment's partition decides which VPC endpoints and Bedrock model IDs get tested reality.
2. **Multi-repo joins.** A client's boundary spans many repos; a taint path or reachability question can cross them. MVP is per-repo graphs with a shared ledger; when does a cross-repo graph become necessary, and does it change the `graph.db`-per-snapshot design?
3. **Webhook vs poll for repo change detection** in enterprises where GitHub Apps with webhooks face approval friction — polling on the MVX clock may be the pragmatic floor.
4. **How does the pipeline overlay get upstreamed?** Technically it mirrors ramprules' overlay model; organizationally it needs a review path so rampscan's adjudications meet the Hub's evidence bar ("every number rendered, never typed").
5. **Bedrock model pinning vs drift.** Tier-3 provenance pins model IDs, but Bedrock retires models; the eval set (Phase 3's gate) must be strong enough to re-qualify a successor model without re-litigating every past finding.
6. **What drives the scheduler at class d?** `VDR-TFR-MVX` defines windows for classes a (SHOULD, 1 month), b (MUST, 7 days), and c (MUST, 3 days) — **there is no class d entry**. The dataset's class-d clock is different in kind: tightest MUST is `VDR-TFR-MVF` (1 month), tightest overall `VDR-TFR-PSD` (SHOULD, 1 day — the tightest deadline in the whole dataset). Until this is settled, the config accepts b and c only; a class-d deployment needs its own cadence derivation from the evidence-plan clock, not a copy of the MVX one. *(Still open under §12: the pivot makes class an explicit config value and lets the owed-side and reporting layers compute against all four classes, but the scheduler's refusal of d stands until RFC-0033 or a cadence derivation settles it — see §12.3.)*

---

## 12. The KSI pivot — the Q0 spec amendment (DECIDED 2026-09-11)

This section is the spec side of `docs/PLAN-KSI-PIVOT.md` Phase Q0: the decisions that must be locked before any code changes, because one of them — the `ValidationMethod` shape — is the costly-to-reverse decision of the entire pivot. Everything in this section is **DECIDED** on merge; the plan's ground rules (announced denominators, cover ≠ automate, dual-source owed side, re-pin per batch, spec-before-schema) apply from here on.

**The inversion in one sentence:** a recipe stops being the register's unit and becomes one *kind* of validation method (`source: pipeline`); the KSI becomes the row; the method count per KSI against the class floor (`FRC-CSX-VVK`) becomes the product's first-class computation; controls become the crosswalk annotation they already are in the dataset.

### 12.1 Target architecture — the four planes

`ARCHITECTURE.md` §3's deployment diagram (Step Functions DAG, Fargate collectors, S3 Object Lock ledger, PocketBase projection) is untouched — the pivot happens in the layer *between* the dataset port and the projection:

```
┌─ OWED (Q1) ──────────────────────────┐  ┌─ PROVEN (built; Q4 widens) ─────────┐
│ KSI catalog port, pinned:            │  │ evidence ledger: signed, anchored,  │
│  · 46 KSIs × statements × controls   │  │ content-addressed, append-only      │
│    crosswalk × 5 artifacts           │  │                                     │
│  · floors as data: VVK 1/2/4,        │  │ sources:                            │
│    MVX 7d/3d, NMV 3mo, MOT 6/18mo    │  │  · pipeline (20 recipes, today)     │
│  · dual-source: ramprules slices ∪   │  │  · ingested signed results of       │
│    fedramp-consolidated-rules.json,  │  │    client-run AWS recipes (Q4)      │
│    adjudication overlay = enrichment │  │  · human attestations, two-key (Q4) │
│ × certification class (offering cfg) │  │ each labeled process|point-in-time  │
└──────────────┬───────────────────────┘  │ at ingestion (G6, Q3)               │
               │                          └──────────────┬──────────────────────┘
               │                                         │
               └───────────► GAP ENGINE (Q2–Q3) ◄────────┘
                    register: KSI → ValidationMethod → evidence
                    taxonomy G1–G13 evaluated per KSI × class,
                    every row citing the rule ID and the evidence;
                    the projector stays the only writer (invariant 6)
                              │
                              ▼
┌─ SURFACES ─────────────────────────────────────────────────────────────────┐
│ Q2: per-KSI board (methods n/floor · age vs window · artifacts k/5 ·       │
│     worst gap class as row color) · frontier v2 · G8 adjudication tab      │
│ Q3: history meter (MOT) · artifact checklist · failure→vulnerability feed  │
│ Q5: OCR fragments + Certification Package fragments (FedRAMP/schemas       │
│     JSON, generated from the projection like OpenVEX — no new state) ·     │
│     package conformance check (FRC-CSO-JSN)                                │
│ deferred: trust-center export (G11) · remediation hand-off (PR drafts)     │
└────────────────────────────────────────────────────────────────────────────┘
```

All ten `ARCHITECTURE.md` §9 invariants survive; two get sharper on Q2 merge:

- **Invariant 3 (the ontology gate)** becomes: *no evidence without method ID + artifact + passing assertions + live anchor.* Stricter than the recipe-keyed form, because a method names exactly one KSI.
- **Invariant 4** becomes per-KSI: *a KSI with zero methods is a G1 row on the board, never an absent row.* The board has 46 rows, always.

### 12.2 The `ValidationMethod` entity

**DECIDED: a method validates exactly one KSI — the (recipe × KSI) pair, not the recipe.** A recipe claiming two KSIs *derives* two methods. Three reasons, one comparator:

1. Every owed number is per-KSI: the `FRC-CSX-VVK` floor, the five artifacts, the `FRC-CSX-MOT` history meter, the assessor's interrogation view. Keying the method the same way makes each of them a `count`/`min` over methods rather than a join with a correction factor.
2. It makes differential standing expressible: "this recipe genuinely evidences KSI-SCR-MIT but only gestures at KSI-CMT-xxx" is two methods with different standing, not one method with a footnote.
3. The only publicly *assessed* 20x machine-readable package agrees: Paramify's `machine-readable-package/schema.yaml` hangs `Validations[]` under exactly one KSI each, with evidence under the validation and controls nowhere in the package (`docs/RESEARCH-PARAMIFY-PILOT.md` §2). The shape below is a superset of that field-tested minimum.

The shape (spec-level; `packages/schema/src/method.ts` implements it verbatim in Q2):

```
ValidationMethod = {
  id:        string          // deterministic: `${source}:${source_ref}#${ksi}`
                             //   e.g. "pipeline:lockfile-pinned-deps#KSI-SCR-MIT"
  ksi:       string          // exactly one KSI id, mnemonic form
  source:    "pipeline" | "aws-ingested" | "attestation"
  automated: boolean         // the FRC-CSX-VVK numerator. Fixed per source today
                             // (pipeline, aws-ingested → true; attestation → false)
                             // but stored, not derived at read time: the numerator
                             // of a legal floor is asserted where an assessor can
                             // see it, and a future source may not be uniform.
  clock:     "machine" | "non-machine"
                             // which cadence family owns this method:
                             // machine → VDR-TFR-MVX (7d/3d by class);
                             // non-machine → VDR-TFR-NMV (3 months).
                             // Follows `automated` today; stored for the same reason.
  standing:  "full" | "partial" | "narrative"
                             // what this method claims FOR THIS KSI — inherits the
                             // recipe's `automatable` uniformly at derivation, with a
                             // per-KSI override permitted (below).
  provenance: <discriminated on source>
    pipeline:      { recipe_id, collector, scope }        // scope: §12.6
    aws-ingested:  { recipe_id, signer_identity, ingest_digest }
    attestation:   { attestor_role, statement_ref }       // two-key identities live
                                                          // in the ledger event
}
```

**What the method does *not* carry, deliberately:**

- **No window, no floor.** Those are owed-side data, `owed(clock | ksi, class)`, read from the pinned catalog at evaluation (Q1.2). Storing them on the method would be typing a number the rules JSON owns — and the number moves (RFC-0033).
- **No `controls[]`.** The crosswalk rides the KSI in the pinned dataset; the method inherits it by its `ksi` key. Recipes keep their `control_ids` (nothing is lost from `recipe.ts`), but the register never joins through them.
- **No run-level provenance.** Tool versions, config hash, commit — those live where they always have, in the signed bundle (invariant 8). Method provenance names the *mechanism*; bundle provenance names the *run*.

**Methods are derived, never authored.** There is no methods table anyone edits. Each method is a pure function of its source artifact: `methodsOf(recipe)` maps `recipe.ksi_ids` to one method each (`source: pipeline`); an ingested bundle's contract yields its method (Q4.1); an attestation event yields its method (Q4.2). This keeps computed-never-typed intact — the register is a derivation over things that are already reviewed artifacts. `recipe.ts` gains one optional field to serve the per-KSI override: `per_ksi?: { [ksi_id]: { automatable?, notes? } }`, absent meaning uniform inheritance. That field is the *only* recipe schema change the pivot makes.

**Evidence attaches to methods.** The bundle predicate gains `method_id` beside the recipe ID it already carries (a superset — nothing existing breaks), and the ontology gate reads it per invariant 3′ above.

**Reviewed against the four consumers on paper** (the Q0 exit gate):

| Consumer | Reads from the shape | Satisfied by |
|---|---|---|
| Q1 owed side | which cadence family and floor apply to a method | `clock`, `automated`, `ksi` — floors/windows stay owed-side, keyed by these |
| Q2 projector / frontier v2 | per-KSI method counts against the floor; join to live bundles | `ksi` + `automated` (G1/G2 numerators); `id` ↔ bundle `method_id` |
| Q3 taxonomy | freshness per (KSI, method); history per KSI; artifact linkage; failure feed | `clock` (G3 window selection); `id` as the history key (G4); artifacts hang off the method's evidence (G5); flips are bundle events joined by `method_id` (G13) |
| Q4 ingestion | a non-pipeline result becoming a counted method with interrogable provenance | `source` discriminant + per-source provenance blocks; `automated: false` path for attestations |

### 12.3 Certification class as offering config

**DECIDED.** `rampscan.config.ts` carries `class: "a" | "b" | "c" | "d"` — one value per scanned offering, the multiplier on everything owed. The split of responsibilities:

- **Owed-side and reporting layers accept all four classes.** Floors, windows, and history requirements are data keyed by class (Q1.2); `frontier --class d` is a legitimate what-if report against d's floors (VVK ≥4, MOT 18 months) regardless of the configured class.
- **The scheduler continues to refuse class d** — §11 open question 6 stands unchanged: `VDR-TFR-MVX` has no d entry, and a d cadence must be *derived*, not copied. The pivot widens what is computable, not what is scheduled.
- **Default for the fixture and the self-scan: class b.** Floors of 1 make a 20-recipe pipeline demonstrably meaningful — the honest demo. Class c is the demo that shows gaps (floors of 2 over a single-source register are mostly unmet), which is also worth printing, but not as the default first impression.

### 12.4 Catalog source strategy — the dual-source contract

**DECIDED** (plan ground rule 3: dual-source from birth). The KSI catalog port in `packages/dataset` exposes one surface, `KsiCatalog` — 46 KSIs × statements × controls crosswalk × the five default artifacts, plus floors and windows as data — loadable from **either** path:

- **Path A — ramprules slices** (the existing client): the KSI catalog as ramprules serves it, with the adjudication overlay available.
- **Path B — `fedramp-consolidated-rules.json` direct** (FedRAMP/rules): the same catalog parsed from the canonical upstream.

Contract rules:

1. **Both paths yield identical `KsiCatalog` values at the pin**, proven by a test (Q1.3). One pin covers both: ramprules' `dataset_version` *is* the FedRAMP/rules dataset version (`2026.07.14.01` verified identical — research §2.2), so `DEFAULT_DATASET_PIN` guards Path B with no fourth pin. The Paramify `CR26/` OSCAL serialization is a third leg for the equivalence test — a cross-check, never a source.
2. **Owed facts are defined only by the rules JSON**, on either path: KSI ids, themes, statements, the controls crosswalk, the five artifacts, every floor and window (`FRC-CSX-VVK`, `FRC-CSX-MOT`, `VDR-TFR-MVX`, `VDR-TFR-NMV`). If the two paths disagree on an owed fact at the same pin, the loader hard-fails — that is a broken port, not a resolvable preference.
3. **The overlay may only enrich, never define.** Enrichment fields: adjudications and dispositions, `leverage`, evidence-plane attributions, upstream recipe references, rationale text. An owed number arriving via overlay is refused by the loader, structurally — the enrichment type simply has no slot for one.
4. **Overlay pins are unchanged** (`DEFAULT_OVERLAY_PINS`, `DEFAULT_PLANE_PINS` and their per-slice/per-plane discipline); Path B introduces no overlay, which is the point of having it.

### 12.5 `frontier` v2 — the output format, designed before implementation

**DECIDED**, because this text is the product's headline and ground rule 1 (announced denominators) governs it. Numbers in braces are computed placeholders — illustrative here, emitted by the command in life; the README quotes the command, never this spec.

```
rampscan frontier — the KSI register
class b · dataset 2026.07.14.01 · frontier overlay 0.7.5

  KSI             methods   freshest        artifacts   worst gap
  KSI-SCR-MIT      2/1 ok    11h / 7d ok     2/5         G5 artifact
  KSI-CMT-{…}      1/1 ok     2d / 7d ok     1/5         G5 artifact
  KSI-CNA-{…}      0/1        —              0/5         G1 coverage
  …                                                      ({46} rows, always)

  floor met on {m} of {46} KSIs · at least one automated method on {k} · no method on {u}
  covering all {46} — a row that says "nothing evidences this from a pipeline" is a row
  adjudication queue: {q} unreviewed, sorted by leverage (--adjudications)

  legacy view: --by-controls   ({23} of {209} controls · {38} reachable at this pin)
```

Format rules, each carrying a ground rule:

1. **The headline sentence** — the one the README quotes — is the `floor met on {m} of {46}` line **followed in the same breath by the covering line**. Cover ≠ automate is stated structurally, not in a footnote (ground rule 2).
2. **`--by-controls` prints today's view unchanged**, and v2's footer names it, so the denominator change is announced on every invocation during the transition (ground rule 1). Neither view is removed until a reviewed decision does it.
3. **Row anatomy:** methods `n/floor` (floor from owed data for the configured class) · freshest live evidence age against the method's window · artifacts `k/5` (Q3; prints `–/5` until modeled, never a fake 0 that implies measurement) · worst gap class as the row's color in the console and its final column in text.
4. **The G8 queue is its own section**, sorted by the dataset's `leverage` field — the unanswered question stays a first-class output, not a residue.
5. **`--class` overrides the configured class for reporting only** — a what-if against another class's floors; it never touches the scheduler (§12.3).

### 12.6 Scan scope is declared method provenance (resolves #16)

**DECIDED.** "Should a checkout scan read gitignored paths?" stops being a global toggle and becomes a declared property of each pipeline method's provenance — the G7 interrogation surface. Every collector manifest declares, and every derived pipeline method inherits, a `scope` block:

```
scope: {
  population: "checkout" | "checkout+generated"
      // did the walked set include artifacts produced during the scan
      // (§5's `built: true` outputs), or only what the pinned commit fetch
      // presents?
  history: boolean
      // did it read git history beyond the pinned commit (gitleaks: yes)?
  gitignored: "excluded" | "included"
      // the #16 axis: paths a .gitignore at the pinned commit masks —
      // relevant exactly when population is "checkout+generated", which is
      // where ignored build outputs come into existence mid-scan
}
```

The rule: a method that read gitignored paths *says so*; one that didn't says that. There is no repository-wide answer to #16 because the honest answer is per-mechanism — and the declaration is what an assessor pulls on when a green depends on what was *not* walked. Collector-by-collector values are set during the Q2 migration; a manifest without a `scope` block fails the catalog test, same enforcement pattern as `empty_means`.

### 12.7 Adoption mechanics

The plan's phases live as GitHub milestones (`Q0 — decisions locked` … `Q5 — schema-target exports`) with issues per numbered item — created at adoption, 2026-09-11. The milestones are the plan of record; this section is the specification the Q1–Q3 issues implement. Positioning (the README's first sentence, the MVX-expansion fix) changes only when `frontier` v2 prints the numbers it quotes — plan §7.5.

### 12.8 The ingestion contract (Q4.1)

The no-SaaS / no-execution boundary holds: ramprules' AWS recipes remain the client's to run, and nothing in the appliance ever executes an AWS call. What Q4.1 adds is the contract under which a client-run result becomes a ledger citizen — the `source: aws-ingested` leg of §12.2's register.

**The submission is the contract's unit** — one result per (upstream recipe × KSI), a self-identifying JSON document:

```
IngestSubmission = {
  _type:           "https://rampscan.dev/ingest-submission/v1"
  recipe_id:       string      // upstream's recipe id — their names, not ours
  ksi:             string      // exactly one KSI, mnemonic form; must resolve
                               // in the pinned catalog
  evidence_class:  "process-generated" | "point-in-time"
                               // the G6 assertion, made by the SUBMITTER —
                               // the one fact the appliance cannot compute
  cadence:         Cadence     // the cycle the client runs this on (artifact 2)
  artifacts:       [{ name, sha256 } | { name, reference? }]        // ≥ 1 digested (S3-1)
  assertions:      [{ description, passed, detail?, population? }] // may be empty (#147)
  timestamp:       ISO 8601    // the client RUN's clock, not the ingest's
  signer_identity: string      // who ran it and stands behind it
  automated?:      boolean     // did a MACHINE validate it — absent = true (S3-1)
  tool_versions?:  { [tool]: version }
  reproduce?:      string
}
```

Strict at every level, the manifest/contract rule: provenance is what an assessor pulls on (`FRR-PVA-AA-06`), and a misspelled field that parses to nothing is a question the interrogation view can no longer answer.

**Verdict is computed, never declared:** any assertion failed → `violated`; every assertion passed → `evidenced`; **no assertion at all → `unevidenced`**. The contract refuses empty `artifacts` structurally — a result with nothing to attest to is not a submission — but permits empty `assertions`, because a collected artifact nothing has evaluated is a real thing an assessor is owed a record of: signed, in the ledger, a method on the board, and a pass on nothing. `evidenced` is earned only by an assertion that passed over rows (#147; `[].every()` is true and is the one truth this function never signs).

**What ingestion mints:** a regular `EvidenceBundle`, signed and appended exactly like a pipeline bundle (the bundle IS the ledger citizenship — no new statement type):

- Subjects are the submitted artifact digests. `anchor_paths: []` and `commit: ""` — ingested evidence has no commit anchor, so it dies superseded or goes stale (G3) but never dies by anchor drift, which is the honest death model for evidence about a cloud account rather than a checkout.
- `method_id = aws-ingested:<recipe_id>#<ksi>`; `evidence_class` copied from the submission — G6 asserted at the bundle's birth, the same slot the pipeline mint asserts.
- The predicate gains an optional strict `ingest { signer_identity, ingest_digest }` block, `ingest_digest = sha256(canonicalJson(submission))` — the address of exactly what was accepted. INCLUDED in evidence identity (`sameEvidence`), on the `collector`/`basis` side of that line: the same verdict handed over by a different signer, or derived from different submitted bytes, is different evidence. Pipeline bundles carry no block on either side of the comparison, so nothing existing re-keys.
- `run_id = ingest:<digest[0..12]>` — derived, never typed; the upstream run's identity is the digest itself.

**The method derivation** (§12.2's Q4.1 promise): `methodOfIngestedBundle(bundle)` is a pure function of the signed bundle — `automated: true`, `clock: "machine"`, `standing: "full"` (fixed per source today, exactly like `automated`; a submission-declared standing is a future field, not a default), provenance `{ recipe_id, signer_identity, ingest_digest }`. Methods stay derived, never authored: the ingested bundle is itself the reviewed artifact the register derives from, so the aws-ingested register is recoverable from the ledger alone.

**The tree adapter** meets clients where they already are (`docs/RESEARCH-PARAMIFY-PILOT.md` §3): `rampscan ingest <dir>` accepts an `Evidence/<family>/<KSI-ID>/<KSI-ID>.{json,csv}` tree plus an `ingest-manifest.json` the client authors — signer identity, evidence class (per-entry override permitted), cadence, and per entry the script name, exit code, timestamp, and optional structured assertions: exactly the facts the tree itself does not carry. The adapter's output IS native submissions, so the digest discipline is identical on both paths. **The exit code is read for what those scripts mean by it (`RESEARCH-PARAMIFY-PILOT.md` §8.1, #147): 0 is a script that finished reading the account, non-zero is one that could not.** Neither is a verdict — the scripts this convention was read from exit 0 over an account with no GuardDuty and no encrypted bucket. So an exit-0 entry's verdict comes from its `assertions`, in the vocabulary `aws-evidence.json`'s recipes use (`field`/`op`/`value`/`where`), evaluated by the appliance with the pipeline's own evaluator over the result file's `results` rows (`population` = those rows; offenders named). An entry declaring none is collected and `unevidenced`. A non-zero exit is a **failed run**: the account was not seen, so there is nothing to attest to and nothing to violate — the entry is skipped and named in the outcome and the log, the way a skipped collector is, and never becomes a bundle. Until 2026-09-15 the adapter wrote `passed: exit_code === 0` as the single assertion, which signed `evidenced` over a non-compliant account; that is the `SECURITY.md` class and it is the reason the rule is spelled out here. The synthetic fixture mirrors those output shapes and is written by us — no code or fixture reuse (their repo has no license).

**The package adapter** (S3-1, `packages/cli/src/ingest-package.ts`): `rampscan ingest <package.yaml>` accepts a machine-readable assessment package — `Package → Assessment → KSIs → Validations → Evidences → Artifacts`, the shape the only publicly assessed 20x package is published in (`RESEARCH-PARAMIFY-PILOT.md` §2, §8.3), which ships no `Evidence/` tree. One native submission per (validation KSI × evidence), so the digest discipline is the tree adapter's. What it signs is narrower than either other path, on purpose: **no assertion** (the package carries a person's reading — `assessmentStatus`, `PASS` — and `validationRules: []`; none of it is a machine assertion the appliance evaluated, so every bundle is `unevidenced`, and a 3PAO's reading belongs on the attestation path under the reader's key); **`automated: false`**, a field the submission contract gained here and the bundle's `ingest` block carries, so the method the register derives is outside the `FRC-CSX-VVK` numerator and on `VDR-TFR-NMV`'s clock — whatever produced the artifact, nothing validated it by machine; **`point-in-time`**, uniformly, because an assessment package is a captured state at `effectiveDate`; and **no invented digest**: the package names its artifacts by reference and ships no bytes, so the one digested subject is the package file itself and the references ride beside it as `ReferencedArtifact`s (the contract now permits pointers beside a digested artifact, never instead of one). `--cadence` is declared by the operator because the package schema has no such field; `signer_identity` is the assessing organisation and the assessor the package names for the validation. **KSI ids are the package's own.** When they are an earlier catalog's, `--crosswalk` names a reviewed `KsiCrosswalk` (`recipes/crosswalks/`) pinned to the dataset version it resolves into — one entry per indicator with a basis, a successor list that may hold two KSIs or none; an indicator with no successor is skipped and named like a failed run, an indicator the crosswalk does not carry refuses the batch, and a crosswalk into another pin is refused rather than reinterpreted. A crosswalk that merges two indicators into one KSI can deliver one evidence twice under one (recipe, KSI); identical bytes are one record kept once and noted, different bytes are keyed by the validation that cited them. The register shows methods outside the numerator as `+N` beside the `automated/floor` cell, only when a row holds any.

**Refusal before append:** a KSI that does not resolve in the pinned catalog, a duplicate (recipe, KSI) within one batch, or any malformed submission refuses the WHOLE batch before anything is signed — validate-then-append, the artifact-judgment pattern applied to evidence.

**Verification (Q4.4).** `rampscan verify` checks an ingested bundle offline exactly as it checks a native one, and that is literally true: the address, the signature and the coverage are one code path for every statement kind. What an ingested bundle cannot share is the *rendering*. It anchors to no commit, so the native `repo @ commit` line has nothing to put after the `@`, and the facts an assessor pulls on are the handoff's — the signer identity and the submission digest, which is why §12.8 put them in the predicate. The report names the method id, the signer, and the handoff digest, and says the evidence has no commit anchor rather than trailing a bare separator.

It also runs one check a native bundle does not need: **the carried `method_id` must be what the signed content derives.** That key is the register's join, so a bundle whose key disagrees with its own content would *count* on a different method than it describes — a signed, correctly-addressed bundle making a claim about the wrong KSI. `ingest` cannot mint one (it derives the key), so a mismatch means the ledger was written by something else, and `verify` is where that surfaces — as a verdict, not a stack trace, which is also why an off-contract multi-KSI ingestion is reported rather than thrown.

And the report states the limit of what the signature means: it covers the **handoff** — that this submission, at this digest, was accepted under the contract — not the cloud account. The appliance executed no AWS call and vouches for no account state; the submission's own bytes stay the client's to produce, and the handoff digest is the address to demand exactly those bytes by. Leaving that implicit is how a report starts being read as the appliance vouching for AWS, which is the one thing the no-execution boundary means it cannot do.

### 12.9 The attestation contract (Q4.2)

The pipeline plane and the ingestion plane both evidence things a machine can observe. What remains after both is **acts-on-people** — the requirements no checkout walk and no AWS API call can reach, and the reason the commit plane's ceiling is a ceiling (plan §7 ground rule 1). `VDR-TFR-NMV` exists for exactly that remainder, and Q4.2 makes the path a counted method rather than an apology: a human statement, signed through the **existing two-key path**, becomes the `source: attestation` leg of §12.2's register.

**The attestation is the third two-key write**, after the `notApplicable` scoping (§6) and the artifact-sufficiency judgment (Q3.3, G5). Same discipline, because it is the same mechanism: drafted by any console identity, made real by an approver's key turn, appended to the **ledger** — PocketBase never holds a fact the ledger doesn't (§6 rule 1).

```
AttestationPredicate = {
  action:          "attested" | "withdrawn"
  statement_id:    string      // the MECHANISM's name ("incident-review"),
                               // slug-shaped; becomes the method's source_ref
  ksi_id:          string      // exactly one KSI, mnemonic form; must resolve
                               // in the pinned catalog
  attestor_role:   string      // the accountable role ("ciso") — a role, not
                               // a person: people change, the mechanism doesn't
  statement:       string      // what is attested, in the attestor's words
  repo:            string
  proposed_by:     string      // console identity that drafted it
  approved_by:     string      // approver whose key turn made it real
  dataset_version: string
  timestamp:       ISO 8601
}
```

The statement's `subject` is `sha256(statement)` under the name `attestation.txt` — what the approver signs is the **claim**, exactly as a scoping's subject is the justification it rests on. There is no separate `justification` field: a second free-text box beside the claim invites "lgtm" to stand where reasoning belongs, and the claim is what both keys are turning for.

**`statement_id` names the mechanism, not the occasion.** The method id is `attestation:<statement_id>#<ksi>`, so the same attestation programme re-signed every quarter stays **one** method whose clock is satisfied again — not a new method each time. This is the §12.2 split applied to a human process: method provenance names the mechanism, the ledger event names the run. It is also why `attestor_role` is a role: the method survives the post-holder.

**The derivation** (§12.2's Q4.2 promise): `methodOfAttestation(event)` is a pure function of the signed event — `automated: false`, `clock: "non-machine"`, `standing: "narrative"`, provenance `{ attestor_role, statement_ref }` where `statement_ref` is the subject digest, the address of exactly the words that were signed. All three are fixed per source, for the same reason `aws-ingested` fixes its own: the numerator of a legal floor is asserted where an assessor can see it, not inferred at read time.

**`automated: false` is the anti-gaming property, not a demotion.** `FRC-CSX-VVK` counts automated methods, so no number of attestations can ever carry a KSI to a class's floor — inventing four roles to reach class d's ≥4 moves nothing. What an attestation does is end G1: a KSI whose only validation is a signed human statement is *covered*, and the board says so while still reporting an unmet automated floor. Cover ≠ automate, kept structurally (ground rule 2) at the one place the temptation to conflate them is strongest — `docs/RESEARCH-KSI-GAP-ENGINE.md` §6 names that conflation the false-attestation failure mode.

**Freshness: the attestation's own timestamp is its evidence instant.** An attestation has no evidence chain — the event *is* the evidence — so the fold joins the live attestation to its method cell and judges `freshAsOf` against `VDR-TFR-NMV`'s 3 months, the same `windowThreshold` arithmetic the machine clock gets (calendar months, day-clamped). An attestation nobody renewed is **G3**, on the same footing as a stale scan. That is the whole point of putting it on a clock: a standing human claim that no one has re-signed in a year is not evidence, and the register stops pretending otherwise without anyone filing a ticket.

**Withdrawal is a decision, not a deletion.** A signed `withdrawn` supersedes a standing `attested` for the same (repo, `statement_id`, KSI) — an append-only ledger un-decides by deciding again, exactly as `insufficient` withdraws a sufficiency judgment. `methodOfAttestation` **refuses** a withdrawn event: deriving a method from a retracted claim would count it. The superseded attestation stays in the ledger, because the history it records is real.

**Refusals, all the contract-rule class:** an empty statement (the approver signs reasoning, so there must be some), a `statement_id` that is not slug-shaped (it becomes part of a composite key — a `#` or `:` inside it would make the method id ambiguous while still looking like an id), a KSI that does not resolve in the pinned catalog, and a withdrawn event handed to the derivation. The check order is validate-then-sign: nothing reaches the ledger that the catalog cannot resolve.

### 12.10 The register spans its sources (Q4.3)

With all three legs built, the register's composition is the thing to state plainly, because the board's `n / floor` is the product's headline number and §12.2 promised it would be a count over methods rather than a join with a correction factor.

**Where each leg comes from.** Pipeline methods are **catalog-derived** — a pure function of the recipe files and their collectors' manifests (`deriveCatalogMethods`), handed to the fold as data, and they apply to every repo the catalog is scanned against. The other two are **ledger-derived**, and the fold derives them itself: the catalog holds *our* recipes, so it can carry neither a client's upstream recipe nor a human's attestation. Both are therefore keyed by **(repo, KSI)** rather than KSI alone — an ingested result and an attestation are each about one offering.

That split is not an inconsistency. It follows the §12.2 rule that a method is a pure function of its source artifact, applied honestly: the reviewed artifact behind a pipeline method is a file in the repo, and the reviewed artifact behind the other two is a signed statement in the ledger. The fold reads the ledger, so the fold derives them.

**The ingested join is by method identity, never through the recipe cell.** The contract mints one submission per (upstream recipe × KSI), so one upstream recipe evidencing two KSIs produces two submissions that share a `recipe_id`. Joining a method to its evidence through the `(repo, recipe_id)` register cell would let one KSI's result stand in for the other's — and with opposite verdicts, that is the difference between a met floor and a violation. The method cell joins to the live submission for *its own* `method_id`, which is also the whole death model §12.8 chose: an ingested bundle has no commit anchor, so the latest submission for a method is the live one, and it dies superseded or goes stale (G3) but never by anchor drift.

**What `automated` now composes to.** The `FRC-CSX-VVK` numerator counts `pipeline` **and** `aws-ingested` methods; `attestation` methods are counted as methods and never as automated ones (§12.9). So the three legs move different numbers, deliberately:

| | counts toward the floor | ends G1 | clock |
|---|---|---|---|
| `pipeline` | yes | yes | `VDR-TFR-MVX` |
| `aws-ingested` | yes | yes | `VDR-TFR-MVX` |
| `attestation` | **no** | yes | `VDR-TFR-NMV` |

A **violated** ingested result still counts as a method. The floor asks whether a validation mechanism exists for a KSI, not whether it currently passes; what a failed validation *says* is G13's business (`VDR-CSO-FAV`), which is why a violated ingestion raises the method count and opens a vulnerability episode in the same fold. Conflating the two would let a provider improve their floor by deleting failing checks.

**Raising and lowering, on an append-only ledger.** The phase gate's "its removal lowers it" is measured the way an append-only store allows: the count is a function of the ledger, so a fold over a ledger without the ingestion is lower. Nothing is deleted to demonstrate it. The attestation leg additionally has a *signed* removal — a `withdrawn` statement (§12.9) — because a human claim can be retracted by its author, where a client's past result simply stands until a newer one supersedes it.

**Empty is not absent.** Discovered by making ingested rows first-class: an ingested register row set `commit: ""` and `introducingCommit: ""` because the *predicate* requires those fields, while the row's own fields are optional precisely so "there is no commit anchor" can be said by saying nothing. Both projection stores read an empty string back as absent, so the projection failed its own `projection ≡ ledger` proof in `rebuild` for every ledger holding an ingestion. The rule, stated once: a row omits an optional field it has no value for, and a store that can represent emptiness must round-trip it (which is why `population` is read with an explicit null check — "0 of 0" is a measurement, not a missing one).

Where a value is *genuinely* empty rather than absent, the store must accept it. A vulnerability episode opened by a violated ingestion has no commit, and PocketBase's `vulnerabilities.commit_sha` was a required field — so the store refused the **entire** projection write with `validation_required` on any ledger holding such an episode, which would have taken `rampscan serve` down rather than degrading. The field is optional now, and `ensureCollection` gained the one non-additive reconciliation it can safely make automatically: a field the spec has **relaxed** from required to optional is relaxed in place. Relaxing cannot invalidate a record already stored, where tightening or retyping can — so that direction migrates itself, and the other stays a deliberate, hand-written migration. Without it a spec fix of this kind reaches only fresh deployments, which is the least useful half of the population.

### 12.11 The schema-target export contract (Q5.1)

**DECIDED.** Two documents, generated from the projection exactly as OpenVEX is — an export, no new state, regenerated per scan, nothing signed: a **Certification Package Overview** (`FRC-CSO-PKG`, `CDS-CSO-PUB`) and an **Ongoing Certification Report** (`CCM-OCR-AVL`), both valid against the pinned FedRAMP schemas per `FRC-CSO-JSN` (G10, G12). They land in `<out>/exports/fedramp/` — amended by §13.8 from `<out>/exports/`, so that every document in the directory `conformance` reads is one a pinned schema gates.

**The declared/computed line, drawn in the type system.** Neither schema is mostly about validation: the overview is offering identity and the OCR is a quarterly narrative. An evidence ledger holds none of that, so each document is two halves —

- **declared**, read from `rampscan.config.json`'s `offering` block and passed through untouched;
- **computed**, read from the projection and therefore attributable to a signed bundle.

The line is structural, not editorial: **the declaration type has no slot for anything the fold computes.** There is no `reportPeriod` key and no `certificationDataChanges` key in `OfferingConfig`, so a provider cannot type a validation history into a config file and have the export repeat it back as measured. Same mechanism as §12.4's rule 3, where an owed number arriving via overlay is refused because the enrichment type has no slot for one. And the split is published, not just enforced: `x-rampscan.fieldSources` labels every top-level field `declared`, `computed` or `mixed`, so a reader holding only the JSON can tell which half the appliance stands behind.

**Three refusals.**

1. **`reportableIncidents.incidents: []` is an attestation, never a default.** The schema says an empty array attests that no FedRAMP Reportable Incidents occurred in the period. An appliance that emitted one because a config key was missing would have made a statement about incidents on behalf of a provider who never made it — so an absent `offering.report` block generates **no OCR at all**, and the outcome says why. The package overview is generated either way, because it contains no attestation.
2. **The G13 feed is not `acceptedVulnerabilities`.** "Accepted Vulnerability" is a term of art for a weakness whose risk the provider has decided to carry; a validation flipping to `violated` (`VDR-CSO-FAV`) is a measurement. Routing the second into the first would report a decision nobody took. The computed feed rides in `x-rampscan.validationVulnerabilities`, and an open record at report time is surfaced as a stated problem.
3. **A computed field cannot be overwritten, only extended.** The ledger speaks for the validation plane alone, so a document asserting the *complete* set of changes to FedRAMP Certification Data from one plane would be precise and wrong. The declaration's slot is `additionalCertificationDataChanges`, appended after the computed lines — it can add a new service or a changed contact, and it cannot suppress what the evidence record says moved.

**`certificationDataChanges` is summarised, not pasted.** `CCM-OCR-AVL` asks for "high-level summaries", and a report carrying four hundred drift rows would satisfy the schema while defeating the requirement. The export groups the period's drift by kind — born, died (by cause), verdict-flipped, scoped — one line each, each naming its plane. With nothing to report it says *no changes were recorded in the evidence ledger*, which is a different sentence from *no changes occurred* and the only one of the two that is true.

**Pinned twice, and the validator fails closed.** FedRAMP semvers each CR26 draft schema independently, so the pin is per file (`FEDRAMP_SCHEMA_PINS`), on `$schemaVersion` **and** on the sha256 of the vendored bytes — these are drafts, and a republication under an unchanged date and version is exactly the class of move `pins.ts` exists to complain about. Conformance is checked by a hand-rolled validator over the closed keyword set those three files actually use, for the reason the house hand-rolled ustar and DSSE; what makes it safe rather than merely smaller is the failure direction: **an unrecognised keyword is an exit, not a pass.** A validator that skipped what it did not implement would report conformance nobody checked. Growing the target set means implementing the keyword or taking the ajv dependency deliberately.

**Every document carries its own verdict.** A nonconforming export is still written, stamped with `x-rampscan.conformance` — the pinned schema, its version and digest, and every violation — then re-validated to prove the stamp did not change the verdict. Withholding it would leave nothing to debug; writing it silently would put a document that fails `FRC-CSO-JSN` next to one that passes with no way to tell them apart. `rampscan exports` exits 1 on any violation; Q5.2 turns that into the CI gate, so a nonconforming export fails our build and not the client's.

**One offering per document.** When the ledger holds more than one repo, `--repo` names the one the document speaks for. A document summing two offerings would describe neither.

### 12.12 The conformance check, and application freshness (Q5.2, Q5.3)

**DECIDED.** Two additions closing Q5: the package conformance check as a command over documents **on disk**, and `FRC-APP-FCP` freshness as a computed stamp on the package overview.

**`rampscan conformance` reads a file, which is the whole point.** `exports` can only ever check the bytes it just produced — the one case where the answer was never in doubt. G10 is "certification JSON not matching FedRAMP schemas", and the document in front of a provider is usually one they already have: written by another tool, edited by hand, or generated by a rampscan that predates the current pins. So the check takes a path (a file, or a directory whose `*.json` documents are all read), resolves which pinned schema gates each one, and validates it. It defaults to `<out>/exports/fedramp/` (§13.8; `<out>/exports/` until R0.3 moved the gated family into its own directory).

**It checks the document's stamp against a fresh validation, and that is the part regeneration cannot do.** A file carrying `x-rampscan.conformance.valid: true` that does not validate is a worse fact than a file with no stamp: its self-description is false, and the self-description is what a reader trusts. It happens honestly — the pins move under a document generated months ago — and it must never pass quietly. The same check runs in the other direction (a document stamped nonconformant that now validates clean: the stamp predates a fix) and on the version (judged at `0.1.3`, pinned at `0.1.4`: the verdict printed is this checkout's, not the one in the file, and saying so is the minimum).

**Resolution never infers from shape.** An explicit `--schema` wins, then the document's own stamp, then the filename rampscan itself writes — and a document matching none of the three is an **exit**, never a skip. Inferring the schema from the fields present would pick the schema a malformed document happens to resemble, which is the one question a conformance check must not answer for itself; and a checker that skipped the file it did not recognise would report a clean directory it never read. Same failure direction as the validator it calls, for the same reason. An empty directory is refused too: nothing checked is not a pass.

**The CI gate, and what it actually gates.** `test.yml` generates both documents from this repository's own declared offering and conformance-checks them, so a nonconforming export fails our build and never a client's. Stated precisely, because the obvious reading is wrong twice over. CI has no ledger, so the fold is empty and the computed half is zeros — the unit suite is what validates a populated computed half, over a fixture register and against the same pinned bytes. And the declared half is not simply "the part a human edits": `OfferingConfig` deliberately mirrors the FedRAMP schema's own constraints, so that a typo fails one layer closer to the person who can fix it, which means a config that parses is already most of the way to a conforming document.

What remains — and it is the reason this step is not ceremony — is **the divergence between the hand-written mirror and the pinned schema it mirrors**. The mirror is maintained by hand against a draft, and the pin will bump. `businessCategory` is the live example today: zod takes any non-empty string, the FedRAMP schema takes one of thirty-six enum values, so a config naming a category FedRAMP does not list parses clean and produces a document that fails the check. That case is pinned in `fedramp-conformance.test.ts`, so the gate is provably able to fail — ground rule 7 applied to our own gate rather than to a recipe.

**`FRC-APP-FCP` is a different clock, and gets its own constant.** The rule requires a package showing status verified within the previous **7 days**. That is an application-time window on the package, flat across every class — not `VDR-TFR-MVX` (7 days class b, 3 days class c) and not `VDR-TFR-NMV` (three months). Two clocks that read the same number for one class are still two clocks, so `APPLICATION_FRESHNESS_WINDOW_DAYS` is its own constant and never reads `catalog.windows`.

**It is computed and unclaimable.** `x-rampscan.freshness` on the package overview only — the rule is about the *initial* package a provider supplies, and an ongoing report answers to `CCM-OCR`'s cadence instead. `OfferingConfig` has no slot for it, so a provider cannot declare their own package fresh; the strict schema **refuses** the key rather than stripping it, because a declaration silently dropped looks accepted to whoever typed it. A method with no live evidence counts as unfresh rather than excused — the fold's own rule for `freshMet`, applied to this clock rather than a stricter one invented here — and an empty register is never fresh, because a package validating nothing shows no status to have verified. A signed two-key `notApplicable` is excluded and counted separately: a decision is not a lapsed clock.

**Both readings are published, neither is chosen.** The rules text supports an argument that `FRC-APP-FCP` governs everything in the package, and an argument that it speaks only to what a machine re-verifies while `VDR-TFR-NMV` keeps its three months for an attestation. `fresh` answers the first and `machineOnlyFresh` the second, both computed, both in the document. An appliance settling that question silently would be making a regulatory interpretation on a provider's behalf in a field the provider is the one who signs.

**Unmet is a stated problem, not a refused export.** A stale package is a true statement about a real posture; refusing to write it would hide it. The document is written, `fresh` reads false, and `problems` names which of the two causes drove it and how many methods each. The conformance gate stays about `FRC-CSO-JSN` — schema validity — and does not fail on freshness, because those are different rules and a gate that conflated them would report the wrong one.

## 13. The artifact plane — the R0 spec amendment (DECIDED 2026-09-13)

This section is the spec side of `docs/PLAN-ARTIFACT-PLANE.md` Phase R0: the decisions locked before any code changes, because one of them — the `Artifact` entity — is the costly-to-reverse decision of this plane exactly as `ValidationMethod` was of the pivot. Everything here is **DECIDED** on merge. The plan's four ground rules apply from here on, and rules 1–10 of the depth and launch plans and the five pivot rules stay active unchanged.

**The addition in one sentence:** rampscan holds an *owed* plane and a *proven* plane and nothing between them — `SDR-CSX-KSI` (MUST) makes the five artifacts the required content of the Security Decision Record, the document `FRD-SDR` defines as the SSP's replacement, so the artifact becomes a first-class signed object with the same lifecycle as evidence and the deliverable documents fall out of it.

### 13.1 Where the plane sits

```
OWED (§12.1)  ──┐                                    ┌── PROVEN (§12.1)
 catalog,       │   ┌─ ARTIFACT (this section) ──┐   │  pipeline · ingested
 floors,        └──►│ (repo, ksi, n∈1..5) → body │◄──┘  · attested
 5 artifacts        │ signed · addressed · clocked│
                    └──────────────┬──────────────┘
                                   ▼
                          GAP ENGINE — G5 stops being unanswerable
                                   ▼
                    SDR (R2) · historical metrics (R3) · VER trio (R4)
```

No new store, no new signature format, and no change to the ten `ARCHITECTURE.md` §9 invariants. The projector stays the only writer (invariant 6); an artifact enters the same way everything else does, as a signed statement appended to the ledger and folded.

### 13.2 The `Artifact` entity

**DECIDED: an artifact fills a slot, and the slot is `(repo, ksi_id, artifact)`.** The KSI is one, mnemonic form, as everywhere since §12.2; `artifact` is 1-based into `info.default_artifacts.KSI`, the rules' own order. A later artifact for the same slot **supersedes** the earlier one — an append-only ledger revises by writing again, never by editing, which is the same rule scoping, judgment and attestation already keep.

**DECIDED: the body rides the predicate and the subject digests it**, exactly as an attestation carries the attestor's statement. The alternative — a digest pointing at bytes in the output dir, the J4 arrangement for tool artifacts — was rejected for one reason: R2 must render `ksiImplementation` *into* a document and R3 must refold a year of them, and a plane whose prose is only reachable through a directory that later runs overwrite would make the SDR unreproducible from the record. What the ledger holds, an assessor holding the ledger can read.

```
Artifact
  ksi_id        exactly one KSI id, mnemonic form
  artifact      1 | 2 | 3 | 4 | 5     (default_artifacts.KSI, the rules' order)
  repo          the offering this speaks for — one offering per document (§12.11)
  source        authored | computed | attested | assessed
  body          Markdown. The SDR's statements are Markdown-typed, so the
                artifact is stored in the form the document wants it.
  body_digest   sha256 over the canonical body bytes — the subject, and the
                address everywhere else
  anchor        { commit, path } when source = authored; ABSENT otherwise, and
                absent means absent — never a commit that merely happened to be
                checked out when a generator ran
  generator     when source = computed: the pin set, the tool versions and the
                exec-journal digest that produced these bytes
  review        when known: the record that this body was reviewed, with its
                own source (R4's forge plane). NEVER asserted, never defaulted,
                and its absence is printed rather than assumed benign
  supersedes    the body_digest this revises, when it revises one
  valid_from    the clock's start (§13.5)
```

**A body is prose, and the ledger is not a document store.** `SDR-CSX-KSI` asks for "short and simple high-level summaries"; a body is bounded at 64 KiB and a longer one is **refused** at append with that sentence quoted. A document larger than its own summary is a document, and a document belongs behind an `evidenceLocation` the SDR already has a slot for — resolved through J4's digest addressing, which is the one place in this system bytes are served from.

### 13.3 The four sources, and what each is allowed to mean

The distinction is load-bearing, not decorative: it is what an assessor reads to know who stood behind a sentence.

- **`authored`** — a file in the scanned repository, commit-anchored, discovered by the generalized `documents` collector (R1.4). This is the CSP engineer's habitat: the artifact lives beside the code, moves through the same review, and **dies by anchor drift** like any other evidence when the thing it describes changes. Appending one is a collector observation signed like evidence — *not* a two-key write, because the repository's own review is the second key and adding a ceremony the pull request already performed would teach people to click through it.
- **`computed`** — rampscan generates the body from the fold. Legitimate for **2**, **4** and **5** only (§13.4). A computed artifact carries `generator` and is regenerated, never edited; its body is a function of the fold, so two runs over the same ledger at the same instant produce the same digest — the same reproducibility R3's metrics are held to.
- **`attested`** — the existing two-key path of §12.9, unchanged, for the acts-on-people remainder. The attestation *is* the body's signature; nothing new is invented here.
- **`assessed`** — the `IVV-IAS-SUM` inbound (R4.5). The independent assessor's summary is **ingested** like a client-run result rather than typed, so the SDR's `ksiAssessment` carries a provenance instead of a paste. Where a paste is the only thing on offer, it is labelled `declared` and says so in the document.

### 13.4 What rampscan will never author

**DECIDED, and this is the constraint the plane exists under.** Artifacts **1** (the explanation of measures, or of the reason and resulting customer risk for not having them) and **3** (verification that the measures demonstrate the indicator, or that the reason is accepted) are the provider's own claims, and `source: computed` is **refused** for them by the schema rather than by a convention somebody remembers.

The generator's output for an unwritten artifact is an **absence with a reason**, never a draft: `artifacts scaffold` writes the computed halves and leaves the human halves conspicuously empty and labelled. An LLM in the loop makes authoring these trivially possible and that is exactly why the refusal is written down here — the moment this appliance emits plausible compliance narrative, `SDR-CSX-KSI` becomes a text-generation benchmark and every signature in the ledger is worth less.

The reason-for-absence path is **first-class, not a failure**: artifact 1 explicitly permits "an explanation of the reason and resulting risk to customers for not having measures available" for that indicator. A provider who writes that has satisfied the rule, and the board must count it as satisfied rather than scold them for it.

### 13.5 The artifact clock

**An artifact is non-machine validation and answers to `VDR-TFR-NMV` — three months — whatever its source.** It is not `VDR-TFR-MVX` (7 days class b, 3 days class c), which is the machine cadence of §12.2's `clock: "machine"` family, and it is not `FRC-APP-FCP`'s flat 7-day application window (§12.12). Three clocks that read a number each is three clocks; the artifact one gets `valid_from` and nothing else.

A **computed** artifact's clock restarts at each fold that produces it. That is not a loophole — it is the true statement that the body was recomputed from current evidence at that instant, and it is exactly as strong as the evidence underneath it, which the same board already ages. An **authored** artifact's clock starts at its anchor's commit date and runs out at three months, which is the point of the plane: every other document tool treats a written artifact as done, and `SDR-CSX-KSI` item 2 asks for the *cycle*.

### 13.6 Judgment, unchanged — and what it now judges

`ArtifactJudgment` (§12's two-key path, `packages/schema/src/artifact-judgment.ts`) keeps its closed `1 | 3 | 4` union: artifacts 2 and 5 are computed by the fold and **no signature may override a computation**. What changes is that the judgment finally judges a body that exists — its `subject` points at the judged `body_digest`, so "artifact 3 is sufficient" names the bytes it approved and a later revision of those bytes is unjudged until judged again.

That is the whole reason to sequence the plane before anything else: today the system can sign that an artifact is sufficient and cannot show you the artifact.

**Two consequences, settled when R1.1 implemented this (2026-09-13):**

- **`body_digest` is optional in the schema and required at the write path.** The ledger is append-only, so a judgment signed before the artifact plane existed must stay readable — the same rule a pre-Q3.4 bundle's absent `evidence_class` keeps. `recordArtifactJudgment` refuses to append a new one for a slot that holds no body: there is no honest digest to name for prose nobody has written, and "artifact 3 is sufficient" about nothing is exactly the checkbox this plane retires. A judgment that names no bytes therefore **applies to none** — it is carried, printed, and decides nothing.
- **Presence on the board is a body.** G5 counts a slot as filled when a signed `Artifact` stands in it and no *applicable* judgment calls those bytes insufficient. The two readings the old counter conflated survive as what they honestly were: `derivable` (the fold holds the material to generate artifacts 2 and 5, and nobody has minted them — a work queue) and `judgment` (the two-key call on 1, 3 and 4). R2 has to render these five into the SDR, and a slot that counted as present with nothing to render would be a gap the document discovers instead of the board.

### 13.6a How an authored artifact dies — the R1.4 amendment (DECIDED 2026-09-13)

§13.3 says an authored artifact "dies by anchor drift like any other evidence". Implementing it exposed a gap the entity did not cover, and this is the decision that closes it.

**The gap.** An `Artifact` has no withdrawal, by §13.2's design: an append-only ledger revises by writing again. That works when a declared file **changes** — the new bytes supersede the old — and fails when a file is **deleted**, because there are no bytes to append. Evidence does not have this problem: a later bundle that *observed* the path is what kills the earlier one. The artifact plane had no equivalent observer, so a deleted artifact would have kept counting toward its KSI's `k / 5` until the three-month clock ran out — the exact failure mode this plane exists to prevent.

**DECIDED: the scan signs what it observed of the declarations, and an explicit absence is what kills the body.** `ArtifactDeclarations` (`packages/schema/src/artifact-declarations.ts`) records, per scan, every declared slot with whether it resolved and — when it did not — why, in the scan's own words. The fold drops a body whose slot a *later* observation names unresolved, and the empty cell carries that sentence, so "nobody filled this" and "this emptied, and here is what happened" are different rows.

Three constraints ride with it:

1. **It may move a board cell, and a run record may not.** `ScanRun` (J1) is about the machinery — which collector ran, which tool resolved — and letting it move a cell would make the board partly a function of the run log. This statement is an observation *of the repository*, signed and anchored to the commit it read, which is the same kind of claim an evidence bundle carries.
2. **Silence is not a statement.** Only an entry naming a slot unresolved kills. A slot that has simply left the config is not killed: a repository that stops declaring a file has stopped claiming it answers for this KSI, which is not the same as saying the answer is gone — and the clock is what ages an artifact nobody maintains. A later *resolved* observation un-kills the slot, so a restored file is restored on the next fold rather than staying wrong until someone re-reads the ledger.
3. **An unresolved entry must carry its reason, in the schema.** The sentence is the record: it is what the board prints and what an assessor reads.

The same amendment settles the authored clock. An authored artifact's anchor is the commit that **last touched its file**, not the commit being scanned, because §13.5's three-month window is asking whether the writing has been revisited and a clock restarted by every scan would answer "yes" forever. That is a read of git history, which `documents.ts` had deliberately not done since the batch-1 audit cut the *currency* limb from both document recipes — and it is not that claim. Reading which commit last touched a file, in order to date the clock the rule owes, asserts nothing about whether the contents are still true; the window is what asks that, and it can only ask it if the clock starts when the writing happened.

Asymmetry worth stating: an **unchanged** authored body is not re-appended on the next scan, while a computed one always is. A computed body's clock restarts because it was genuinely recomputed from current evidence; an authored body's `valid_from` is its anchor commit's date and does not move, so a second identical statement would say nothing and cost a ledger entry per scan.

### 13.7 Class-optional KSIs — the denominator decision

**DECIDED: optionality is read, never inferred, and an unstated class is required.**

Five indicators carry `varies_by_class` with a class-`b` statement beginning `**Optional:**` and a class-`c` statement that does not — `KSI-CNA-EIS`, `KSI-MLA-ALA`, `KSI-SVC-PRR`, `KSI-SVC-RUD`, `KSI-SVC-VCM`. The catalog loader reads `varies_by_class` for the three class-varying FRR floors and only those, so every meter prints a 46 denominator at every class when class B's honest figure is 41. A tool whose pitch is *computed, never typed* cannot leave that standing, and it is fixed here rather than later because every number R1 onward prints divides by it.

Three decisions make it honest:

1. **The prefix is the only signal the pinned JSON gives, so the prefix is what is read** — at the start of the class statement, exactly. The five indicators carrying it today are pinned in a test, so a republication that changes the vocabulary (an `optional` field, a different marker) fails that test rather than quietly restoring 46. Ground rule 7 applied to our own reader.
2. **A class the map does not name is required, not optional.** `varies_by_class` on these indicators names `b` and `c` and nothing else; `VDR-TFR-MVX` already establishes that an absent class means the rule states nothing there, and the honest response to silence is the conservative one. Under-counting the denominator flatters the provider; over-counting only ever creates work that turns out to be unnecessary, and only one of those errors is discovered by an assessor.
3. **An optional KSI keeps its row and leaves the denominators.** Invariant 4 is unchanged — the board has 46 rows at every class, because a KSI that vanished from the board would be a KSI nobody remembers at the class where it returns. It is excluded from both the numerator and the denominator of the class meters, labelled optional with the rule's own word, and counted on its own line: `5 optional at class b`, named, with how many are evidenced anyway. A provider who exceeds what their class owes should see that they did, and should never see 42 of 41.

### 13.8 One directory per gated family

**DECIDED: the schema-gated package documents land in `<out>/exports/fedramp/`, and `conformance` defaults there.**

`scan` writes `openvex.json` into `<out>/exports/` (§M4, a published path that does not move) and `exports` writes the FedRAMP documents beside it, so `conformance` on its own default path meets a document no FedRAMP schema gates and exits — correctly, per §12.12's fail-closed resolution, and uselessly. CI dodges it today by exporting into a temp directory with an absent ledger.

The fix is the directory, not the resolution rule. Loosening resolution to skip what it does not recognise would trade a false alarm for the one failure mode a conformance checker must not have — reporting a clean directory it never read. Giving the gated family its own directory means every document in the checked path is a document the check gates, which stays true as R2's SDR and R4's VER trio join it, and `conformance <path>` over an arbitrary file is unchanged for the case it was built for: a document another tool wrote.

### 13.9 Adoption mechanics

The plan's phases live as GitHub milestones (`R0 — the object, locked` … `R5 — the reviewer surface`) with issues per numbered item, created at adoption 2026-09-13 (#92). The milestones are the plan of record; this section is the specification the R1–R5 issues implement.

## 14. The runner contract — the T spec amendment (ADOPTED 2026-09-15)

`docs/PLAN-CLOUD-RUNNER.md` is the plan; this section is what it changes in the contract. It amends §12.8 by adding a second way an `aws-ingested` submission comes to exist, and it amends nothing about what the appliance is: **the appliance still holds no AWS credential and makes no AWS call.** What §12.8 called "the client's to run" is now, optionally, run by a program the client deploys in their own account, on a request the appliance signs and a transcript the appliance reads. Two programs, two identities: the runner has an AWS role and no ledger key; the appliance has a ledger key and no AWS role. Neither alone can mint cloud evidence, and T3-5 makes that a test rather than a sentence.

### 14.1 The two documents (`packages/schema/src/transcript.ts`)

```
RunRequest = {                       // minted by the appliance, signed into the ledger (T4-1)
  _type:          "https://rampscan.dev/run-request/v1"
  nonce:          string             // single-use; a second transcript for it is a replay
  recipe_id:      string             // upstream's id, as pinned
  recipe_digest:  sha256
  ksi:            string
  params:         { [name]: string } // the reviewed bindings (T1-3) — never an example literal
  issued_at, expires_at: ISO 8601    // the window a transcript must fall inside
  requester:      string             // the console identity that clicked
}

RunTranscript = {                    // signed by the runner's own key (T3-2); the DSSE payload
  _type:          "https://rampscan.dev/run-transcript/v1"
  request_digest: sha256             // of the canonical RunRequest it answers
  nonce, recipe_id, ksi
  runner:         { name, caller_arn, account, partition, region }
                                     // what `sts get-caller-identity` returned, as the runner saw it
  self_check?:    { probes: [action], all_denied: boolean }   // T3-3, carried in every run
  steps:          [{ argv, exit_code, started_at, finished_at,
                     stdout_sha256, stdout_bytes, stderr_class }]
  started_at, finished_at
}
stderr_class = "none" | "access-denied" | "throttled" | "not-enabled" | "incomplete" | "other"
```

Strict at every level, like the ingestion contract this feeds. Three absences are the contract:

- **No verdict field, anywhere.** The runner reports what it ran (`argv`, so the command run is the command published) and what came back (`stdout` by digest, the bytes riding beside the transcript). It does not evaluate assertions and has no field to put an evaluation in. A compromised or buggy runner can fail to collect; it cannot declare a pass.
- **No stderr bytes.** The runner classifies stderr and discards it, because AWS error text carries ARNs, account ids and resource names into whatever log holds the transcript. The class is what intake needs (§14.2); the bytes are what an assessor does not.
- **No account it did not observe.** `runner.account` and `caller_arn` are what STS returned during the run, not configuration. Intake compares them to the appliance's configured account and refuses a transcript from anywhere else.

### 14.2 Intake, and the order of refusal (`packages/cli/src/runs-intake.ts`)

`intakeTranscript(transcript, outputs, ctx)` returns exactly one of three things, and the Runs page shows all three:

- `submission` — every check below passed, the bytes were evaluated, and the result is a native §12.8 `IngestSubmission` handed to the existing `ingest`. There is no second signing path and no second bundle shape. The predicate's `ingest` block gains a strict optional `runner { name, caller_arn, account, partition, region, request_digest }` (T0-1), so a manual submission and a runner's stay distinguishable to an assessor, and `signer_identity` names both parties: `runner:<name>` and the caller ARN.
- `failed(class)` — the account was not seen. `denied`, `not-enabled`, `throttled`, `incomplete` (an async report not ready), or `error`. A visible failed run; **never a bundle under any verdict.** This is ground rule 7 (no vacuous passes) applied to a new input, and it is where the tree adapter's #147 lesson lives: a step that exited non-zero, or exited zero with anything but `stderr_class: "none"`, has printed nothing an assertion may be evaluated over. `count_eq 0` over the empty output of a denied call is zero rows, not zero offenders.
- `refused(reason)` — the transcript does not answer a request this appliance made. Checked **before a single output byte is read**, in this order: the runner's signature (on the envelope, by the intake route — T4-2 — before the payload reaches `intakeTranscript`); the nonce (not the request's, or already accepted — a replay); the request digest (a run for a request the appliance never made, or for a different recipe or parameters); the caller account and partition against the configured ones; the run's timestamps against the request window and the receipt time.

Only a `submission` reaches the evaluator, and the evaluator is the pipeline's own (`packages/core/src/assert.ts`), over the captured bytes, with `population` set — the same function that judges the tree adapter's rows. A recipe that carries no structured assertion yields a submission with `assertions: []`, which §12.8 already signs as `unevidenced`: a collected artifact that enters the two-key artifact-sufficiency judgment before it counts (T0-2). One click collects; one approver decision accepts; both are visible.

### 14.3 What the signatures mean

The appliance's signature on the minted bundle covers the **handoff**, as §12.8 says: this submission, at this digest, was accepted under the contract. The runner's signature on the transcript covers **the observation**: this role, in this account, ran these commands and received bytes of these digests. Neither vouches for the account being compliant — the verdict is computed by the appliance from the bytes, and the bytes are addressable by digest for anyone who wants to check the computation. `rampscan verify` on a runner-produced bundle names the runner, the caller ARN and the request digest beside the handoff digest.

### 14.4 The emulator (T3-0)

The runner is exercised in CI against an AWS API emulator behind `AWS_ENDPOINT_URL` (`compose.emulator.yaml`, Moto in server mode; the `emulator` job in `test.yml`). That is where the runner is *tested*. It is never where a claim about a client's account is made, and the plan's exit gates are worded *in a sandbox account* because a mock cannot prove that a role is read-only: the denial self-check (T3-3) and the gate runs happen against real IAM. A suite that cannot reach the emulator skips, named — a missing emulator is a skipped collector, not a green run.

### 14.4a The two assertion vocabularies (T2-5)

The pipeline's evaluator reads **row-wise** assertions: `field` names a column of every row the collector emitted, `where` filters rows, `population` is the row count. That is the tree adapter's vocabulary and the credential report's (`mfa_active eq TRUE where password_enabled eq TRUE`). It is not most of upstream's. Of the 22 pinned AWS recipes with assertions, 20 write `field` as **`<label>.<JMESPath>`** — `mfa-enabled-for-iam-console-access.EvaluationResults count_eq 0`, `describe-organization.Organization.FeatureSet eq ALL`, `list-roots.Roots[0].PolicyTypes[?Type=='SERVICE_CONTROL_POLICY'] | [0].Status exists` — where the label names the step (its Config rule name, or its CLI operation) and the path is evaluated over that step's whole JSON document. Intake therefore keeps every step's parsed output under its label (by rule the step's `--config-rule-name`, else its CLI operation; by a reviewed row in `recipes/aws-actions/labels.json` where upstream chose a name by hand — steps sharing a label merge their documents, which is how three calls about one Config rule read as one) as well as the union of its collection rows, and evaluates each assertion in the vocabulary its `field` is in (`packages/core/src/assert-labeled.ts`, since T2-5): resolve the label, evaluate the JMESPath over that document, apply the op to what it yields — `count_eq`/`count_lte` over the length, `eq`/`in`/`lte`/`gte`/`max_age_days` over a scalar or every element, `exists`/`not_exists` over presence — with `population` the element count and **nothing vacuous**: `eq` over an empty projection fails, a label the run did not produce fails naming it, a path that does not parse fails naming the recipe's own defect. A failing element that names a resource under AWS's keys becomes an offender pointer with `resource_id`, `resource_type`, `region`. One approximation, stated in the result's detail: a labeled `where` names its own path, which cannot be aligned element-for-element with the assertion's, so it is a guard — the assertion applies when any element at the where-path satisfies it, and is then judged over every element (one pinned assertion uses this).

### 14.5 What T0-4 already holds the contract to

`packages/cli/test/runs-intake.test.ts` commits, under `it.fails` until T2-2/T2-3, the five transcripts a naive reading would sign `evidenced` and this section forbids: an AccessDenied step; `count_eq 0` over a non-zero exit's empty output; a credential report still `STATE=STARTED`; a transcript from a different account; a replayed nonce. Each asserts no `evidenced` bundle and a class or refusal. They failed at `b2133f0` because no intake existed; they pass since T2-2/T2-3, so §14.2 is enforced by a test.
