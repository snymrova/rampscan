# rampscan — working spec

**Status:** draft spec, brainstorm-grade. Decisions marked **DECIDED** are settled unless contradicted by building; everything else is a recommendation with the reasoning attached.
**Date:** 2026-08-13 · **amended 2026-09-11** (§12, the KSI pivot — the Q0 spec amendment of `docs/PLAN-KSI-PIVOT.md`)
**Reads against:** `docs/COMPLIANCE-SCAN-HARNESS.md` (the founding doc — its §11 decisions bind this spec), `docs/context/ramprules/` (dataset 2026.07.14.01), `docs/context/harnessarch/` (the code-graph and domain-harness arguments); §12 additionally reads against `docs/RESEARCH-KSI-GAP-ENGINE.md` and `docs/RESEARCH-PARAMIFY-PILOT.md`.

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
  artifacts:       [{ name, sha256 }]                              // ≥ 1
  assertions:      [{ description, passed, detail?, population? }] // ≥ 1
  timestamp:       ISO 8601    // the client RUN's clock, not the ingest's
  signer_identity: string      // who ran it and stands behind it
  tool_versions?:  { [tool]: version }
  reproduce?:      string
}
```

Strict at every level, the manifest/contract rule: provenance is what an assessor pulls on (`FRR-PVA-AA-06`), and a misspelled field that parses to nothing is a question the interrogation view can no longer answer.

**Verdict is computed, never declared:** every assertion passed → `evidenced`; any failed → `violated`. There is no `unevidenced` submission — a run that observed nothing has nothing to submit, and the contract refuses empty `artifacts`/`assertions` structurally.

**What ingestion mints:** a regular `EvidenceBundle`, signed and appended exactly like a pipeline bundle (the bundle IS the ledger citizenship — no new statement type):

- Subjects are the submitted artifact digests. `anchor_paths: []` and `commit: ""` — ingested evidence has no commit anchor, so it dies superseded or goes stale (G3) but never dies by anchor drift, which is the honest death model for evidence about a cloud account rather than a checkout.
- `method_id = aws-ingested:<recipe_id>#<ksi>`; `evidence_class` copied from the submission — G6 asserted at the bundle's birth, the same slot the pipeline mint asserts.
- The predicate gains an optional strict `ingest { signer_identity, ingest_digest }` block, `ingest_digest = sha256(canonicalJson(submission))` — the address of exactly what was accepted. INCLUDED in evidence identity (`sameEvidence`), on the `collector`/`basis` side of that line: the same verdict handed over by a different signer, or derived from different submitted bytes, is different evidence. Pipeline bundles carry no block on either side of the comparison, so nothing existing re-keys.
- `run_id = ingest:<digest[0..12]>` — derived, never typed; the upstream run's identity is the digest itself.

**The method derivation** (§12.2's Q4.1 promise): `methodOfIngestedBundle(bundle)` is a pure function of the signed bundle — `automated: true`, `clock: "machine"`, `standing: "full"` (fixed per source today, exactly like `automated`; a submission-declared standing is a future field, not a default), provenance `{ recipe_id, signer_identity, ingest_digest }`. Methods stay derived, never authored: the ingested bundle is itself the reviewed artifact the register derives from, so the aws-ingested register is recoverable from the ledger alone.

**The tree adapter** meets clients where they already are (`docs/RESEARCH-PARAMIFY-PILOT.md` §3): `rampscan ingest <dir>` accepts an `Evidence/<family>/<KSI-ID>/<KSI-ID>.{json,csv}` tree plus an `ingest-manifest.json` the client authors — signer identity, evidence class (per-entry override permitted), cadence, and per entry the script name, exit code, and timestamp: exactly the facts the tree itself does not carry. The adapter's output IS native submissions (exit code → the single assertion; `population` = the result rows the script emitted), so the digest discipline is identical on both paths. The synthetic fixture mirrors those output shapes and is written by us — no code or fixture reuse (their repo has no license).

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
