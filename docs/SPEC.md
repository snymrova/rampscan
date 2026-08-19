# rampscan — working spec

**Status:** draft spec, brainstorm-grade. Decisions marked **DECIDED** are settled unless contradicted by building; everything else is a recommendation with the reasoning attached.
**Date:** 2026-08-13
**Reads against:** `docs/COMPLIANCE-SCAN-HARNESS.md` (the founding doc — its §11 decisions bind this spec), `docs/context/ramprules/` (dataset 2026.07.14.01), `docs/context/harnessarch/` (the code-graph and domain-harness arguments).

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
6. **What drives the scheduler at class d?** `VDR-TFR-MVX` defines windows for classes a (SHOULD, 1 month), b (MUST, 7 days), and c (MUST, 3 days) — **there is no class d entry**. The dataset's class-d clock is different in kind: tightest MUST is `VDR-TFR-MVF` (1 month), tightest overall `VDR-TFR-PSD` (SHOULD, 1 day — the tightest deadline in the whole dataset). Until this is settled, the config accepts b and c only; a class-d deployment needs its own cadence derivation from the evidence-plan clock, not a copy of the MVX one.
