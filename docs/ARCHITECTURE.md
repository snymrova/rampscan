# rampscan — architecture and data flow

**Status:** consolidated reference, derived from the spec and plan — it introduces no new decisions. Where this document and `docs/SPEC.md` disagree, the spec wins; where the spec and the founding doc's §11 decisions disagree, §11 wins (except §11.3's signing mechanism, superseded by the spec's cosign + KMS choice).
**Date:** 2026-08-13; built/design marking pass 2026-09-15 (`docs/PLAN-SOUNDNESS.md` S2-3).
**Reads against:** `docs/SPEC.md` (§2–§8), `docs/COMPLIANCE-SCAN-HARNESS.md` (§11–§13), `docs/context/README.md` (dataset facts, 2026.07.14.01).

---

## 1. What this document is

One place to see the whole machine: the system context, the components and their responsibilities, the data flow of a single scan end to end, the stores and what may write to them, the trust boundaries, and the lifecycle of an evidence bundle. It exists so that neither an agent nor a reviewer has to reassemble the architecture from three documents.

**Two halves, and the document marks which is which.** The machine is described in its appliance form — the deployment inside a client's AWS account that the spec designs. What *runs today* is the local half of the same architecture: every AWS dependency is a port in `packages/core`, each port has a local adapter, and the CLI runs the whole pipeline from a clone (README, "How it is run"). Nothing in the AWS half is built: there is no Terraform in the tree, no `@aws-sdk` or `cosign` dependency in any `package.json`, and `packages/core/src/` holds exactly one adapter family, `local.ts`. Where this document names an AWS service in the present tense, read it as *design*; §3's component table says per row what runs today and what is designed, and §7 marks each control the same way. Schemas, collector manifests, the bundle format, the join, and the projector are the same code in both halves — that is the ports-and-adapters claim, and it is the half that is built.

---

## 2. System context

rampscan is designed as a **single-tenant appliance deployed inside the client's AWS account**. Nothing — code, evidence, or model traffic — leaves the client's authorization boundary. The external world touches it in exactly four places, all narrow. (*Design.* Today the same boundary holds trivially, because the whole system is one process on the operator's machine reading a local checkout: the only outbound traffic is what a scan tool makes for itself, and `SECURITY.md` lists it.)

```
                                  ┌────────────────────────────────┐
   GitHub / GitLab  ──read-only──►│                                │
   (client's repos,   App token   │   rampscan appliance           │
    revocable)                    │   (client's AWS account,       │
                                  │    client's VPC, client's      │
   ramprules /api/* ──inbound────►│    S3 + KMS)                   │──► exports:
   (pinned dataset_version)       │                                │    OpenVEX ·
                                  │                                │    evidence packages ·
   OSV / package     ──inbound───►│                                │    frontier report
   metadata (proxy allowlist)     │                                │    (read by 3PAO
                                  │                                │     assessor + client)
   client SSO (OIDC) ──inbound───►│  console                       │
                                  └────────────────────────────────┘
```

The division of labor with ramprules, stated once: **ramprules answers *what is owed* and *what AWS APIs can prove*; rampscan supplies *what the repository and pipeline can prove*** — the `pipeline` evidence source that ramprules' automation frontier reserves (pinned rollup: 209 KSI-reached controls, 97 covered — 88 aws · 9 pipeline — 112 uncovered). Executing ramprules' AWS recipes is out of scope, as is any SaaS control plane.

Two consequences that shape everything below:

- **Operator-absent by design.** Nobody is at a terminal. EventBridge drives the MVX clock, runs happen unattended, and every human touchpoint is a two-key write surfaced through the console. (*Design*, except the two-key write, which is built. Today an operator is at a terminal, and the clock is `rampscan daemon` running in it.)
- **The appliance is inside the perimeter it produces evidence about** — which is what makes its attestations credible as evidence rather than as a third party's claims.

---

## 3. Component architecture

Single account, single tenant, two planes — and the control plane is deliberately almost nothing. The **Today** column is what a clone runs, with the package that runs it; the **Appliance** column is the design, none of it built.

| Component | Today (built) | Appliance (design) | Responsibility | Must never |
|---|---|---|---|---|
| **Scheduler** | `rampscan daemon`: a `setTimeout` tick chain in one process (`packages/scheduler`), warnings to stdout | EventBridge Scheduler | Fire scans so the freshest evidence never exceeds the class's MVX window (7d class b, 3d class c) | Accept class d until its cadence is derived (spec §11 open question 6) |
| **Scan pipeline** | `rampscan scan`: one process, collectors run one after another (`packages/cli/src/scan.ts`); the run record is signed into the ledger | Step Functions DAG | Orchestrate fetch → graph → collect → sign → append; retries, timeouts, run records | Be a barrier chain — stages pipeline; the only barrier is dedup/aggregation before projection |
| **Fetch task** | none — the operator points `scan` at a checkout already on disk; no GitHub App, no token | Fargate task: short-lived GitHub App token → shallow clone at a pinned commit into task-local storage | The commit hash of what is scanned is the anchor for everything downstream | Hold long-lived credentials; write anywhere but the workspace |
| **Graph-build task** | the `graph` collector (`packages/graph`): the TypeScript compiler's parser with lexical resolution, TypeScript/JavaScript only; exact vs inferred marked per edge; entry points detected over every application root | Fargate task; tree-sitter + SCIP for resolved references across languages | `graph.db` per repo-snapshot: symbols, imports, calls, routes, dependency nodes (the design adds IaC resources, log sinks, crypto uses) | Emit an inferred edge unlabeled |
| **Collector tasks ×N** | child processes spawned by the CLI, each tool a binary on `PATH` or a pinned container image (`packages/collectors`, `tools.json`); the only sandbox is the container's own | Fargate tasks, sandboxed (§7) | One per collector family (syft, osv-scanner, grype, gitleaks, semgrep packs, checkov, spectral, repo-facts…); emit findings + evidence candidates in the one shared schema | Reach the signing key; egress beyond the proxy allowlist; touch durable storage beyond the declared artifact prefix |
| **Join** | built: `packages/core/src/join.ts` | the same code | Findings × pinned ramprules dataset: recipe ID → KSI IDs → control IDs; produce per-recipe verdicts | Emit evidence for anything that doesn't resolve to a recipe (the ontology gate — such output is a finding only) |
| **Sign task** | `packages/signer`: ECDSA P-256 via `node:crypto`, a keypair on disk under `rampscan-keys/`, cosign's envelope format so `cosign verify-blob-attestation` can check it; in-process, reachable only from the CLI (§7, boundary 2) | a separate Fargate task class signing via cosign with the harness KMS key | Wrap each bundle as an in-toto statement and sign it | Execute repo content (it only reads artifacts — a compromised scan can corrupt its own artifacts but cannot sign them) |
| **Evidence ledger** | `packages/ledger`: a content-addressed append-only directory, `rampscan-ledger/objects/<sha256>` + `index.jsonl` | S3, Object Lock (compliance mode), KMS, content-addressed | The system of record: append-only signed bundles + `graph.db` snapshots + the incremental cache | Be rewritten, ever, by anything |
| **Projector** | built: `packages/projector`, pure, `rampscan rebuild` proves projection ≡ ledger | the same code, run after every write | `ledger → SQLite/PocketBase`: coverage per control, the three registers, freshness clocks, drift deltas, **anchor-death computation** | Hold a fact the ledger doesn't; be written by anything else |
| **Console** | `rampscan serve`: PocketBase + Next.js on localhost, PocketBase's own auth; projection collections writable by the projector alone, enforced by PocketBase rules | one ECS service, client SSO in front | Registers (evidenced / violated / unevidenced), clock view, drift, approvals queue, exports | Become the record — total loss of the projection costs one projector run |
| **Tier-3 verifiers** (Phase 3) | not built | Fargate tasks → Bedrock via VPC endpoint | Model-judged hypotheses on diff hunks with no deterministic collector; adversarially verified; survivors enter the ledger as `PLAUSIBLE`, visually quarantined | Borrow deterministic evidence's credibility; be the last step before an assertion |

Two surfaces the table does not list, because they are not stages of a scan, are built and run today: `rampscan ingest`, which accepts a client-run result as a ledger citizen (spec §12.8), and `rampscan artifacts`, the artifact plane (spec §13).

### Ports and adapters — one architecture, two deployments

Every AWS dependency is an interface in `packages/core` (`ports.ts`); the local prototype and the appliance differ only in adapters. Schemas, collector manifests, bundle format, and the projector are **identical** in both worlds. The left column below is built; the right column is the design, and no adapter in it exists.

| Port | Local adapter (prototype, M0–M5) | AWS adapter (appliance) |
|---|---|---|
| `LedgerStore` | content-addressed append-only dir (`ledger/objects/<sha256>`, `index.jsonl`) | S3 + Object Lock + KMS |
| `Signer` | cosign keypair on disk | cosign + AWS KMS |
| `Runner` | child process / Docker | Fargate task |
| `Scheduler` | node-cron + CLI (`rampscan daemon`) | EventBridge Scheduler |
| `RepoSource` | local path or git clone | GitHub App, short-lived tokens |
| `Projector` | pure — identical in both worlds | pure — identical in both worlds |

---

## 4. Data flow — one scan, end to end

Drawn in its appliance form. Today the same eleven steps, minus ② and ⑪, run inside one `rampscan scan` process against a checkout on disk, with the local adapter from §3 standing in at every box that names an AWS service: the trigger is the CLI or `rampscan daemon`, the ledger is a directory, the signature is a key on disk, the projection is PocketBase on localhost, and the alerts channel is the daemon's stdout.

```
 EventBridge clock ─┐
 push webhook ──────┼──► ① trigger ──► ② fetch ──► ③ graph build ──► ④ dirty set
 console "run now" ─┘                 (commit =                      (diff vs last
                                       the anchor)                    scanned commit)
                                                                          │
                     ⑧ append ◄── ⑦ sign ◄── ⑥ join ◄── ⑤ collect ◄──────┘
                     (S3 ledger,   (in-toto,   (recipe→KSI→   (Fargate fan-out,
                      Object Lock,  cosign+KMS) control IDs)   sandboxed, per
                      anchor death)                            collector family)
                          │
                          ▼
                     ⑨ project ──► ⑩ surface ──► (Phase 3: ⑪ escalate)
                     (fold ledger    (registers, alerts,
                      → PocketBase)   exports regenerate)
```

Step by step, with the invariant each step carries:

1. **Trigger.** EventBridge (the MVX clock), a repo push webhook, or a console button. Trigger metadata enters the run record — the run itself is evidence of the scan having happened (Step Functions execution history is retained for exactly this reason).
2. **Fetch.** Short-lived installation token → shallow clone at a pinned commit into task-local storage. **The commit hash is the anchor for everything downstream**; no artifact exists without it.
3. **Graph build.** tree-sitter (structure) + SCIP (resolved references) → `graph.db` for this snapshot. Every edge labeled exact or inferred.
4. **Dirty set.** Diff against the last scanned commit → changed nodes + blast radius per collector's declared depth. First scan is full; steady state is incremental. Cache key: `(collector, toolVersion, nodeContentHash, configHash, dataset_version)` — tool and dataset versions participate so upgrades invalidate honestly. A scheduled full re-scan diffs against the incremental result: **the cache verifies itself.**
5. **Collect.** Fargate tasks fan out, one per collector family, sandboxed (§8). Stages pipeline — a fast collector's output proceeds to signing while a slow one still runs. Each emits **findings** (shared schema + `ksi_ids`/`control_ids`) and **evidence candidates** (artifact + assertion results per pipeline recipe).
6. **Join.** Findings and candidates join to the pinned ramprules dataset: recipe ID → KSI IDs → control IDs, producing per-recipe verdicts (`evidenced | violated | unevidenced`). **The ontology gate:** anything that can't resolve to a recipe is a finding only, never evidence.
7. **Sign.** Each bundle becomes an in-toto statement — subject: artifact digests; predicate: recipe ID, commit, dataset version, tool versions, assertions, run ID — signed via cosign with the harness KMS key, in a task that never executed repo content.
8. **Append.** Bundles land in S3, content-addressed, under Object Lock. Evidence edges from prior commits whose anchoring content hash changed at this commit are marked `dead(anchor-drift)` **by the projector computing it**, with the killing commit recorded — never by anyone remembering to.
9. **Project.** The projector folds the ledger into PocketBase: current coverage per control, the three registers, freshness clocks, drift deltas. This is the DAG's one legitimate barrier — dedup/aggregation needs the whole run.
10. **Surface.** Registers update in realtime (PocketBase subscriptions); expiring-evidence alerts go to the client's channel (SNS → their choice); exports regenerate (OpenVEX, per-control evidence packages, the frontier report in ramprules' covered/partial/narrative/unreviewed vocabulary).
11. **(Phase 3) Escalate.** The routing model flags diff hunks implicating KSIs with no deterministic collector; tier-3 Bedrock tasks judge; adversarial verifiers refute or confirm; survivors enter the ledger as `PLAUSIBLE`, visually quarantined from deterministic evidence.

### 4.1 The join, magnified — this is the product

```
  collector output                 pinned ramprules dataset (dataset_version)
  ─────────────────                ─────────────────────────────────────────
  findings[]        ─┐             pipeline recipes: id → ksi_ids → control_ids,
  evidence           ├── join ──►  assertions, cadence, automatable, caveats
  candidates[]      ─┘                    │
  (artifacts +                            ▼
   assertion results)      per-recipe verdict
                           ├─ evidenced   (artifact + passing assertions + live anchor)
                           ├─ violated    (negative evidence — same shape, same rigor)
                           └─ unevidenced (the honest default; always displayed)
```

The reasoner rule is mechanical and total: **no evidence without a recipe ID + artifact + passing assertions + live anchor.** The unevidenced register is never hidden — the gap between catalog and graph *is* the product.

### 4.2 The two-key write path

Human judgments (`notApplicable` scoping, narrative approvals) flow *through* the console but *land* in the ledger:

```
 draft in console ──► approver signs (their SSO identity,     ──► appended to ledger ──► appears in
 (proposal object)     recorded in the attestation)                as a signed event        registers via
                       [Phase 3: independent second judgment                                projection
                        precedes the human key]
```

Two signature classes, never mixed: machine facts carry the harness KMS identity; human judgments carry the approver's identity. One key for both would launder machine claims into human ones and vice versa. (*Design* — today one on-disk keypair signs both and the approver is a recorded field; §7, boundary 3, says exactly how far that gets.) PocketBase never holds a fact the ledger doesn't; if they ever disagree, the ledger wins and the projection is rebuilt.

### 4.3 The projection loop

`projector: ledger → SQLite` is a **pure function**. It is the only writer of projection collections, it runs after every ledger write, and it can rebuild the entire console state from the ledger at any time (`rampscan rebuild` proves byte equality on every run, and the e2e suite CI runs exercises it over every ledger citizen — bundles, scoping events, judgments, attestations, ingested results). This property is load-bearing: it is what keeps PocketBase an index instead of a record, and what makes swapping the projection store a one-component rewrite rather than a data migration.

---

## 5. Data at rest

Each store is named by its appliance form; what holds it today is in parentheses, and every one of those paths is gitignored and local to the machine that ran the scan.

| Store | Contents | Properties | Sole writer | Readers |
|---|---|---|---|---|
| **Evidence ledger** (S3; today `rampscan-ledger/`) | signed in-toto bundles, two-key write events, demotion events | append-only (Object Lock compliance mode), content-addressed, KMS-encrypted, client-owned; retention ≥ authorization timeline | sign task / ledger adapter | projector, `verify`, exports, assessor |
| **`graph.db` snapshots** (S3, beside bundles; today under `rampscan-out/` per run) | per-repo-snapshot code graph: symbols, imports, calls, routes, IaC resources, log sinks, crypto uses, dependency nodes | derived artifact, rebuildable from the commit; SQLite queried by recursive CTE (`reaches`, `pathBetween`); never loaded into PocketBase | graph-build task | reachability join, route-auth queries, console deep-links (Phase 4 canvas) |
| **Incremental cache** (today `rampscan-cache/`, used by `rampscan daemon`) | prior collector results keyed by `(collector, toolVersion, nodeContentHash, configHash, dataset_version)` | disposable; self-verifying via scheduled full scans | pipeline | pipeline |
| **Projection** (PocketBase/SQLite; today `console/pocketbase/data/`, or `rampscan-projection.db` for `rebuild`) | registers, coverage rollups, freshness clocks, drift deltas, users/roles | rebuildable; total loss costs one projector run | projector only | console, realtime subscriptions |
| **Dataset cache** (today the committed snapshot in `docs/context/ramprules/derived/`) | pinned ramprules slices (`/api/*`) | version-pinned; the system refuses to run on a `dataset_version` mismatch | dataset client | join, tier-3 context assembly |
| **Config** (`rampscan.config.json`, client's repo) | target class, repos in scope, semgrep packs, suppression policy, alert channels, entrypoint overrides | versioned, client-reviewed, hash-pinned into every run's provenance | client | pipeline |

### Anatomy of an evidence bundle

```
in-toto statement
├─ subject:    artifact digests (SBOM, VEX doc, call path, scan output …)
├─ predicate:  recipe ID → ksi_ids → control_ids   (the join, resolved)
│              commit hash                          (the anchor)
│              dataset_version, tool versions, config hash, run ID
│              assertion results                    (pass/fail, per recipe)
│              provenance flags (built: true, inferred edges, model IDs+prompts for tier 3)
└─ signature:  harness KMS key (machine)  —or—  approver identity (two-key writes)
```

---

## 6. Evidence lifecycle

Every evidence edge moves through this machine; no transition requires human memory:

```
                 join passes assertions,
                 bundle signed + appended
    (born) ──────────────────────────────► EVIDENCED ────────────► EXPIRING
                                            │  freshness clock      (age approaches the
                                            │  runs from append     class's MVX window;
                                            │                       alert fires BEFORE
              re-scan, assertions fail      │                       the window closes)
    VIOLATED ◄──────────────────────────────┤                            │
    (negative evidence — same               │                            │ re-scan on cadence
     shape, same signature rigor)           │                            ▼
                                            │                    re-EVIDENCED (new bundle,
              anchor content hash changed   │                     new anchor; old bundle
    DEAD(anchor-drift) ◄────────────────────┤                     remains in the ledger,
    killing commit recorded;                │                     verifiable forever)
    computed by the projector               │
                                            │  tool version bump / assertion flip
    DEAD(other causes) ◄────────────────────┘  → surfaced in the drift view: movement is the finding
```

Parallel states outside this machine: `unevidenced` (the default for every in-scope recipe with no bundle — displayed, never hidden), `notApplicable` (only via the two-key write), and `PLAUSIBLE` (tier-3 survivors, quarantined until a deterministic check is written for them — the demotion pipeline, itself recorded as ledger events).

---

## 7. Trust boundaries

Three boundaries, each with a stated rule, and each marked with what enforces it today. A rule is an operating control only where something in the tree refuses the crossing; the rest is design, and a reader weighing the appliance's security posture should weigh only the first kind.

**Boundary 1 — untrusted repo content vs the client's account.** Scanning executes untrusted code (resolvers, build scripts). Collector tasks are designed to run with: no internet route except a proxy allowlist (ramprules dataset, OSV, the registries a given collector legitimately needs); task IAM scoped to write one artifact prefix and read the clone, nothing else; ephemeral workspaces that die with the task; and a static-first bias (lockfile resolution over `npm install`) — where a build is unavoidable it runs in the most restricted task class and its outputs carry `built: true` so an assessor can discount them. *Design — none of the four is deployed.* Today collectors are child processes with the operator's own privileges and network, sandboxed only as far as a tool's container image sandboxes itself; what is built is the static-first bias — no collector runs a build or an install (`SECURITY.md`, "What rampscan sends anywhere"), so today there is nothing for a `built: true` flag to mark and the schema does not carry one.

**Boundary 2 — scan output vs the signature.** The signing key is not available to collector tasks. Signing is a separate task that reads artifacts and never executes repo content. A compromised scan can corrupt its own artifacts but cannot sign them. *Built, as a code boundary rather than a process one:* `packages/signer` is importable only from `packages/cli` by this repository's own architecture contract (`rampscan.config.json`, rule `signer-only-through-the-cli`), and `rampscan check` fails the pull request that crosses it. Signing happens in the same process as collection today; the separate task class is design.

**Boundary 3 — machine claims vs human judgment.** The two signature classes (§4.2). FedRAMP's own split between automated evidence and narrative is exactly this line; the signatures follow it. *Half built, and the half matters:* a scoping event or an artifact judgment carries the approver's identity in the signed predicate — what the approver signs is the reasoning, and the projector flips a register only on that event — and the schema refuses `source: computed` for the two artifacts that are the provider's own claim (spec §13.4). But the *signature* on a human judgment today comes from the same on-disk keypair that signs machine bundles; the two classes are separated by a recorded field, not by two keys. The second key — the approver's SSO identity as the signing identity — is design, and until it exists a reader should treat the human/machine line as declared rather than cryptographically enforced.

Supporting rules, all *design*: Bedrock traffic stays in-account via VPC endpoint (GovCloud when the boundary requires); repo access is a read-only GitHub App whose activity appears in the client's audit log — the access is itself evidenced; and the appliance updates only by client-initiated Terraform version bump — no auto-update channel into the boundary. Built today from that list: collector tool versions are pinned per release (`packages/collectors/tools.json`) and ride in every bundle's provenance, so the last clause holds without the deployment it was written for.

---

## 8. The clock

The scheduler exists because of one requirement: `VDR-TFR-MVX` ("Persistent Machine Verification and Validation") — a MUST with a window of **7 days at class b, 3 days at class c**. The cadence logic is: class → window → re-scan early enough that no live bundle's age exceeds the window, with nearing-expiry alerts firing *before* the window closes, not after. Class a is SHOULD/1 month; **class d has no MVX entry** and is refused by config until its cadence is derived from the evidence-plan clocks (spec §11, open question 6).

The clock is also why the ledger's shape matters: with `asOf` anchors on every edge, "are we compliant?" reduces to "which evidence edges died since the last window?" — drift detection with a legal meaning.

---

## 9. Invariants — the rules that hold the architecture together

1. **The ledger is the record; everything else is a projection or a cache.** Append-only, content-addressed, signed, client-owned.
2. **Every evidence claim carries a commit anchor**, and dies automatically when the anchor changes. Staleness is computed, not confessed.
3. **The ontology gate:** no evidence without recipe ID + artifact + passing assertions + live anchor. Unresolvable output is a finding, never evidence.
4. **The unevidenced register is always visible.**
5. **Two signature classes, never mixed**; the signing key never coexists with repo-content execution. (The first clause is design until the second key exists — §7, boundary 3; the second is a code boundary today, and a process one in the design.)
6. **The projector is pure and is the only writer of the projection.** Ledger wins every disagreement.
7. **Collectors are manifests, not pipeline code** — one shared finding schema, Zod-enforced; adding a collector adds a manifest.
8. **Versions pin everything**: `dataset_version`, tool versions, config hash, model IDs — all in the cache key and the provenance.
9. **Tier 3 never borrows tier 1's credibility**: model output is `PLAUSIBLE`, quarantined, and only graduates by demotion into a deterministic rule — every demotion a ledger event.
10. **The graph is derived, honest, and secondary**: rebuildable from the commit, inferred edges labeled, and never the primary console surface — registers first.
