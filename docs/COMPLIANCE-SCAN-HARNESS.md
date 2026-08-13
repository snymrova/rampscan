# The Compliance-Scan Harness — a brainstorm

**Status:** brainstorm, not committed work — since amended by the decisions log (§11–§13) and superseded in detail by `docs/SPEC.md`. Written in the harnessarch repo; it now lives here as rampscan's founding doc, and references to "this repo" in §11.5 mean harnessarch.
**Date:** 2026-08-13
**Reads against:** `docs/context/harnessarch/CODE-GRAPH-HARNESS.md` (the shared code graph, the finding schema, the three tiers), `docs/context/harnessarch/DOMAIN-HARNESSES.md` §4.3 (compliance is the non-code domain that kept its compiler) and §5.1 (the ontology gate), and — in the harnessarch repo, where this was written — the eleven primitives (`src/lib/pillars.ts`) and the `OntologyGate` widget in `src/components/diagrams/widgets/`.

---

## 1. The idea in one paragraph

A harness that scans a codebase **for compliance** — not "compliance" as a checkbox product, but as the two earlier brainstorms colliding on purpose. The code-graph doc says: build one shared graph of the code that every analyzer writes findings onto. The domain doc says: compliance is the rare domain whose oracle is *published* — the control catalog is enumerated, versioned, machine-readable, and nobody's invention. Put them together and you get a harness whose job is to **connect two formal models** — a graph of what the code *is* and an ontology of what the rules *require* — and to manufacture the edges between them, with evidence attached, continuously. The output is not a report. It is a living claim: *control AC-6 is satisfied by these seven code facts, here is the artifact for each, and here is the commit where one of them stopped being true.*

The claim worth testing: **compliance tooling today is either code-blind or catalog-blind.** Scanners (Semgrep, CodeQL, Snyk, trivy) see the code and emit findings with no idea which obligation a finding serves. GRC platforms (Vanta, Drata, and the audit spreadsheets they replaced) see the catalog and collect evidence by questionnaire and API screenshot, with no model of the code at all. The join — *this control, evidenced by this symbol, in this commit* — is done by a human, once a year, under deadline, and it rots the day the audit ends.

---

## 2. Why this is the strongest possible harness case

Walk the four luxuries from `DOMAIN-HARNESSES.md` §2 and notice something unusual: **this domain keeps all four.**

| Luxury | Status here |
|---|---|
| A compiler / test suite | **Kept twice.** The code has its compilers; the domain has its catalog. Two oracles, one on each side of the join. |
| Git | Kept. Evidence can be anchored to commits, and drift is a diff. |
| Text corpus, self-describing, local | Kept. Code, IaC, CI config, policy docs — all text, all in repos. |
| Operator is technical | Kept — mostly. The engineer runs the scan; the *auditor* reads the output. Axis 5 bites at the reporting boundary, not the scanning one. |

Most domain harnesses are defined by which luxury they lose and what rebuilds it. This one is defined by having both formal models already in hand and **the join missing**. That makes it the cheapest place to demonstrate the site's deepest claim — that verification outside the happy path comes from a formal model of the domain, not from a longer prompt. The ontology gate widget makes that argument on one refund. This harness makes it on an entire regulatory catalog.

And the reasons to scan are plural by nature, which is exactly the code-graph doc's "many variables, one graph" shape:

- **Security controls** — access control, crypto, logging, session handling (NIST 800-53, SOC 2 CC-series, FedRAMP baselines).
- **Data protection** — PII flows, retention, residency, erasure paths (GDPR, HIPAA, DPDP).
- **Licensing & provenance** — SBOM, license conflicts, supply-chain attestations (SPDX, SLSA).
- **Payment & industry rules** — cardholder-data scope, key management (PCI-DSS).
- **AI-specific obligations** — model usage disclosure, logging of automated decisions, data-lineage duties (EU AI Act — new enough that no incumbent owns it, which matters).

Five reasons to scan, one codebase, one graph. The silo boundary between them is where the useful questions live — "does any dependency of the payment path carry a copyleft license?" needs the license scanner and the reachability graph to share a substrate.

---

## 3. The three ontologies

"Use ontologies" is the brief. The precise version: this harness needs **three**, and the third is the product.

### 3.1 The control ontology (the demand side)

Not invented — *ingested*. NIST publishes 800-53 in **OSCAL** (machine-readable JSON/XML: catalogs, profiles, system security plans, assessment results). FedRAMP baselines are OSCAL profiles over it. SOC 2, ISO 27001, and PCI have community crosswalks (e.g., the Secure Controls Framework). The ontology layer adds what the flat catalog lacks:

```
Control ─ partOf ─→ ControlFamily
Control ─ requires ─→ Capability        ("encryption at rest", "audit logging", "least privilege")
Control ─ satisfiedBy ─→ EvidenceKind   (config | code-fact | attestation | process-doc)
Control ─ mapsTo ─→ Control             (cross-framework: AC-6 ≈ CC6.3 ≈ ISO A.8.2)
Control ─ supersededBy ─→ Control       (revision lineage — Rev4 → Rev5 is a real migration)
```

`mapsTo` is quietly the highest-value relation in the file: evidence gathered once should discharge obligations across every framework that shares the capability. That is the fact that makes multi-framework compliance sublinear instead of N audits — and it is a graph query, not a feature.

### 3.2 The system ontology (the supply side)

This is the code graph from `CODE-GRAPH-HARNESS.md` §3, extended with the node kinds compliance cares about and code-scanning tools ignore:

```
kind ∈ ... | data-store | data-flow | trust-boundary | identity | secret-ref
         | crypto-use | log-sink | third-party-service | deployment-target
```

The edges that matter are **data-flow edges** — `reads`, `writes`, `transmits`, `crossesBoundary` — because nearly every data-protection obligation is a statement about where a class of data may and may not travel. The static-analysis honesty rule from the code-graph doc applies with extra force: a taint edge inferred by a model must be *marked* as inferred, because an auditor relying on a guessed edge is worse than an auditor with no graph.

### 3.3 The mapping ontology (the join — the actual product)

The bridge relations, and the discipline that they are **claims requiring evidence**, never annotations:

```
CodeFact ─ evidences ─→ Control        { confidence, evidence[], asOf: commitHash, expiresWhen }
CodeFact ─ violates ─→ Control         { same shape — a violation is a negative evidence edge }
Control  ─ notApplicableTo ─→ System   { justification, approvedBy — the two-key write }
Control  ─ unevidenced                 { the honest default state }
```

Three design rules, each one a lesson imported from elsewhere in the docs:

1. **`asOf: commitHash` on every edge.** Evidence is a statement about a snapshot. The content-hash anchoring from the code-graph doc (§3.1) is what lets an evidence edge *die honestly* when the code it described changes — which is the entire difference between continuous compliance and a screenshot folder.
2. **`unevidenced` is the default, and it is displayed.** A compliance board that only shows green and red is hiding its largest category. The unevidenced set is the work queue.
3. **`notApplicableTo` requires the two-key write** (`DOMAIN-HARNESSES.md` §5.2). Scoping a control out is the single most abused move in real audits; here it is a proposal that a named human commits, with the justification stored as a first-class object.

The reasoning layer over the triple store can be genuinely boring technology — datalog or SHACL, not a model. "Every Control in the active profile must have ≥1 `evidences` edge whose `asOf` is within the current evaluation window, or appear in the unevidenced report" is a rule an engine checks in milliseconds, deterministically, forever. **The ontology gate generalized: no compliance assertion ships unless it resolves to a control ID and an artifact.** That sentence is already in DOMAIN-HARNESSES §4.3; this harness is that sentence with an implementation.

---

## 4. The scanners, tiered by oracle strength

Same discipline as the code-graph doc §4 — cheapest and most certain first, and tier 3 never borrows tier 1's credibility.

### Tier 1 — deterministic. No model. Run on every commit.

- **SBOM generation + license resolution** (SPDX / CycloneDX) — every dependency, its license, its lineage. License conflicts against a declared policy are a lattice check, not a judgment.
- **Advisory matching** (OSV, GHSA) against the SBOM — with the crucial upgrade in tier 2 below.
- **Secrets & credential scan** — entropy plus provider-specific patterns; findings anchor to `secret-ref` nodes.
- **Crypto inventory** — every use of a crypto API, resolved to algorithm and mode. FIPS-relevant controls are then a *set-membership check* against an allowed list. This one variable discharges a surprising fraction of a FedRAMP crypto narrative.
- **IaC posture** — Terraform/K8s/CI config against policy-as-code (**OPA/Rego or Cedar**). Encryption-at-rest flags, public-bucket checks, network policy. The policies themselves live in the repo, versioned, which makes Instructions inspectable.
- **Logging coverage** — which routes/handlers emit to an audit `log-sink`, mechanically. AU-family controls want exactly this table.
- **Semgrep/CodeQL query packs, one pack per control family** — each query annotated with the control IDs it evidences, so a passing query *writes an `evidences` edge* and a failing one writes a `violates` edge. This is the move that makes existing scanners catalog-aware without rebuilding them.
- **Config drift vs. the SSP** — the deployed configuration diffed against what the System Security Plan claims. Movement is the finding.

### Tier 2 — flow-sensitive and generated. Run on the dirty set.

- **PII taint analysis.** Annotate sources (`data-store` nodes holding personal data, request fields) and sinks (third-party services, logs, analytics), then propagate. The finding is a *path* — "email address reaches the analytics SDK through these four hops" — which is simultaneously a GDPR Article 28 fact and a debuggable trace. The path **is** the evidence.
- **Reachability-gated advisories (VEX).** An advisory in a dependency whose vulnerable function is unreachable from any entry point is a different obligation than one on the request path. The code graph's `reaches()` query turns a 400-line vulnerability report into a ranked one, and the output is a **VEX document** — a machine-readable "affected / not-affected, because" statement, which is itself audit evidence. This is the single clearest place where the shared graph pays for itself: no SBOM tool can do this without the call graph, and no call-graph tool bothers because it doesn't hold the SBOM.
- **Erasure-path testing.** GDPR's right to erasure is a *testable property*: create a synthetic subject, exercise the deletion path, then scan every `data-store` for residue. A generated test, run in a sandbox, producing a pass/fail artifact — tier 2 exactly as the code-graph doc defines it.
- **Retention verification** — do the TTLs configured in code match the retention schedule the policy documents claim? A join between a config scan and a parsed policy doc.
- **Boundary tests** — generated probes that verify a declared `trust-boundary` actually rejects what the SSP says it rejects.

### Tier 3 — model-judged. Hypotheses until adversarially verified.

- **Novel-code-to-control mapping.** A new module lands; which control families does it implicate? This is a routing judgment over the whole diff — the model proposes `evidences`/`violates` candidate edges, verification tries to refute them, and only survivors reach the graph, marked `PLAUSIBLE` until a deterministic check can be *written* for them (see §6 — this is the demotion pipeline).
- **Narrative ↔ code consistency.** The SSP says "all administrative actions require MFA"; does the code agree? The model reads both sides of the join and reports mismatches — the one job neither formal model can do alone, because one side is prose.
- **Policy-doc drift** — the internal policy changed; which existing evidence edges does the change invalidate?
- **Logic-level control violations** — the authorization check that types cannot see; the second refund. The OntologyGate widget's home turf.

---

## 5. Micro-LLMs — the cascade, and why this domain wants them badly

"Micro-LLM" here means small models — sub-1B to ~3B, fine-tuned, cheap enough to run **inside CI on every commit, on-prem** — sitting between tier 1's regexes and tier 3's frontier calls. Compliance is the domain where they earn their keep for a reason beyond cost:

**The data cannot always leave.** A compliance scanner that ships the codebase to a frontier API is, for many of its best customers, itself a compliance violation. A cascade whose first two model tiers run locally is not an optimization — it is a market-access requirement. (The de-identified sandbox pattern, §5.5 of the domains doc, applied to the harness itself.)

The cascade:

```
tier 0   regex / AST / policy engine        — free, exact, always
tier 0.5 micro-LLM classifiers (local)     — ~ms, runs on every hunk
tier 3   frontier model (escalation only)  — expensive, rare, adversarially verified
```

Jobs the micro tier is genuinely good at — all classification, none generation:

- **Control-relevance routing.** "Which control families does this diff plausibly touch?" A multi-label classifier over hunks. Its job is not to be right; its job is to decide *which expensive analyzers run*, which turns full-catalog scans into dirty-set scans.
- **PII-shape detection** in code, fixtures, logs, and schema definitions — pattern-plus-context judgments where regexes drown in false positives.
- **License-text classification** for the vendored files and README fragments SPDX matching misses.
- **Finding triage & dedup** — "are these two findings the same problem?" — the barrier stage of the fan-out, run locally.
- **Commit/PR classification** — does this change claim to be compliance-relevant? Feeds the evidence ledger's timeline.

**The distillation loop is the Evolution primitive made literal**, and it is the most interesting design element in this doc:

```
tier-3 finding → adversarially CONFIRMED → labeled example
  → periodically fine-tune the micro tier on accumulated confirmations/refutations
  → a class of judgment that was frontier-priced becomes CI-priced
  → and where possible, demote further: confirmed pattern → Semgrep rule → tier 1
```

The harness gets cheaper and sharper simultaneously, the frontier model's role shrinks toward the genuinely novel, and every demotion is *documented* — which, in this domain, means the scanner can explain its own detection lineage to an auditor. No other domain pays you twice for the same loop like that.

---

## 6. The rest of the cutting edge, each earning its line

- **GraphRAG, properly.** Context delivery for tier 3 is not embedding search over source files — it is *graph traversal*: the subgraph reachable from the diff, joined to the control subgraph implicated by the routing classifier, serialized compactly. Smaller and truer than any vector top-k. (This is the code-graph doc's §7 claim, and compliance is its best client: the relevant context is almost never textually similar to the question.)
- **Neurosymbolic division of labor.** The model *proposes* edges; the datalog/SHACL layer *decides* what the edges entail. The model is never the last step before an assertion. This is the single sentence that separates the design from "LLM compliance checker," and everything in §3.3 exists to enforce it.
- **Signed findings (in-toto / Sigstore).** Every finding and every `evidences` edge is an attestation: signed, timestamped, tied to analyzer version + commit + config hash. The evidence ledger becomes tamper-evident — meaning the *harness's output* is itself audit-grade, not a report about audit-grade things. SLSA provenance for the build pipeline slots in as just another tier-1 variable.
- **OSCAL out, not just in.** The harness *emits* OSCAL assessment results and (eventually) drafts the SSP's implemented-requirements section from the evidence graph. The SSP stops being a Word document written annually and becomes a build artifact with a diff. This is the demo that makes an auditor sit up.
- **Continuous compliance as drift detection.** With `asOf` anchors, "are we compliant?" becomes "which evidence edges died since the last window?" — the seo-drift shape (`DOMAIN-HARNESSES.md` §4.8) pointed at a domain where drift has a legal meaning.
- **The remediation loop, two-keyed.** An agent proposes the fix for a `violates` edge in a worktree; the gate is mechanical (the violation clears, no new finding in the blast radius, tier 1 green) *plus* a human key for anything touching a control narrative. Same loop as the code-graph doc §7, stricter second key.

---

## 7. The eleven slots

| Primitive | In this harness |
|---|---|
| **Instructions** | The active profile: which frameworks, which baselines, which policies-as-code. Versioned in-repo; the harness's "house rules" are literally the org's declared obligations. |
| **Context Delivery** | Graph traversal over the joined ontologies (§6), never fuzzy search. The control catalog is context too — delivered by ID, not by similarity. |
| **Context Management** | The unevidenced set and the died-edges set are ranked into the window; 400 findings is noise with control IDs. |
| **Tool Interfaces** | Every scanner emits the one finding schema (code-graph doc §5), extended with `controls: string[]`. That one field is the whole integration story. |
| **Execution Environment** | Scans run on untrusted code (build scripts execute); erasure-path tests need a synthetic-data sandbox; and the cascade's local tiers exist because code may not leave the boundary. |
| **Durable State** | The evidence ledger — triple store + attestations — with audit-cycle retention measured in years and re-openable per episode. The domains doc called this compliance's load-bearing slot; still true. |
| **Orchestration** | Routing classifier → dirty-set fan-out → dedup barrier → verification pipeline. Analyzers pipeline; only dedup barriers. |
| **Sub-agents** | Adversarial verifiers per tier-3 hypothesis; independent concurrence on `notApplicable` proposals — the clinical second-reader justification, not the throughput one. |
| **Skills** | One procedure per control family: "how we evidence AU-2," "how we investigate a PII path." The demotion pipeline turns confirmed procedures into query packs. |
| **Verification** | The catalog is the oracle; the reasoner is the gate; tier 3 is hypothesis-only. The harness also verifies itself: false-positive rate per analyzer is a tracked variable with its own drift alarm. |
| **Evolution** | The distillation loop (§5) plus the demotion pipeline: frontier judgment → micro-LLM → deterministic rule. Sharper and cheaper on the same evidence, model frozen. |

Every slot has a non-obvious answer. Same tell as last time: that is the argument it is a harness and not a scanner.

---

## 8. Positioning, honestly

The incumbents each hold one piece: **Semgrep/CodeQL** (code, no catalog), **Wiz/Prisma** (cloud posture, no code graph), **Vanta/Drata** (catalog + integrations, no model of the code — evidence is API screenshots and policy acknowledgments), **FOSSA/Snyk** (SBOM, no reachability into *your* call graph joined to *your* control profile), **paramify/OSCAL tooling** (document plumbing, no scanning).

**The bet is the join** — the mapping ontology with evidence-carrying edges, anchored to commits, emitted as attestations. Nobody holds a graph where a Semgrep result, a taint path, and a FedRAMP control ID are three nodes with edges between them.

**And the risk, stated plainly:** the failure mode of this category is *compliance theater with better tooling* — a system that proves the paperwork is complete and internally consistent while describing a deployment that doesn't exist. The domains doc already wrote the sentence: *the catalog says what must be true, never whether it is true in this deployment.* Three commitments separate the useful version from the theater, and if the build can't hold all three it shouldn't start:

1. **Evidence edges die automatically** when their anchor changes. No manual re-attestation theater; staleness is computed, not confessed.
2. **The unevidenced set is always visible.** The product never hides the gap between the catalog and the graph — the gap *is* the product.
3. **Runtime tells on code.** At least one tier-1 variable diffs the deployed config against the claimed one, so the graph is tethered to a running system and not only to a repo.

---

## 9. Where it runs out of road

- **The ontology encodes what someone thought to encode.** Every axiom arrives the day after the loss that motivated it. The mapping ontology is a growing artifact, and its gaps are invisible from inside it.
- **Process controls have no code anchor.** Background checks, security training, incident-response tabletops — a third of any catalog never touches the repo. The harness must represent these as `EvidenceKind: process-doc` honestly rather than pretend the codebase is the whole system.
- **Taint analysis lies at boundaries.** Dynamic dispatch, serialization, queues, cross-service hops — the PII paths you most need are the ones static analysis loses. Marked-as-inferred edges mitigate the dishonesty, not the blindness.
- **The auditor is the real render target,** and auditors accept what they understand. An evidence graph nobody on the assessment team can read loses to a spreadsheet everybody can. The non-technical console (§5.8 of the domains doc) is not a nice-to-have here; it decides adoption.
- **Micro-LLM drift is a compliance surface.** A fine-tuned router that silently degrades will silently *not run* the expensive analyzers. The cascade needs its own eval set and its own drift alarm — the harness inherits the obligation to verify its cheapest components, not only its smartest ones.
- **Framework revisions are migrations.** Rev4 → Rev5 renumbered and split controls; every `evidences` edge keyed to the old ID needs a lineage-aware migration, or the ledger's history becomes unreadable. This is the memory pillar's stale-fact failure with a legal deadline attached.

---

## 10. Build order, if it were built

The smallest loop that is genuinely useful the day it lands — and, as before, it is **not** the graph:

**SBOM + reachability-gated advisories → VEX.** Dependency scan, call-graph reachability from entry points, and the output is "of 61 advisories, 9 are reachable; here are the paths; here is the signed VEX." One tier-1 variable, one tier-2 join, one artifact an auditor and a security team both already want, no ontology store, no model anywhere. It also forces the two hardest substrates (SBOM + call graph) to exist early.

Then, by value per unit of work:

1. **Crypto inventory + logging coverage** — two more tier-1 variables that each discharge a whole control-family narrative.
2. **The control ontology + mapping store** — ingest OSCAL, land the `evidences` edge schema, ship the unevidenced report. The moment two variables map to controls, the join has to exist.
3. **Semgrep/CodeQL packs annotated with control IDs** — makes the existing scanner ecosystem write into the graph.
4. **PII taint paths** — the flagship tier-2 variable and the GDPR story.
5. **The micro-LLM router** — only now, once there are enough analyzers that *routing* is worth a model.
6. **OSCAL assessment-results out, attestation signing** — the auditor-facing artifact.
7. **Tier 3 + distillation** — last, deliberately, after tiers 0–2 have earned the board's credibility and generated the labeled data the micro tier trains on.

---

## 11. Decisions (2026-08-13) — the open questions, closed

The five open questions were resolved after reading the sibling project `~/Projects/ramprules.com/fedramp-rules-hub` — the FedRAMP Rules Hub. Its dataset changes the project's shape enough to get its own section (§12).

1. **Framework: FedRAMP only, and 20x-native.** Not generic OSCAL. The demand side is modeled the way FedRAMP 20x actually works — KSIs (Key Security Indicators) over control IDs, FRR requirements with force (MUST/SHOULD) and per-class clocks — because that model already exists, versioned and tested, in ramprules. §3.1's OSCAL framing survives as the import format, not the working ontology.
2. **Shared vs per-repo mapping: the line is the recipe.** The shared layer *is ramprules* — dataset + overlays, consumed via its `/api/*` slices and pinned to a `dataset_version`. The harness's contribution to the commons is a new overlay source ramprules already reserves a slot for: **`pipeline` evidence recipes** (currently 0 covered / 121 unreviewed in its automation frontier). The per-repo layer — which code facts in *this* repo discharge which recipe — lives in the scanned repo, keyed by recipe ID. Demand-side shared, supply-side local, joined on recipe IDs.
3. **Who signs: two signature classes, never mixed.** Machine facts are signed by the harness's workload identity (Sigstore keyless via the CI job's OIDC identity — the attestation names the exact pipeline run that produced the evidence). Human judgments — the two-key writes: `notApplicable`, narrative approvals — are signed by the approver's identity, separately. One org key for both would launder machine claims into human ones and human ones into machine ones; FedRAMP's own split between automated evidence and narrative is exactly this line, so the signatures follow it. *(Mechanism superseded by the spec §2: §13's in-account deployment removed the CI-OIDC premise, so machine facts are signed with cosign + AWS KMS instead of Sigstore keyless. The principle — two signature classes, never mixed — stands unchanged.)*
4. **Model tier: Amazon Bedrock, cascade for speed.** Bedrock is FedRAMP-authorized (High, in GovCloud), which dissolves the boundary problem that motivated local micro-LLMs — so the local tier is demoted from requirement to optimization. Speed and accuracy come from the cascade shape, not the model choice: dirty-set scanning keeps most commits at tier 0–1 (no model at all); a fast Bedrock model (Haiku-class) does routing and triage; the expensive model runs only on escalations and is adversarially verified. The distillation loop (§5) still runs — its target is now "fewer Bedrock calls per commit," measured as `costTokens` per confirmed finding on the board.
5. **harnessarch.com: no.** This is a standalone build in the ramprules orbit, not site content. The brainstorm stays in this repo's docs only because it was written here.

---

## 12. The ramprules substrate — what changed on contact

What the FedRAMP Rules Hub already holds (dataset `2026.07.14.01`):

- **The KSI graph:** 10 themes, 46 indicators, 373 KSI→control edges reaching 209 controls across 17 families. This is §3.1's control ontology, native to 20x.
- **246 FRR requirements** with force distribution, per-class variation, deadlines, and notification duties — including the one that justifies this entire harness: **`VDR-TFR-MVX`, "Persistent Machine Verification and Validation," a MUST with a clock — 7 days at class b, 3 days at class c.** Continuous machine-verified evidence is not this product's pitch; it is the regulation's text.
- **Evidence recipes** (`aws-evidence.json` overlay): recipe → KSI IDs → control IDs → AWS service → collection commands → expected output → assertions → cadence → `automatable` disposition → GovCloud caveats. This is §3.3's mapping ontology, already carrying evidence, already versioned against the dataset, already honest about what no API can prove.
- **The automation frontier:** of 209 KSI-reached controls, 88 covered by AWS recipes, 121 uncovered; automation ceiling ~52%; and a `bySource.pipeline` register at **zero** — the acknowledged, empty slot for repo/CI/code-derived evidence.

So the harness is no longer "build three ontologies and join them." It is: **fill the pipeline slot.** ramprules answers *what is owed* (per class, with clocks) and *what AWS can prove*; this harness supplies *what the repository and pipeline can prove* — SBOM and reachability-gated VEX, crypto inventory, SLSA provenance, IaC posture, logging coverage, taint paths — each emitted as a pipeline recipe in the same shape as the AWS ones, signed, anchored to a commit, and scheduled inside the MVX clock for the target class.

That reframing also fixes the build's cold-start problem: the first deliverable is not a graph or a scanner fleet, it is **pipeline recipes for the 121-control uncovered set**, adjudicated one control at a time exactly the way ramprules already adjudicates AWS coverage (automatable / partial / narrative), and contributed back as an overlay its frontier register is structured to receive.

---

## 13. Path ahead

**Scope and deployment model (2026-08-13).** Executing ramprules' AWS evidence recipes is **out of scope** — rampscan is the pipeline source only. And it ships as **software deployed into the client's AWS account**, not SaaS: a Terraform/CDK module (or AMI/ECS service) that runs inside the client's VPC, fetches their repos over a read-only, least-privilege connection (deploy key / GitHub App), scans in an ephemeral egress-restricted workspace, and writes signed evidence to a ledger the client owns (their S3/DynamoDB, their KMS keys). Bedrock calls stay in the same account and region — GovCloud when the client's boundary demands it. Three consequences worth stating:

- **The boundary argument closes.** Code, evidence, and model traffic never leave the client's authorization boundary. For a FedRAMP-pursuing client, the scanner is inside the perimeter it is producing evidence about — which is also what makes its attestations credible as evidence rather than as a third party's claims.
- **The Execution Environment primitive gets sharp.** Scanning means executing untrusted repo content (builds, resolvers) *inside a client's account*. The sandbox is not optional hygiene; it is the difference between an evidence collector and a supply-chain incident. No egress except an allowlist (ramprules dataset, package advisories), no IAM beyond the ledger write.
- **This is the Flue shape, not the OpenCode shape.** Nobody is at a terminal. EventBridge drives the MVX clock, runs happen unattended, and every human touchpoint is a two-key write surfaced through the client's own channels. The operator-absent design in `DOMAIN-HARNESSES.md` Axis 5 is the governing constraint from day one.

**Phase 0 — the contract.** Define the pipeline-recipe schema by mirroring `aws-evidence.json`'s recipe shape (`ksi_ids`, `control_ids`, collection, assertions, cadence, `automatable`, caveats) with `collection.kind: pipeline` and a commit-hash anchor. Pin to `dataset_version`. Adjudicate the 121 uncovered controls against what a repo/CI scan could ever prove — this produces the honest ceiling for pipeline evidence before any scanner is written, the same move ramprules made for AWS.

**Phase 1 — first collectors, tier 0/1 only.** SBOM + reachability-gated VEX, crypto inventory, SLSA provenance, IaC posture, logging coverage — chosen because each discharges whole KSI clusters from the adjudicated set. Output: signed evidence bundles (recipe ID + dataset version + commit + artifacts), runnable in CI, no model anywhere.

**Phase 2 — the clock and the ledger.** The evidence ledger with `asOf` anchors and automatic edge death; a scheduler that knows the target class's MVX window (3 or 7 days) and re-collects before edges expire. This is the point where the product does something the regulation demands and nothing else does.

**Phase 3 — Bedrock tier 3, last.** Narrative↔code consistency, novel-code-to-KSI routing, taint-path judgment — adversarially verified, `PLAUSIBLE` until refuted-or-confirmed, distilled downward into rules and recipes over time. Deliberately last, after the deterministic tiers have earned the board's credibility and produced the labeled data.
