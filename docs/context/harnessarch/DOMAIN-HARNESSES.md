# Domain Harnesses — a brainstorm

**Status:** brainstorm, not committed work. Nothing here is site content yet.
**Date:** 2026-08-12
**Reads against:** `src/lib/pillars.ts` (the eleven primitives), `src/lib/teardowns.ts` (OpenCode, pi, Flue), the FDE pillar's closing claim.

---

## 1. The gap this doc is poking at

The Harness pillar names eleven primitives. The Teardowns register walks three shipping harnesses down them — OpenCode, pi, Flue. Every one of those three is the same species: a **general-purpose coding harness, operated by an engineer, working on a repository**.

That is not a criticism of the register. It is the honest prior art available. But it means the site currently demonstrates the eleven slots on the single domain where the slots are easiest to fill — and never says so out loud.

The FDE pillar already promises the other half and then stops at the door:

> "Look at what an FDE actually deploys: instructions shaped to one customer's business, tools wired into their systems, procedures, verification — primitives assembled around a problem. That's a harness with a go-to-market."

If that sentence is true, there is a whole second register waiting: not *prior art* but **deployments** — the same eleven slots, filled by a business domain instead of a repo. This doc is the brainstorm for what those look like.

The generative question throughout:

> **When you leave the repository, which of the eleven slots stops having an easy answer — and what fills it instead?**

---

## 2. Four luxuries the coding domain gets for free

Before the domains, the thing that makes them different. Coding harnesses are the easy case for four specific reasons, and every reason is a primitive quietly pre-solved.

| Luxury | Which primitive it pre-solves | What it costs elsewhere |
|---|---|---|
| **A compiler and a test suite** | Verification & Observability | Most domains have no oracle. "Correct" is a judgment, and it arrives late or never. |
| **Git** | Durable State + Execution Environment | Actions are cheap to snapshot and cheap to undo. A refund, a dose, a filing, a published post — none of those revert. |
| **The corpus is text, self-describing, and local** | Context Delivery | `grep` works because code explains itself in the same medium the model reads. X-rays, phone calls, invoices, and video do not. |
| **The operator is an engineer at a terminal** | Orchestration | Approval gates work because someone competent is watching. In most domains the operator is a vet, a teacher, or nobody at all. |

Every domain below is characterised by **which of the four it loses**. That is the whole method.

Note the second-order effect: a harness that loses a luxury does not simply do without it. It **rebuilds it out of a different primitive** — and that substitution is where domain-specific architecture actually lives. Lose the compiler, and Verification & Observability gets replaced by a formal model of the domain (the ontology gate) or by a sampled human rubric. Lose git, and Execution Environment stops being a sandbox and starts being a *proposal queue*. That is the interesting content.

---

## 3. Five axes that shape a domain harness

A cleaner frame than "list of verticals". Any domain can be placed on five axes, and its position predicts which primitives carry the weight.

**Axis 1 — Reversibility of the terminal action.**
`git revert` → a draft email → a published post → a wire transfer → a drug dose.
The further right, the more Execution Environment and Orchestration dominate, and the more the harness's real product is a *gate*, not an output.

**Axis 2 — Verification substrate.**
Compiler → schema/ontology → published rule catalog → rubric → expert review → market outcome → nothing.
This is the single strongest predictor of harness cost. Domains with a formal catalog (compliance) are far closer to coding than they look. Domains where correctness is taste (media) need an entirely different verification story.

**Axis 3 — Latency of ground truth.**
Milliseconds (a type error) → minutes (a render) → days (a support resolution) → months (did the student actually learn? did the dog get better?).
Long-latency truth breaks the loop: the run ends long before its own result exists. Those harnesses need a *re-openable episode* — an episodic memory record you can come back and grade weeks later, and an Evolution mechanism that consumes graded episodes rather than in-run failures.

**Axis 4 — Corpus modality.**
Text in a repo → PDFs and forms → images and scans → audio and video → sensors and telemetry.
Off the text axis, Context Delivery stops being retrieval and becomes a *pipeline*: transcribe, OCR, segment, caption, index. The delivery layer grows its own sub-harness.

**Axis 5 — Operator literacy.**
An engineer at a terminal → a technical domain expert → a non-technical professional → nobody watching.
This is the FDE 2×2 restated as a harness property. Approval gates only work if the approver can evaluate what they are approving; otherwise the gate is theatre and the real check has to be structural. Note that "nobody watching" (Flue's premise) and "a non-technical operator" (FDE's premise) demand *the same* answer: the check cannot be a human reading a diff.

---

## 4. Case files — grounded in work that already exists

These are drawn from the actual project portfolio on this machine. They are the strongest candidates because they can be reasoned about concretely rather than invented.

### 4.1 Veterinary & pet-health advice
**Where it lives:** `ohmydog.rocks`, `ohmyvet-rocks`, `everything-dog`, `pawdhar`, `bos-dog`
**Unit of work:** one owner's question about one animal, answered.

**Luxury lost:** all four, but chiefly the oracle. There is no test that says the advice was right, and the feedback — the animal got better, or didn't — arrives days later through a channel the harness does not own.

**Load-bearing primitives:** Instructions (scope of practice is a *refusal boundary*, not a tone), Verification (provenance), Orchestration (escalation).

**What replaces the test suite:** two things stacked. First, **provenance as a required output** — every claim traces to a citable veterinary source, and an answer that cannot cite is an answer that does not ship. Second, a **red-flag classifier as a gate before generation, not after** — bloat, seizure, toxin ingestion, laboured breathing, and the rest short-circuit the whole loop into "call a vet now."

**The irreversible action:** there isn't one in software. The irreversible action happens in the owner's house, hours later, because the harness sounded confident. This is the domain's defining property — *the blast radius is entirely outside the system*, which means no amount of rollback machinery helps and the entire safety budget has to be spent before the words leave.

**Failure symptom → layer (LayerDebugger, extended):**
- "It gave dosage advice for a 4kg puppy" → Instructions (no scope boundary) + Tool Interfaces (no gate on the class of claim)
- "It reassured someone whose dog was bloating" → Verification (no triage classifier in the path)
- "It cited a source that doesn't say that" → Verification (provenance was requested, never checked)

**Runs out of road:** a harness can enforce that advice is cited, hedged, and escalated. It cannot make an owner call the vet. Beyond the gate, the domain's most important failure mode is unobservable to the system that caused it.

---

### 4.2 Clinical practice & medical imaging
**Where it lives:** `drkunal` (pulmonology practice), `lunglens` (imaging)
**Unit of work:** a scan read, a patient query triaged, a note drafted.

**Luxury lost:** the corpus is images and dictation; the operator is a clinician whose time is the scarcest resource in the system; and regulation makes the execution environment a legal object rather than a convenience.

**Load-bearing primitive:** **Execution Environment**, and it is not close. Flue's line — *"never API keys, tokens, or cloud credentials"* — restates exactly as *never identifiers*. The de-identification boundary is the same architectural move as the secrets boundary: the model does not avoid PHI, it never receives it. Identifiers are stripped on the way in and re-attached on the way out, outside the model's reach.

**What replaces the test suite:** a **second reader**. Sub-agents earn their place here for a reason they don't in coding — not throughput, but independent concurrence. Two readings that disagree is a signal, and the disagreement itself is the output that goes to the clinician.

**The irreversible action:** a finding that alters treatment. So the harness's terminal action is never the finding — it is a *draft finding queued for a licensed human*, which is the two-key write pattern (§5.2) in its strictest form.

**Runs out of road:** every gain in throughput is spent on the reviewing clinician's attention. A harness that drafts ten notes for one doctor to sign has moved the bottleneck, not removed it — and if the drafts are good enough to rubber-stamp, the gate has quietly stopped being a gate.

---

### 4.3 Compliance & controls
**Where it lives:** `ramprules-com-fedramp-rules-hub`
**Unit of work:** one control, evidenced.

**Luxury kept — and this is the interesting one.** Compliance is the rare non-code domain that *has a compiler*. The control catalog is published, enumerated, versioned, and machine-readable. Every requirement has an identifier. Every claim of satisfaction can be checked against a named control rather than against taste.

That makes this the **best first domain sheet on the site**, because it demonstrates the argument the OntologyGate widget already makes — that the missing verification layer in non-code domains is a *formal model of the domain* — on a domain where the formal model already exists and is nobody's invention.

**Load-bearing primitives:** Verification (the catalog is the oracle), Durable State (evidence has to survive an audit cycle measured in years, and be re-openable long after the run), Skills (each control family is a procedure).

**What replaces the test suite:** nothing needs to. The catalog *is* the test suite. The harness's job is to make every assertion resolve to a control ID and an artifact, and to refuse assertions that resolve to neither.

**Failure symptom → layer:**
- "It claimed a control was met with no evidence" → Verification (assertion accepted without artifact)
- "It cited a control from the superseded revision" → Semantic memory / Forgetting (stale fact outranking a current one — the memory pillar's exact failure)

**Runs out of road:** the catalog says what must be true, never whether it *is* true in this deployment. The harness can prove the paperwork is complete and still be describing a system that doesn't exist.

---

### 4.4 Learning & assessment
**Where it lives:** `miles`, `milesedu`, `scorm-tool`, `BOS/ed-cli`
**Unit of work:** a lesson authored, a learner assessed, a course packaged.

**Luxury lost:** ground truth is months out (Axis 3 at its extreme). Whether the course worked is knowable only after the cohort finishes.

**Interesting split — this domain is really two harnesses:**
1. **Authoring** — nearly a coding harness. SCORM packaging *does* have a compiler: the package either imports into an LMS or it doesn't. Verification is cheap. Ship this one first.
2. **Tutoring / assessment** — the hard one. The oracle is a rubric, the corpus is a learner's history, and the durable state is a **learner model that persists across months and must handle contradiction** ("they knew this in March; they got it wrong in May"). That is not a session store, it is the Memory pillar's semantic-plus-episodic problem with the forgetting layer doing real work.

**Load-bearing primitives:** Durable State and Context Assembly for tutoring; Verification for authoring.

**Runs out of road:** a tutor harness optimises what it can measure. Rubric-shaped learning is the risk — the harness gets very good at producing assessable answers, which is not the same as teaching.

---

### 4.5 Media production
**Where it lives:** `video-pipeline` (OpenMontage), `content-production`, HyperFrames, the OhMyDog reel and carousel pipelines
**Unit of work:** one rendered artifact.

**Luxury lost:** the oracle entirely — correctness is taste — and the corpus is audio and video.

**Load-bearing primitives:** **Orchestration and Durable State**, for a reason unique to this domain: *the tool calls are expensive and slow*. A render, a TTS generation, a model-generated clip — minutes each, money each, and non-idempotent. Flue's `step.do` recording exists precisely for this shape of work: record the step's result so recovery replays it instead of paying for it twice.

**What replaces the test suite:** a three-tier stack, cheapest first —
1. **Mechanical checks** that are genuinely objective and cover more than people expect: duration, aspect ratio, safe margins, audio peak levels, caption/audio sync drift, missing assets. This tier is a real compiler and is chronically under-built.
2. **Rubric evals** on a sample, judged by a model against a brand-locked spec.
3. **Human taste**, once, at the end — the scarcest resource, so it must be spent on the artifact and never on catching a wrong aspect ratio.

**Failure symptom → layer:**
- "It re-rendered everything after a crash" → Durable State (no step recording)
- "Every slide used a different accent colour" → Skills (procedure not shared across parallel workers) — the parallel-inconsistency failure, in a brand
- "The captions drift out by half a second at the end" → Verification (no mechanical check in the loop)

**Runs out of road:** taste doesn't compress into a rubric. A harness can guarantee the brand-locked constraints hold and produce something no one wants to watch.

---

### 4.6 Support desk
**Where it lives:** `telegram-support-harness-omd`, `telegram-support-bot` — already named a harness
**Unit of work:** one conversation, resolved or escalated.

**Luxury lost:** the operator. Nobody is at a terminal; work arrives from a channel at 2am. This is **Flue's premise exactly** — `dispatch()` from a verified webhook, running where no one is watching — which makes it the cleanest bridge from the Teardowns register to a domain sheet.

**Load-bearing primitives:** Orchestration (intake, verified channel, replay window), Context Assembly (the customer's history is the context), Verification (did this actually resolve?).

**What replaces the test suite:** the **reopen rate**. A ticket closed that comes back is a failed run, discovered days later. That is an Evolution feed with a long delay — and it argues for exactly the graded-episode mechanism in §5.3.

**The irreversible action:** anything that touches the customer's money or account. Which routes straight to the ontology gate — the LayerDebugger's "refunded the same order twice" symptom is a *support* failure before it is a commerce one.

**Runs out of road:** the harness resolves what it has seen. Its confidence is highest exactly where its coverage is — and a novel failure reads, to the model, like a familiar one.

---

### 4.7 Commerce operations
**Where it lives:** Shopify tooling
**Unit of work:** one write to a live ledger.

This is the OntologyGate widget's home domain, and the site already has the argument built. The whole domain sheet is one claim: **the tool schema has no objection to a well-formed catastrophe.** A second refund on the same order is a real order ID and a positive amount — type-valid, business-invalid — and the rule against it lived in the prompt, competing for attention with everything else.

**Load-bearing primitive:** Verification, in its ontology form. Types at the door, a formal model of the domain at the ledger, no side effect until both clear.

**Runs out of road:** the ontology encodes what someone thought to encode. It is a growing artifact, and every new axiom arrives the day after the loss that motivated it.

---

### 4.8 Search & marketing operations
**Where it lives:** the `claude-seo` toolchain
**Unit of work:** a page, changed and then judged by a third party.

**Luxury lost:** the oracle is *owned by someone else and changes without notice*. This is the only domain in the list where the test suite is adversarial and non-stationary.

**Load-bearing primitive:** Observability — specifically drift detection. The `seo-drift` agent's shape is the correct one: baseline the state, compare later, classify the delta. When you cannot verify a change is good, you can at least detect that the ground moved.

**Runs out of road:** attribution. The rank changed; the harness cannot prove it was the edit.

---

### 4.9 Publishing & CMS
**Where it lives:** `instatic`, `horizon`, the blog engine, this site
**Unit of work:** a page published.

Closest to home, and the closest to a coding harness — the corpus is text in a repo, git works, the build is a compiler. Worth including for exactly that reason: it is the **control** in the set, the domain where the four luxuries mostly survive, and the comparison makes the others legible.

The one primitive that changes character: Instructions become a *voice*, and voice is enforceable only by eval, not by lint. (This document's own house style is a case in point.)

---

### 4.10 Personal / life agent
**Where it lives:** `life-agent`
**Unit of work:** something in a real life, moved forward.

**Luxury lost:** the corpus has no boundary. Everything is potentially relevant, so Context Assembly and Forgetting carry the entire load, and there is no repo to scope retrieval to.

**Load-bearing primitives:** the whole Memory pillar, undiluted. This is the domain where the memory pillar's five questions *are* the architecture, and where "perfect recall with no forgetting is the coworker who reads out their entire diary" stops being a metaphor.

**Runs out of road:** trust is not a component. The most capable version of this harness is the one a person is least willing to run.

---

## 5. Patterns that recur across domains

The part worth extracting. These are candidate *named mechanisms* — the kind of thing the site's vocabulary is built from — and each one appears in three or more of the cases above.

**5.1 The ontology gate.** Where no test can exist, a formal model of the domain checks the write before it commits. Types at the door, ontology at the ledger. *(Commerce, compliance, clinical, support.)* Already built as a widget; the domain register would show it is not a one-domain trick.

**5.2 The two-key write.** The harness's terminal action is never the act — it is a *proposal* in a queue, and a second key commits it. The second key is a licensed human, an independent second agent, or a rule engine, and the choice is a function of Axis 5. This is the general form of "human in the loop," and stating it as a *write pattern* rather than a *UI* is what makes it survive the operator being absent. *(Clinical, commerce, compliance, support.)*

**5.3 The delayed-truth ledger.** When ground truth arrives weeks after the run, the episode has to be re-openable: a durable record that can be graded later, and an Evolution loop that consumes graded episodes rather than in-run failures. The harness learns on the domain's clock, not the session's. *(Vet, education, support, SEO.)*

**5.4 Escalation as a tool, not a failure.** Handing off to a human is a first-class tool call with a schema, a trigger set, and its own observability — not the absence of an answer. A harness that treats escalation as failure will train itself out of escalating. *(Vet, clinical, support.)*

**5.5 The de-identified sandbox.** The secrets boundary, generalised. The model never receives the identifiers; they are stripped inbound and re-attached outbound, outside its reach. *(Clinical, life-agent, support, anything with a customer.)*

**5.6 The three-tier oracle.** Mechanical checks → rubric evals on a sample → human taste, once. Cheapest tier first, and the human tier is spent only on what the first two provably cannot catch. The recurring mistake is skipping tier one because the domain "is subjective" — most subjective domains have more mechanical surface than they admit. *(Media, education, publishing, vet.)*

**5.7 The delivery sub-harness.** Off the text axis, Context Delivery grows its own pipeline — transcribe, OCR, segment, caption, index — with its own failure modes that present as model failures. A bad transcript looks exactly like a bad answer. *(Media, clinical, support, education.)*

**5.8 The non-technical console.** When the operator can't read a diff, the gate must show the *domain object* — the draft note, the proposed refund, the flagged control — never the tool call. This is FDE's fourth quadrant expressed as an interface constraint, and it is the reason a domain harness ships with a UI while a coding harness ships with a TUI.

---

## 6. The comparison grid

Which primitives carry unusual weight, by domain. Sized like the Teardowns grid: `●` dominant, `◐` material, blank means it behaves as it does in the coding case.

| Primitive | Vet | Clinical | Compliance | Learning | Media | Support | Commerce | Life |
|---|---|---|---|---|---|---|---|---|
| Instructions | ● | ◐ | ◐ | ◐ | ● | ◐ | | ◐ |
| Context Delivery | ◐ | ● | ◐ | ◐ | ● | ◐ | | ● |
| Context Management | | ◐ | | ● | | ◐ | | ● |
| Tool Interfaces | | | ◐ | | ◐ | ● | ● | ◐ |
| Execution Environment | | ● | ◐ | | ◐ | ◐ | ● | ● |
| Durable State | ◐ | ● | ● | ● | ● | ◐ | ◐ | ● |
| Orchestration | ● | ● | | | ● | ● | ● | ◐ |
| Sub-agents | | ● | ◐ | | ◐ | | | |
| Skills | | ◐ | ● | ● | ● | ● | | |
| Verification | ● | ● | ● | ● | ● | ● | ● | ◐ |
| Evolution | ◐ | | ◐ | ◐ | ◐ | ● | ● | ● |

Two things fall out of the grid, and both are worth saying on the site:

1. **Verification is dominant in every column.** In the coding domain it is the slot you get for free; outside it, it is the slot that defines the build. That single row is the strongest argument the domain register could make.
2. **Sub-agents are mostly empty.** In coding harnesses, delegation is about throughput and context hygiene. In domain harnesses it is rare — and where it appears (clinical), it is for *independent concurrence*, which is a completely different justification. Worth naming: the same primitive, used for an unrelated reason.

---

## 7. Adjacent domains, unbuilt

Sketched only. Included because they stress the axes in ways the portfolio doesn't.

- **Legal** — the corpus is authoritative text (good), the oracle is precedent and a partner's judgment (bad), and the irreversible action is a filing with a deadline. Closest cousin to compliance, with taste added.
- **Financial back office** — reconciliation is an ontology gate with money attached; every failure is a two-key-write failure. The domain where §5.2 is a regulatory requirement rather than a design choice.
- **Field & physical operations** — the terminal action dispatches a *human in a van*. Maximum irreversibility, minimum observability, and the execution environment is the physical world. The pure case for the proposal queue.
- **Scientific lab work** — the tool call takes three days and consumes reagents. Media production's expensive-step problem with the cost curve made vertical.
- **Public sector / benefits** — Axis 5 at its hardest: a non-technical operator, a citizen affected, and a legal duty to explain the decision. Provenance stops being good practice and becomes the output.

---

## 8. If this ships on harnessarch.com

Three shapes, weakest to strongest.

**A fifth pillar ("Domains").** Wrong, probably. The four pillars are a closed chain — harness → memory → sdlc → fde → harness — and the chain closing is the product. Inserting a fifth breaks the one structural claim the site makes.

**A second register beside Teardowns.** Right shape. Teardowns are *prior art*; this would be *deployments* — the same eleven slots, walked down a domain instead of a codebase, with the same `● ◐ ○` marking and the same "runs out of road" close. It inherits the whole visual and vocabulary system for free, which is most of the build.

**A single essay plus one worked domain.** The honest minimum, and the best first step. The essay is §2 and §3 — the four luxuries and the five axes — and the worked domain is **compliance**, because it is the one domain with a real published oracle, no invented evidence, and an existing widget (OntologyGate) that already makes half its argument.

### The evidence constraint — read this before writing any of it

PRODUCT.md Principle 5 and the Evidence section are binding here and they bite hard:

> There are **no** case studies, client names, employer names, testimonials, logos, user counts, engagement metrics, revenue figures, or credentials. None exist. Future work must never fabricate them.

A domain register is *much* easier to fabricate than a teardown register. A teardown cites a repository; a domain sheet is tempted to cite a deployment. Three ways to stay inside the rule:

1. **Design study, labelled as such.** The sheet reasons from the eleven primitives to what a domain would require — an argument, not a report. The label has to be on the page, not in the author's head.
2. **Grounded in published prior art**, same rule as Teardowns: an open-source clinical or compliance harness, someone else's published architecture, cited.
3. **Grounded in own work** — the projects in §4 are Sunny's own repositories, not clients. This is honest, but it is a real change to how the site presents itself, and it is a decision to make deliberately rather than drift into. **Open question, not resolved here.**

Option 1 is the safe default. Option 3 is the one with actual authority behind it, and the one worth deciding on purpose.

---

## 9. Open questions

1. Is the domain register a *second* register, or does it eventually become the site's main argument — with coding harnesses reframed as the easy special case?
2. Does the "four luxuries" framing survive contact? It is clean, which is suspicious. Is there a fifth — the model's *training distribution*? Code is the domain frontier models are most heavily trained on, which may be a bigger free luxury than all four combined, and it belongs to no primitive at all.
3. Do the five axes reduce? Reversibility and verification substrate may be the same axis observed twice.
4. Does the chain-of-limitations mechanism work *within* a domain? The site's whole method is that each primitive runs out of road into the next. A domain sheet that is just a filled grid abandons that method — and the grid is the weaker form.
5. Which domain gets written first? The argument above says compliance. The argument against is that vet/pet is where the real body of work is, and where the failure modes are felt rather than described.
