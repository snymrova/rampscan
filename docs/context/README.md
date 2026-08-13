# Context snapshots — read this first

Everything under `docs/context/` is a **snapshot copied from sibling projects on 2026-08-13**, placed here so an agent working on rampscan has the demand-side dataset and the founding arguments in-reach without leaving the repo. Snapshots rot; when a fact matters, verify it against the source of truth:

| Directory | Source of truth | What it is |
|---|---|---|
| `ramprules/` | `~/Projects/ramprules.com/fedramp-rules-hub` | The FedRAMP Rules Hub — dataset version **2026.07.14.01**. `DATASET-FACTS.md` is the generated summary; `derived/` holds the published JSON slices (`search.json` omitted); `types.ts` / `raw-types.ts` are the schema. rampscan pins against `dataset_version` — never against these copies. |
| `harnessarch/` | `~/Projects/harnessarch.com/docs` | The two brainstorms rampscan descends from: the code-graph harness (shared graph, finding schema, three tiers) and domain harnesses (four luxuries, five axes, ontology gate, two-key write). |

The founding document is one level up: [`../COMPLIANCE-SCAN-HARNESS.md`](../COMPLIANCE-SCAN-HARNESS.md) — read it before the spec; the spec assumes its argument. Decisions already taken there (§11): FedRAMP 20x only · shared/per-repo line is the recipe · two signature classes · Bedrock cascade · deployed in the client's AWS account · AWS recipe execution **out of scope**.

Key facts an agent should not re-derive (from dataset 2026.07.14.01):

- KSI graph: 10 themes, 46 indicators, 373 KSI→control edges, 209 controls reached.
- Automation frontier: 88 controls covered by AWS recipes, **121 uncovered**; `bySource.pipeline` is **empty** — that slot is rampscan's product.
- `VDR-TFR-MVX` ("Persistent Machine Verification and Validation"): MUST, re-verify within **7 days (class b) / 3 days (class c)**. This clock drives the scheduler.
- The recipe shape to mirror lives in `derived/aws-evidence.json` → `data.recipes[]`.
