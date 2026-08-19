# How recipes are prepared, and the pipeline that runs them

Recipes are hand-authored JSON data artifacts — the code never generates them,
it only validates them. Preparation runs **adjudicate → draft → validate →
CI-gate**; the scan pipeline then runs the catalog against a checkout using
version-pinned external tools.

![Recipe preparation and scan pipeline](images/recipe-pipeline.svg)

<details>
<summary>Mermaid source (renders natively on GitHub)</summary>

```mermaid
flowchart TD
    subgraph prep["Recipe preparation — data work by humans, gated by CI"]
        frontier["ramprules automation frontier<br/>112 uncovered controls, pinned dataset"]
        adjudicate["Adjudicate each control<br/>recipes/adjudications/*.json<br/>disposition + rationale + remainder + citesUpstream"]
        disp{"disposition?"}
        narrative["narrative — no recipe ever<br/>(the honest ceiling)"]
        draft["Draft recipe by hand<br/>recipes/commit/*.json<br/>ksi_ids + control_ids, assertions,<br/>caveats, plain-English prose, anchor: commit"]
        zod["Load + schema check<br/>Zod PipelineRecipe parse,<br/>duplicate-id rejection (recipes.ts)"]
        reach["Dataset validation<br/>KSIs resolve in crosswalk,<br/>controls reachable from KSIs"]
        ci["CI policy gates (vitest)<br/>recipes.test.ts — IDs resolve, manifests agree<br/>plain.test.ts — all 3 prose paragraphs, no stubs"]
        catalog[("Recipe catalog<br/>ready to scan against")]
    end

    frontier --> adjudicate --> disp
    disp -->|narrative| narrative
    disp -->|automatable / partial| draft
    draft --> zod --> reach --> ci --> catalog

    subgraph pipeline["Scan pipeline — rampscan scan"]
        checkout["Repository checkout<br/>+ rampscan.config.json"]
        resolve{"Tool resolution per collector<br/>(tools.ts, Docker-first policy)"}
        binary["Binary on PATH<br/>version recorded as provenance"]
        docker["Pinned Docker image<br/>from tools.json"]
        collectors["Collectors run in order, sandboxed<br/>emit observations + findings + artifacts"]
        joinNode["Join (join.ts)<br/>observations × recipe assertions<br/>→ evidenced / violated / unevidenced"]
        signer["Signer<br/>node:crypto, keys in rampscan-keys/"]
        ledger[("Append-only ledger<br/>signed ScanResult bundles")]
        projector["Projector fold<br/>SQLite / PocketBase registers"]
        outputs["Reports + exports<br/>scan report, board, per-control<br/>evidence packages, frontier report"]
    end

    subgraph tools["External tools (pinned in tools.json)"]
        t1["gitleaks v8.24.3 — secrets in history"]
        t2["syft v1.51.0 — SBOM"]
        t3["grype v0.117.0 — vulnerabilities"]
        t4["osv-scanner v2.5.0 — advisories"]
        t5["semgrep 1.173.0 — SAST"]
        t6["checkov 3.3.11 — IaC baseline"]
        t7["spectral 6.16.3 — API spec lint"]
        t8["pure collectors — no external tool:<br/>documents, repo-facts, contract,<br/>graph, journal, reachability"]
    end

    catalog --> joinNode
    checkout --> resolve
    resolve -->|found on PATH| binary
    resolve -->|not on PATH| docker
    binary --> collectors
    docker --> collectors
    tools -.-> collectors
    collectors --> joinNode
    joinNode --> signer --> ledger --> projector --> outputs
```

</details>

## The preparation flow, stage by stage

1. **Adjudicate** — `recipes/adjudications/*.json`, one file per control from
   ramprules' 112 uncovered controls (`rampscan frontier`'s count against the
   pinned dataset). Each records a disposition
   (`automatable | partial | narrative`), paragraph-length rationale, an
   explicit `remainder` (what the pipeline plane can never prove, split into
   control and boundary limbs), and `citesUpstream` (agreement or divergence
   with ramprules' AWS-plane verdict). Controls adjudicated `narrative` stop
   here — that refusal is the product's honesty, not a gap.
2. **Draft** — `recipes/commit/*.json`, mirroring ramprules'
   `aws-evidence.json` recipe shape (one rename: `govcloud` → `caveats`) so
   the overlay can be contributed upstream. Each recipe carries the
   control mapping (`ksi_ids` + `control_ids`), machine `assertions`, honest
   `caveats`/`notes`/`empty_means`, and the three-paragraph `plain` prose.
3. **Validate** — `packages/cli/src/recipes.ts`: Zod parse against
   `PipelineRecipe` (schema in `packages/schema/src/recipe.ts`), duplicate-id
   rejection, then `validateRecipeIds` — every KSI must resolve in the pinned
   crosswalk and every control must be reachable from the recipe's KSIs.
4. **CI-gate** — `packages/cli/test/recipes.test.ts` (schema-valid, IDs
   resolve, made-up controls rejected, collector manifests agree with recipes)
   and `packages/cli/test/plain.test.ts` (all three prose paragraphs present,
   real prose not stubs, no verdicts in prose, glossary coverage). The schema
   keeps `plain` optional because it mirrors upstream's shape; the tests make
   it mandatory for the shipped catalog — shape is schema's job, completeness
   is policy's.

## Tool resolution at scan time

Collectors never spawn tools ad hoc (`packages/collectors/src/tools.ts`,
Docker-first policy): a binary already on PATH is used as-is with its version
recorded as provenance; otherwise the collector runs the **pinned image** from
`packages/collectors/tools.json`. A tool on neither path makes the collector
skip with a stated reason — which surfaces as `unevidenced`, never as silence.
