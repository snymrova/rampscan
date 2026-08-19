# How controls map to reports

rampscan never maps controls to reports directly — **recipes are the single join
point**. Control IDs enter the system only through the pinned ramprules
crosswalk, get bound to recipes under a reachability check, ride each recipe
verdict through the join into the ledger, and every report is a different
projection of those verdict-attached `control_ids`.

![Controls-to-reports flow](images/controls-to-reports.svg)

<details>
<summary>Mermaid source (renders natively on GitHub)</summary>

```mermaid
flowchart TD
    subgraph upstream["ramprules — pinned dataset (dataset_version + overlay_version)"]
        crosswalk["Crosswalk slice<br/>controls ⟷ KSI indicators"]
        frontierReg["Automation frontier<br/>per-control dispositions (aws / pipeline)"]
    end

    subgraph mapping["The single join point: recipes"]
        recipe["PipelineRecipe<br/>ksi_ids (min 1) + control_ids (min 1)"]
        validate{"Load-time validation<br/>every KSI resolves in crosswalk,<br/>every control reachable via controlsFor(ksi)"}
    end

    subgraph scan["Scan run"]
        collectors["Collectors<br/>observations + findings"]
        join["Join<br/>observations × recipe assertions"]
        gate{"Ontology gate<br/>resolves to a recipe?"}
        verdict["RecipeResult<br/>verdict: evidenced / violated / unevidenced<br/>carries ksi_ids + control_ids forward"]
        finding["Finding only — never evidence<br/>(names ksi_ids / control_ids it implicates)"]
    end

    ledger[("Ledger<br/>ScanResult, append-only")]

    subgraph reports["Reports — projections of recipe verdicts"]
        scanReport["Scan report<br/>per-recipe table + coverage:<br/>N of M recipe-mapped controls, families"]
        projector["Projector fold → rollup by control id<br/>precedence: violated > unevidenced > evidenced"]
        registers[("SQLite / PocketBase<br/>controls + ksis registers → board")]
        evpkg["Per-control evidence package<br/>tar: every recipe mapped to the control,<br/>including unevidenced"]
        frontierRpt["Frontier report<br/>our pipeline evidence vs upstream dispositions,<br/>filed by source plane"]
    end

    crosswalk --> validate
    validate -->|"control not reachable → fail"| recipe
    recipe --> join
    collectors --> gate
    gate -->|yes| join
    gate -->|no| finding
    join --> verdict
    verdict --> ledger
    finding --> ledger
    ledger --> scanReport
    ledger --> projector
    projector --> registers
    ledger --> evpkg
    ledger --> frontierRpt
    frontierReg --> frontierRpt
```

</details>

## Where each edge lives

- **Crosswalk slice** — `packages/dataset/src/types.ts` (`CrosswalkControl`,
  `CrosswalkIndicator`); version pins in `packages/dataset/src/pins.ts`.
- **Recipe shape** — `packages/schema/src/recipe.ts` (`ksi_ids` and
  `control_ids`, each `min(1)`).
- **Reachability validation** — `packages/cli/src/recipes.ts`: every KSI must
  resolve in the crosswalk, and every claimed control must be reachable from
  the recipe's KSIs via `dataset.controlsFor(ksi)`.
- **Join and ontology gate** — `packages/core/src/join.ts`: collector output ×
  recipe assertions → per-recipe verdict; anything that doesn't resolve to a
  recipe is a finding only, never evidence.
- **Scan report** — `packages/cli/src/report.ts`: coverage counts are over
  *recipe-mapped* controls, not the whole catalog.
- **Projector rollup** — `packages/projector/src/fold.ts` (`rollup()`):
  violated beats unevidenced beats evidenced; `notApplicable` wins only when
  every mapped recipe is scoped out.
- **Per-control evidence package** — `packages/cli/src/export.ts`: every recipe
  mapped to the control appears in the manifest, including unevidenced ones.
- **Frontier report** — `packages/cli/src/frontier.ts`: dispositions filed
  under the upstream plane (`aws` / `pipeline`) that wrote them.
