# rampscan

Pipeline-source evidence for FedRAMP 20x: a scan harness deployed **inside the client's AWS account** that fetches their repositories, scans code / IaC / CI, and produces signed, commit-anchored evidence — keyed to [ramprules](https://ramprules.com) recipe and control IDs — on the MVX re-verification clock (7 days class b, 3 days class c).

ramprules answers *what is owed* and *what AWS APIs can prove*. rampscan supplies the other half: *what the repository and pipeline can prove* — the `pipeline` evidence source that ramprules' automation frontier reserves and currently holds at zero.

Out of scope, deliberately: executing ramprules' AWS evidence recipes (the client runs those directly — they're copy-pasteable by design), and any SaaS control plane that would move code or evidence out of the client's boundary.

## Status

Local prototype, M3 complete: `pnpm rampscan scan <path>` runs five collectors (repo-facts, gitleaks, syft, osv-scanner, grype) over a checkout, joins their output against the 12 starter recipes in [`recipes/pipeline/`](recipes/pipeline/), and records each evidenced/violated row as a signed, commit-anchored bundle in an append-only content-addressed ledger. Re-scans keep unchanged evidence alive under its original signature; when an anchoring file changes, the projector marks that evidence `dead(anchor-drift)` with the killing commit.

`pnpm rampscan serve` is the visual loop: PocketBase (pinned binary, fetched + sha256-verified by `pnpm fetch-pocketbase`) as projection store and auth, a Next.js console with the coverage board (evidenced / violated / unevidenced / not-applicable, filterable by KSI theme, control family, repo), the clock view (bundle age vs the MVX window — b=7d, c=3d — expiring first), the drift view (born / died / verdict-flipped / scoped, with cause and killing commit), and the two-key queue: any signed-in identity proposes a `notApplicable`, an approver's key turn signs a scoping event into the **ledger**, and the register flips only when the projector re-folds it. The projector is the only writer of projection collections — enforced by PocketBase rules, not discipline — and a ledger watcher re-projects on every append, so a scan in another terminal moves the board live. `pnpm rampscan rebuild` drops the projection, refills it from the ledger, and proves byte equality; `pnpm rampscan verify <digest>` checks any bundle or scoping offline. Next: M4 (the code graph and reachability VEX), per the implementation plan.

Setup: Node 22 + pnpm, then `pnpm install && pnpm test`; `pnpm fetch-pocketbase` before the first `serve`. Scan tools resolve Docker-first: a binary already on PATH is used as-is; otherwise, with Docker present, the pinned image from [`packages/collectors/tools.json`](packages/collectors/tools.json) runs automatically — **rampscan never installs anything on the host**. `pnpm doctor` shows how each tool resolves; only with neither binary nor Docker does a collector skip (gracefully, with its recipes reporting unevidenced and the reason recorded).

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — consolidated architecture and data flow reference: components, the scan pipeline end to end, stores, trust boundaries, evidence lifecycle, invariants.
- [`docs/IMPLEMENTATION-PLAN.md`](docs/IMPLEMENTATION-PLAN.md) — the local prototype plan: milestones M0–M5, ports-and-adapters, MVP scope.
- [`docs/PLAN-OF-ACTION.md`](docs/PLAN-OF-ACTION.md) — the working checklist for local development: task order, exit tests, session log. Updated as work lands.
- [`docs/SPEC.md`](docs/SPEC.md) — the working spec: tech, architecture, dataflow, primitives, UI.
- [`docs/COMPLIANCE-SCAN-HARNESS.md`](docs/COMPLIANCE-SCAN-HARNESS.md) — the founding brainstorm, including the decisions log (§11–§13).
- [`docs/context/`](docs/context/README.md) — snapshots of the ramprules dataset and the harnessarch brainstorms, for agent context. Read its README before trusting a number.
