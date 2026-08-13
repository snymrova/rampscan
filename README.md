# rampscan

Pipeline-source evidence for FedRAMP 20x: a scan harness deployed **inside the client's AWS account** that fetches their repositories, scans code / IaC / CI, and produces signed, commit-anchored evidence — keyed to [ramprules](https://ramprules.com) recipe and control IDs — on the MVX re-verification clock (7 days class b, 3 days class c).

ramprules answers *what is owed* and *what AWS APIs can prove*. rampscan supplies the other half: *what the repository and pipeline can prove* — the `pipeline` evidence source that ramprules' automation frontier reserves and currently holds at zero.

Out of scope, deliberately: executing ramprules' AWS evidence recipes (the client runs those directly — they're copy-pasteable by design), and any SaaS control plane that would move code or evidence out of the client's boundary.

## Status

Documentation phase. Nothing builds yet. Next step: the local prototype, per the implementation plan.

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — consolidated architecture and data flow reference: components, the scan pipeline end to end, stores, trust boundaries, evidence lifecycle, invariants.
- [`docs/IMPLEMENTATION-PLAN.md`](docs/IMPLEMENTATION-PLAN.md) — the local prototype plan: milestones M0–M5, ports-and-adapters, MVP scope.
- [`docs/PLAN-OF-ACTION.md`](docs/PLAN-OF-ACTION.md) — the working checklist for local development: task order, exit tests, session log. Updated as work lands.
- [`docs/SPEC.md`](docs/SPEC.md) — the working spec: tech, architecture, dataflow, primitives, UI.
- [`docs/COMPLIANCE-SCAN-HARNESS.md`](docs/COMPLIANCE-SCAN-HARNESS.md) — the founding brainstorm, including the decisions log (§11–§13).
- [`docs/context/`](docs/context/README.md) — snapshots of the ramprules dataset and the harnessarch brainstorms, for agent context. Read its README before trusting a number.
