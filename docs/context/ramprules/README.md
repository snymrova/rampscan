# FedRAMP Rules Hub

Turn "you owe FedRAMP evidence" into a scoped, copy-pasteable collection plan.

State a certification class once (`b` ≈ Low, `c` ≈ Moderate, `d` ≈ High) and get
back every piece of evidence that class owes, the AWS call that fetches it, the
cadence the rules demand, the control the call proves — and an honest register
of what no API can prove and must be written by a human.

## Who it's for

- **A developer told to "collect FedRAMP evidence on AWS."** Not a compliance
  specialist; has a terminal open in the other window. Wins every design
  tie-break.
- **The GRC / compliance reader.** Arrives at a specific artifact by permalink
  and often prints it.
- **Agents and crawlers.** A model asked the developer's question should be able
  to read this dataset without stripping HTML — hence `/api/*`, `/llms.txt` and
  `/md/*` as shipped surfaces, not afterthoughts.

## Agent-readable surfaces

| Surface | What it serves |
| --- | --- |
| `/api/*` | JSON slices consumers can pin against |
| `/llms.txt` | Site summary in the `llms.txt` convention |
| `/md/*` | Markdown twin of every entity page |

Every control, KSI and requirement page has a Markdown twin: append `.md` to the
permalink (`/control/ac-17.md`) and you get a page a model can read directly.

## Getting started

```bash
pnpm install
pnpm dev
```

## The gates

CI runs these in order, and `.github/workflows/ci.yml` is the source of truth:

```
test · validate · gen:types · derive · typecheck · lint · format:check · build
```

A ninth runs last because it needs the build:

```bash
pnpm exec playwright install chromium   # once
pnpm test:a11y                          # Playwright + axe, fails on serious/critical
```

## Working on the data

`data/derived/` and `docs/DATASET-FACTS.md` are **committed build output**. The
site, the JSON API and the tests all read them. After any change to
`data/overlays/` or to a lens under `lib/fedramp/`:

```bash
pnpm derive && pnpm test
```

Commit the rewritten slices alongside the change. CI fails on a stale cache —
that gate is what keeps a published API honest.

See [`AGENTS.md`](AGENTS.md) for the full working rules, [`PRODUCT.md`](PRODUCT.md)
for scope, and [`DESIGN.md`](DESIGN.md) for the design system.
