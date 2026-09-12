# fixtures

## vulnerable-app

The planted-fault toy repo (plan §M0 B4): a secret in git history but not at
HEAD, a known-vulnerable dependency (lodash 4.17.15), an unpinned CI action
with no provenance step, and an EOL Docker base image.

The fixture needs its own git history (gitleaks scans history; M2's anchor
death needs commits), and a nested `.git` cannot be committed — so the
fixture is **generated**, deterministically, by the committed script:

```bash
node fixtures/build-vulnerable-app.mjs
```

`fixtures/vulnerable-app/` itself is gitignored. Timestamps and identity are
fixed, so the generated commit SHAs are identical on every machine.

## ingest-evidence-tree

The synthetic client-run evidence tree for the Q4.1 ingestion contract
(SPEC §12.8): an `Evidence/<family>/<KSI-ID>/<KSI-ID>.{json,csv}` layout plus
the client-authored `ingest-manifest.json`, mirroring the de facto output
shapes of client-run AWS evidence scripts (JSON results array + CSV + exit
code — `docs/RESEARCH-PARAMIFY-PILOT.md` §3). Three entries: a passing DoS
protection check (KSI-CNA-RVP), a passing encryption-status capture declared
`point-in-time` (KSI-SVC-SIN — the per-entry evidence-class override, and
G6's specimen), and a failing IAM lifecycle check (KSI-IAM-AAM, exit 3 →
`violated`). Every ARN and account id is synthetic; the content is written
by us, shapes-only — no code or fixture reuse from the observed repository
(it carries no license). Static and committed: unlike vulnerable-app it
needs no git history, because ingested evidence has no commit anchor.
