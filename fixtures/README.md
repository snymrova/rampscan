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

## ingest-package

The synthetic machine-readable assessment package for the package adapter
(SPEC §12.8, plan S3-1): `Package → Assessment → KSIs → Validations →
Evidences → Artifacts`, the shape the only publicly assessed 20x package is
published in (`docs/RESEARCH-PARAMIFY-PILOT.md` §2). Its KSI ids are the
Phase One numbered form on purpose, so ingesting it goes through the reviewed
crosswalk in `recipes/crosswalks/`. Four validations: one Phase One indicator
→ one 2026 KSI (CNA-01, three evidences, one name repeated), one → two
(PIY-06), one with no 2026 successor (SVC-07, skipped and named), and one
assessed `Partial` whose artifact carries neither reference nor date
(IAM-01). Written by us, shapes only — no content from the observed package,
which carries no license. Static and committed.

## ingest-prowler

A synthetic Prowler OCSF compliance output for the P3 adapter
(`docs/RESEARCH-PROWLER-INGEST.md`): a bare JSON array of `ComplianceFinding`
rows against `FedRAMP-20x-KSI-2026.07.14.01`, in §10a's field shape. Thirteen
reported rows on six AWS checks (one maps to six KSIs), including a muted FAIL
(`iam_user_accesskey_unused`) and a FAIL forced by the scan's own config over a
raw PASS (`cognito_user_pool_password_policy_lowercase`), plus one synthetic
`MANUAL` row for each of the thirteen indicators the pinned framework maps no
AWS check to. Written by us from the documented shape, not captured from a real
scan; the account id is synthetic.

