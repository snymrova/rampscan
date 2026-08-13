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
