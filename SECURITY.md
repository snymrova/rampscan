# Security policy

## Reporting a vulnerability

**Use GitHub's private vulnerability reporting.** On this repository, open the
**Security** tab and choose **Report a vulnerability**. That opens a private
advisory visible only to you and the maintainers, where a fix can be developed and
a CVE requested before anything is public.

**Do not open a public issue for a vulnerability.** Issues here are public from the
moment they are filed, and the three issue templates exist for bugs, recipe
proposals and adjudication disagreements — not for this.

### What to expect

rampscan is `v0.1.0-beta` and maintained by one person, so the promise is
deliberately modest and deliberately specific:

| | |
|---|---|
| Acknowledgement | within **7 days** of the report |
| First assessment | within **14 days** — whether it is accepted, and roughly how serious |
| Fix or public statement | best effort, and you will be told which |
| Credit | in the advisory, unless you ask otherwise |

Only `main` is supported. There is no back-porting to tags, and the fix for any
accepted report is a commit on `main`.

If you do not hear back inside those windows, the report did not arrive — say so in
a public issue **without describing the vulnerability**, and it will be picked up.

### What counts

The obvious things — code execution from scanning a hostile repository, escape from
the sandboxed tool invocations, signature forgery or ledger tampering that survives
`rampscan verify`, credential disclosure through logs or artifacts.

And one that is specific to what this tool is: **a check that reports `evidenced`
without the evidence being there.** A compliance tool that passes a control it
cannot prove is not producing a wrong answer, it is producing a false attestation,
and someone will hand it to an assessor. If you find a repository state where a
recipe reports `evidenced` while the thing it claims is not true — a vacuous pass,
a bypassable assertion, an anchor that does not die when the file it anchors to
changes — that is a security report, not a bug report, and it is the most valuable
one this project can receive.

Out of scope: findings in `fixtures/vulnerable-app`. Its faults are planted on
purpose and its tests depend on them.

## What rampscan sends anywhere

Nothing.

- **Collectors take no network access**, by design, and the pinned scan tools run
  either from a binary already on `PATH` or from a pinned container image. rampscan
  never installs anything on the host.
- **Execution is local.** Scanning, joining, projection and the console all run on
  the machine that holds the checkout. There is no control plane, no telemetry, and
  no SaaS component — a deliberate scope decision, because moving code or evidence
  out of the client's boundary is the thing this design exists to avoid.
- **Signing is `node:crypto`** — an ECDSA P-256 keypair in the cosign envelope
  format, generated and held locally. `rampscan verify <digest>` checks any bundle
  offline. No key ever leaves the machine and no signing service is contacted.

The one thing that does leave your machine is whatever your own scan tools do when
they fetch advisory databases, and that is the tool's behaviour under its own
configuration, not rampscan's.

## Handling of secrets found during a scan

The `gitleaks` collector reads your full committed history and will find real
credentials if they are there. Findings are redacted in the collector's output and
in anything rendered by the console. The scan artifacts under `rampscan-out/` and
the local signing key under `rampscan-keys/` are gitignored and must stay that way
— both are excluded from this repository's own history and neither is allowlisted
in any scanner config, deliberately (see `CONTRIBUTING.md`).
