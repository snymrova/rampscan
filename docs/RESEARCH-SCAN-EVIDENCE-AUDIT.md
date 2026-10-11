# Audit: the code-scanning plane as FedRAMP 20x evidence

**Date:** 2026-10-03 · **Commit:** `dcc798c` (branch `feat/design-depth-axis`; the scanning code is the same as on `main`) · **Rules pin:** 2026.09.13.02

**Scope.** Everything between a git checkout and a signed KSI row:
- the 13 collectors and the pinned tool manifest;
- the 20 commit recipes;
- the assertion evaluator, the join, bundle signing, the ledger and the fold;
- the reachability, SBOM and OpenVEX path;
- the fit of all of it to the pinned FedRAMP 20x rules.

Out of scope: Prowler/AWS ingest, the console, and the cloud runner.

**Method.**
- **A fresh self-scan** into a scratch ledger (`10 evidenced · 4 violated · 6 unevidenced`).
- **Four parallel audits:** collectors; recipes/assertions/signing; KSI fit against the pinned rules; reachability/VEX. Each was required to reproduce what it claimed.
- **My own independent re-check of the four sharpest claims:**
  - the reachability repeat (§1.1), with a real `scan` on a fresh git repo;
  - gitleaks' exit code (§1.2), by running gitleaks 8.24.3 directly;
  - the dirty-tree path (§1.3), by reading the code;
  - the PVA citation (§3.3), with a grep of the pinned rules.

A finding marked **CONFIRMED** was reproduced end to end or is unambiguous in the code. **PLAUSIBLE** means it was read from the code but not run. Every repro is in the session scratchpad (§8).

---

## 0. The verdict, in five lines

1. **The posture is right and the implementation leaks.** The design rules are sound: empty-set discipline, skips with stated reasons, "unknown counts", SBOM edges proving presence only, schema-valid exports with declared and computed fields labelled. But at least **eight paths sign `evidenced` or `not_affected` without the evidence**, each of the class `SECURITY.md` names as the worst defect this project can have.
2. **The reachability gate has a repeat of GHSA-7jff-6v53-r56x.** The `@/` path alias that create-next-app sets up by default, `require('x')()`, `import x = require()`, `.vue` importers and Worker entry points all let a reachable CRITICAL be signed `not_affected` (§1.1). WAY-AHEAD §4's settled rule ("unreachability is proven positively or not claimed") is broken again, so **S1 is not closed in fact**.
3. **Each of the four headline scanners can be made to read clean.** gitleaks, semgrep and checkov can be silenced by a file the scanned repo commits. The scan signs the working tree as if it were the HEAD commit, and gitleaks signs a failed scan as "full history clean".
4. **The FedRAMP mapping is wider than the evidence.** 11 of the 28 recipe→KSI pairs are overclaims made by a shared 800-53 control rather than by the KSI statement. The method floor is counted on mappings, not on methods that ran. The README cites a rule (`FRR-PVA-AA-06`) that does not exist at the pin.
5. **The vulnerability evidence does not speak VDR.** VDR asks for:
   - PAIN N-ratings × internet-reachable × likely-exploitable;
   - per-vulnerability timeframes;
   - accepted vulnerabilities;
   - a KEV join.

   rampscan has CVSS ≥ 7, a zero-tolerance count per recipe, no timeframes and no KEV. Unrated advisories, malware included, pass uncounted.

**Your own product, from the self-scan:**
- `next@15.5.23` carries a **reachable CRITICAL** (GHSA-2xp9-vwfh-vxw4) and a second advisory (GHSA-p293-qw3h-jr36).
- `postcss@8.4.31` has four advisories.
- Upgrading `next` in `console/web` is the one-line fix worth doing this week, independent of everything below.

---

## 1. Critical — a false claim gets signed

### 1.1 Reachability signs `not_affected` whenever the walk misses an importer — CONFIRMED (independently reproduced)

**Where:**
- `packages/collectors/src/reachability.ts:197`: `missed = dep !== undefined && !dep.reachable`.
- `packages/graph/src/scope.ts:158-161`: a root counts as "walked" once any one file in it is reached.

**The mechanism.** A dependency node exists because *some* first-party file imports it. If the walk never reached that file, the package is signed `not_affected`. Nothing checks that every importer was reached or classified. So any gap in the extractor's model of how files reach each other becomes a signed negative.

The gaps found:

| Gap | Where | Example |
|---|---|---|
| Path aliases are treated as npm packages | `extract.ts:530-541` (`importTarget` → `packageOf`) | tsconfig `paths`/`baseUrl` (the `@/…` that create-next-app sets up by default), package.json `imports` (`#lib/*`) |
| A call's callee is never visited, only its arguments | `extract.ts:~824` | `require('debug')('app')`, `app.use(require('helmet')())`, `import('./x').then(…)`, `require('./p/'+n).init()` (this also **bypasses S4-1's opaque-require refusal**) |
| No TS `import x = require("…")` | `extract.ts:~612` | `ImportEqualsDeclaration` unhandled |
| An unresolved relative import silently ends the walk | `extract.ts:539`, `SKIP_DIRS` at :95 | an importer under `out/`, `build/`, `dist/` or `vendor/`; `.vue`/`.svelte`/`.astro` importers |
| Entry points missing | `entrypoints.ts:146,254` | `new Worker(new URL(…))`, fork/spawn; `main`/`bin` → `dist/` (recorded as unresolved but never refused); Next metadata routes (`opengraph-image`, `sitemap`, `icon`…); loads by string name (`view engine 'ejs'`, knex `client:'pg'`) |

**Independent repro** (`scratchpad/mine/app`, a real `pnpm rampscan scan` on a fresh git repo):
- `app/page.tsx` does `import { render } from "@/lib/md"` and calls it with `searchParams.q`.
- `lib/md.ts` does `import marked from "marked"` (`marked@0.3.6`).
- `openvex.json` gets **five `not_affected` statements for marked**, each `vulnerable_code_not_in_execute_path`.

The audit's own fixture `fxB` signed 29 `not_affected` statements, including tar's GHSA-23hp-3jrh-7fpw (9.2 CRITICAL).

**FedRAMP impact.**
- RA-5/SI-2 evidence is false on KSI-SCR-MON and KSI-CMT-VTD.
- A signed VEX hides a reachable CRITICAL from anyone who consumes it.
- On real repositories this is the common case, not the edge case.
- The SAST gate inherits the same walk (`walkWidth`), so it has the same hole.

**Fix direction.**
1. Refuse `not_affected` unless **every** file importing the package was reached or positively classified, and record those importers in `rampscan:scope`. This one change closes the class whatever the extractor misses.
2. Then narrow the misses:
   - visit `node.expression`;
   - handle `ImportEqualsDeclaration`;
   - resolve tsconfig `paths` and package `imports`;
   - treat reached phantom edges, `createRequire`, Worker, fork and non-identifier callees as opaque;
   - refuse when `entrypoints_unresolved` is non-empty.

**Process.** This is the S0 situation again. Under S0-1 (public advisory, no embargo, fix in the open) and S0-2 (supersede, never delete), this warrants a second GHSA. **Whether to file it is the owner's call**; the precedent argues yes.

### 1.2 gitleaks: a failed or partial scan reads as "no secrets in history" — CONFIRMED (independently reproduced)

**Where:** `packages/collectors/src/gitleaks.ts:60` treats exit 1 as "leaks found". At `:71`, `readFile(...).catch(() => "[]")` turns a missing report into "no leaks".

**The behaviour.** gitleaks 8.24.3 exits **1** on fatal errors too. Run on a directory that is not a git repo, it logs `partial scan completed … no leaks found in partial scan`, exits 1, and writes `[]`. The collector reads that as a clean exhaustive search. The audit reproduced the same outcome for:
- an unreadable git object;
- "dubious ownership" (a root container over a checkout owned by the runner, which is common in CI);
- a report path that cannot be written.

**Signed claim:** "zero committed credentials across the full commit history" (IA-5(6), SC-28, KSI-SVC-ASM/SIN), for history that was never read.

**Fix:**
- pass `--exit-code 99` and treat 1 as an error;
- require the report file to exist;
- refuse when stderr contains `partial scan`;
- record the commit count gitleaks prints to stderr as the population.

### 1.3 A dirty working tree is signed as the HEAD commit — CONFIRMED

**Where:** `packages/cli/src/scan.ts:241` resolves HEAD and never checks that the tree is clean. repo-facts, documents, grype and checkov read the working tree, and syft excludes untracked files but still reads modified ones. Anchors are hashed from the working file, and `verify.ts:244-270` never re-derives them from the commit.

**Repro (`scratchpad/recipes/f2`):**
1. Commit a Dockerfile with no `USER` line.
2. Add `USER app` without committing it.
3. Scan.

`container-runs-nonroot` is signed **evidenced at commit 14067a5**, with an anchor hash that does not exist in that commit, and `verify` says OK.

**Impact:** a signed claim about a commit whose bytes say the opposite. An assessor who checks out the commit gets a different answer.

**Fix:** refuse to scan a dirty tree, or read every input from the commit's blobs (`git archive` into a temp dir). Then make `verify` re-derive the anchors from the commit.

### 1.4 The scanned repository can silence its own scanners, and nothing records it — CONFIRMED

| Tool | Suppression the repo controls | Recorded? |
|---|---|---|
| gitleaks | `# gitleaks:allow`; a root `.gitleaksignore`; a root `.gitleaks.toml`, which **replaces the whole rule set**, so "pinned rule set" is false | no; the result is `count 0`, `anchor_paths: []` |
| semgrep | `// nosemgrep`; `.semgrepignore`; semgrep's default ignores (`tests/`, `*.min.js`) | no |
| checkov | `# checkov:skip=…`; a repo `.checkov.yaml` `skip-check` | `skipped_checks` is dropped by the schema at `checkov.ts:76-82` |
| grype | a `.grype.yaml` in the cwd. Binaries run with no `cwd` (`tools.ts:273`), so `rampscan scan .` picks up the repo's config. Repro: 229 matches (7 CRITICAL) → `matches 0` | only inside the artifact |

**Impact.** Every "empty means clean" recipe can be made to sign clean by committing one file, and the signed bundle carries no trace of it. A 3PAO would treat an undisclosed suppression as a finding against the provider. Here it is invisible to the assessor.

**Fix:**
- run every tool with a vendored config and ignore files disabled: gitleaks `--config <vendored> --ignore-gitleaks-allow --gitleaks-ignore-path <empty>`; semgrep `--disable-nosem` with a pinned ignore set; checkov `--config-file <vendored>`;
- run binaries with `cwd: artifactDir`;
- where a suppression should be honoured, emit the suppressed hit as a row (`suppressed: true`) and anchor and sign the suppression file. That is the same "accepted vulnerability" channel VDR wants (§3.4).

---

## 2. High — vacuous passes and integrity gaps

### 2.1 Vacuous passes

| # | Finding | Where | Status |
|---|---|---|---|
| 2.1a | **SAST signs clean on any repo with no JS/TS.** The ruleset is three rules, JS/TS only. A Python app with `eval(sys.argv[1])` and `os.system(…+argv)` is signed "no dangerous construct in the execute path" (SA-11, SI-10, KSI-PIY-RSD). semgrep `errors[]` (the self-scan has a `PartialParsing` on `support.ts:99`) is counted but never read by `sast-gate.ts`. | `semgrep-rules.yaml`, `sast-gate.ts:491`, `semgrep.ts:183` | CONFIRMED |
| 2.1b | **The dependency inventory can be empty of real dependencies and still read clean.** For a repo with `requirements.txt` (`django<2`) and a lockfile-less `package.json` (`lodash 4.17.4`), syft catalogued only `actions/checkout`. `component_count` was 2, `sbom-exists-and-fresh` passed, osv returned `[]`, and `no-critical-reachable-advisories` was **evidenced**. Nested manifests with no lockfile and `vendor/`/`dist/` copies are also invisible. | `syft.ts:73-81,213`, `repo-facts.ts:241-247` | CONFIRMED |
| 2.1c | **Unrated advisories are dropped, malware included.** `normalizeSeverity` → `UNKNOWN`, which falls outside `in [CRITICAL, HIGH]`. What drops: MAL-2025-19413 (malicious npm package), 10 of 21 unscored `golang.org/x/net` GO-* advisories, and CVE-2023-44487, which is **KEV-listed but GHSA MODERATE**. When unreached, malware is signed `vulnerable_code_not_in_execute_path`, though install scripts run without any import. This breaks the project's own "unknowns count" rule. | `osv-report.ts:50-63`, `reachability.ts:257` | CONFIRMED |
| 2.1d | **Shallow clone signed as full history.** For a `--depth 1` clone of a repo whose secret was added and then removed, the scan is `count 0` → evidenced. That is actions/checkout's default. The repo's own CI sets `fetch-depth: 0`; a client's CI may not. | `gitleaks.ts:58` | CONFIRMED |
| 2.1e | **checkov: a parse failure reads clean.** A malformed `main.tf` gives `passed 0, failed 0`, exit 0 → evidenced. `parsing_errors` is dropped. | `checkov.ts:76-82` | CONFIRMED |
| 2.1f | **Reachability matches advisories to graph nodes by bare name.** A PyPI `redis` CRITICAL was signed `not_affected` because an npm `redis` node exists. With npm aliases (`"lodash4": "npm:lodash@…"`) the reached alias does not protect `lodash`'s advisories. | `reachability.ts:182` | CONFIRMED |
| 2.1g | **Build and test tooling is signed "not in execute path".** `vite` imported only by `vite.config.ts` was signed `not_affected`, and so was the self-scan's `vitest`. CI runs these with secrets and they shape the shipped artifact (SR-3, SA-15, KSI-SCR-MIT). | no build/test plane in the graph | CONFIRMED |
| 2.1h | **repo-facts misreads CI and containers.** It reads only `jobs.*.steps`, so a job-level `uses: evil-org/…@main` with `secrets: inherit` gives 0 rows and `ci-actions-pinned` passes. `lastUser` never resets on `FROM`, so a `USER node` in a builder stage makes a root final stage read non-root; `USER root:root` and `USER 0:0` read non-root too. `--provenance=false` counts as provenance. `echo "skipping npm test"` counts as a test step, and triggers are never checked. A workflow that fails to parse gives 0 rows and passes. | `repo-facts.ts:46-48,100,170-177` | CONFIRMED |
| 2.1i | **route-auth matches any symbol containing "auth".** An unauthenticated `app.delete("/posts/:id")` that calls `getAuthor()` is evidenced for KSI-IAM-ELP. | `graph/src/config.ts:13`, `query.ts:358-363` | CONFIRMED |
| 2.1j | **spectral matches spec files by name.** An `openapitools.json` generator config or an empty `openapi.yaml` gets `unrecognized-format` → evidenced; a real invalid `api.yaml` beside it was never linted. | `spectral.ts:271` | CONFIRMED |

### 2.2 Integrity of what is signed

| # | Finding | Where | Status |
|---|---|---|---|
| 2.2a | **Evidence does not die when a collector stops observing.** An unevidenced row appends nothing (`scan.ts:379-384`), and the fold kills a bundle only on a successor or an anchor change. Delete the Dockerfile, or uninstall gitleaks, and the old bundle stays `evidenced` until the MVX window (7d at class b) ages it into G3. The register never says "withdrawn". | `scan.ts:379-384`, `fold.ts:306-325` | CONFIRMED |
| 2.2b | **An assessor cannot re-derive surviving evidence.** Artifacts and `scan-result.json` are overwritten at fixed paths every scan, and the ledger holds only digests. A live bundle's subject (`repo-facts.json` sha `5ffe…`) no longer exists on disk (`c673…`). The vulnerability DB snapshot (grype DB build, OSV query time) is not signed, and the advisory bundle records only `reachability 0.4.0+graph…`, not the osv-scanner or grype versions. | `scan.ts:252-254`, `bundle.ts:239-241` | CONFIRMED |
| 2.2c | **`verify` cannot run from a public key, and the trust model is one key.** `verify` goes through `loadOrCreateKeypair`. With only `rampscan.pub` present it crashes with EEXIST *after writing a random private key into the assessor's directory*; with an empty directory it mints a fresh pair and reports "signature FAILED". There is no keyid pinning, no keyring and no rotation path. The private key is unencrypted PKCS#8 (0600). The "two-key" scoping and attestation events are **one appliance signature** over two identity strings, and no proposer≠approver check exists in the CLI path. | `signer/src/local.ts:42-58`, `core/src/scoping.ts:44-54` | CONFIRMED |
| 2.2d | **Omissions from the ledger are undetectable.** There is no hash chain or `prev` link. Deleting the violated line from `index.jsonl` leaves a clean, verifiable history. | `ledger` | CONFIRMED |
| 2.2e | **Population is not the domain.** `population` is the count of finding rows, so every clean result is "0 of 0". The commits gitleaks scanned, the files semgrep scanned, grype's package count and checkov's `passed_count` are thrown away or left in the artifact. `sameEvidence` also ignores population, so an old "0 of 412" survives a run that saw 0. | `assert.ts:149`, `bundle.ts:325-347` | CONFIRMED |
| 2.2f | **Recipe content is not signed.** No recipe digest or `where` clause is in the predicate or in evidence identity. A recipe edit keeps the old signature, and an assessor cannot tell which filter produced a bundle. A binary on PATH beats the pinned image; the run record is honest about it, but recipe notes claiming "pinned rule set" are then false. The cache key uses `"resolved-at-run"`, not the resolved version. | `tools.ts:147-171`, `cache.ts:178-185` | CONFIRMED |

---

## 3. FedRAMP 20x fit

### 3.1 KSI fit: 4 strong, 13 partial, 11 overclaim (of 28 pairs)

All 13 KSI IDs exist at 2026.09.13.02. The problem is how they were attached: every pair joins on a shared 800-53 control in the crosswalk, never on the KSI's own statement.

| Recipe | KSI | Fit | Why |
|---|---|---|---|
| ci-actions-pinned | SCR-MIT | **STRONG** | a direct supply-chain mitigation |
| lockfile-pinned-deps | SCR-MIT | **STRONG** | direct mitigation (once 2.1b is fixed) |
| no-critical-reachable-advisories | SCR-MON | **STRONG** | automated upstream monitoring (once 1.1/2.1c are fixed) |
| container-base-image-patched | SCR-MON | **STRONG** | CRITICAL only; scans the FROM tag, not the built image |
| arch-boundaries-hold | CNA-DFP | partial | code-level only |
| arch-route-auth-declared / route-auth-coverage | IAM-ELP | partial | authentication presence by name heuristic, not least privilege; **the same walk counted twice** |
| ci-provenance-present | SCR-MIT | partial | a step exists, nothing verifies it; fits SVC-VRI better |
| container-runs-nonroot | IAM-ELP | partial | a workload slice; fits CNA-DFP better |
| dependency-update-automation | SCR-MON | partial | the config exists, which does not show the service is on |
| iac-baseline-clean | SVC-ACM | partial | intended state only; **not mapped to MLA-EVC, which it fits STRONG** |
| no-critical-reachable-advisories | CMT-VTD | partial | nothing shows it sits in the deploy path |
| no-reachable-dangerous-code | PIY-RSD | partial | three rules |
| no-secrets-in-history | SVC-ASM, SVC-SIN | partial ×2 | detection, not management or rotation |
| sbom-exists-and-fresh | PIY-GIV | partial | one repo, not "all information resources" |
| tests-in-ci | CMT-VTD | partial | configured, not shown to gate deploy |
| access-control-policy-present | SVC-SIN | **OVERCLAIM** | a policy file is not "secured information"; joined via ac-1 |
| api-spec-lint-clean | SVC-ACM | **OVERCLAIM** | doc quality (sa-5), not configuration management |
| arch-boundaries-hold | SVC-ACM | **OVERCLAIM** | import boundaries are not machine-resource configuration |
| codeowners-defined | CMT-RVP | **OVERCLAIM** | the KSI is "effectiveness of change procedures persistently reviewed" |
| container-base-image-patched | CMT-VTD, CNA-IBP | **OVERCLAIM ×2** | a tag scan is not change validation, and a CVE count is not a best-practice comparison |
| dependency-update-automation | CMT-VTD | **OVERCLAIM** | a config file does not validate changes |
| no-reachable-dangerous-code | SCR-MIT | **OVERCLAIM** | first-party SAST is not supply chain |
| security-disclosure-published | PIY-RVD | **OVERCLAIM** | the KSI is reviewing VDP effectiveness, not its existence |
| system-documentation-present | SVC-ACM | **OVERCLAIM** | docs are not automated config management |
| tests-in-ci | SCR-MIT | **OVERCLAIM** | testing is not supply-chain mitigation |

Removing the overclaims empties CMT-RVP, PIY-RVD and CNA-IBP. The README's "floor met on 13 of 41" becomes about 10. Folding in 3.2 as well leaves about 8 defensible KSIs.

### 3.2 The method floor is counted on mappings, not on methods that run — CONFIRMED

`floorMet: true` is shown for KSI-SVC-ACM with **4 methods and 0 with evidence**, and likewise for CNA-DFP, CNA-IBP, PIY-RSD and PIY-RVD. G2 reports 0 rows while 15 of the 28 methods have never produced a bundle for this offering. FRC-CSX-VVK reads "implement automated methods to persistently verify and validate", and a recipe that has never run for the offering is not implemented. **The floor should count methods with at least one live bundle.**

### 3.3 The cited G6 rule does not exist at the pin — CONFIRMED

`FRR-PVA-AA-06` is cited by `gaps.ts:13,260`, `ksi-register.ts`, `artifact-generators.ts:496`, `verify.ts`, and **published at `README.md:41`**. The pinned rules contain **zero** `PVA` rules; it is a Phase One (2025) ID. The nearest pinned text is a note on IVV-IAS-VIM/VEF ("don't simply review documentation or screenshots"), and nothing at the pin makes point-in-time evidence "rejectable when standalone". For a project whose ground rule is that every published claim comes from a command, this line needs a pinned rule ID or has to go. Persistence lives in VDR-TFR-MVX, VDR-TFR-NMV, FRC-CSX-VVK, FRC-CSX-MOT and SDR-CSX-KMT.

### 3.4 The vulnerability model contradicts VDR

| VDR asks | rampscan has |
|---|---|
| Ratings by PAIN N-level × internet-reachable × likely-exploitable (VER-EVA-EPA/EIR/ELX) drive deadlines (VDR-TFR-PVR) | CVSS ≥ 7. A reachable MEDIUM that is N4 and likely exploitable has an 8-day deadline at class b, and rampscan never sees it. "Reachable from entry points" is not "internet-reachable". |
| *All* detected vulnerabilities managed (VDR-CSO-RES) | only CRITICAL/HIGH counted; unrated ones dropped (2.1c) |
| Timeframes: detection → evaluation → remediation (PVR, PSD, PDD, PCD); KEV (VDR-CSO-AKE, VDR-TFR-KEV); 192-day accepted (VER-TFR-MAV) | none of these exist in `packages/`; no KEV join |
| An evaluated vulnerability inside its window is compliant | `violated` the moment it is detected |
| Accepted vulnerabilities are a reported state (VER-RPT-AVI, CCM-OCR-AVL) | no acceptance channel; the README frames refusing it as a virtue |
| Per-vulnerability records (VER-RPT-VDT) | one episode per **recipe cell** (`fold.ts:1012`): N CVEs, no per-CVE ID or detection time; 3 of 11 VDT fields filled |

**VDR-CSO-FAV is applied backwards.** The fold turns every *violated recipe* into a "validation vulnerability" (`fold.ts:1012`, `ports.ts:605`), so a missing CODEOWNERS file lands in the vulnerability feed. FAV is about failures of the *detection process*: a skipped collector, or a tool missing from PATH. Those are exactly what the fold never records.

### 3.5 Medium-weight fit issues

- **Declared cadences contradict MVX.** Two recipes are `monthly` and twelve are `weekly`. Weekly hits class b's 7-day window with no slack and fails class c's 3-day window. The daemon actually schedules at 0.5 × MVX (`scheduler/src/cadence.ts:45`), so the declared cadence is decorative, yet the SDR's cycle artifact (`artifact-generators.ts:461`) prints it as the explanation.
- **"Persistent" is designed, not operated.** The newest bundle in the real ledger is 2026-09-14, and 0 of 41 KSIs are inside their window. Every pipeline bundle says `process-generated`, but a manual `scan` with no schedule behind it is point-in-time in fact. A commit scan validates *code*; nothing joins the scanned commit to the deployed digest.
- **The exports carry the scan only by digest.**
  - In the SDR, `ksiTests` holds method IDs only: no tool, version, ruleset or population.
  - `ksiEvidence.evidenceLocation` is an `ni:` hash nobody without the ledger can fetch.
  - All 152 bundles in the real ledger carry `dataset_version 2026.07.14.01`.
  - The FedRAMP Vulnerability Detail Report schema is not pinned.
- **The README's "28 of 41 are what a repository can never answer" (`README.md:50`) overstates.** CNA-RNT/MAT/ULN/OFA, MLA-EVC/LET, SVC-VRI, IAM-SNU, CMT-RMV and RPL-ABO are all partly evidenced by IaC and CI config.

---

## 4. Lower

- `pnpm rampscan --help` fails with "Unknown option '--help'", but README §14 tells readers to run it. The usage text prints only with no command.
- **Offering identity is the local path.** The ledger holds this repo as `.`, as the absolute path, and as fixture paths; `frontier` defaults to the stale `.`; the signed `repo` is a filesystem path, not a remote.
- `check` exits 0 when gates are unevidenced or crashed.
- `sbom-exists-and-fresh`'s `max_age_days 1` is always met on a fresh run.
- A clean SAST result with no `rampscan.config.json` is "evidenced but nothing to attest to — NOT recorded", so a prior violated bundle sticks.
- `documents` never checks that a declared path stays inside the checkout (`../../etc/hostname` → present).
- The grype `FROM` parse is case-sensitive, matches heredoc lines, breaks on `\` continuations, and records no resolved digest. Only the root `Dockerfile` is read, and only CRITICAL counts.
- The MVX windows are hardcoded (`scheduler/src/mvx.ts:9`); they match the pin today.
- G4 says "class b owes no number", but SDR-CSX-KMT is MUST at class b. The SDR does carry the metrics; the register line does not say so.
- **The self-scan includes the test fixtures.** `iac-baseline-clean` is violated by `fixtures/vulnerable-app/.github/…`. That is conservative, but there is no declared boundary (MAS) to scope a real offering's tests and examples in or out.

---

## 5. Checked and sound

- **Field names and severity spellings** match between all 20 recipes and their collectors. The evaluator does what it documents.
- **Honest skips work.** No IaC, no spec, no Dockerfile, no tool, a timeout, ENOENT and a malformed output file all end unevidenced with a reason.
- **What is signed is well formed.** DSSE PAE over canonical JSON, ECDSA P-256. The predicate carries commit, collector tool version, artifact digests, per-assertion population, basis and dataset version. Objects are re-hashed on every read.
- **The S1 fixes hold for what they cover:**
  - S1-1: no node → unknown → counts.
  - S1-2: SBOM edges only add reachability.
  - S1-3: an unentered root refuses.
  - S1-4: an excluded, unreached entry point refuses.
  - S4-1: a statement-level `require(expr)` refuses (but see 1.1's call-target bypass).
  - 76/76 reachability and graph tests pass. A non-JS repo skips the graph, so every advisory counts.
- **The journal** signs every tool resolution (version, path, image digest) and every exit code.
- **The OpenVEX envelope** is valid v0.2.0, and grype 0.117 applies it. The defect is *what* it scopes (H5 below), not the format.
- **Rescanning the same commit** keeps every bundle (8/8). Evidence identity is stable.
- **The exports** are schema-valid, label declared vs computed fields, and report 37 of 41 KSIs as `Not Implemented` honestly. VDR-CSO-DAC and VDR-CSO-ADT (detect after change, automate detection) are well served.

**H5, the VEX scoping defect** (high, CONFIRMED). `reachability.ts:220-236` names the *vulnerable package* as the product (`pkg:npm/tar@6.1.0`), with no `subcomponents` and no tie to the commit. Applied with `grype --vex`, the same file suppressed all 18 tar advisories on an **unrelated** SBOM. A VEX from commit X suppresses findings on every later build. **Fix:** make the product the application (`pkg:github/owner/repo@<commit>` or the OCI digest), move the package into `subcomponents`, and add statement timestamps.

---

## 6. Recommended order of work

**1. Soundness first: reopen S1 as S5, "the signed negatives".** Failing test first under `it.fails` for each, per house rule.
   1. 1.1: refuse `not_affected` unless every importer was reached or classified. Then the extractor fixes, and H5 (scope the VEX product to the app).
   2. 1.2 and 2.1d: gitleaks exit code, report required, partial-scan refusal, shallow-clone refusal, commit count as population.
   3. 1.3: scan from the commit, not the working tree; `verify` re-derives anchors.
   4. 1.4: vendored configs, ignore files off, `cwd: artifactDir`, suppressions as signed rows.
   5. 2.1a, 2.1b, 2.1c, 2.1e: language domain for SAST; manifest→SBOM coverage; UNKNOWN and MAL-* fail closed; checkov parse errors and zero-checks → unevidenced.
   6. Owner call: a second GHSA for 1.1, under S0-1.

**2. Evidence integrity (2.2).**
   - a signed "withdrawn" statement when a run cannot re-evidence a recipe;
   - content-addressed artifacts in the ledger;
   - verify from a public key with keyid pinning;
   - a hash-chained index;
   - domain counts in identity;
   - the recipe digest in the predicate.

**3. FedRAMP fit (3.x).**
   - Drop or remap the 11 overclaims (remap `iac-baseline-clean` → MLA-EVC).
   - Count the floor on methods with live evidence.
   - Replace the `FRR-PVA-AA-06` citation.
   - Fix FAV's direction.
   - Then VDR proper: per-advisory episodes with detection time, a KEV join, and an accepted-vulnerability channel. That is a plan of its own, and the earlier VDR research (`docs/RESEARCH-VULNERABILITY-HARNESS.html`) is the place to start it.

**4. New recipes for KSIs a checkout *can* partly evidence.** Each is intended state only; pair it with the Prowler `aws-ingested` method for runtime state, which also gives class c its second method.
   1. `iac-network-restricted` (checkov subset) → CNA-RNT/MAT/ULN
   2. `iac-encryption-enforced` → SVC-SIN (replacing the policy-doc overclaim)
   3. `ci-workload-identity` (OIDC, no long-lived keys, scoped `permissions:`) → IAM-SNU, IAM-ELP, SVC-ASM
   4. `artifact-integrity-pinned` (FROM `@sha256`, cosign verify, signed tags) → SVC-VRI
   5. `iac-audit-logging-enabled` → MLA-LET/OSM, plus `deploy-from-version-control` → CMT-RMV

**Now, outside the plan:** upgrade `next` in `console/web` (reachable CRITICAL), and triage the gitleaks hit in `docs/context/prowler/fedramp_20x_ksi_2026.json:663` (vendored; likely a false positive, but it is the one row keeping `no-secrets-in-history` violated).

---

## 7. What this means for the pitch

The project's distinctive claim is that every row is *computed, signed and anchored, and unknowns count against you*. That holds as a design. As shipped it does not yet hold, and the gap is in exactly the places an assessor or a sharp reader would probe first:
- suppression files;
- a shallow CI checkout;
- the path alias every Next.js app ships with;
- `verify` run with only a public key.

The fixes in §6.1 are mostly small and local. Fixing them in public, with failing tests first and the advisory filed, is a stronger story than the original claim was.

---

## 8. Reproductions

All under `/tmp/claude-1000/-home-sunny-Projects-rampscan/7a45753a-d1ed-46b8-9ef7-2df640cf07f2/scratchpad/`:

| Dir | What |
|---|---|
| `selfscan/` | the fresh self-scan (`scan.log`, artifacts, `openvex.json`) |
| `mine/app` | independent repro of 1.1 (`@/` alias → five `not_affected` for marked@0.3.6) |
| `mine/gl` | independent repro of 1.2 (gitleaks exits 1 with `[]` on a failed scan) |
| `reach/` | `harness.mts`, fixtures `fxA`–`fxI`, end-to-end `runB/out/exports/openvex.json`, `g-vex.json` (the VEX applied to an unrelated SBOM) |
| `recipes/` | `harness.mts`, `pysast.mts`, `pop.mts`; fixtures `f1`–`f6`; ledgers `r1`–`r6` (dirty tree, withdrawal, suppression, Python SAST, auth heuristic, ledger omission) |
| `collectors/` | `r.sh <collector> <dir>`; gitleaks corrupt/ownership/suppression, semgrep, checkov, grype `.grype.yaml`, spectral, documents cases |
| `ksi/` | `frontier.txt`, `gaps.txt`, `frr.txt`, scratch-generated SDR/OCR/package overview |

Nothing tracked was modified except this document.
