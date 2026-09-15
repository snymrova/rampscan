# rampscan — plan of action: one-click cloud evidence through a client runner (Phases T0–T5)

**Status:** **adopted 2026-09-15** with the merge of PR #146 (T0-1 to T0-3 decided by the owner; milestones T0–T5 on GitHub). Deliverable: *an operator clicks "Collect evidence" on a KSI row, a runner deployed in their own AWS account runs the published ramprules recipe under a read-only role, and the board moves — while the appliance itself still holds no AWS credential and makes no AWS call.* Nothing here is decided until it is merged and milestones T0–T5 exist on GitHub, the same bar the soundness plan cleared.
**Date:** 2026-09-14; re-read against `main` 2026-09-15 (session log).
**Phase letter:** **T**. A–N, P, Q, R and S are taken (O is skipped because it reads as zero). T follows S and reads as *trigger*.
**Sequencing against the plan of record:** the owner decided on 2026-09-14 to **plan now and build after S1 closes**. S1 closed 2026-09-15 (`286c566`), and S2 and S4 closed the same day, so the precondition is met and T may start. It does not displace S3, whose RFC-0033 comment (#72) is due **2026-10-09**. R2–R5 stay paused as `docs/PLAN-SOUNDNESS.md` §8 says.
**Reads against:** `main` at `285aabe` (first drafted against `c0a4d0a`); `docs/SPEC.md` §12.8 (the ingestion contract), §12.9 and §12.10; `SECURITY.md`; `console/web/PRODUCT.md`; `packages/cli/src/ingest.ts`; `packages/core/src/assert.ts`; `packages/schema/src/{ingest,method,bundle}.ts`; the pinned upstream overlay `docs/context/ramprules/derived/aws-evidence.json` (dataset `2026.07.14.01`); `docs/RESEARCH-PARAMIFY-PILOT.md` §3 and §8.

**Thesis in one line:** the ingestion contract already makes client-run AWS results count, but nobody runs recipes by hand on a 7-day clock. The missing piece is not execution inside the appliance. It is a runner that belongs to the client and can be triggered from the console, so the separation that makes rampscan trustworthy survives the convenience.

---

## 0. Ground rules, active from T0

The ten in `CONTRIBUTING.md` and the four in `PLAN-SOUNDNESS.md` §0 stay active. Five more are specific to this plan.

1. **The appliance never holds an AWS credential or makes an AWS call.** The runner does. They are separate programs with separate identities: the runner has an AWS role and no ledger key, and the appliance has a ledger key and no AWS role. This is enforced by a test, not by convention (T3-5). Neither side alone can mint cloud evidence.
2. **A run that could not look is never evidence.** `AccessDenied`, throttling, an unenabled service, a disabled region, a non-zero exit, or empty output from an API that errored produces a **failed run** that is visible on the Runs page. It never produces an `evidenced` bundle. This is ground rule 7 (no vacuous passes) applied to a new input, and it is the most likely way this plan ships a false attestation.
3. **The verdict is computed by the appliance from the raw bytes, never reported by the runner.** The runner uploads what the AWS CLI printed plus a signed transcript. It does not evaluate assertions. A compromised or buggy runner can then fail to collect, but it cannot declare a pass.
4. **Read-only by allowlist, never by blocklist.** A recipe is runnable only when every command's AWS action is on a reviewed list of non-mutating actions. Anything else is shown as *manual only*, with the reason.
5. **One click never means unreviewed.** Registering a runner and widening its allowlist are two-person decisions, through the same mechanism as N/A scoping, attestations and artifact judgments. Clicking "Collect evidence" is single-key because it only requests a read.

---

## 1. What exists, and what is missing

**Exists (Q4.1, SPEC §12.8):** `rampscan ingest` turns a client-produced `IngestSubmission` into a signed bundle with `source: aws-ingested`. It validates everything before appending anything. It has no commit anchor, so ingested evidence dies superseded or stale, never by anchor drift. `rampscan verify` checks it offline. First drafted, it had only ever been exercised on a synthetic fixture; since S3-1 it has read two real Phase One packages (`docs/RESEARCH-PARAMIFY-REGISTER.md`).

**Exists since S3-0 (#147, 2026-09-15) — T2's centre, landed early.** The appliance evaluates a submission's structured assertions itself with the pipeline's own evaluator (`packages/core/src/assert.ts`: `eq`, `exists`, `not_exists`, `in`, `lte`, `gte`, `max_age_days`, `count_eq`, `count_lte`, `where` filters, `population` always set, `max_age_days` judged against the run's own timestamp). A non-zero exit is a failed run — skipped and named, never a bundle. No assertion is `unevidenced`, never `evidenced`; `submissionVerdict` has no vacuous arm. The tree adapter takes exactly the rule T2-3 asked for. What T2 still owes is the failure *classes* beyond the exit code (T2-2) and the transcript adapter (T2-3's first half).

**Exists upstream, pinned:** `aws-evidence.json` holds **49 recipes over 36 KSIs**. 38 are `cli` and 11 are `config-rule`, rated 12 `full`, 36 `partial` and 1 `narrative`. **22 carry structured assertions** (`field`/`op`/`value`/`where`, ops `eq`, `count_eq`, `exists`, `not_exists`, `lte`, `max_age_days`). The other 27 carry only prose (`expected_output`, `notes`).

**First-pass executability.** A naive classifier (verb allowlist, placeholder and pipe detection, run 2026-09-14 over the pinned overlay) gives:

| | recipes | KSIs reached |
|---|---|---|
| Runnable as published | 24 | 21 |
| Contain a literal to parameterize (example account IDs, ARNs, dates, `s3://` paths) | 23 | — |
| Contain a pipe (`\| base64 --decode`, `\| jq`) | 3 | — |
| Contain an action not on a naive read-only list | 5 | — |

The five non-read actions are the reason ground rule 4 exists:
- `ssm send-command --document-name AWS-RunShellScript` **executes a shell on production instances** (`clock-synchronization-and-timestamps`). It is refused outright.
- `athena start-query-execution` writes results to S3. It is refused.
- `cloudtrail validate-logs`, `logs start-query` and `cloudtrail start-query` are read-only in effect. They are admitted by explicit review, which a verb regex would never do.

**Missing:**
- A way to trigger a run.
- A runner.
- Parameter binding for account-specific literals.
- ~~An appliance-side assertion evaluator.~~ Landed under S3-0.
- A failure model beyond the exit code.
- An emulator so the runner is exercised in CI (T3-0).
- A console surface for any of it.

---

## 2. The design

```
 console (appliance)                          client AWS account
 ┌───────────────────────────────┐            ┌──────────────────────────────┐
 │ KSI row ─ [Collect evidence]  │            │ rampscan-runner              │
 │    │ single key               │            │   own P-256 key (registered, │
 │    ▼                          │   pull     │   two-key)                   │
 │ RunRequest (signed, ledger)   │◄───────────┤   IAM role: read-only,       │
 │  recipe digest · params ·     │  outbound  │   generated from allowlist   │
 │  nonce · expiry · requester   │  from      │   │                          │
 │                               │  runner    │   ▼ argv exec, no shell      │
 │ /api/runs/intake  ◄───────────┼────────────┤ aws <cmd>  ·  sts            │
 │  verify runner sig + nonce    │  signed    │   get-caller-identity        │
 │  evaluate assertions on bytes │  transcript│   transcript = cmds, exit,   │
 │  → IngestSubmission → ingest  │  + raw     │   stderr class, timestamps,  │
 │  → bundle, board re-folds     │  outputs   │   caller ARN, region, digests│
 └───────────────────────────────┘            └──────────────────────────────┘
```

**Why pull.** The runner polls the console outbound, the same way a CI runner does. The appliance never reaches into the account, and no inbound port opens in the client's AWS. The console already runs inside the client's account (`PRODUCT.md`, Operating context), so the runner is a neighbour, not a remote caller.

**The same runner, three ways to host it.** One program with one contract:
1. **Sidecar** on the appliance host, as a separate process with its own instance-profile role. This is the default and the smallest deployment.
2. **One-shot in AWS CloudShell** for accounts that will not grant a standing role. The console shows a one-line command carrying a single-use request token. It is one paste rather than one click, and it uses exactly the same code path.
3. **Scheduled container (ECS task or Lambda).** This is T5, not the first slice.

**Identity and what the signature means.** The runner signs its transcript with its own key. The appliance verifies that signature, checks the request's nonce (single-use, recorded in the ledger), checks the recipe digest and parameters match what was requested, and checks the run's timestamps fall between issue and receipt. Only then does it evaluate assertions and mint the bundle through the existing ingest path. `signer_identity` names both parties: the runner (`runner:<name>`) and the AWS caller ARN it observed through `sts get-caller-identity`. The requesting console identity rides in the request event.

As SPEC §12.8 already states, the appliance's signature covers the **handoff**. It does not vouch for the account. The runner's signature covers "this role, in this account, received these bytes."

**Where it sits in the register.** It is still `source: aws-ingested`: the client's account, the client's runner, the client's role. The method union stays closed. The ingest provenance gains a strict optional `runner { name, caller_arn, account, partition, region, request_digest }` block, so a manual submission and a runner submission stay distinguishable to an assessor. Whether that block is enough or a fourth source is warranted is **T0-1**.

**Recipes without structured assertions (27 of 49).** The only automatic assertion available is "the command succeeded and printed N rows", and that proves collection, not compliance. Counting it as `evidenced` would be the vacuous pass ground rule 2 forbids. These runs therefore produce a collected artifact that enters the existing **artifact-sufficiency judgment** (Q3.3, G5, two-key) before it counts. The operator gets one click to collect and one approver decision to accept, and both are visible. **T0-2** confirms this choice.

---

## 3. Sequencing

```
T0 ──► T1 ──► T2 ──► T3 ──► T4 ──► T5
decide  which  judge   the    the    on a
& the   recipes the    runner button clock
tests   can run bytes
first
```

T1 and T2 are pure functions over pinned data and synthetic outputs, so they need no AWS account and can be tested exhaustively. T3 is the first phase that touches a real account, and T4 is the first that touches the console. The dangerous judgments (what is read-only, what counts as passed) are therefore settled and tested before anything can execute.

**Where an emulator fits, and where it does not.** T3 runs the real `aws` binary. Its happy path and its failure classes can run in CI against an AWS API emulator (T3-0) so every pull request exercises the runner end to end without an account. Two things stay on a real sandbox account and are never claimed from a mock: the denial self-check (T3-3, real IAM policy semantics) and the phase exit gates, which the plan words as *in a sandbox account* on purpose. A green emulator run is evidence that the runner works; it is not evidence that the role is read-only.

Estimates, in focused-work days: T0 0.5 · T1 1 · T2 0.5 (was 1.5; T2-1 and the tree half of T2-3 landed under S3-0) · T3 2.5 (T3-0 added) · T4 1.5 · T5 1. **Total ≈ 7 days.** T5 is optional for the first release.

### Phase T0 — decisions and the failing tests first (0.5 day)

- [x] **T0-1. Provenance shape** *(owner).* Recommendation: keep `aws-ingested` and add a strict `runner` provenance block. The alternative, a fourth `source`, changes the `FRC-CSX-VVK` numerator reasoning and every fold test for no gain an assessor can see. **Decided 2026-09-15: keep `aws-ingested`, add the strict optional `runner { name, caller_arn, account, partition, region, request_digest }` block.**
- [x] **T0-2. What counts for a recipe with no structured assertion** *(owner).* Recommendation: collected, then a two-key sufficiency judgment. The alternatives are refusing such recipes entirely, which cuts the runnable set roughly in half, or counting collection as evidence, which violates ground rule 7. **Decided 2026-09-15: collected and `unevidenced`, then the existing two-key artifact-sufficiency judgment (Q3.3) before it counts.**
- [x] **T0-3. First host** *(owner).* Recommendation: the sidecar plus CloudShell one-shot. ECS or Lambda waits for T5. **Decided 2026-09-15: sidecar (`poll`) plus CloudShell one-shot (`once`); ECS/Lambda stay in T5.**
- [x] **T0-4. The failing tests, first. (#165)** Before any runner code, commit the vacuous-pass cases the evaluator must refuse, under `it.fails`, each asserting *no `evidenced` bundle*:
  - an `AccessDenied` transcript;
  - a `count_eq 0` over output from a command that exited non-zero;
  - a credential report still in `STATE=STARTED`;
  - a transcript whose caller account differs from the configured account;
  - a replayed nonce.

  *Done 2026-09-15, PR #188.* The five cases are `packages/cli/test/runs-intake.test.ts`, under `it.fails`, each ending in `expectNoEvidencedBundle` and a class or refusal. Their input is the runner contract's first appliance-side shape, `packages/schema/src/transcript.ts` (`RunRequest`, `RunTranscript`, `TranscriptStep` with a `stderr_class` and never the bytes, `RunnerSelfCheck`), and the hole they fall through is `packages/cli/src/runs-intake.ts` — `intakeTranscript` typed to return `submission | failed(class) | refused(reason)` and implemented as the throw T2-2/T2-3 must replace. Run unwrapped at `b2133f0` before the PR: `5 tests | 5 failed`, every one at `runs-intake.ts:51` — `T2-2/T2-3 (#172, #173): the appliance does not read a run transcript yet — no intake exists, so no case in runs-intake.test.ts can pass until one does`. Every output byte in the cases is written by hand (T2-4's rule); the README figure moved to `1,205 tests across 97 files` and the numbers gate caught it first.
- [ ] **T0-5. SPEC §12.11 and `SECURITY.md` drafted. (#166)** Record the runner contract. The "What rampscan sends anywhere: Nothing" section changes to say precisely: the appliance still sends nothing, and the optional runner calls AWS read APIs in the client's own account under the client's role.

**Exit gate:** T0-1 to T0-3 are recorded decisions, and T0-4's cases exist and fail for the stated reason.

### Phase T1 — which recipes can run (1 day)

- [ ] **T1-1. The action allowlist. (#167)** A reviewed, checked-in list of AWS CLI actions. Every entry carries its IAM action name and one line on why it does not mutate. Admitting an action is a code-reviewed change; nothing is admitted by pattern.
- [ ] **T1-2. `classifyAwsRecipe(recipe, params)`. (#168)** A pure function returning `runnable` or `manual(reason[])`. Reasons are:
  - an action not on the allowlist;
  - an unbound parameter;
  - a shell construct (pipe, redirection, substitution);
  - a config-rule the account has not deployed (known only at run time, so it reports as a failed run, not a classification).
- [ ] **T1-3. Parameter binding. (#169)** `rampscan.config.json` gains `aws: { account_id, partition, regions[], trail_arn?, config_aggregator?, … }`. Upstream literals are mapped to parameters by a reviewed table keyed by recipe id; nothing is detected by regex at run time. A recipe whose literal has no binding is `manual(unbound: trail_arn)`. It is never run with the example account ID.
- [ ] **T1-4a. A `kubectl` allowlist. (#170)** The Paramify pilot's four EKS scripts run `kubectl get`/`describe` inside the cluster (`docs/RESEARCH-PARAMIFY-PILOT.md` §8.2). That is a second axis: cluster RBAC and an access entry for the runner's role, not an IAM policy. First release: `get` and `describe` on a named list of resource kinds, a read-only `ClusterRole` the runner prints beside the IAM policy (T3-3), and a cluster-side denial probe. Until those exist, recipes needing `kubectl` are `manual(kubectl)`.
- [ ] **T1-4. The three pipes become steps. (#170)** `base64 --decode` and `jq` projections are re-expressed as in-runner transforms over captured bytes. The raw output is still the stored artifact, so the transform is reproducible.
- [ ] **T1-5. `rampscan recipes --aws` (#171)** prints the classification for the pinned overlay and the configured parameters. It lists every `manual` recipe with its reasons: ground rule 4 (computed, never typed) for the runnable count.

**Exit gate:** classification is golden-tested over all 49 pinned recipes. `ssm send-command` and `athena start-query-execution` are `manual` with the reason stated. The runnable count in this document is replaced by the command's output.

### Phase T2 — the appliance judges the bytes (0.5 day remaining)

- [x] **T2-1. Assertion evaluator** over the six upstream ops, with `where` filters, on CSV and JSON outputs. `max_age_days` is judged against the **transcript's** timestamp, not the ingest clock. Output is `IngestedAssertion[]` with `population` always set, so "0 of 0" and "0 of 412" stay distinguishable. *Landed under S3-0 (#147, `packages/core/src/assert.ts`, wired in `ingest.ts` with `new Date(entry.timestamp)` as the clock). JSON rows only so far; CSV rows arrive with the transcript adapter (T2-3), since the credential report is the one CSV recipe and the runner captures it whole.*
- [ ] **T2-2. Failure classification. (#172)** A transcript maps to exactly one of `ok`, `denied`, `not-enabled`, `throttled`, `incomplete` (async report not ready) or `error`. Only `ok` proceeds to evaluation. T0-4's cases are unwrapped here. *Today the adapter knows one class, exit ≠ 0; the runner's classified stderr (T3-1) is what makes the others decidable.*
- [ ] **T2-3. Transcript → `IngestSubmission` → existing `ingest`. (#173)** There is no second signing path and no second bundle shape. Recipes without assertions go to the sufficiency-judgment queue instead (T0-2). ~~**The tree adapter takes the same rule** (#147): `ingest.ts:157` currently treats a script's exit 0 as a pass~~ — *done under S3-0: exit 0 is collection, the entry's declared assertions are evaluated by the appliance, none is `unevidenced`, non-zero is a failed run.* What remains is the transcript half: the runner's signed transcript is the input, and its `assertions` are **never** read from the transcript — on the native path a submitter's assertions are its own claim, and the runner is not permitted one (ground rule 3).
- [ ] **T2-4. Outputs are written by us. (#174)** Synthetic AWS outputs cover each op, including a planted non-MFA user, a 120-day-old key and an empty but valid list. No fixture is copied from upstream or from Paramify's unlicensed repository. *S3-0's fixture covers `eq` over JSON rows with a planted NONCOMPLIANT principal; the rest is owed, and doubles as the emulator's seed (T3-0).*

**Exit gate:** every T0-4 case passes. A planted violation yields `violated` with the offending row named. An `ok` empty population is reported as such, never silently as a pass.

### Phase T3 — the runner (2.5 days)

- [ ] **T3-0. The emulator, for CI only. (#175)** An AWS API emulator the runner is pointed at through `AWS_ENDPOINT_URL`, so the real `aws` binary runs end to end on every pull request with no account. Choose **Moto in server mode** (`moto[server]`, one container in a compose file and a CI service) over LocalStack: Moto mocks the services the pinned recipes read (IAM credential reports, CloudTrail, Config, GuardDuty, KMS, S3, EC2) and has opt-in IAM enforcement (`INITIAL_NO_AUTH_ACTION_COUNT`), which is what T2-2's `denied` class needs; LocalStack's enforcement is a paid feature, so its free tier can only give the happy path. The seed is T2-4's synthetic fixtures loaded through the same CLI: a planted non-MFA user, a 120-day-old key, an account with no GuardDuty detector. The suite is tagged and **skips, named, when the endpoint is absent** — a missing emulator is a skipped collector, not a green run. Recorded in `SECURITY.md` beside ground rule 1: the emulator is where the runner is tested, never where a claim about a client's account is made. *Verify before adopting:* whether Moto answers `iam simulate-principal-policy` and `iam generate-credential-report` → `get-credential-report` with the `STATE=STARTED` first response T0-4 needs; if not, those two stay stubbed at the transcript level.
- [ ] **T3-1. `packages/runner`. (#176)** Node, **no runtime dependencies**, and no import of `@rampscan/ledger`, `signer`, `projector` or `cli`. It executes the `aws` CLI with argv arrays (never `sh -c`), so the command run is the published command. It captures stdout bytes, exit code, a classified stderr (never raw, which can carry account detail into logs), timestamps, region and `sts get-caller-identity`.
- [ ] **T3-2. The runner key and registration. (#177)** `rampscan-runner init` generates a P-256 key and prints its public key. An operator proposes the runner in the console, and an approver's key turn records it as a signed ledger event (the fourth two-key write). Revocation is a signed `revoked` that supersedes it.
- [ ] **T3-3. `rampscan runner policy` (#178)** generates the IAM policy from the allowlist, and only for recipes classified runnable under the current parameters. At start-up the runner checks with `iam simulate-principal-policy` that a probe set of mutating actions is **denied**, and refuses to run if any is allowed. The result goes into every transcript.
- [ ] **T3-4. Modes: (#179)** `poll` (sidecar) and `once --request <token>` (CloudShell).
- [ ] **T3-5. The boundary test. (#180)** A test fails if any package other than `packages/runner` can spawn `aws`, declares an `@aws-sdk/*` dependency, or reads `AWS_*` environment variables. It also fails if `packages/runner` imports a rampscan package that can sign a bundle. Ground rule 1 gets an *Enforced by* line on the day it is written.

**Exit gate:** in a **sandbox** AWS account, `once` runs `iam-credential-report` end to end, the self-check denial probe passes, and the transcript verifies. The runner is shown to fail closed under a role with `iam:CreateUser` allowed. The same `once` run, and a `denied` run, pass in CI against the emulator (T3-0); the emulator result is reported as what it is and is not the gate.

### Phase T4 — the button (1.5 days)

- [ ] **T4-1. "Collect evidence" (#181)** on Board and Queue KSI rows, and on Clock rows as "Re-run now". It lists the KSI's runnable recipes, with manual ones and their reasons beneath. Clicking mints a signed `RunRequest` ledger event binding the recipe digest, parameters, nonce, expiry and requester.
- [ ] **T4-2. `/api/runs/next` and `/api/runs/intake`. (#182)** Both authenticate the runner by signature, not by a console session. Intake is strict and size-limited, is idempotent on nonce, and follows the decide routes' order: ledger first, projection follows.
- [ ] **T4-3. The Runs page shows the lifecycle: (#183)** `requested → claimed → submitted → accepted | refused(reason) | failed(class)`. A failed run is a row with its class, never an absence.
- [ ] **T4-4. The CloudShell path. (#184)** For a request with no registered sidecar, the dialog shows the one-line `once` command with its token, and a copy button.
- [ ] **T4-5. Playwright smoke (#185)** against a stub runner that replays a recorded transcript, so CI needs no AWS account.

**Exit gate (the plan's):** in a sandbox account, one click on `KSI-IAM-APM` raises its method count on the board. `rampscan verify` on the new bundle names the runner, the caller ARN and the handoff digest. A planted MFA-less user turns the row `violated`. Removing the role's `iam:GetCredentialReport` yields a `failed(denied)` run and **no** bundle. The appliance process's environment contains no AWS credential.

### Phase T5 — on a clock (1 day, optional for first release)

- [ ] **T5-1. Scheduled requests. (#186)** The existing `scheduler` package mints `RunRequest`s ahead of each method's MVX window (7 days at class b, 3 days at class c), so machine-verified KSIs stay fresh without anyone clicking.
- [ ] **T5-2. ECS task and Lambda packaging (#187)** of the same runner, with a GovCloud (`aws-us-gov`) partition test.

**Exit gate:** a runnable method's freshness is renewed on schedule in the sandbox across one simulated window.

### Explicitly not in this plan

- **The appliance calling AWS through an SDK.** That is option 3 of the 2026-09-14 decision, and it was not chosen.
- **Writing or remediating anything in the account.** rampscan collects evidence. It does not fix findings.
- **Our own AWS recipes.** Upstream's recipe ids and commands are used as published. Where one is unsafe or unbindable it is `manual`, and a correction goes upstream as an issue, not as a local fork of the recipe.
- **Multi-account fan-out through Organizations.** One runner per account first. Aggregator recipes that already read organization-wide still work where the role allows.

---

## 4. What is true when it is done

- An operator can collect cloud evidence from the console for every recipe that is safe to run automatically. Every other recipe is listed with the reason it is not.
- The appliance still holds no AWS credential, and a test says so.
- A run that could not see the account never becomes evidence. It becomes a visible failed run.
- Every verdict is computed from bytes the assessor can fetch by digest, by code the runner does not contain.
- Machine-verified KSIs can stay inside their MVX window without anyone remembering to rerun a script.

---

## 5. Honest constraints and risks

1. **This widens the trust boundary even though the appliance does not execute.** A runner with a standing read-only role is a new principal in the client's account, and reading IAM, CloudTrail and Config is highly sensitive. The mitigations are the generated least-privilege policy, the self-check, the two-key registration and CloudShell mode for clients who refuse a standing role. The boundary is still wider than "the client pastes commands", and `SECURITY.md` must say so plainly.
2. **Upstream recipes were written to be read by people, not executed by machines.** 23 of 49 embed example literals, three pipe to other tools, and one runs a shell on production hosts. The allowlist and binding table are ongoing maintenance that moves with every overlay bump. A dataset pin bump without re-review can only turn recipes `manual`, never admit a new action.
3. **The runnable set is smaller than it looks.** Roughly 24 recipes run as published, and only the 22 with structured assertions can be judged without a human. The first release makes about half the upstream plane one-click. The Runs and recipe views must print that fraction and not round it up.
4. **Sensitive bytes enter the ledger's artifact store.** Credential reports list every principal. The artifacts stay inside the boundary, as all evidence does. The console must still redact principal names in rendering, as the gitleaks path already does, and the plan must not make these artifacts easier to exfiltrate than today's scan output.
5. **This is not soundness work, and it is sequenced after S1 for that reason.** Making evidence easier to produce while the reachability gate still signs claims it has not earned would be building on the defect.

---

## 6. Adoption

This document decides nothing until it is merged and milestones T0–T5 exist on GitHub, with T0-1 to T0-3 recorded as decisions. Building starts at the S1 exit. S3's #72 deadline takes precedence over any T phase it collides with.

---

## Session log

- **2026-09-15 (T0-4, #165)** — Plan adopted at `b2133f0`. The five vacuous-pass cases committed under `it.fails` against a transcript contract (`packages/schema/src/transcript.ts`) and an intake that does not exist yet (`runs-intake.ts` throws); recorded failing at `b2133f0`. Next: T0-5 (#166), SPEC §12.11 and `SECURITY.md` from the contract the cases now name.
- **2026-09-15** — Re-read against `main` at `285aabe`, with S1, S2 and S4 closed and the build precondition met. S3-0 (#147) landed T2-1 and the tree half of T2-3 ahead of this plan: the appliance evaluates declared assertions with `packages/core/src/assert.ts`, exit ≠ 0 is a failed run, no assertion is `unevidenced`. T2 marked accordingly (0.5 day left: failure classes and the transcript adapter). Added T3-0, an AWS API emulator (Moto server mode) for CI, with the boundary stated: it tests the runner, it never stands in for the sandbox account at a gate or for the denial self-check. Total ≈ 7 days. The owner then took the three T0 decisions, each the recommended option; the plan is adopted with this merge.
- **2026-09-14 (later)** — Re-read the Paramify pilot against this plan (`RESEARCH-PARAMIFY-PILOT.md` §8). Its 23 scripts are admissible under T1-1 as-is, all `describe/get/list`; four need `kubectl`, added as T1-4a. Their exit-code convention turned out to mean *collected*, not *compliant*, which is what the existing tree adapter assumes — #147, noted at T2-3.
- **2026-09-14** — Drafted after the owner chose, over two alternatives, a one-click trigger through a client-deployed runner rather than guided copy-and-upload or execution inside the appliance, and chose to plan now and build after S1. Numbers in §1 come from reading the pinned `aws-evidence.json` overlay (49 recipes, 36 KSIs, 22 with structured assertions, 38 `cli` / 11 `config-rule`) and from a first-pass classifier that is deliberately naive; T1-5 replaces its counts with a command. Found while reading: `clock-synchronization-and-timestamps` uses `ssm send-command AWS-RunShellScript` against production-tagged instances, which is why read-only is an allowlist of reviewed actions and not a verb pattern. Not yet adopted.
