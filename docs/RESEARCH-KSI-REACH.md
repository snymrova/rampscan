# Per-KSI reach — the north star, and a plan built around it

**Status:** brainstorm, 2026-09-21, at `main` = `0e9c8a8`, rules 2026.09.13.02. Not adopted. Every number below came from a command or a pinned file; the projections in §5 are arithmetic over those numbers and are labelled as projections.

**The decision this records:** the owner said the per-KSI reach table is the north star. Everything else — console, exports, runner, adapters — is ranked by how many rows of that table it moves, and how far up.

---

## 1. What "reach" means, so the number cannot be gamed

A tool on the shelf is not reach. A recipe in the catalog is not reach. Ground rule 7 applies to our own headline: the only row that counts is one an assessor can pull on. So reach is a **ladder per KSI**, and each rung is computed from the ledger and the pins, never typed:

| Rung | Meaning | Computed from |
|---|---|---|
| 0 `unreachable` | no tool on any plane can observe it; attestation only | the pins say so (§2) |
| 1 `reachable` | a tool exists somewhere that can observe it | pipeline catalog ∪ upstream AWS recipes ∪ Prowler framework |
| 2 `wired` | rampscan has a recipe or adapter that turns that tool's output into a method | `recipes/commit/`, `recipes --aws` runnable, an ingest adapter |
| 3 `run` | a signed bundle for that method exists in the ledger | the fold |
| 4 `fresh` | the newest bundle is inside its owed window | G3 |
| 5 `floor` | `automated ≥ class floor` (1 / 2 / 4 for b / c / d) | G2 |
| 6 `distinct` | the methods that meet the floor come from distinct evidence planes | method `source` |

**The north star is rung 4, counted over the 41 KSIs class b obliges:** *KSIs with at least one automated method inside its window.* Today that number is **0**. Rung 6 exists because the RFC-0033 draft's second point says four methods from one API call are one method; we should hold ourselves to what we asked FedRAMP for.

---

## 2. The table today

| KSI | pipeline recipes | upstream AWS recipes | runner executable now | Prowler AWS checks | best rung today |
|---|---|---|---|---|---|
| KSI-CED-RAT | 0 | 0 |  | 0 | 0 unreachable |
| KSI-CMT-LMC | 0 | 2 | yes | 16 | 2 wired |
| KSI-CMT-RMV | 0 | 6 | yes | 2 | 2 wired |
| KSI-CMT-RVP | 1 | 1 |  | 0 | 3 run (stale) |
| KSI-CMT-VTD | 4 | 2 |  | 0 | 3 run (stale) |
| KSI-CNA-DFP | 1 | 1 |  | 6 | 3 run (stale) |
| KSI-CNA-EIS | 0 | 0 |  | 4 | 1 reachable · optional at b |
| KSI-CNA-IBP | 1 | 1 | yes | 8 | 3 run (stale) |
| KSI-CNA-MAT | 0 | 1 |  | 35 | 1 reachable |
| KSI-CNA-OFA | 0 | 0 |  | 37 | 1 reachable |
| KSI-CNA-RNT | 0 | 2 |  | 11 | 1 reachable |
| KSI-CNA-RVP | 0 | 1 |  | 20 | 1 reachable |
| KSI-CNA-ULN | 0 | 3 | yes | 9 | 2 wired |
| KSI-IAM-AAM | 0 | 3 | yes | 6 | 2 wired |
| KSI-IAM-APM | 0 | 7 | yes | 13 | 2 wired |
| KSI-IAM-ELP | 3 | 12 | yes | 10 | 3 run (stale) |
| KSI-IAM-JIT | 0 | 4 |  | 24 | 1 reachable |
| KSI-IAM-SNU | 0 | 2 | yes | 13 | 2 wired |
| KSI-IAM-SUS | 0 | 1 |  | 3 | 1 reachable |
| KSI-INR-AAR | 0 | 1 |  | 0 | 1 reachable |
| KSI-INR-RIR | 0 | 1 |  | 0 | 1 reachable |
| KSI-INR-RPI | 0 | 1 |  | 0 | 1 reachable |
| KSI-MLA-ALA | 0 | 0 |  | 4 | 1 reachable · optional at b |
| KSI-MLA-EVC | 0 | 2 | yes | 1 | 2 wired |
| KSI-MLA-LET | 0 | 3 | yes | 43 | 2 wired |
| KSI-MLA-OSM | 0 | 5 | yes | 7 | 2 wired |
| KSI-MLA-RVL | 0 | 2 | yes | 0 | 2 wired |
| KSI-PIY-GIV | 1 | 2 |  | 3 | 3 run (stale) |
| KSI-PIY-RES | 0 | 0 |  | 0 | 0 unreachable |
| KSI-PIY-RIS | 0 | 0 |  | 0 | 0 unreachable |
| KSI-PIY-RSD | 1 | 0 |  | 0 | 3 run (stale) |
| KSI-PIY-RVD | 1 | 0 |  | 0 | 3 run (stale) |
| KSI-RPL-ABO | 0 | 2 | yes | 17 | 2 wired |
| KSI-RPL-ARP | 0 | 1 |  | 3 | 1 reachable |
| KSI-RPL-RRO | 0 | 1 |  | 0 | 1 reachable |
| KSI-RPL-TRC | 0 | 1 |  | 1 | 1 reachable |
| KSI-SCR-MIT | 5 | 4 |  | 10 | 3 run (stale) |
| KSI-SCR-MON | 3 | 3 |  | 5 | 3 run (stale) |
| KSI-SVC-ACM | 4 | 2 | yes | 3 | 3 run (stale) |
| KSI-SVC-ASM | 1 | 1 |  | 33 | 3 run (stale) |
| KSI-SVC-EIS | 0 | 4 | yes | 1 | 2 wired |
| KSI-SVC-PRR | 0 | 0 |  | 4 | 1 reachable · optional at b |
| KSI-SVC-RUD | 0 | 0 |  | 0 | 0 unreachable · optional at b |
| KSI-SVC-SIN | 2 | 7 | yes | 97 | 3 run (stale) |
| KSI-SVC-VCM | 0 | 2 |  | 3 | 1 reachable · optional at b |
| KSI-SVC-VRI | 0 | 3 | yes | 7 | 2 wired |

Sources: `recipes/commit/*.json` (20 recipes); `docs/context/ramprules/derived/aws-evidence.json` (57 recipes, overlay 4.3.0); `pnpm rampscan recipes --aws` with no `aws` block (22 runnable, 17 KSIs); `docs/context/prowler/fedramp_20x_ksi_2026.json` (443 AWS checks, 33 KSIs); `pnpm rampscan frontier` (13 with a method, all 39 days old against 7).

**Rung counts today, over 46:** unreachable 4 · reachable-only 14 · wired-only 12 · run 13 · fresh 0.

**Reached by every plane's union: 42 of 46.** The four at rung 0 — training review, executive support, security investment, unwanted-data removal — are people-and-money KSIs and stay attestation by design. They are the honest ceiling of the north star: **41 owed at class b, of which 40 are machine-reachable** (`KSI-CED-RAT`, `KSI-PIY-RES`, `KSI-PIY-RIS` are required at b; `KSI-SVC-RUD` is optional).

---

## 3. What moves rows, ranked by rows moved per day, with what blocks each

The order is not the phase order. §5 sequences it.

| Move | Rows moved | Rung change | Effort | Blocked on |
|---|---|---|---|---|
| **A. Run the pipeline on a clock** | 13 | run → fresh | 1 day | nothing |
| **B. Sandbox AWS account + T exit gates** | 17 now, up to 26 with the pipeline union | wired → run → fresh | owner's account; the code is done | owner |
| **C. Bind `aws.params`** | executable recipes 22 → 47; KSIs 17 → up to 36 | reachable → wired | config, half a day; exact count from the command | nothing, but proves nothing until B |
| **D. Prowler run against a real account** | 33 | reachable → run | one client run; adapter is built | an account (B's) |
| **E. Checkov rule → KSI crosswalk** | up to 8 on the commit plane (`CNA-MAT`, `CNA-RNT`, `CNA-ULN`, `IAM-SNU`, `MLA-LET`, `MLA-OSM`, `RPL-ABO`, `SVC-VCM`), as *declared state* | reachable → run on a second plane | 2 days | nothing |
| **F. SARIF ingest adapter** | admits a client's CodeQL, trivy, kics, zizmor, Scorecard, gitleaks output as methods | wired for whatever the client runs | 2–3 days, Prowler-shaped | nothing |
| **G. OCSF generalised** | Security Hub via Security Lake beside Prowler | wired on the cloud plane | 1–2 days on top of P3 | verify Security Lake's OCSF class matches |
| **H. Forge plane (R4.4)** | `CMT-RVP` on a second plane; `PIY-RVD` via advisories | run | 2 days | GitHub App or token |
| **I. Systems-of-record ingest for the reviewing KSIs** | `INR-AAR/RIR/RPI`, `MLA-RVL`, `RPL-RRO` | reachable → run, `automated: false` unless the tracker is the machine | manifest-shaped, like the tree adapter | a client with a tracker |
| **J. Security-audit skill as a detection source** | `PIY-RSD`, `SVC-EIS` as detection; opens VDR episodes | not a method; feeds R4 | one session to run; adapter later | nothing |
| **K. Attestation for the four** | 4 | unreachable → covered, never automated | built | a human |

Two things this table makes plain. **B is the single largest jump and it is the only owner-blocked one.** And **A costs one day and is the only move that changes the north-star number today**, because the number counts fresh rows and every row is stale.

---

## 4. Design notes per move — the constitution applied

**A. The clock.** Recipes declare their cadence (14 weekly, 4 daily, 2 monthly); `packages/scheduler` computes the MVX window; nothing invokes a scan. Options for the self-scan: (i) a `schedule:` workflow that runs `rampscan scan` on `main` weekly and uploads the ledger as a workflow artifact — the signing key becomes a repository secret, and the ledger is reproducible from the artifact; (ii) the same, appending to a ledger held in a separate private repository or a release asset, so the history (R3) accumulates across runs. (ii) is what "keep on providing" means; (i) proves the clock in a day. Either way the README's register is regenerated from the fresh ledger under ground rule 4, and the current `39d / 7d` on every row becomes the number the clock produced. T5 (scheduled `RunRequest`s) is the same move for the cloud plane and is already specified.

**E. Checkov as many methods, not one.** `iac-baseline-clean` evidences `KSI-SVC-ACM` with the whole checkov result set. Checkov's rules already separate network, logging, backup, encryption and IAM concerns; a reviewed, pinned rule-id → KSI crosswalk (the same shape as `recipes/crosswalks/`) derives one recipe per KSI over the same artifact. What it proves must be stated on the row: **intended state, from the declaration**, not the account's state — `KSI-CNA-EIS` is literally "enforcing intended state", and a checkov pass is the intent half. It corroborates the cloud plane; it does not replace it. That is why it counts as a *distinct* plane for rung 6 and why it never stands alone at rung 5 for a class-c floor of 2 without a cloud method beside it — a rule worth writing into the crosswalk's header.

**F. SARIF, the commit plane's OCSF.** One adapter, many tools. The mapping question is the same one Prowler answered: whose crosswalk? Prowler shipped its own KSI framework, so P3 pinned it. SARIF tools ship rule ids, not KSIs, so the crosswalk is ours, reviewed and pinned per tool version, and a rule id the crosswalk does not carry refuses the batch exactly as an unknown KSI does today. The four refusals carry over unchanged: our assertion over rows (`count_eq 0 where level = error`), the tool's verdict is data, empty rows pass only if the run's population is stated, exit code decides only whether the run failed. **What it does not get:** the reachability gate. A client's SARIF has no `graph.db` behind it, so its rows are `unknown` reachability and count against — which is honest, and which is also the argument for running rampscan's own collectors where the checkout is available.

**H and I. The reviewing KSIs.** Thirteen KSIs have no check on any Prowler provider; upstream's AWS recipes reach nine of them with document pulls (an after-action report in a bucket is still an artifact). The machine evidence for "reviewing" is that a review happened in a system of record: a pull-request approval, a closed incident ticket with a review field, a log-review ticket on a schedule. The forge plane (R4.4) is the first of these and it is where `KSI-CMT-RVP` gets a second plane. The rest are manifest-shaped ingests (the tree adapter's pattern) until a tracker API is worth a runner recipe. `automated` is `true` only when the tracker itself produced the row on a clock, never when a person exported it.

**J. Detection is not validation.** A security-audit run against the repository evidences that SDLC security review *ran* (`KSI-PIY-RSD`, via its coverage ledger) and produces *detections* for the VDR plane, never methods on the KSI plane. It belongs in R4's re-scope, not in the reach ladder, and is here so nobody counts it twice.

**Distinctness (rung 6).** The register already carries `source` on every method. Rung 6 is a fold: for each KSI at rung 5, the count of distinct `source` values among the automated methods that meet the floor. Printing it costs an afternoon and makes the RFC-0033 argument a number rampscan reports about itself first.

---

## 5. The plan, in order — and what the table reads after each step

Projections are arithmetic over §2 and are labelled as such; the real number is whatever `frontier` prints after the step lands.

1. **N0 — the ladder in `frontier` and on the KSI page.** One column, computed, README-gated. The north star becomes a printed number before anything moves it. *Half a day. Blocked on nothing. Lands inside U1, which is the KSI page anyway.*
   → reads: fresh **0 / 41**, and says so.
2. **N1 — the clock (move A).** Weekly self-scan on `main`, ledger persisted, README regenerated from it.
   → projected: fresh **13 / 41**. First non-zero north star.
3. **N2 — the commit plane widened (moves E, then F).** Checkov crosswalk first, because it moves rows on this repository; SARIF second, because it moves rows on a client's.
   → projected: run **up to 21 / 41** on the commit plane, fresh the same once N1 is running.
4. **N3 — the cloud plane lit (moves C, then B, then D).** Bind params now; run the runner and Prowler the day the sandbox account exists.
   → projected: run **up to 38 / 41** across planes; distinct planes on the 11 KSIs both the pipeline and AWS reach.
5. **N4 — the reviewing KSIs (moves H, I, K).** Forge plane, tracker ingests, attestations for the four.
   → projected: covered **41 / 41**, automated on **up to 40**, and the ladder says which rung each one earned.

Rung 6 is printed from N0 onward and rises as N3 and N4 land; it is not a phase.

---

## 6. What this reorders in the way-ahead, and what it does not

- **U1 stays next**, and N0 rides inside it: the KSI page is where the ladder lives.
- **N1 goes ahead of U2.** One day, moves the headline from 0, and nothing on the console is more persuasive than a register that is fresh.
- **R4 is re-scoped as the VER plane** per `RESEARCH-VULNERABILITY-HARNESS.html` §4, and stays paused until the owner calls it; move J waits with it.
- **T's exit gates and the sandbox account** are what N3 waits on; nothing here changes that it is the owner's.
- **#72 and the S3 sends** are untouched; rung 6 gives the RFC comment a number of its own if it is ever filed.

**Not in this plan:** a harness, a model as a method, a fourth `MethodSource` before a second cloud provider is wanted, and any row that counts a tool on the shelf.
