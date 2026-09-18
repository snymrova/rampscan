import { evaluateAssertion } from "@rampscan/core";
import type { ObservationRows } from "@rampscan/core";
import type {
  Cadence,
  DigestedArtifact,
  IngestSubmission,
  IngestedAssertion,
  RecipeAssertion,
} from "@rampscan/schema";
import type { SkippedEntry } from "./ingest.js";
import {
  PROWLER_COMPLIANCE_ID,
  PROWLER_FRAMEWORK_PIN,
  PROWLER_PROVIDERS,
  uncoveredKsis,
} from "./prowler-framework.js";
import type { ProwlerKsiFramework } from "./prowler-framework.js";
import type { ProwlerOcsfDocument, ProwlerOcsfRow } from "./prowler-ocsf.js";

// The Prowler adapter (docs/RESEARCH-PROWLER-INGEST.md §4c, §6): the contract
// declared by P3-2, the body built by P3-3, the coverage measure by P3-3a, and
// the muting decision and provider guard by P3-4.
//
// WHY THE CONTRACT CAME BEFORE THE BODY. §7 of the note: "the risk is not
// effort, it is the vacuous pass — which is why P3-2 is written before P3-3
// rather than after." The three obligations below are the ones that, if
// forgotten, sign `evidenced` for the thirteen indicators this input has the
// LEAST evidence about. They are written down, and tested, before there is an
// implementation that could quietly not meet them.
// `prowler-ingest-soundness.test.ts` held them under `it.fails` until P3-3
// unwrapped them; they now pass.
//
// THE THREE OBLIGATIONS (§4c, in the note's order).
//
//   1. A `MANUAL` ROW IS NEVER EVIDENCE. Prowler's framework routes every
//      requirement no check reaches to the universal writer, which emits one
//      synthetic row for it. The obvious assertion — "no FAIL rows for this
//      indicator" — therefore passes VACUOUSLY over exactly the thirteen
//      indicators nothing looked at. P3-1 already made the first half of this
//      structural: `ProwlerOcsfDocument.byKsi` has NO ENTRY for a MANUAL-only
//      indicator, so an adapter cannot reach rows it might mint a pass from.
//      What is owed HERE is the second half: those indicators are skipped and
//      NAMED (`SkippedEntry`, the way #147's failed run is), never a bundle
//      under any verdict. They then land in G1 — "no validation method
//      derives, nothing to cite is the finding" — which is the honest place,
//      and the board reads exactly as it would had Prowler never run.
//
//   2. THE ASSERTION STATES ITS OWN POPULATION. `count_eq 0` over zero
//      surviving rows must FAIL, not pass. `evaluateAssertion` passes an empty
//      filtered set by design and is shared with every pipeline recipe, so the
//      non-emptiness check is carried HERE rather than by changing an
//      evaluator under other callers' feet. (`assert-labeled.ts` already takes
//      this position for its own ops: "`every element` over nothing is the
//      vacuous pass ground rule 7 forbids.")
//
//   3. THE EXIT CODE DECIDES NOTHING. Prowler exits 3 when unmuted failures
//      exist, 1 on a critical error, 0 otherwise — and exit 3 is suppressed by
//      `-z` / `--ignore-exit-code-3`, and is not emitted at all when every
//      failure is muted. So a clean exit 0 is consistent with a scan that
//      failed everything and muted it. This exit 0 is WEAKER than the tree
//      adapter's, and #147's rule applies with more force, not less: non-zero
//      is a failed run and is skipped; zero is a run that finished, and the
//      verdict comes from the assertion over the rows.
//
// WHY THE EXIT CODE IS DECLARED RATHER THAN READ. §10b: the OCSF compliance
// output is a bare array of findings with no header of any kind — no scan id,
// no arguments, no start/end pair, and no exit code. Everything scan-level has
// to be stated by the client, the way the tree manifest states it, which is
// also why P3-3a measures the population it evaluated instead of describing a
// filtered scan as a scan.

//
// WHAT P3-3 ADDED, beyond the three obligations.
//
//   - ONE SUBMISSION PER (CHECK, KSI), never per row (§10e). One check over
//     forty IAM users is forty rows for one KSI, and ingest refuses a
//     duplicate `(recipe, KSI)` by refusing the WHOLE batch. `recipe_id` is
//     the Prowler check id — upstream's name, not ours (§4a).
//   - THE ASSERTION IS RAMPSCAN'S, over `status_code` (§4b, §10d). The
//     effective status, not the nested raw check status: a scan's own config
//     can force a requirement to FAIL while the check read PASS, and taking
//     the nested one reopens the hole upstream closed. The divergence is
//     counted into the transcript, because it is the one piece of scan-level
//     context this input carries at all.
//   - `automated` FOLLOWS THE RUNNER'S RULE, `assertions.length > 0`
//     (`runs-intake.ts`): a machine validated this only because rampscan
//     evaluated an assertion over it, never because Prowler said PASS.
//
// P3-3a — THE POPULATION, STATED. §10b: a `--status PASS` scan and a clean
// scan are the same document, so nothing here may describe what it read as
// "a scan". What IS computable is, per KSI, how many of the AWS checks the
// pinned framework maps to it actually reported. That is recorded on every
// assertion's `detail` and returned as `coverage` for the log. It is a real
// but bounded defence — hiding a FAIL with `--status PASS` drops that check
// from the reported set unless the same check passed on another resource —
// which is why it is printed rather than treated as proof of a complete scan.
//
// P3-4 — MUTING, DECIDED: A MUTE WAIVES NOTHING HERE. A muted finding
// (`status == "Suppressed"`) stays in the population with its own
// `status_code`; a muted FAIL still fails the assertion, and the count of
// muted rows is named in the detail. §4c offered two outcomes — exclude and
// name, or refuse — and this is the stricter reading of the first one's
// intent. Excluding a muted FAIL would let a provider's mutelist move the
// FRC-CSX-VVK numerator by deleting the evidence against it; rampscan's own
// waiver path is an adjudication, signed by someone, and a Prowler mutelist
// is neither. It also closes obligation 2 structurally: a group is built
// from reported rows, so no assertion here ever runs over nothing.
//
// P3-4 — THE PROVIDER GUARD. §4a scopes P3 to AWS inside `aws-ingested`, so a
// non-AWS Prowler document is refused rather than minted under the wrong
// source. The compliance output names no provider field this reader trusts,
// so the guard is the JOIN: every reported check must be one the pinned
// framework maps on AWS for that KSI. An Azure/GCP/Kubernetes/M365 check
// fails that join and is named with the provider that does map it; an
// account uid that is not a twelve-digit AWS account is refused beside it.

/**
 * What the client must state about the run, because the document does not.
 *
 * Deliberately not a superset of the tree manifest: only the facts P3's
 * obligations and a submission's required fields turn on.
 */
export interface ProwlerRunDeclaration {
  /**
   * The process exit status the client's orchestrator recorded. Obligation 3:
   * non-zero is a failed run and everything in the document is skipped; zero
   * is a run that finished and decides nothing else.
   */
  exit_code: number;
  /** who ran it and stands behind it — the `runner:` convention (§6, P3-3) */
  signer_identity: string;
  /** the cycle the client runs the scan on — the document carries none */
  cadence: Cadence;
  /**
   * The compliance file itself, by the digest of the bytes the appliance
   * read. Every submission cites it: the bundle attests to that file, and
   * the rows it evaluated are a projection of it.
   */
  artifact: DigestedArtifact;
}

/** P3-3a: one KSI's mapped-check coverage in this document */
export interface ProwlerCoverage {
  ksi: string;
  /** the AWS check ids the pinned framework maps to this KSI, upstream's order */
  mapped: readonly string[];
  /** which of them produced at least one reported row, in `mapped` order */
  reported: readonly string[];
}

/**
 * The adapter's output, in `loadSubmissions`' shape so the Prowler path joins
 * ingest where the tree and package paths already do.
 */
export interface ProwlerSubmissions {
  submissions: IngestSubmission[];
  /**
   * Obligation 1's half: an indicator Prowler declared uncovered, named here
   * rather than minted. Also obligation 3's: every indicator in a failed run.
   */
  skipped: SkippedEntry[];
  /** P3-3a, for every KSI the framework maps an AWS check to, ascending */
  coverage: ProwlerCoverage[];
  /** what the input said about itself, for the log */
  notes: string[];
}

class ProwlerIngestError extends Error {}

/** the `script` a skip names when no one check is the subject */
const PROWLER_SCRIPT = "prowler";

/**
 * The assertion rampscan evaluates over one (check, KSI) group. Pinned here,
 * not read from the input: the whole of §4b is that Prowler's verdict is data
 * and this is the claim.
 */
export const PROWLER_NO_FAILING_FINDINGS: RecipeAssertion = {
  field: "effectiveStatus",
  op: "count_eq",
  value: 0,
  where: [{ field: "effectiveStatus", op: "eq", value: "FAIL" }],
  description:
    "No finding this Prowler check reported for the indicator reads FAIL (effective status_code; muted findings counted)",
};

/** the evaluator's view of one reported row — named so a failing row points somewhere */
function observation(row: ProwlerOcsfRow): Record<string, unknown> {
  return {
    effectiveStatus: row.effectiveStatus,
    rawCheckStatus: row.rawCheckStatus,
    muted: row.muted,
    configOverride: row.configOverride,
    check_id: row.checkId,
    resource_id: row.findingUid,
    ...(row.region !== undefined ? { region: row.region } : {}),
    ...(row.account !== undefined ? { account: row.account } : {}),
  };
}

/** the checks a KSI maps that did not report, the first few named and the rest counted */
function notReported(c: ProwlerCoverage): string {
  const missing = c.mapped.filter((m) => !c.reported.includes(m));
  if (missing.length === 0) return "";
  const shown = missing.slice(0, 5).join(", ");
  return ` (not reported: ${shown}${missing.length > 5 ? `, +${missing.length - 5} more` : ""})`;
}

/** the latest `time_dt` in a group — the run's clock, as late as it read */
function latest(rows: readonly ProwlerOcsfRow[]): string {
  return rows.reduce((a, r) => (Date.parse(r.timestamp) > Date.parse(a) ? r.timestamp : a), rows[0]!.timestamp);
}

/**
 * P3-4's provider guard, as the join it is. Returns the refusals; the caller
 * reports them together, the way ingest reports a batch's problems.
 */
function providerRefusals(
  doc: ProwlerOcsfDocument,
  mappedAws: ReadonlyMap<string, ReadonlySet<string>>,
  fw: ProwlerKsiFramework,
): string[] {
  const problems: string[] = [];
  for (const [ksi, rows] of doc.byKsi) {
    const aws = mappedAws.get(ksi) ?? new Set<string>();
    for (const checkId of new Set(rows.map((r) => r.checkId))) {
      if (aws.has(checkId)) continue;
      const req = fw.requirements.find((r) => r.id === ksi);
      const elsewhere = PROWLER_PROVIDERS.filter((p) => p !== "aws" && req?.checks[p].includes(checkId));
      problems.push(
        elsewhere.length > 0
          ? `${checkId} on ${ksi} is a ${elsewhere.join("/")} check — P3 ingests Prowler's AWS provider only, as aws-ingested (§4a); a second provider is a fourth MethodSource, a schema change, never a file that started deriving methods`
          : `${checkId} on ${ksi} is not a check the pinned framework maps to that indicator on any provider — the scan's mapping is not the one this checkout pins`,
      );
    }
  }
  for (const account of doc.accounts) {
    if (!/^\d{12}$/.test(account)) {
      problems.push(
        `account "${account}" is not a twelve-digit AWS account id — P3 ingests Prowler's AWS provider only (§4a)`,
      );
    }
  }
  return problems;
}

/**
 * Turn a read Prowler compliance document into submissions.
 *
 * `framework` is the pinned framework, passed rather than loaded for the
 * reason `parseProwlerOcsf` takes its catalog: this is a join between pinned
 * sides, and each side is handed in so a test can plant the other.
 */
export function prowlerSubmissions(
  document: ProwlerOcsfDocument,
  run: ProwlerRunDeclaration,
  framework: ProwlerKsiFramework,
): ProwlerSubmissions {
  if (document.standard !== `${PROWLER_FRAMEWORK_PIN.framework}-${PROWLER_FRAMEWORK_PIN.version}`) {
    throw new ProwlerIngestError(
      `the document states ${document.standard}, and the adapter joins against ${PROWLER_FRAMEWORK_PIN.framework}-${PROWLER_FRAMEWORK_PIN.version}`,
    );
  }
  if (framework.version !== PROWLER_FRAMEWORK_PIN.version) {
    throw new ProwlerIngestError(
      `the framework handed to the adapter is ${framework.version}, pinned ${PROWLER_FRAMEWORK_PIN.version}`,
    );
  }

  const mappedAws = new Map<string, ReadonlySet<string>>(
    framework.requirements.map((r) => [r.id, new Set(r.checks.aws)]),
  );

  // The document's MANUAL rows and the framework's uncovered set must agree:
  // the writer emits a MANUAL row exactly for a requirement the framework
  // maps no check to, so a MANUAL row on a KSI the pin DOES map is a scan
  // that ran a different mapping.
  const uncoveredAws = new Set(uncoveredKsis(framework, "aws"));
  const problems = document.manual
    .filter((ksi) => !uncoveredAws.has(ksi))
    .map(
      (ksi) =>
        `${ksi} arrives as a MANUAL row, but the pinned framework maps AWS checks to it — the scan's framework is not this checkout's`,
    );
  problems.push(...providerRefusals(document, mappedAws, framework));
  if (problems.length > 0) {
    throw new ProwlerIngestError(
      `Prowler ingestion refused — nothing minted:\n${problems.map((p) => `  ${p}`).join("\n")}`,
    );
  }

  // P3-3a, computed before any verdict so a failed run states it too
  const coverage: ProwlerCoverage[] = framework.requirements
    .filter((r) => r.checks.aws.length > 0)
    .map((r) => {
      const seen = new Set((document.byKsi.get(r.id) ?? []).map((row) => row.checkId));
      return { ksi: r.id, mapped: r.checks.aws, reported: r.checks.aws.filter((c) => seen.has(c)) };
    })
    .sort((a, b) => a.ksi.localeCompare(b.ksi));
  const coverageOf = new Map(coverage.map((c) => [c.ksi, c]));

  const notes: string[] = [
    `prowler: ${document.rowCount} row(s) from Prowler ${document.prowlerVersions.join(", ")} against ` +
      `${document.standard}, account(s) ${document.accounts.join(", ") || "(none stated)"}`,
    `prowler: the scan's arguments are not recoverable from its output (§10b) — what follows is the ` +
      `population this document carries, not a claim that the scan was unfiltered`,
    ...coverage.map(
      (c) =>
        `prowler: ${c.ksi} coverage ${c.reported.length}/${c.mapped.length} mapped AWS checks reported` +
        notReported(c),
    ),
  ];

  // Obligation 1: MANUAL-only indicators are named, never minted — on a
  // clean run and a failed one alike.
  const skipped: SkippedEntry[] = document.manual.map((ksi) => ({
    ksi,
    script: PROWLER_SCRIPT,
    ...(run.exit_code !== 0 ? { exit_code: run.exit_code } : {}),
    reason:
      run.exit_code !== 0
        ? `exit ${run.exit_code} is a failed run, and no check reaches this indicator in any case (Prowler wrote a MANUAL row) — skipped, not signed`
        : `no check reaches this indicator at the pinned framework — Prowler wrote a MANUAL row, which is a statement that nothing looked, never evidence; skipped, not signed (it stays in G1)`,
  }));

  const groups = new Map<string, { ksi: string; checkId: string; rows: ProwlerOcsfRow[] }>();
  for (const [ksi, rows] of document.byKsi) {
    for (const row of rows) {
      const key = `${row.checkId}#${ksi}`;
      const g = groups.get(key);
      if (g === undefined) groups.set(key, { ksi, checkId: row.checkId, rows: [row] });
      else g.rows.push(row);
    }
  }
  const ordered = [...groups.values()].sort(
    (a, b) => a.ksi.localeCompare(b.ksi) || a.checkId.localeCompare(b.checkId),
  );

  // Obligation 3b: a non-zero exit is a failed run — every group is named
  // and none becomes a bundle. The account was not fully read, so there is
  // nothing to attest to and nothing to violate.
  if (run.exit_code !== 0) {
    for (const g of ordered) {
      skipped.push({
        ksi: g.ksi,
        script: g.checkId,
        exit_code: run.exit_code,
        reason: `exit ${run.exit_code} is a failed run — Prowler did not finish reading the account, so there is nothing to attest to and nothing to violate; skipped, not signed`,
      });
    }
    return { submissions: [], skipped, coverage, notes };
  }

  const versions = document.prowlerVersions.join(",");
  const submissions: IngestSubmission[] = ordered.map((g) => {
    const rows: ObservationRows = g.rows.map(observation);
    const now = new Date(latest(g.rows));
    const evaluated = evaluateAssertion(PROWLER_NO_FAILING_FINDINGS, rows, now);
    const cov = coverageOf.get(g.ksi)!;
    const muted = g.rows.filter((r) => r.muted).length;
    const overridden = g.rows.filter((r) => r.configOverride).length;
    const facts = [
      `${g.rows.length} finding(s) from ${g.checkId}` + (muted > 0 ? `, ${muted} muted and counted` : ""),
      ...(overridden > 0
        ? [`${overridden} forced to FAIL by the scan's own config while the check read PASS (§10d)`]
        : []),
      `${g.ksi} coverage ${cov.reported.length}/${cov.mapped.length} mapped AWS checks reported`,
    ].join("; ");
    const assertion: IngestedAssertion = {
      ...evaluated,
      detail: `${evaluated.detail ?? ""} — ${facts}`,
    };
    // Obligation 2, carried by the caller rather than the shared evaluator:
    // a pass must have looked at something. Unreachable while groups are
    // built from reported rows — kept so a change to grouping cannot make it
    // reachable silently.
    if (assertion.passed && (assertion.population ?? 0) === 0) {
      assertion.passed = false;
      assertion.detail = `no finding survived to evaluate — a pass over nothing is not evidence; ${facts}`;
    }
    const assertions = [assertion];
    return {
      _type: "https://rampscan.dev/ingest-submission/v1",
      recipe_id: g.checkId,
      ksi: g.ksi,
      evidence_class: "process-generated",
      cadence: run.cadence,
      artifacts: [run.artifact],
      assertions,
      timestamp: latest(g.rows),
      signer_identity: run.signer_identity,
      automated: assertions.length > 0,
      tool_versions: { prowler: versions },
      reproduce:
        `prowler aws --compliance ${PROWLER_COMPLIANCE_ID} ` +
        `--output-formats json-ocsf  # framework ${PROWLER_FRAMEWORK_PIN.version} at ${PROWLER_FRAMEWORK_PIN.commit.slice(0, 12)}; ` +
        `the original arguments are not recoverable from the output (§10b)`,
    } satisfies IngestSubmission;
  });

  return { submissions, skipped, coverage, notes };
}
