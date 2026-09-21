import { evaluateAssertion } from "@rampscan/core";
import type { ObservationRows } from "@rampscan/core";
import type {
  Cadence,
  DigestedArtifact,
  IngestSubmission,
  IngestedAssertion,
  RecipeAssertion,
  SarifCrosswalk,
} from "@rampscan/schema";
import { sarifCrosswalkName, sarifRuleIndex } from "@rampscan/schema";
import type { SkippedEntry } from "./ingest.js";
import type { SarifDocument, SarifResult } from "./sarif.js";

// The SARIF adapter (docs/PLAN-REACH.md N2-2), Prowler-shaped: a reader
// (`sarif.ts`), this adapter, a per-tool crosswalk pinned to the tool
// version, and the same refusals — restated here because each is the vacuous
// pass in a different coat.
//
//   1. THE ASSERTION IS RAMPSCAN'S. `count_eq 0` where `level = error`, over
//      the rows the log carries for one rule. The tool's `level` and `kind`
//      are DATA; a client's SAST saying "pass" is never signed as a pass —
//      the appliance counts the error-level rows and signs what it counted.
//   2. A SUPPRESSED RESULT IS COUNTED, NEVER WAIVED (the Prowler mute rule).
//      `suppressions[]` is the tool's or the client's opinion that a finding
//      does not matter; rampscan's own waiver is a signed adjudication, and a
//      suppression is neither. It stays in the population, it fails the
//      assertion at error level, and the count of suppressed rows is named.
//   3. A RUN THAT DID NOT FINISH IS SKIPPED AND NAMED. SARIF records no exit
//      code, so the client declares one (`--exit-code`), and the log's own
//      `invocations[].executionSuccessful` is read beside it: either says the
//      run failed and every rule is set aside — nothing to attest to, nothing
//      to violate (#147's rule, again).
//   4. A ZERO-RESULT RULE IS CLEAN ONLY WHEN THE TOOL SAYS IT RAN. A rule the
//      log reports nothing for gets a submission only if `tool.driver.rules`
//      declares it AND the invocation succeeded — the tool's own statement of
//      population. Otherwise it is skipped and named: silence about a rule
//      is not a clean result for it.
//   5. A RULE THE CROSSWALK DOES NOT CARRY REFUSES THE BATCH. The crosswalk is
//      the reviewed statement of which rule speaks to which indicator; a log
//      carrying an unfiled rule is either a version the crosswalk was not
//      written against or an audit nobody reviewed, and either way nothing is
//      minted until someone has read it.
//
// AND ONE FACT EVERY ROW STATES: REACHABILITY IS UNKNOWN. rampscan's own SAST
// recipe gates semgrep hits against the code graph and waives a hit no entry
// point reaches. A client's log has no graph behind it, so every hit counts,
// and the submission says so rather than letting a reader assume the gate
// ran. The same rows through the pipeline can only read better, never worse.
//
// The plane is `commit` (the crosswalk says so): a client's SAST observes the
// checkout, as the pipeline does, and the ladder counts them as one plane.

/** what the client must state about the run, because the log does not */
export interface SarifRunDeclaration {
  exit_code: number;
  signer_identity: string;
  cadence: Cadence;
  /** the log itself, by the digest of the bytes the appliance read */
  artifact: DigestedArtifact;
}

export interface SarifSubmissions {
  submissions: IngestSubmission[];
  skipped: SkippedEntry[];
  notes: string[];
}

export class SarifIngestError extends Error {}

/** rampscan's assertion over one rule's rows — the claim, with the tool's verdict as data */
export const SARIF_NO_ERROR_LEVEL_RESULTS: RecipeAssertion = {
  field: "level",
  op: "count_eq",
  value: 0,
  where: [{ field: "level", op: "eq", value: "error" }],
  description:
    "No result this rule reported reads level error (the tool's level, or its rule's default; suppressed results counted; reachability unknown — no graph behind a client's log)",
};

/** the evaluator's view of one result — named so a failing row points somewhere */
function observation(r: SarifResult): Record<string, unknown> {
  return {
    level: r.level,
    kind: r.kind,
    suppressed: r.suppressed,
    check_id: r.ruleId,
    ...(r.file !== undefined ? { file: r.file } : {}),
    ...(r.line !== undefined ? { line: r.line } : {}),
    message: r.message,
  };
}

/** the submission's recipe id: the tool's rule id, prefixed with the tool where the tool does not already */
export function sarifRecipeId(toolSlug: string, ruleId: string): string {
  return ruleId.startsWith(`${toolSlug}/`) ? ruleId : `${toolSlug}/${ruleId}`;
}

/**
 * Turn a read SARIF log into submissions under one crosswalk.
 *
 * `timestamp` is the client's declared instant for the run: SARIF carries
 * none at the log level a reader may trust (`invocations[].endTimeUtc` is
 * optional and rarely written), so the declaration owns it the way it owns
 * the exit code.
 */
export function sarifSubmissions(
  document: SarifDocument,
  run: SarifRunDeclaration & { timestamp: string },
  crosswalk: SarifCrosswalk,
): SarifSubmissions {
  if (document.tool.name !== crosswalk.tool) {
    throw new SarifIngestError(
      `the log was written by "${document.tool.name}" and the crosswalk ${sarifCrosswalkName(crosswalk)} joins "${crosswalk.tool}" — pass the crosswalk for the tool that wrote it`,
    );
  }
  if (document.tool.version !== crosswalk.version) {
    throw new SarifIngestError(
      `the log was written by ${document.tool.name} ${document.tool.version} and the crosswalk is pinned to ${crosswalk.version} — rule ids move between versions, so the join is refused rather than guessed; re-pin the crosswalk deliberately`,
    );
  }
  const index = sarifRuleIndex(crosswalk);
  const toolSlug = sarifCrosswalkName(crosswalk).replace(/^sarif-/, "").replace(/-[^-]+$/, "");

  // 5. an unfiled rule refuses the batch — every one named
  const unfiled = [...new Set(document.results.map((r) => r.ruleId))]
    .filter((id) => !index.has(id))
    .sort();
  if (unfiled.length > 0) {
    throw new SarifIngestError(
      `SARIF ingestion refused — nothing minted: the log carries ${unfiled.length} rule id(s) the crosswalk ` +
        `${sarifCrosswalkName(crosswalk)} does not file: ${unfiled.join(", ")}. A rule nobody has read against ` +
        "the indicators is not filed under one by default; add it with its basis, or drop it from the run",
    );
  }

  const byRule = new Map<string, SarifResult[]>();
  for (const r of document.results) {
    (byRule.get(r.ruleId) ?? byRule.set(r.ruleId, []).get(r.ruleId)!).push(r);
  }
  const declared = new Set(document.declaredRules);
  const suppressedTotal = document.results.filter((r) => r.suppressed).length;
  const notes: string[] = [
    `sarif: ${document.results.length} result(s) from ${document.tool.name} ${document.tool.version} in ${document.runCount} run(s); ` +
      `${document.declaredRules.length} rule(s) declared by the driver; ` +
      `invocation ${document.executionSuccessful === null ? "unrecorded" : document.executionSuccessful ? "succeeded" : "FAILED"}` +
      (suppressedTotal > 0 ? `; ${suppressedTotal} suppressed and counted` : ""),
    "sarif: reachability unknown — there is no graph behind a client's log, so every finding counts; " +
      "the same rules through rampscan's own pipeline can only read better",
    `sarif: plane ${crosswalk.plane} — the log observes the checkout, as the pipeline does; one plane, not two`,
  ];

  // 3. a run that did not finish: everything set aside, named per rule
  const failed = run.exit_code !== 0 || document.executionSuccessful === false;
  const skipped: SkippedEntry[] = [];
  const ruleIds = [...new Set([...byRule.keys(), ...crosswalk.entries.map((e) => e.rule)])].sort();
  if (failed) {
    const why =
      run.exit_code !== 0
        ? `exit ${run.exit_code} is a failed run`
        : "the log's own invocation records executionSuccessful: false";
    for (const ruleId of ruleIds) {
      const entry = index.get(ruleId)!;
      skipped.push({
        ksi: entry.ksi,
        script: sarifRecipeId(toolSlug, ruleId),
        ...(run.exit_code !== 0 ? { exit_code: run.exit_code } : {}),
        reason: `${why} — the tool did not finish reading the checkout, so there is nothing to attest to and nothing to violate; skipped, not signed`,
      });
    }
    return { submissions: [], skipped, notes };
  }

  const submissions: IngestSubmission[] = [];
  for (const ruleId of ruleIds) {
    const entry = index.get(ruleId)!;
    const rows = byRule.get(ruleId) ?? [];
    const recipeId = sarifRecipeId(toolSlug, ruleId);
    // 4. nothing reported and nothing declared: named, never minted
    if (rows.length === 0 && (!declared.has(ruleId) || document.executionSuccessful !== true)) {
      skipped.push({
        ksi: entry.ksi,
        script: recipeId,
        reason:
          !declared.has(ruleId)
            ? "the log reports no result for this rule and its driver does not declare it ran (tool.driver.rules) — silence about a rule is not a clean result; skipped, not signed"
            : "the log reports no result for this rule and records no successful invocation — a clean result needs the tool's word that it ran; skipped, not signed",
      });
      continue;
    }
    const observations: ObservationRows = rows.map(observation);
    const evaluated = evaluateAssertion(SARIF_NO_ERROR_LEVEL_RESULTS, observations, new Date(run.timestamp));
    const suppressed = rows.filter((r) => r.suppressed).length;
    const facts = [
      rows.length === 0
        ? `0 result(s); the driver declares ${ruleId} ran and the invocation succeeded — population is the tool's word`
        : `${rows.length} result(s) from ${ruleId}` + (suppressed > 0 ? `, ${suppressed} suppressed and counted` : ""),
      "reachability unknown (no graph behind a client's log)",
      `filed under ${entry.ksi} by ${sarifCrosswalkName(crosswalk)}`,
    ].join("; ");
    const assertion: IngestedAssertion = { ...evaluated, detail: `${evaluated.detail ?? ""} — ${facts}` };
    submissions.push({
      _type: "https://rampscan.dev/ingest-submission/v1",
      recipe_id: recipeId,
      ksi: entry.ksi,
      evidence_class: "process-generated",
      cadence: run.cadence,
      artifacts: [run.artifact],
      assertions: [assertion],
      timestamp: run.timestamp,
      signer_identity: run.signer_identity,
      automated: true,
      tool_versions: { [toolSlug]: document.tool.version },
      reproduce: crosswalk.reproduce,
      plane: crosswalk.plane,
    });
  }
  return { submissions, skipped, notes };
}
