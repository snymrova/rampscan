import type { IngestSubmission } from "@rampscan/schema";
import type { SkippedEntry } from "./ingest.js";
import type { ProwlerOcsfDocument } from "./prowler-ocsf.js";

// The Prowler adapter's CONTRACT, declared by P3-2 and implemented by P3-3
// (docs/RESEARCH-PROWLER-INGEST.md §4c, §6).
//
// WHY THIS FILE EXISTS BEFORE ITS BODY. §7 of the note: "the risk is not
// effort, it is the vacuous pass — which is why P3-2 is written before P3-3
// rather than after." The three obligations below are the ones that, if
// forgotten, sign `evidenced` for the thirteen indicators this input has the
// LEAST evidence about. They are written down, and tested, before there is an
// implementation that could quietly not meet them.
// `prowler-ingest-soundness.test.ts` holds them under `it.fails`; P3-3 is not
// done until it unwraps all three.
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

/**
 * What the client must state about the run, because the document does not.
 *
 * Deliberately not a superset of the tree manifest: only the facts P3's
 * obligations turn on are here, and P3-3 adds what minting a submission needs
 * (signer identity, cadence) rather than this file guessing at them now.
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
  /** what the input said about itself, for the log */
  notes: string[];
}

/**
 * Turn a read Prowler compliance document into submissions.
 *
 * NOT IMPLEMENTED — P3-3. The signature and the three obligations above are
 * P3-2's deliverable; the body is the next item's. Throwing here rather than
 * returning an empty result is deliberate: an adapter that answered "no
 * submissions, nothing skipped" would be indistinguishable from a scan that
 * evidenced nothing, which is the same conflation P3-1's missing-file refusal
 * exists to prevent.
 */
export function prowlerSubmissions(
  _document: ProwlerOcsfDocument,
  _run: ProwlerRunDeclaration,
): ProwlerSubmissions {
  throw new Error(
    "the Prowler adapter is P3-3 and is not built yet — P3-2 declared its obligations " +
      "(docs/RESEARCH-PROWLER-INGEST.md §4c) and tests them in prowler-ingest-soundness.test.ts",
  );
}
