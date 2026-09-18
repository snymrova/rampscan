import { readFile } from "node:fs/promises";
import { PROWLER_COMPLIANCE_ID, PROWLER_FRAMEWORK_PIN } from "./prowler-framework.js";

// The Prowler OCSF compliance reader (P3-1, docs/RESEARCH-PROWLER-INGEST.md
// §10a and §6) — the half of P3 that decides which documents are evaluable at
// all, before the adapter (P3-3) decides what they say.
//
// WHAT IT READS. A Prowler scan run with `--compliance fedramp_20x_ksi_2026`
// writes a bare JSON ARRAY of OCSF `ComplianceFinding` events (`class_uid`
// 2003), serialised `exclude_none=True`, one row per (finding × requirement).
// There is no header object of any kind: no scan id, no arguments, no
// mutelist path, no start/end pair. Everything this file can know is per-row,
// which is §10b's finding and the reason P3-3 states the population it
// evaluated rather than describing what it read as "a scan".
//
// THE FIELD NAMES ARE §10a'S, NOT §2d'S. §2d documented the CSV row, because
// that is what the universal writer's TABLE path emits. This is the OCSF
// sibling — a different function with different names — and a reader written
// against `Status`, `CheckId`, `Muted`, `Requirements_Id` finds none of them.
// The research note corrected itself there rather than letting this file
// discover it at a user's expense.
//
// THE TWO REFUSALS THAT ARE THE POINT OF THE FILE.
//
//   1. A `MANUAL` ROW IS SET ASIDE HERE, NOT DOWNSTREAM. The framework routes
//      every requirement no check reaches to the universal writer, which emits
//      one synthetic row per uncovered requirement. So the obvious assertion —
//      "no FAIL rows for this indicator" — passes VACUOUSLY over precisely the
//      thirteen indicators nothing looked at (§4c). That is #147 arriving
//      through a new door, and the defence is structural rather than
//      remembered: `byKsi` carries reported rows only, and a KSI whose sole
//      row is MANUAL is ABSENT from the map rather than present with an empty
//      array. An adapter that forgets the rule cannot mint a pass from this
//      reader's output; it gets `undefined` and has nothing to evaluate.
//
//   2. AN ABSENT OR EMPTY FILE IS A REFUSAL, NOT ZERO FINDINGS.
//      `OCSFComplianceOutput.__init__` guards `if findings:` before the
//      transform, and the manual rows are emitted INSIDE that transform — so a
//      scan that produced nothing writes no file, and no thirteen MANUAL rows
//      either (§10a). "The file is missing" and "the scan evidenced nothing"
//      are therefore different facts, and conflating them would be the same
//      vacuous pass one level up.
//
// WHY THE STANDARD STRING IS CHECKED AGAINST THE PIN. `compliance.standards[0]`
// is `framework + "-" + version`. rampscan resolves each row's KSI against the
// VENDORED framework at `PROWLER_FRAMEWORK_PIN`, so a scan run with a Prowler
// whose framework has moved is a join against a mapping this checkout has not
// read. That arrives here as a refusal instead of as quietly different
// coverage.

/**
 * The one standard this reader accepts, built from the pin rather than typed,
 * so bumping the framework cannot leave a literal behind pointing at the old
 * one.
 */
export const PROWLER_OCSF_STANDARD =
  `${PROWLER_FRAMEWORK_PIN.framework}-${PROWLER_FRAMEWORK_PIN.version}` as const;

/**
 * Upstream's stable marker for §10d's case, documented by them as opening
 * every such message so it "doubles as a stable marker for detecting the case
 * programmatically". Matched, never parsed further: what it means is that the
 * requirement was forced to FAIL by the scan's own config while the nested
 * check still read PASS, and the only thing rampscan does with it is record
 * the divergence.
 */
export const CONFIG_NOT_VALID_PREFIX = "Configuration not valid for this requirement." as const;

/** `status_code`, the EFFECTIVE status — §10d's stricter of the two readings */
export type ProwlerEffectiveStatus = "PASS" | "FAIL" | "MANUAL";

const EFFECTIVE_STATUS = new Set<string>(["PASS", "FAIL", "MANUAL"]);

/**
 * `status` is `Suppressed` when the finding was muted and `New` otherwise —
 * NOT a boolean, which is what §2d's CSV column had led the note to expect.
 * The vocabulary is CLOSED because muting decides whether a FAIL counts, and a
 * third value read as "not suppressed" would be a mute this appliance did not
 * notice.
 */
const REPORTED_STATUS = new Set<string>(["New", "Suppressed"]);

export interface ProwlerOcsfRow {
  /** the indicator, from `compliance.requirements[0]`; resolves at the pin */
  ksi: string;
  /** `metadata.event_code` — the check that produced this finding */
  checkId: string;
  /** `status_code`: what rampscan evaluates (§10d) */
  effectiveStatus: Exclude<ProwlerEffectiveStatus, "MANUAL">;
  /** `compliance.checks[].status` for this check — the looser reading, carried for the transcript */
  rawCheckStatus: string;
  /**
   * True when the scan's own config forced the requirement to FAIL while the
   * check itself passed. A FACT ABOUT THE SCAN'S CONFIGURATION, which is the
   * one piece of scan-level context this input carries at all — so it is
   * recorded rather than discarded.
   */
  configOverride: boolean;
  /** `status === "Suppressed"` */
  muted: boolean;
  /** `time_dt`, the client RUN's clock */
  timestamp: string;
  /** `finding_info.uid` — unique per (resource × requirement) */
  findingUid: string;
  /** `message`, kept whole for P3-3's transcript */
  message: string;
  /** `unmapped.cloud.account.uid`, when the row carries one */
  account?: string;
  /** `unmapped.cloud.region`, when the row carries one */
  region?: string;
}

export interface ProwlerOcsfDocument {
  /** `compliance.standards[0]`, identical on every row */
  standard: string;
  /**
   * Reported rows, grouped by indicator, in file order. MANUAL rows are NOT
   * here — see the header. An indicator with no reported row is ABSENT, and
   * that distinction is the whole defence.
   */
  byKsi: ReadonlyMap<string, readonly ProwlerOcsfRow[]>;
  /**
   * The indicators whose rows were all MANUAL, ascending. Named so P3-3 can
   * skip them explicitly and say so, rather than minting an unevidenced row
   * for each or — worse — an evidenced one.
   */
  manual: readonly string[];
  /** every distinct `metadata.product.version` seen, ascending */
  prowlerVersions: readonly string[];
  /** every distinct account uid seen, ascending */
  accounts: readonly string[];
  /** how many rows the file carried, MANUAL included */
  rowCount: number;
}

class ProwlerOcsfError extends Error {}

function obj(node: unknown): Record<string, unknown> | undefined {
  return node !== null && typeof node === "object" && !Array.isArray(node)
    ? (node as Record<string, unknown>)
    : undefined;
}

function firstString(node: unknown, at: string, field: string, origin: string): string {
  if (!Array.isArray(node) || node.length === 0) {
    throw new ProwlerOcsfError(`${origin}: ${at} has no ${field}`);
  }
  const [head] = node;
  if (typeof head !== "string" || head.length === 0) {
    throw new ProwlerOcsfError(`${origin}: ${at} has a ${field} that is not a string`);
  }
  return head;
}

/**
 * Parse a Prowler OCSF compliance document, refusing anything it cannot read.
 *
 * `ksiIds` is the catalog at THIS checkout's dataset pin, passed in rather
 * than loaded here for the reason `loadPinnedProwlerFramework` takes a
 * `repoRoot`: this is a join between two pinned sides, and a reader that
 * fetches one of its own sides can never be shown disagreeing with the other.
 */
export function parseProwlerOcsf(
  doc: unknown,
  origin: string,
  ksiIds: readonly string[],
): ProwlerOcsfDocument {
  if (!Array.isArray(doc)) {
    throw new ProwlerOcsfError(
      `${origin}: not a Prowler OCSF compliance output — the file is a bare JSON array of ComplianceFinding events, with no wrapper object and no header. A document with a top-level key is a different writer's output (the JSON-OCSF findings file, or the ASFF one), and reading it as this one would resolve nothing`,
    );
  }
  if (doc.length === 0) {
    throw new ProwlerOcsfError(
      `${origin}: is an empty array. Prowler writes no file at all when a scan produces no findings — the transform that emits both the reported rows and the MANUAL ones is guarded on there being findings — so an empty document is not "the scan evidenced nothing", it is a file this appliance cannot account for. Refusing rather than reading 46 indicators as unevidenced`,
    );
  }

  const catalog = new Set(ksiIds);
  const byKsi = new Map<string, ProwlerOcsfRow[]>();
  const manual = new Set<string>();
  const reported = new Set<string>();
  const versions = new Set<string>();
  const accounts = new Set<string>();
  let standard: string | undefined;

  doc.forEach((entry, i) => {
    const at = `[${i}]`;
    const r = obj(entry);
    if (r === undefined) {
      throw new ProwlerOcsfError(`${origin}: ${at} is not an object`);
    }

    const compliance = obj(r["compliance"]);
    if (compliance === undefined) {
      throw new ProwlerOcsfError(
        `${origin}: ${at} carries no compliance object — every row of a compliance output has one, so this is either a different writer's file or a row this reader does not understand`,
      );
    }

    const rowStandard = firstString(compliance["standards"], at, "compliance.standards", origin);
    if (standard === undefined) {
      standard = rowStandard;
    } else if (rowStandard !== standard) {
      throw new ProwlerOcsfError(
        `${origin}: ${at} states standard "${rowStandard}" where an earlier row stated "${standard}" — one document carries one standard, and a concatenation of two scans is refused rather than folded into one population`,
      );
    }
    if (rowStandard !== PROWLER_OCSF_STANDARD) {
      throw new ProwlerOcsfError(
        `${origin}: the scan ran against "${rowStandard}", but this checkout pins the Prowler KSI framework at ${PROWLER_FRAMEWORK_PIN.framework} ${PROWLER_FRAMEWORK_PIN.version} (docs/context/prowler/). The KSI→check mapping rampscan would resolve against is not the mapping this scan used, so the join is refused. Re-pin deliberately, re-read the diff, then re-run`,
      );
    }

    const requirements = compliance["requirements"];
    if (!Array.isArray(requirements) || requirements.length !== 1) {
      throw new ProwlerOcsfError(
        `${origin}: ${at} carries ${Array.isArray(requirements) ? requirements.length : "no"} requirements where this reader expects exactly one requirement per row. Prowler emits one row per (finding × requirement); a row naming two would mean reading requirements[0] is dropping an indicator per row rather than reading one`,
      );
    }
    const ksi = firstString(requirements, at, "compliance.requirements", origin);
    if (!catalog.has(ksi)) {
      throw new ProwlerOcsfError(
        `${origin}: ${at} names ${ksi}, which does not resolve in this checkout's pinned catalog. Ingesting it would derive a method for an indicator that is not on the board`,
      );
    }

    const metadata = obj(r["metadata"]);
    if (metadata === undefined) {
      throw new ProwlerOcsfError(`${origin}: ${at} carries no metadata`);
    }
    const product = obj(metadata["product"]);
    const version = product?.["version"];
    if (typeof version !== "string" || version.length === 0) {
      throw new ProwlerOcsfError(
        `${origin}: ${at} states no metadata.product.version — the Prowler version is per-row here, and it is what P3-3's reproduce line names`,
      );
    }
    versions.add(version);

    const statusCode = r["status_code"];
    if (typeof statusCode !== "string" || !EFFECTIVE_STATUS.has(statusCode)) {
      throw new ProwlerOcsfError(
        `${origin}: ${at} states status_code "${String(statusCode)}", which is outside PASS / FAIL / MANUAL. The effective status decides the assertion, so a fourth value is read by a person before it decides anything`,
      );
    }

    const findingInfo = obj(r["finding_info"]);
    const findingUid = findingInfo?.["uid"];
    if (typeof findingUid !== "string" || findingUid.length === 0) {
      throw new ProwlerOcsfError(`${origin}: ${at} states no finding_info.uid`);
    }
    const eventCode = metadata["event_code"];
    if (typeof eventCode !== "string" || eventCode.length === 0) {
      throw new ProwlerOcsfError(`${origin}: ${at} states no metadata.event_code`);
    }

    // §10a gives three INDEPENDENT markers for the synthetic row. They are
    // checked together rather than any one being trusted: a row carrying some
    // and not others is not a row this reader understands, and guessing which
    // marker wins is guessing whether thirteen indicators get evaluated.
    const markers = [
      statusCode === "MANUAL",
      eventCode === "manual",
      findingUid.startsWith("manual-"),
    ];
    const manualMarkers = markers.filter(Boolean).length;
    if (manualMarkers > 0 && manualMarkers < markers.length) {
      throw new ProwlerOcsfError(
        `${origin}: ${at} carries ${manualMarkers} of the 3 MANUAL markers (status_code=${statusCode}, event_code=${eventCode}, finding_info.uid=${findingUid}). A synthetic non-coverage row and a real finding are told apart by all three agreeing; a row where they disagree decides whether an indicator nothing looked at is evaluated, and that is not guessed at`,
      );
    }
    if (manualMarkers === markers.length) {
      // Set aside HERE. No check id, no resources, no cloud block on these —
      // and, more to the point, nothing looked at this indicator.
      manual.add(ksi);
      return;
    }

    const status = r["status"];
    if (typeof status !== "string" || !REPORTED_STATUS.has(status)) {
      throw new ProwlerOcsfError(
        `${origin}: ${at} states status "${String(status)}", which is outside New / Suppressed. Muting decides whether a FAIL counts, so a third value is not read as "not suppressed"`,
      );
    }

    // The check id is taken from `metadata.event_code`, which unambiguously
    // names the check that produced this finding, and `compliance.checks` is
    // then searched for THAT check's own status. The note's table lists both
    // `compliance.checks[0].uid` and `event_code` as carrying the id without
    // establishing that `checks` has exactly one entry, so indexing [0] would
    // be an assumption about arity; matching is the same read without it, and
    // a row where no entry matches is refused rather than attributed to
    // whichever check happened to be first.
    const checks = compliance["checks"];
    if (!Array.isArray(checks) || checks.length === 0) {
      throw new ProwlerOcsfError(
        `${origin}: ${at} is a reported row with no compliance.checks to attribute it to. Only the synthetic MANUAL row omits them, and this row carries none of that row's three markers`,
      );
    }
    const check = checks
      .map((c) => obj(c))
      .find((c) => c !== undefined && c["uid"] === eventCode);
    if (check === undefined) {
      throw new ProwlerOcsfError(
        `${origin}: ${at} names check "${eventCode}" in metadata.event_code, but compliance.checks carries no entry with that uid. The two name the same check on every row this reader was written against, and a row where they part is one whose raw status cannot be attributed`,
      );
    }
    const rawCheckStatus = check["status"];
    if (typeof rawCheckStatus !== "string" || rawCheckStatus.length === 0) {
      throw new ProwlerOcsfError(`${origin}: ${at} states no status for check "${eventCode}"`);
    }

    const timestamp = r["time_dt"];
    if (typeof timestamp !== "string" || timestamp.length === 0) {
      throw new ProwlerOcsfError(
        `${origin}: ${at} states no time_dt — the submission carries the client RUN's clock, not the ingest's`,
      );
    }

    const message = typeof r["message"] === "string" ? r["message"] : "";
    const detail = typeof r["status_detail"] === "string" ? r["status_detail"] : "";
    const configOverride =
      message.startsWith(CONFIG_NOT_VALID_PREFIX) || detail.startsWith(CONFIG_NOT_VALID_PREFIX);

    const cloud = obj(obj(r["unmapped"])?.["cloud"]);
    const account = obj(cloud?.["account"])?.["uid"];
    const region = cloud?.["region"];
    if (typeof account === "string" && account.length > 0) accounts.add(account);

    const built: ProwlerOcsfRow = {
      ksi,
      checkId: eventCode,
      effectiveStatus: statusCode as Exclude<ProwlerEffectiveStatus, "MANUAL">,
      rawCheckStatus,
      configOverride,
      muted: status === "Suppressed",
      timestamp,
      findingUid,
      message: message.length > 0 ? message : detail,
      ...(typeof account === "string" && account.length > 0 ? { account } : {}),
      ...(typeof region === "string" && region.length > 0 ? { region } : {}),
    };

    reported.add(ksi);
    const bucket = byKsi.get(ksi);
    if (bucket === undefined) byKsi.set(ksi, [built]);
    else bucket.push(built);
  });

  // An indicator cannot be both looked at and declared uncovered in one scan.
  // If it is, the framework the scan ran with and the rows it emitted disagree
  // about whether anything reaches it, and that is not a document to average.
  for (const ksi of manual) {
    if (reported.has(ksi)) {
      throw new ProwlerOcsfError(
        `${origin}: ${ksi} carries both a synthetic MANUAL row and reported findings. One says no check reaches this indicator and the other is a check's result for it; nothing here can decide which, so the document is refused`,
      );
    }
  }

  return {
    standard: standard as string,
    byKsi,
    manual: [...manual].sort(),
    prowlerVersions: [...versions].sort(),
    accounts: [...accounts].sort(),
    rowCount: doc.length,
  };
}

/**
 * Read a Prowler OCSF compliance output from disk.
 *
 * A MISSING FILE IS A REFUSAL, and it shares its wording with the empty-array
 * case on purpose: both mean the same thing about the scan, and neither means
 * the scan evidenced nothing.
 */
export async function loadProwlerOcsf(
  path: string,
  ksiIds: readonly string[],
): Promise<ProwlerOcsfDocument> {
  let bytes: Buffer;
  try {
    bytes = await readFile(path);
  } catch {
    throw new ProwlerOcsfError(
      `${path}: no such file. Prowler writes no file at all when a scan produces no findings, so a missing compliance output is a scan this appliance cannot account for — never 46 indicators evidenced by an absence. Check the scan ran with --compliance ${PROWLER_COMPLIANCE_ID} and that the output directory is the one being read`,
    );
  }
  if (bytes.byteLength === 0) {
    throw new ProwlerOcsfError(`${path}: is empty — see the no file at all case; this is the same fact`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(bytes.toString("utf8"));
  } catch (err) {
    throw new ProwlerOcsfError(`${path}: is not JSON (${(err as Error).message})`);
  }
  return parseProwlerOcsf(parsed, path, ksiIds);
}
