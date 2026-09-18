import {
  effectiveForce,
  optionalKsis,
  type KsiCatalog,
  type OfferingClass,
  type RuleRegister,
} from "@rampscan/dataset";
import { omittedRules } from "./sdr.js";

// The rule-compliance verdict over a Security Decision Record (R2.3, #104;
// docs/PLAN-SDR.md §5). `conformance` has always answered one question, which
// is whether a document validates against its pinned schema (`FRC-CSO-JSN`).
// For an SDR that answer is not enough. The schema requires only two top-level
// fields, so a record with no KSI rows and no rule rows validates clean while
// failing every rule the record exists to meet. This module answers the second
// question, rule by rule, and `conformance` prints the two answers side by side.
// It never merges them into one verdict (parent plan, ground rule 3).
//
// EACH CHECK IS A PRESENCE CHECK, AND SAYS SO. It counts whether a row exists
// and whether its statements are non-empty. It never grades the prose inside,
// because judging whether an explanation is adequate is the assessor's job,
// not an appliance's.
//
// FOUR VERDICTS, NOT TWO. `met` and `unmet` are measurements. `awaiting` is a
// requirement only another party can fill (the independent assessor). It is
// counted, and it is never read as a pass. `unmeasured` means the check could
// not run: no class, or no companion file. It is printed with the reason and is
// never read as a pass either (ground rule 7).

export type SdrRuleVerdictKind = "met" | "unmet" | "awaiting" | "unmeasured";

export interface SdrRuleVerdict {
  ruleId: string;
  /** which part of the rule this line checks */
  check: string;
  verdict: SdrRuleVerdictKind;
  detail: string;
}

export interface SdrRuleInput {
  document: Record<string, unknown>;
  /** the `frrID`s the reader accepted; absent when the document could not be read for coverage */
  answeredRules?: ReadonlySet<string>;
  register: RuleRegister;
  catalog: KsiCatalog;
  /** the class the rules are judged at; absent when none could be resolved */
  offeringClass?: OfferingClass;
  /** where the class came from, printed beside the verdicts */
  classSource?: string;
  /** the pinned schema's top-level `required`, for divergence 1 */
  schemaRequired: readonly string[];
  /** the sha256 of the JSON file's bytes */
  jsonSha256: string;
  /** the human-readable companion: absent when none was found beside the JSON */
  companion?: { path: string; digest: string | null };
}

const obj = (v: unknown): Record<string, unknown> =>
  v !== null && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : {};
const nonEmpty = (v: unknown): boolean => Array.isArray(v) && v.some((s) => typeof s === "string" && s.trim() !== "");

function list(ids: readonly string[], max = 8): string {
  return ids.length <= max ? ids.join(", ") : `${ids.slice(0, max).join(", ")} and ${ids.length - max} more`;
}

export function checkSdrRules(input: SdrRuleInput): SdrRuleVerdict[] {
  const doc = input.document;
  const verdicts: SdrRuleVerdict[] = [];
  const cls = input.offeringClass;

  // ---- SDR-CSO-FRR: both formats ------------------------------------------
  if (input.companion === undefined) {
    verdicts.push({
      ruleId: "SDR-CSO-FRR",
      check: "both formats",
      verdict: "unmeasured",
      detail:
        "no human-readable companion was found beside this JSON, so whether the record exists \"in both human-readable and JSON formats\" is unknown. A lone file is not a pass",
    });
  } else if (input.companion.digest === null) {
    verdicts.push({
      ruleId: "SDR-CSO-FRR",
      check: "both formats",
      verdict: "unmet",
      detail: `${input.companion.path} carries no \`JSON sha256:\` line, so nothing ties it to this JSON. Two formats that cannot be shown to agree are two documents`,
    });
  } else if (input.companion.digest !== input.jsonSha256) {
    verdicts.push({
      ruleId: "SDR-CSO-FRR",
      check: "both formats",
      verdict: "unmet",
      detail: `${input.companion.path} was rendered from JSON sha256 ${input.companion.digest.slice(0, 12)}…, and the JSON beside it hashes to ${input.jsonSha256.slice(0, 12)}…. One of them changed after the other was written. Regenerate both with \`rampscan sdr\``,
    });
  } else {
    verdicts.push({
      ruleId: "SDR-CSO-FRR",
      check: "both formats",
      verdict: "met",
      detail: `${input.companion.path} names this JSON's exact bytes`,
    });
  }

  // ---- SDR-CSO-MTD --------------------------------------------------------
  const meta = obj(doc["metadata"]);
  const missingMeta = ["version", "lastUpdated", "updateSource"].filter(
    (k) => typeof meta[k] !== "string" || (meta[k] as string).trim() === "",
  );
  verdicts.push({
    ruleId: "SDR-CSO-MTD",
    check: "metadata",
    verdict: missingMeta.length === 0 ? "met" : "unmet",
    detail:
      missingMeta.length === 0
        ? "version, last update and update source are present"
        : doc["metadata"] === undefined
          ? "the document has no metadata block. The schema makes it optional and SDR-CSO-MTD does not"
          : `metadata lacks ${missingMeta.join(", ")}`,
  });

  if (cls === undefined) {
    // Everything below is judged per class: which rules are addressable, which
    // KSIs are obliged, whether metrics are owed. With no class there is no
    // denominator, and a check with no denominator is skipped out loud.
    for (const [ruleId, check] of [
      ["SDR-CSO-FRR", "a row per addressable rule"],
      ["SDR-CSX-KSI", "a row per obliged KSI"],
      ["SDR-CSX-KMT", "historical metrics"],
    ] as const) {
      verdicts.push({
        ruleId,
        check,
        verdict: "unmeasured",
        detail: "no offering class could be resolved: pass --class, or check a record rampscan wrote, which names its class",
      });
    }
    return verdicts;
  }

  // ---- SDR-CSO-FRR: coverage (the same diff as submission --sdr) -----------
  const rules = Array.isArray(doc["fedRampRequirements"]) ? (doc["fedRampRequirements"] as unknown[]).map(obj) : [];
  if (input.answeredRules === undefined) {
    verdicts.push({
      ruleId: "SDR-CSO-FRR",
      check: "a row per addressable rule",
      verdict: "unmeasured",
      detail: "the document could not be read for rule coverage (no fedRampRequirements array)",
    });
  } else {
    const omitted = omittedRules(input.register, cls, input.answeredRules).map((r) => r.id);
    verdicts.push({
      ruleId: "SDR-CSO-FRR",
      check: "a row per addressable rule",
      verdict: omitted.length === 0 ? "met" : "unmet",
      detail:
        omitted.length === 0
          ? `every rule addressable at class ${cls} has a row`
          : `${omitted.length} rule(s) addressable at class ${cls} have no row: ${list(omitted)}. This is the same diff \`submission --sdr\` reports as reason 3`,
    });
    const emptyRows = rules
      .filter((r) => !nonEmpty(r["frrImplementation"]))
      .map((r) => String(r["frrID"] ?? "?"));
    if (emptyRows.length > 0) {
      verdicts.push({
        ruleId: "SDR-CSO-FRR",
        check: "each row explains",
        verdict: "unmet",
        detail: `${emptyRows.length} row(s) carry an empty frrImplementation: ${list(emptyRows)}. The schema accepts an empty array; the rule wants how the rule is followed, or why not`,
      });
    }
  }

  // ---- SDR-CSX-KSI -----------------------------------------------------------
  const optional = new Set(optionalKsis(input.catalog, cls));
  const obliged = input.catalog.ksis.map((k) => k.id).filter((id) => !optional.has(id));
  if (!Array.isArray(doc["keySecurityIndicators"])) {
    // Divergence 1 (#105), reported by name. The schema's top-level required
    // array does not name keySecurityIndicators, so this document can validate
    // clean with no KSI rows at all.
    const required = input.schemaRequired.join(", ");
    verdicts.push({
      ruleId: "SDR-CSX-KSI",
      check: "a row per obliged KSI",
      verdict: "unmet",
      detail: `the document has no keySecurityIndicators, and the pinned schema accepts that: its top-level required is [${required}]. SDR-CSX-KSI still owes a row for each of the ${obliged.length} KSIs class ${cls} obliges. This is the schema/rule divergence #105 reports upstream`,
    });
  } else {
    const rows = (doc["keySecurityIndicators"] as unknown[]).map(obj);
    const present = new Set(rows.map((r) => String(r["ksiId"] ?? "")));
    const missing = obliged.filter((id) => !present.has(id));
    verdicts.push({
      ruleId: "SDR-CSX-KSI",
      check: "a row per obliged KSI",
      verdict: missing.length === 0 ? "met" : "unmet",
      detail:
        missing.length === 0
          ? `all ${obliged.length} KSIs class ${cls} obliges have a row`
          : `${missing.length} of ${obliged.length} obliged KSI(s) have no row: ${list(missing)}`,
    });
    const obligedRows = rows.filter((r) => obliged.includes(String(r["ksiId"])));
    const noImplementation = obligedRows.filter((r) => !nonEmpty(r["ksiImplementation"])).map((r) => String(r["ksiId"]));
    const noValidation = obligedRows.filter((r) => !nonEmpty(r["ksiValidation"])).map((r) => String(r["ksiId"]));
    verdicts.push({
      ruleId: "SDR-CSX-KSI",
      check: "artifact statements present (counted, not judged)",
      verdict: noImplementation.length === 0 && noValidation.length === 0 ? "met" : "unmet",
      detail:
        noImplementation.length === 0 && noValidation.length === 0
          ? "every obliged row carries implementation and validation statements. They are counted here, not judged"
          : [
              noImplementation.length > 0
                ? `${noImplementation.length} obliged row(s) have an empty ksiImplementation (artifacts 1–2): ${list(noImplementation)}`
                : "",
              noValidation.length > 0
                ? `${noValidation.length} have an empty ksiValidation (artifacts 3–5): ${list(noValidation)}`
                : "",
            ]
              .filter((s) => s !== "")
              .join("; "),
    });

    // ---- the independent items (SDR-CSO-FRR's own list includes them) ----
    const awaitingKsis = obligedRows.filter((r) => !nonEmpty(r["ksiAssessment"])).length;
    const awaitingRules = rules.filter((r) => !nonEmpty(r["frrAssessment"])).length;
    if (awaitingKsis + awaitingRules > 0) {
      verdicts.push({
        ruleId: "SDR-CSO-FRR",
        check: "independent verification and validation",
        verdict: "awaiting",
        detail: `${awaitingKsis} obliged KSI row(s) and ${awaitingRules} rule row(s) carry no assessment statement. That content is the independent assessor's to supply, and it is counted here as awaited, never as met`,
      });
    }
  }

  // ---- SDR-CSX-KMT: cannot be met in-schema ----------------------------------
  const kmt = input.register.rules.find((r) => r.id === "SDR-CSX-KMT");
  const kmtForce = kmt !== undefined ? effectiveForce(kmt, cls) : null;
  if (kmtForce === "MUST" || kmtForce === "SHOULD") {
    const carried = obj(obj(doc["x-rampscan"])["metrics"]);
    verdicts.push({
      ruleId: "SDR-CSX-KMT",
      check: "historical metrics",
      verdict: "unmet",
      detail:
        `${kmtForce} at class ${cls}, and it cannot be met inside the pinned schema, which has no field for historical metrics (FedRAMP/schemas#10). ` +
        (Object.keys(carried).length > 0 ? carriedMetrics(carried, obliged, cls) : "The record carries none, inside the schema or out"),
    });
  }

  return verdicts;
}

/**
 * What x-rampscan.metrics holds, measured against what SDR-CSX-KMT asks at
 * the class (R3.3): both summaries for every obliged KSI, and at class c the
 * daily data. Carriage outside the schema never turns the verdict to met.
 */
function carriedMetrics(carried: Record<string, unknown>, obliged: readonly string[], cls: string): string {
  const perKsi = obj(carried["ksis"]);
  const noSummary = obliged.filter((id) => {
    const row = obj(perKsi[id]);
    return Object.keys(obj(row["past30Days"])).length === 0 || Object.keys(obj(row["pastYear"])).length === 0;
  });
  const dailyWanted = cls === "c" || cls === "d";
  const noDaily = dailyWanted ? obliged.filter((id) => !Array.isArray(obj(perKsi[id])["daily"])) : [];
  const parts = [
    `The record carries them under x-rampscan.metrics, outside the schema: the 30-day and one-year summaries for ${obliged.length - noSummary.length} of ${obliged.length} obliged KSIs`,
  ];
  if (dailyWanted) parts.push(`the daily data for ${obliged.length - noDaily.length} of ${obliged.length}`);
  if (typeof carried["coveredFrom"] !== "string") parts.push("and no day is covered, because the ledger holds no scan of the offering in reach");
  else parts.push(`covered from ${carried["coveredFrom"]}`);
  const missing = [...new Set([...noSummary, ...noDaily])];
  return `${parts.join(", ")}${missing.length > 0 ? `. Missing for: ${list(missing)}` : ""}`;
}

/** every verdict met; `awaiting` and `unmeasured` are not */
export function rulesMet(verdicts: readonly SdrRuleVerdict[]): boolean {
  return verdicts.every((v) => v.verdict === "met");
}
