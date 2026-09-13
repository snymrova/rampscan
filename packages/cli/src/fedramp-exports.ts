import type {
  DriftEvent,
  MethodRegisterRow,
  ValidationVulnerability,
} from "@rampscan/core";
import type { OfferingClass } from "@rampscan/dataset";
import type { OfferingConfig } from "@rampscan/schema";
import { monthsBefore } from "@rampscan/projector";
import { OCR_SCHEMA, PACKAGE_OVERVIEW_SCHEMA } from "./fedramp-schemas.js";

// The two FedRAMP schema-target exports (plan Q5.1 — G10, G12): a Certification
// Package Overview fragment (`FRC-CSO-PKG`, `CDS-CSO-PUB`) and an Ongoing
// Certification Report fragment (`CCM-OCR-AVL`), as JSON valid against the
// pinned schemas.
//
// GENERATED EXACTLY AS OpenVEX IS: an export, no new state, regenerated per
// scan. Nothing here is appended to the ledger, nothing here is signed, and
// running it twice over the same ledger at the same instant produces the same
// bytes. The projection is the input; these documents are a rendering of it
// beside a declaration, and a rendering is never a record.
//
// WHY "FRAGMENT" IS THE HONEST WORD. Neither schema is mostly about validation.
// The package overview is offering identity — provider, service, contacts,
// assessor, trust center — and the OCR is a quarterly narrative with a
// provider attestation inside it. An evidence ledger holds none of that. So
// each document is two halves with a line between them:
//
//   DECLARED  — read from rampscan.config.json's `offering` block, passed
//               through untouched. rampscan does not know these facts and does
//               not pretend to compute them.
//   COMPUTED  — read from the projection, and therefore attributable to a
//               signed bundle. The `x-rampscan` block carries the detail and
//               the provenance; the schema fields carry the summary.
//
// The line is not a comment: `x-rampscan.fieldSources` names every top-level
// field as declared or computed IN THE DOCUMENT, so a reader holding the JSON
// alone can tell which half this appliance stands behind. A document that
// blurred the two would be asking an assessor to trust our typing.
//
// THREE REFUSALS, ALL DELIBERATE.
//
//   1. `reportableIncidents.incidents: []` is an ATTESTATION that none
//      occurred. It is never a default — an absent declaration means no OCR is
//      generated, and the outcome says why. See `offering.ts`.
//   2. `acceptedVulnerabilities` is not the G13 feed. Acceptance is a provider
//      determination; a validation flipping to `violated` is a measurement.
//      The feed rides in `x-rampscan.validationVulnerabilities`, labelled.
//   3. `certificationDataChanges` is computed and cannot be overwritten. The
//      declaration's slot is `additionalCertificationDataChanges`, appended
//      after — because the ledger speaks for the validation plane and a
//      document asserting the complete set from one plane would be wrong.

export interface FedrampExportInput {
  offering: OfferingConfig;
  /** the configured class — the multiplier on every floor the summary cites */
  offeringClass: OfferingClass;
  /** the scanned repo the computed half reads; absent when the ledger holds none */
  repo?: string;
  /** the fold's instant — every date in the computed half derives from it */
  projectedAt: string;
  datasetVersion: string;
  /** the method register (Q2.3/Q4.3), already filtered to `repo` by the caller */
  methodRegisters: MethodRegisterRow[];
  /** the failure→vulnerability feed (Q3.5) */
  vulnerabilities: ValidationVulnerability[];
  /** movement, oldest first, as the projection carries it */
  drift: DriftEvent[];
}

export interface FedrampExport {
  /** the name this lands under in `out/exports/fedramp/` */
  filename: string;
  /** the pinned schema that gates it (Q5.2) */
  schemaFile: string;
  document: Record<string, unknown>;
  /**
   * Facts a reader must see, never smoothed over — the same discipline as the
   * evidence package's `problems`. A fragment with a stated shortfall is worth
   * more than a complete-looking one.
   */
  problems: string[];
}

export const PACKAGE_OVERVIEW_ARTIFACT = "fedramp-certification-package-overview.json";
export const OCR_ARTIFACT = "fedramp-ongoing-certification-report.json";

/** `2026-09-12T08:00:00.000Z` → `2026-09-12`. */
function day(iso: string): string {
  return iso.slice(0, 10);
}

// ---------------------------------------------------------------------------
// the computed half, shared by both documents
// ---------------------------------------------------------------------------

export interface ValidationSummary {
  /** the class every floor below is keyed to */
  offeringClass: OfferingClass;
  repo?: string;
  /** KSIs the register holds a row for */
  ksisTracked: number;
  /** automated methods across them — the FRC-CSX-VVK numerator, summed */
  automatedMethods: number;
  /** the per-KSI floor the fold was given; null when the class owes no number */
  methodFloor: number | null;
  /** KSIs whose automated-method count reaches the floor; null when there is none */
  ksisMeetingFloor: number | null;
  /** methods outside their owed window at projectedAt — the G3 numerator */
  staleMethods: number;
  /** the freshest live evidence anywhere in the register */
  freshestEvidence?: string;
  /** where the validation history begins — the earliest bundle, dead ones included */
  historySince?: string;
  /** KSIs carrying a computed gap class, counted by class */
  gapsByClass: Record<string, number>;
}

function summarise(input: FedrampExportInput): ValidationSummary {
  const rows = input.methodRegisters;
  const floors = rows.map((r) => r.methodFloor).filter((f): f is number => f !== null);
  // one floor per class, so the register agrees with itself; if it somehow does
  // not, the largest is the honest one to publish
  const methodFloor = floors.length > 0 ? Math.max(...floors) : null;

  const summary: ValidationSummary = {
    offeringClass: input.offeringClass,
    ksisTracked: rows.length,
    automatedMethods: rows.reduce((n, r) => n + r.automatedMethods, 0),
    methodFloor,
    ksisMeetingFloor: methodFloor === null ? null : rows.filter((r) => r.floorMet === true).length,
    staleMethods: rows.reduce((n, r) => n + r.staleMethods, 0),
    gapsByClass: {},
  };
  if (input.repo !== undefined) summary.repo = input.repo;

  const fresh = rows.map((r) => r.freshAsOf).filter((v): v is string => v !== undefined);
  if (fresh.length > 0) summary.freshestEvidence = fresh.reduce((a, b) => (a > b ? a : b));

  const history = rows.map((r) => r.historySince).filter((v): v is string => v !== undefined);
  if (history.length > 0) summary.historySince = history.reduce((a, b) => (a < b ? a : b));

  for (const row of rows) {
    if (row.gap === undefined) continue;
    summary.gapsByClass[row.gap] = (summary.gapsByClass[row.gap] ?? 0) + 1;
  }
  return summary;
}

// ---------------------------------------------------------------------------
// FRC-APP-FCP — application freshness (Q5.3)
// ---------------------------------------------------------------------------

/**
 * `FRC-APP-FCP`'s window, and it is NOT the class window. VDR-TFR-MVX gives
 * class b seven days and class c three, and VDR-TFR-NMV gives a non-machine
 * method three months; this rule is a flat seven days on the package at
 * application time, the same number for every class. Two clocks that happen to
 * read 7 for one class are still two clocks, so this constant is its own and
 * never reads `catalog.windows`.
 */
export const APPLICATION_FRESHNESS_WINDOW_DAYS = 7;

const DAY_MS = 86_400_000;

export interface ApplicationFreshness {
  ruleId: "FRC-APP-FCP";
  windowDays: number;
  /** the fold instant every age below is measured against */
  asOf: string;
  /**
   * Every counted method was verified inside the window. The LITERAL reading
   * of the rule: the package shows the current status of the offering, and a
   * method whose evidence is older than seven days is not part of a status
   * verified within seven days.
   */
  fresh: boolean;
  /**
   * The same question asked of machine-clock methods only — for a reader who
   * holds the narrower reading, in which VDR-TFR-NMV's three months governs an
   * attestation and FRC-APP-FCP speaks only to what a machine re-verifies.
   * Published rather than chosen between: the rules text supports an argument
   * either way and this document should not settle it silently.
   */
  machineOnlyFresh: boolean;
  /** the freshest live evidence anywhere in the counted set */
  verifiedAt?: string;
  /** the ELDEST live evidence among counted methods — the one that binds */
  oldestVerifiedAt?: string;
  /** methods judged: every method cell the register holds, less the scoped ones */
  methodsCounted: number;
  methodsInWindow: number;
  /** live evidence, older than the window */
  methodsOutOfWindow: number;
  /**
   * No live evidence at all. Counted as unfresh rather than excused, which is
   * the fold's own rule for `freshMet` (a method with no live evidence is not
   * being validated at any cadence) applied to this clock.
   */
  methodsWithoutEvidence: number;
  /** signed two-key notApplicable — not a lapsed clock, so not counted */
  scopedOut: number;
  /** of the counted methods, how many run on the non-machine clock */
  nonMachineMethods: number;
  /**
   * …and how many on the machine clock. Carried because `machineOnlyFresh`
   * would otherwise pass VACUOUSLY on a register holding no machine method at
   * all — "every machine method is fresh" is trivially true of none, and a
   * green that survives no interrogation is the one bug this product may not
   * ship (ground rule 7).
   */
  machineMethods: number;
  basis: string;
}

/**
 * Computed from the register, never typed — `OfferingConfig` has no slot for
 * any field here, so a provider cannot declare their package fresh (§12.4's
 * rule 3, the same mechanism that keeps a report period out of the config).
 */
export function applicationFreshness(input: FedrampExportInput): ApplicationFreshness {
  const asOfMs = Date.parse(input.projectedAt);
  const cutoff = asOfMs - APPLICATION_FRESHNESS_WINDOW_DAYS * DAY_MS;

  let methodsCounted = 0;
  let methodsInWindow = 0;
  let methodsOutOfWindow = 0;
  let methodsWithoutEvidence = 0;
  let scopedOut = 0;
  let nonMachineMethods = 0;
  let machineMethods = 0;
  let machineUnfresh = 0;
  let newest: string | undefined;
  let oldest: string | undefined;

  for (const row of input.methodRegisters) {
    for (const cell of row.methods) {
      // a signed two-key N/A is a decision, not a lapsed clock — the same
      // exclusion `freshMet` makes, for the same reason
      if (cell.state === "notApplicable") {
        scopedOut += 1;
        continue;
      }
      methodsCounted += 1;
      if (cell.clock === "machine") machineMethods += 1;
      else nonMachineMethods += 1;

      const at = cell.freshAsOf;
      if (at === undefined) {
        methodsWithoutEvidence += 1;
        if (cell.clock === "machine") machineUnfresh += 1;
        continue;
      }
      if (newest === undefined || at > newest) newest = at;
      if (oldest === undefined || at < oldest) oldest = at;

      if (Date.parse(at) >= cutoff) {
        methodsInWindow += 1;
      } else {
        methodsOutOfWindow += 1;
        if (cell.clock === "machine") machineUnfresh += 1;
      }
    }
  }

  const freshness: ApplicationFreshness = {
    ruleId: "FRC-APP-FCP",
    windowDays: APPLICATION_FRESHNESS_WINDOW_DAYS,
    asOf: input.projectedAt,
    fresh: methodsCounted > 0 && methodsOutOfWindow === 0 && methodsWithoutEvidence === 0,
    machineOnlyFresh: machineMethods > 0 && machineUnfresh === 0,
    methodsCounted,
    methodsInWindow,
    methodsOutOfWindow,
    methodsWithoutEvidence,
    scopedOut,
    nonMachineMethods,
    machineMethods,
    basis:
      "Computed from the method register at the fold instant. FRC-APP-FCP's seven days is an application-time window on the package and is NOT the class window (VDR-TFR-MVX / VDR-TFR-NMV): it reads the same for every class. `fresh` counts a method with no live evidence as unfresh, which is the fold's own rule for freshMet rather than a stricter one invented here; `machineOnlyFresh` answers the narrower reading in which a non-machine method keeps its own three-month cadence, and is false when there is no machine method to have asked about rather than vacuously true of none. An empty register is never fresh — a package validating nothing shows no status to have verified.",
  };
  if (newest !== undefined) freshness.verifiedAt = newest;
  if (oldest !== undefined) freshness.oldestVerifiedAt = oldest;
  return freshness;
}

/**
 * The sentences a reader needs when the package is not fresh. Separate from
 * the computation so the numbers stay assertable without parsing prose.
 */
export function freshnessProblems(f: ApplicationFreshness): string[] {
  if (f.fresh) return [];
  if (f.methodsCounted === 0) {
    return [
      "FRC-APP-FCP is unmet: the register holds no validation method in scope, so this package shows no current status that could have been verified within the previous 7 days. A package that validates nothing is not a fresh package; it is an empty one",
    ];
  }
  const causes = [
    ...(f.methodsOutOfWindow > 0
      ? [`${f.methodsOutOfWindow} carry live evidence older than ${f.windowDays} days (oldest ${f.oldestVerifiedAt ?? "unknown"})`]
      : []),
    ...(f.methodsWithoutEvidence > 0
      ? [`${f.methodsWithoutEvidence} carry no live evidence at all, and a method nothing validates was verified within no window`]
      : []),
  ].join("; ");
  const narrower = f.machineOnlyFresh
    ? " Every MACHINE-clock method is inside the window, so a reader holding the narrower reading — FRC-APP-FCP speaking only to what a machine re-verifies, VDR-TFR-NMV governing the rest — would read this package as fresh. `x-rampscan.freshness.machineOnlyFresh` carries that answer; this appliance publishes both rather than choosing for the reader."
    : "";
  return [
    `FRC-APP-FCP is unmet: of ${f.methodsCounted} validation method(s) in scope at ${f.asOf}, ${f.methodsInWindow} were verified within the previous ${f.windowDays} days — ${causes}. Re-scanning refreshes the machine-clock methods; a non-machine method is refreshed by a new signed attestation.${narrower}`,
  ];
}

/**
 * The `x-rampscan` block. Legitimate rather than a liberty: `FRC-CSO-JSN`'s own
 * note says the schemas are "designed to be lightweight and flexible to
 * establish a minimum set of structured information while allowing providers to
 * improve on the format and structure of the information as needed", and none
 * of the three pinned files sets `additionalProperties: false`. The conformance
 * check (Q5.2) proves the second half of that sentence rather than trusting it.
 */
function extensionBlock(
  input: FedrampExportInput,
  fieldSources: Record<string, "declared" | "computed" | "mixed">,
): Record<string, unknown> {
  const summary = summarise(input);
  const open = input.vulnerabilities.filter((v) => v.status === "open");
  return {
    generator: "rampscan",
    projectedAt: input.projectedAt,
    datasetVersion: input.datasetVersion,
    /**
     * Which half of this document each top-level field came from. The point of
     * publishing it: an assessor reading the JSON alone can tell what was
     * measured from what was typed.
     */
    fieldSources,
    validation: summary,
    validationVulnerabilities: {
      note: "VDR-CSO-FAV records: a validation entering `violated` is a vulnerability with detection-and-response obligations. These are NOT this document's `acceptedVulnerabilities` — acceptance is a provider risk determination, and rampscan makes none.",
      open: open.length,
      resolved: input.vulnerabilities.length - open.length,
      records: input.vulnerabilities.map((v) => ({
        ksiIds: v.ksiIds,
        recipeId: v.recipeId,
        detectedAt: v.detectedAt,
        commit: v.commit,
        bundleDigest: v.bundleDigest,
        status: v.status,
        ...(v.resolvedAt !== undefined ? { resolvedAt: v.resolvedAt } : {}),
        ...(v.resolvingDigest !== undefined ? { resolvingDigest: v.resolvingDigest } : {}),
      })),
    },
  };
}

// ---------------------------------------------------------------------------
// Certification Package Overview (FRC-CSO-PKG, CDS-CSO-PUB)
// ---------------------------------------------------------------------------

/**
 * The package overview is DECLARED end to end — there is no schema field in it
 * an evidence ledger could fill, which is worth stating plainly rather than
 * hiding behind a generator. What rampscan contributes is that the declaration
 * is machine-readable, strictly typed, and conformance-gated in CI before it
 * reaches a trust center, plus the `x-rampscan` validation summary an assessor
 * can cross-check against the register.
 */
export function buildPackageOverview(input: FedrampExportInput): FedrampExport {
  const o = input.offering;
  const problems: string[] = [];

  const serviceIdentification: Record<string, unknown> = {
    fedRampPackageId: o.fedRampPackageId,
    providerName: o.providerName,
    serviceName: o.serviceName,
    serviceAcronym: o.serviceAcronym,
    serviceDescription: o.serviceDescription,
    certificationType: o.certificationType,
    website: o.website,
    logo: o.logo,
  };
  if (o.ueiNumber !== undefined) serviceIdentification["ueiNumber"] = o.ueiNumber;

  const serviceProperties: Record<string, unknown> = {
    serviceType: o.serviceType,
    deploymentModel: o.deploymentModel,
  };
  if (o.businessCategory !== undefined) serviceProperties["businessCategory"] = o.businessCategory;
  if (o.trustCenter !== undefined) serviceProperties["trustCenter"] = o.trustCenter;
  if (o.secureConfigurationGuidance !== undefined) {
    serviceProperties["secureConfigurationGuidance"] = o.secureConfigurationGuidance;
  }
  if (o.additionalRepositories !== undefined) {
    serviceProperties["additionalRepositories"] = o.additionalRepositories;
  }
  if (o.nextOngoingCertificationReportDate !== undefined) {
    serviceProperties["nextOngoingCertificationReportDate"] = o.nextOngoingCertificationReportDate;
  }

  if (o.trustCenter === undefined) {
    problems.push(
      "no trust center declared — CDS-CSO-UTC makes a FedRAMP-compatible trust center the definitive source for this data, and G11 is deliberately out of scope for this appliance (plan §6): this document is designed to be what a trust center serves, not the trust center",
    );
  }
  if (o.nextOngoingCertificationReportDate === undefined) {
    problems.push(
      "no next Ongoing Certification Report date declared — CCM-OCR-NRD requires it published, and it is a calendar commitment the ledger cannot compute",
    );
  }
  if (o.assessor === undefined) {
    problems.push(
      "no independent assessment service declared — CDS-CSO-PUB lists the current FedRAMP Recognized assessor among the facts a provider must publish",
    );
  }

  // FRC-APP-FCP (Q5.3). Stamped on the OVERVIEW and not on the OCR: the rule
  // is about the INITIAL package a provider supplies, and an ongoing report
  // answers to CCM-OCR's cadence instead. Computed from the register — there is
  // no config key that could have said this, by construction.
  const freshness = applicationFreshness(input);
  problems.push(...freshnessProblems(freshness));

  const document: Record<string, unknown> = {
    serviceIdentification,
    serviceProperties,
    contactInformation: o.contactInformation,
  };
  if (o.assessor !== undefined) document["assessor"] = o.assessor;
  if (o.certifiedServices !== undefined) document["certifiedServices"] = o.certifiedServices;
  if (o.thirdPartyInformationResources !== undefined) {
    document["thirdPartyInformationResources"] = o.thirdPartyInformationResources;
  }

  document["x-rampscan"] = {
    ...extensionBlock(input, {
      serviceIdentification: "declared",
      serviceProperties: "declared",
      contactInformation: "declared",
      assessor: "declared",
      certifiedServices: "declared",
      thirdPartyInformationResources: "declared",
    }),
    // after the spread, never before it: a computed stamp that a shared block
    // could quietly overwrite is a stamp nobody can rely on
    freshness,
    note: "Every schema field in this document is DECLARED, read from rampscan.config.json's `offering` block. An evidence ledger holds none of these facts and this generator invents none of them. The validation summary below is computed from signed bundles and is the only part of this file rampscan attests to.",
  };

  return {
    filename: PACKAGE_OVERVIEW_ARTIFACT,
    schemaFile: PACKAGE_OVERVIEW_SCHEMA,
    document,
    problems,
  };
}

// ---------------------------------------------------------------------------
// Ongoing Certification Report (CCM-OCR-AVL)
// ---------------------------------------------------------------------------

export interface OcrOutcome {
  export?: FedrampExport;
  /** why no OCR was generated — a legitimate state, never a silent absence */
  skipped?: string;
}

/**
 * The lines that go in `certificationDataChanges`: high-level summaries, per
 * CCM-OCR-AVL, computed from the drift the projection already explains.
 *
 * Grouped by kind rather than one line per event on purpose. The rule asks for
 * "high-level summaries", and a report that pasted four hundred drift rows
 * would satisfy the schema while defeating the requirement.
 *
 * Every line names its plane. The ledger holds the validation record and
 * nothing else, so "no changes" here means no changes rampscan can see — which
 * is why the sentence says that rather than "no changes occurred".
 */
export function certificationDataChanges(events: DriftEvent[]): string[] {
  const byKind = new Map<DriftEvent["kind"], DriftEvent[]>();
  for (const event of events) {
    const bucket = byKind.get(event.kind);
    if (bucket === undefined) byKind.set(event.kind, [event]);
    else bucket.push(event);
  }

  const recipes = (list: DriftEvent[]): string => {
    const ids = [...new Set(list.map((e) => e.recipeId))].sort();
    return ids.length <= 6 ? ids.join(", ") : `${ids.slice(0, 6).join(", ")} and ${ids.length - 6} more`;
  };

  const lines: string[] = [];
  const born = byKind.get("born") ?? [];
  if (born.length > 0) {
    lines.push(
      `Pipeline validation evidence: ${born.length} validation${born.length === 1 ? "" : "s"} newly evidenced (${recipes(born)}).`,
    );
  }
  const died = byKind.get("died") ?? [];
  if (died.length > 0) {
    const drifted = died.filter((e) => e.cause === "anchor-drift").length;
    const superseded = died.length - drifted;
    const causes = [
      ...(drifted > 0 ? [`${drifted} to anchor drift (the attested code moved)`] : []),
      ...(superseded > 0 ? [`${superseded} superseded by a later bundle`] : []),
    ].join(", ");
    lines.push(
      `Pipeline validation evidence: ${died.length} bundle${died.length === 1 ? "" : "s"} ceased to stand live — ${causes} (${recipes(died)}).`,
    );
  }
  const flipped = byKind.get("verdict-flipped") ?? [];
  if (flipped.length > 0) {
    const toViolated = flipped.filter((e) => e.to === "violated").length;
    // the violated clause appears only when there were any: "0 of them into
    // violated" is a sentence that reads like a hedge for a fact worth none
    const violatedClause =
      toViolated > 0
        ? `, ${toViolated} of them into \`violated\` and therefore reported as VDR-CSO-FAV vulnerabilities`
        : ", none of them into `violated`";
    lines.push(
      `Pipeline validation evidence: ${flipped.length} validation${flipped.length === 1 ? "" : "s"} changed verdict${violatedClause} (${recipes(flipped)}).`,
    );
  }
  const scoped = byKind.get("scoped") ?? [];
  if (scoped.length > 0) {
    lines.push(
      `Assessment scope: ${scoped.length} validation${scoped.length === 1 ? "" : "s"} scoped out of the assessment with a signed two-key justification (${recipes(scoped)}).`,
    );
  }

  if (lines.length === 0) {
    lines.push(
      "Pipeline validation evidence: no changes recorded in the evidence ledger during this period. This states what the validation plane holds; it is not an assertion about FedRAMP Certification Data the ledger does not cover.",
    );
  }
  return lines;
}

export function buildOngoingCertificationReport(input: FedrampExportInput): OcrOutcome {
  const report = input.offering.report;
  if (report === undefined) {
    return {
      skipped:
        "no `offering.report` block declared — an Ongoing Certification Report contains a provider attestation about reportable incidents (CCM-OCR-AVL), and this appliance does not make attestations on a provider's behalf. Declare the block to generate one; the package overview is generated either way",
    };
  }

  const problems: string[] = [];
  const to = day(input.projectedAt);
  const from = report.previousReportThrough ?? day(monthsBefore(input.projectedAt, 3));
  if (report.previousReportThrough === undefined) {
    problems.push(
      "no `previousReportThrough` declared — the report period opens three calendar months before the fold instant, which is correct for a FIRST report and wrong for any later one: CCM-OCR-AVL requires the entire period since the previous summary",
    );
  }

  // the computed half reads only what moved inside the period
  const inPeriod = input.drift.filter((e) => day(e.at) >= from && day(e.at) <= to);
  const computed = certificationDataChanges(inPeriod);
  const declaredExtra = report.additionalCertificationDataChanges ?? [];

  if (report.reportableIncidents.incidents.length === 0) {
    problems.push(
      "`reportableIncidents.incidents` is an empty array, which ATTESTS that no FedRAMP Reportable Incidents occurred in this period. That attestation is the declaration's, made by declaring it — rampscan computes nothing about incidents and would refuse to generate this report rather than default the field",
    );
  }

  const open = input.vulnerabilities.filter((v) => v.status === "open").length;
  if (open > 0) {
    problems.push(
      `${open} validation vulnerability record(s) stand open (VDR-CSO-FAV). They are NOT written into \`acceptedVulnerabilities\` — acceptance is a provider determination — but an open failed validation at report time is a fact a reader of this report should be pointed at, and \`x-rampscan.validationVulnerabilities\` holds them`,
    );
  }

  const document: Record<string, unknown> = {
    certificationPackageOverviewUri: report.certificationPackageOverviewUri,
    reportPeriod: { from, to },
    certificationDataChanges: [...computed, ...declaredExtra],
    plannedCertificationDataChanges: report.plannedCertificationDataChanges,
    acceptedVulnerabilities: report.acceptedVulnerabilities,
    transformativeChanges: report.transformativeChanges,
    updatedRecommendations: report.updatedRecommendations,
    activeAgencies: report.activeAgencies,
    reportableIncidents: report.reportableIncidents,
    "x-rampscan": {
      ...extensionBlock(input, {
        certificationPackageOverviewUri: "declared",
        reportPeriod: "computed",
        certificationDataChanges: "mixed",
        plannedCertificationDataChanges: "declared",
        acceptedVulnerabilities: "declared",
        transformativeChanges: "declared",
        updatedRecommendations: "declared",
        activeAgencies: "declared",
        reportableIncidents: "declared",
      }),
      reportPeriodBasis:
        report.previousReportThrough !== undefined
          ? "the declared `previousReportThrough` opens the period — CCM-OCR-AVL's entire-period-since-the-previous-summary rule"
          : "no previous report was declared, so the period opens three calendar months before the fold instant — correct for a first report only",
      certificationDataChangesBasis: {
        computedLines: computed.length,
        declaredLines: declaredExtra.length,
        driftEventsInPeriod: inPeriod.length,
        note: "The computed lines summarise the validation plane's drift inside the report period. The declared lines are appended from `offering.report.additionalCertificationDataChanges`; they cannot replace or suppress a computed line.",
      },
    },
  };

  return {
    export: { filename: OCR_ARTIFACT, schemaFile: OCR_SCHEMA, document, problems },
  };
}
