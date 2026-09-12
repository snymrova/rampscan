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
  /** the name this lands under in `out/exports/` */
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
