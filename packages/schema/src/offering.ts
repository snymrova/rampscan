import { z } from "zod";

// The declared `offering` block of rampscan.config.json (plan Q5.1) — the
// provider-side half of the two FedRAMP schema-target exports.
//
// WHY A DECLARATION AT ALL. A Certification Package Overview is almost entirely
// facts no evidence ledger can hold: who the provider is, which agencies use
// the product, who assesses it, where the trust center lives. rampscan computes
// the validation record and nothing else, so those facts arrive declared or
// they do not arrive. A generated document that invented them would be the
// screenshot folder this product exists to replace, in JSON.
//
// THE LINE THIS TYPE DRAWS, STRUCTURALLY. Every field the LEDGER computes is
// absent from this schema — not optional, absent. There is no slot for
// `reportPeriod` and no slot for `certificationDataChanges`, so a provider
// cannot type a validation history into a config file and have the export
// repeat it back as though it were computed. Same mechanism as the dual-source
// contract's rule 3 (SPEC §12.4): an owed number arriving via overlay is
// refused because the enrichment type has no slot for one. A declaration is
// refused here for the same reason and by the same means.
//
// Field NAMES mirror the FedRAMP schemas deliberately. Renaming `serviceAcronym`
// to something of our own would buy a vocabulary nobody asked for and cost the
// reader the ability to hold the config and the schema side by side. What the
// strictness buys instead is that a misspelled key is an exit, never a field
// that quietly declared nothing.

/** A repository location, per the package overview schema's `$defs.repository`. */
export const DeclaredRepository = z
  .strictObject({
    /** one or more categories; a single repository may satisfy several */
    repositoryType: z.array(z.string().min(1)).min(1),
    url: z.string().url(),
    repositoryDescription: z.string().min(1),
    authenticationRequired: z.boolean(),
    /** the schema's own if/then: required exactly when authentication is */
    accessRequestInstructions: z.string().min(1).optional(),
  })
  .refine((r) => !r.authenticationRequired || r.accessRequestInstructions !== undefined, {
    message:
      "authenticationRequired is true but accessRequestInstructions is absent — the schema's own if/then requires it, and a gated repository with no way to request access is a dead end pointed at an assessor",
  });
export type DeclaredRepository = z.infer<typeof DeclaredRepository>;

/**
 * One contact. `contactPhone` carries the schema's pattern rather than a
 * looser one: a number the export would have to reject downstream is better
 * rejected at the declaration, where the person who typed it is still looking.
 */
export const DeclaredContact = z.strictObject({
  contactType: z.string().min(1),
  contactName: z.string().min(1).optional(),
  contactEmail: z.string().email().optional(),
  contactPhone: z
    .string()
    .regex(/^[0-9]{3}-[0-9]{3}-[0-9]{4}$/, "phone must be ###-###-#### (e.g. 202-555-0123)")
    .optional(),
});
export type DeclaredContact = z.infer<typeof DeclaredContact>;

export const DeploymentModel = z.enum([
  "Public Cloud",
  "Government-Only Cloud",
  "Hybrid Cloud",
  "Community Cloud",
  "Government Community Cloud",
]);

export const ServiceModel = z.enum(["SaaS", "PaaS", "IaaS"]);

const isoDate = z
  .string()
  .regex(/^\d{4}-\d{2}-\d{2}$/, "must be a calendar date, YYYY-MM-DD");

/**
 * The declared half of the Ongoing Certification Report (CCM-OCR-AVL).
 *
 * `reportableIncidents` is REQUIRED, and that is the load-bearing decision in
 * this file. The schema says an empty `incidents` array attests that no
 * FedRAMP Reportable Incidents occurred in the period — so an empty array is an
 * ATTESTATION, not a default, and an appliance that emitted one because a
 * config key was missing would have signed a statement about incidents on
 * behalf of a provider who never made it. Declaring `{ incidents: [] }` is a
 * deliberate act. Omitting the key means the OCR cannot be generated, and the
 * export says so rather than filling the hole.
 *
 * `acceptedVulnerabilities` is declared for a subtler reason, stated here
 * because the temptation is real: rampscan HAS a vulnerability feed (Q3.5,
 * `VDR-CSO-FAV` — a validation flipping to `violated`), and it is not this
 * field. "Accepted Vulnerability" is a FedRAMP term of art for a weakness whose
 * risk the provider has decided to carry. Acceptance is a provider judgment;
 * a failing validation is a measurement. Routing the second into the first
 * would report a decision nobody took. The computed feed rides in the export's
 * `x-rampscan` block instead, where it is labelled as what it is.
 */
export const DeclaredReport = z.strictObject({
  /** the provider's published overview document — the OCR's required back-link */
  certificationPackageOverviewUri: z.string().url(),
  /**
   * The end of the LAST report's period, when there was one. The new period
   * begins here, per CCM-OCR-AVL's "covering the entire period since the
   * previous summary". Absent for a first report: the period then opens three
   * calendar months back, and the export states which of the two it did.
   */
  previousReportThrough: isoDate.optional(),
  plannedCertificationDataChanges: z.strictObject({
    planningHorizonThrough: isoDate,
    changes: z.array(z.string().min(1)),
  }),
  acceptedVulnerabilities: z.string().min(1),
  /**
   * Changes the LEDGER cannot see, ADDED to the computed ones — never
   * replacing them. The name is the contract: `certificationDataChanges` has
   * no slot in this type, so a provider cannot overwrite or suppress what the
   * evidence record says moved. But the ledger only holds the validation
   * plane, and a document that asserted the complete set of changes to
   * FedRAMP Certification Data while covering one plane would be precise and
   * wrong. A new service, a changed contact, a re-scoped boundary belongs
   * here, and the export appends it after the computed lines.
   */
  additionalCertificationDataChanges: z.array(z.string().min(1)).optional(),
  transformativeChanges: z.array(z.string().min(1)),
  updatedRecommendations: z.array(z.string().min(1)),
  activeAgencies: z.array(z.string().min(1)),
  reportableIncidents: z.strictObject({
    incidents: z.array(
      z.strictObject({
        summary: z.string().min(1),
        occurredAt: z.string().datetime({ offset: true }).optional(),
        resolvedAt: z.string().datetime({ offset: true }).optional(),
        incidentLessonsLearned: z.array(z.string().min(1)).optional(),
      }),
    ),
  }),
});
export type DeclaredReport = z.infer<typeof DeclaredReport>;

/**
 * The block itself. `{ offering: { ... } }` in rampscan.config.json, beside
 * `graph`, `contract` and `documents`.
 */
export const OfferingConfig = z.strictObject({
  providerName: z.string().min(1),
  serviceName: z.string().min(1),
  serviceAcronym: z.string().min(1),
  serviceDescription: z.string().min(1),
  certificationType: z.enum(["20x", "Rev5"]),
  /**
   * The schema's own instruction, quoted so nobody invents an identifier:
   * "Unique identifier assigned to the CSP by FedRAMP. If no FedRAMP ID is
   * available, use the CSP's name and acronym." An offering that has not been
   * assigned one declares the name — never a plausible-looking number.
   */
  fedRampPackageId: z.string().min(1),
  /** absent when SAM.gov has assigned none; the schema says leave it blank */
  ueiNumber: z.string().min(1).optional(),
  website: z.string().url(),
  /** the schema constrains the extension; a URL that is not an image is refused here */
  logo: z
    .string()
    .url()
    .regex(
      /\.(png|jpe?g|gif|svg|webp|ico|bmp|tiff?)([?#].*)?$/,
      "logo must point at an image file (png, jpeg, gif, svg, webp, ico, bmp, tiff)",
    ),
  serviceType: z.array(ServiceModel).min(1),
  deploymentModel: DeploymentModel,
  businessCategory: z.array(z.string().min(1)).optional(),
  trustCenter: DeclaredRepository.optional(),
  secureConfigurationGuidance: DeclaredRepository.optional(),
  additionalRepositories: z.array(DeclaredRepository).optional(),
  /** CCM-OCR-NRD — the next report's date, published ahead of it */
  nextOngoingCertificationReportDate: isoDate.optional(),
  /**
   * CDS-CSO-PUB requires at least one Security and one Sales contact, and the
   * schema enforces it with two `contains` clauses. Enforced here too, so the
   * failure lands on the config rather than on the conformance check: the
   * person who can fix it is the one editing this file.
   */
  contactInformation: z
    .array(DeclaredContact)
    .min(1)
    .refine((cs) => cs.some((c) => c.contactType === "Security"), {
      message:
        'CDS-CSO-PUB requires a Security contact — add one with contactType "Security"',
    })
    .refine((cs) => cs.some((c) => c.contactType === "Sales"), {
      message: 'CDS-CSO-PUB requires a Sales contact — add one with contactType "Sales"',
    }),
  assessor: z
    .strictObject({
      name: z.string().min(1),
      /**
       * Six digits, per the package overview schema's own pattern. Carried
       * here for `contactPhone`'s reason: a value the conformance check would
       * reject two layers away is better rejected at the declaration, where
       * the person who typed it is still looking at it.
       */
      assessorID: z
        .string()
        .regex(/^\d{6}$/, "assessorID must be the six-digit FedRAMP assessor identifier"),
    })
    .optional(),
  certifiedServices: z
    .array(
      z.strictObject({
        serviceName: z.string().min(1),
        serviceDescription: z.string().min(1),
        dateAvailable: isoDate.optional(),
      }),
    )
    .optional(),
  thirdPartyInformationResources: z
    .strictObject({
      certified: z
        .array(
          z.strictObject({
            fedRampCertifiedThirdPartyInformationResource: z.string().min(1),
            useCase: z.string().min(1),
          }),
        )
        .optional(),
      nonCertified: z
        .array(
          z.strictObject({
            name: z.string().min(1),
            provider: z.string().min(1),
            website: z.string().url().optional(),
            useCase: z.string().min(1),
          }),
        )
        .optional(),
    })
    .optional(),
  /**
   * Absent means the OCR is not generated — and that is a legitimate state,
   * not a broken config. The package overview is a standing document; the OCR
   * is a quarterly act with an attestation inside it. A provider setting up the
   * appliance gets the first without having to make the second.
   */
  report: DeclaredReport.optional(),
});
export type OfferingConfig = z.infer<typeof OfferingConfig>;
