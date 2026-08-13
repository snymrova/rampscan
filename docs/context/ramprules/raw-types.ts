/**
 * The adapter between FedRAMP's generated schema types and this codebase's
 * vocabulary (plan decision C2).
 *
 * `types.generated.ts` names things after the schema's `$defs` keys —
 * `FedRAMPConsolidatedRulesSchema`, `FrrRequirement1`, `KsiIndicator1`. Those
 * names are upstream's to change, and two of them are artefacts of how
 * json-schema-to-typescript renders a `oneOf`. This module is the only place
 * that depends on them: it aliases the handful the data layer actually needs
 * onto stable local names, so an upstream rename lands here and nowhere else.
 *
 * Import rule: `build-index.ts` and `frr-index.ts` only. Everything
 * downstream consumes the normalized types in `types.ts`.
 */

import type {
  AffectedParty as GeneratedAffectedParty,
  ClassKey as GeneratedClassKey,
  FedRAMPConsolidatedRulesSchema,
  ForceEnum as GeneratedForceEnum,
  FrdDefinition as GeneratedFrdDefinition,
  FrrRequirement as GeneratedFrrRequirement,
  FrrRequirementLevel as GeneratedFrrRequirementLevel,
  KsiIndicator as GeneratedKsiIndicator,
  NotificationMethod as GeneratedNotificationMethod,
  NotificationParty as GeneratedNotificationParty,
  PainTimeframeEntry as GeneratedPainTimeframeEntry,
  TimeframeType as GeneratedTimeframeType,
} from "./types.generated"

/** The whole dataset, exactly as `docs/fedramp-consolidated-rules.json`. */
export type FedRampDataset = FedRAMPConsolidatedRulesSchema

/** Certification class keys as the dataset writes them: lowercase a-d. */
export type ClassKey = GeneratedClassKey

/**
 * Who a rule binds. The schema declares six; the data uses five —
 * `Everyone` never occurs today. Treat the enum as authoritative and derive
 * any UI list from the data, so neither an unused member renders as an empty
 * row nor a newly-used one silently disappears.
 */
export type AffectedParty = GeneratedAffectedParty
export type ForceEnum = GeneratedForceEnum
export type TimeframeType = GeneratedTimeframeType
export type NotificationMethod = GeneratedNotificationMethod
export type NotificationParty = GeneratedNotificationParty
export type FrdDefinition = GeneratedFrdDefinition
export type PainTimeframeEntry = GeneratedPainTimeframeEntry

export type FrrDocument = FedRampDataset["FRR"][string]
export type FrrRequirement = GeneratedFrrRequirement
export type FrrRequirementLevel = GeneratedFrrRequirementLevel

export type KsiTheme = FedRampDataset["KSI"][string]
export type KsiIndicator = GeneratedKsiIndicator

/** Raw CTL guidance, before `build-index.ts` flattens it (C2). */
export type ControlGuidanceRaw = NonNullable<
  FedRampDataset["CTL"]
>[string][string]
