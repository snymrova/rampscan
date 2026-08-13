/**
 * Types for the FedRAMP consolidated rules dataset.
 *
 * Two layers live here, and the split is the point:
 *
 * 1. RAW dataset shapes — re-exported from `raw-types.ts`, which adapts
 *    `types.generated.ts`, which is generated from FedRAMP's own schema
 *    (plan decision D3). Nothing raw is hand-written any more. The previous
 *    hand-maintained version is what typed `FRR` as
 *    `Record<string, { info: unknown; data: unknown }>` — and that one line
 *    hid the Rev5 baselines for the entire life of the project, which is why
 *    `family-heatmap-data.ts` still carried a comment claiming baseline
 *    membership "isn't in the dataset yet". It was. It always was.
 *
 * 2. NORMALIZED index shapes — hand-written, below. These are ours: the
 *    stable contract lens functions and components consume. They
 *    deliberately do not mirror the dataset. Only `build-index.ts` and
 *    `frr-index.ts` touch the raw layer (plan decision C2), so a
 *    schema-shaped `oneOf` never reaches a React component.
 */

import type {
  AffectedParty,
  ClassKey,
  ForceEnum,
  FrdDefinition,
  TimeframeType,
} from "./raw-types"

export type {
  AffectedParty,
  ClassKey,
  ControlGuidanceRaw,
  FedRampDataset,
  ForceEnum,
  FrdDefinition,
  NotificationMethod,
  NotificationParty,
  TimeframeType,
} from "./raw-types"

// ---- Normalized index types (produced by build-index.ts) ----

export interface ParsedControlId {
  /** Lowercase family code, e.g. "ac" — the `control_id` family segment. */
  family: string
  /**
   * Base control number. A NUMBER, not a padded string: FedRAMP's `control_id`
   * is `\d+` and unbounded, and the previous 2-digit padded form both invented
   * a dialect FedRAMP does not use and capped the space at 99.
   */
  base: number
  /** Enhancement number, or null for a base control. */
  enhancement: number | null
}

export interface ControlRef {
  /** FedRAMP `control_id`, e.g. "ac-2.13". Map key, API key, URL segment. */
  canonicalId: string
  /** FedRAMP `rev5_control_id`, e.g. "AC-02 (13)". */
  displayId: string
  /** Uppercase family code, e.g. "AC". */
  family: string
}

export interface ControlParameter {
  parameterId: string
  value: string
}

export interface ControlClassData {
  guidance?: string[]
  parameters?: ControlParameter[]
}

/**
 * CTL guidance flattened at index time (plan decision C2). The raw shape is a
 * generated type carrying `@minItems` tuple unions; normalizing here means
 * `detail-panel.tsx` renders plain arrays and never imports anything
 * generated.
 */
export interface ControlGuidance {
  guidance?: string[]
  parameters?: ControlParameter[]
  varies_by_class?: Partial<Record<"b" | "c" | "d", ControlClassData>>
}

export interface KsiIndicatorNode {
  id: string
  themeId: string
  themeKey: string
  themeName: string
  name: string
  statement: string | null
  hasVariesByClass: boolean
  controlRefs: ControlRef[]
  terms: string[]
}

export interface KsiThemeNode {
  id: string
  key: string
  name: string
  webName: string
  indicators: KsiIndicatorNode[]
}

export interface ControlNode {
  canonicalId: string
  displayId: string
  family: string
  guidance: ControlGuidance | null
  indicatorIds: string[]
}

export interface FamilyNode {
  code: string
  controlIds: string[]
}

// ---- Normalized FRR types (produced by frr-index.ts) ----

/**
 * The three certification classes that carry a Rev5 baseline. Class A has
 * none — it is not an empty baseline, it is the absence of one, and the UI
 * must say so rather than render `0 / 0`.
 */
export type BaselineClass = "b" | "c" | "d"

export interface BaselineSet {
  class: BaselineClass
  /** Canonical `control_id`s, e.g. "ac-2.1". */
  controlIds: Set<string>
  /** Family code -> canonical ids, for per-family coverage. */
  byFamily: Map<string, Set<string>>
}

/** One timeframed obligation. `num`/`type` are always the dataset's own. */
export interface TimeframedEntry {
  requirementId: string
  documentKey: string
  documentName: string
  /** "all" | "20x" | "rev5" — the applicability group it came from. */
  group: string
  subset: string
  name: string
  statement: string
  force: ForceEnum | null
  /** Who the parent requirement binds. Always non-empty. */
  affects: AffectedParty[]
  /** null when the timeframe sits at requirement level, not per-class. */
  class: ClassKey | null
  num: number
  type: TimeframeType
  /** Ordering only — never rendered, never exported. See duration.ts (T2). */
  sortKey: number
}

export interface NotificationItem {
  requirementId: string
  documentKey: string
  requirementName: string
  party: string
  /** Drives how `target` renders — see T1. Never sniff the string instead. */
  method: "email" | "form" | "update" | "varies" | "web"
  target: string
  name: string
  url?: string
}

/** One cell of a PAIN grid: a severity level crossed with a scenario column. */
export interface PainCell {
  /** "1".."5" — the schema pins these five but leaves the level open. */
  level: string
  /** The scenario key, e.g. "iir" or "irv_lev". Data-derived (D1). */
  column: string
  description: string
  num: number
  type: TimeframeType
}

/**
 * A PAIN grid for one requirement/class. Columns are derived from that
 * requirement's own data, never a fixed list: the schema declares
 * `pain_timeframe_group` as `additionalProperties`, and in practice
 * IEC-CSO-IIR/OIR/FIR use `iir`/`oir`/`fir` while VDR-TFR-PVR uses
 * `irv_lev`/`nirv_lev`/`nlev`. A hardcoded column set renders three of the
 * four carrying requirements blank.
 */
export interface PainGrid {
  requirementId: string
  documentKey: string
  requirementName: string
  class: ClassKey
  /** Ordered, data-derived column keys for THIS requirement. */
  columns: string[]
  /** Ordered level keys present for THIS requirement. */
  levels: string[]
  /** Human label per column, taken from the entries' own `description`. */
  columnLabels: Record<string, string>
  /** `cells[level][column]`, absent where the dataset has no entry. */
  cells: Record<string, Record<string, PainCell>>
}

export interface RolloutEntry {
  documentKey: string
  documentName: string
  /** null for a top-level `info.effective`, else "20x" | "rev5". */
  certificationType: string | null
  /** The effective-rule kind, e.g. "obtain" | "maintain". */
  rule: string
  date: string
  comment?: string
}

/**
 * Both totals, published side by side and explicitly labelled (D7). They
 * differ because 111 forces live inside `varies_by_class`; quoting either
 * number alone without saying which it is has already caused one wrong
 * count in this repo (`analyze-rules.py`, which merged them into a third
 * number matching neither).
 */
export interface ForceDistribution {
  /** Requirement-level `force` only. Totals 217. */
  requirement: Record<ForceEnum, number>
  /** Requirement-level plus every `varies_by_class` force. Totals 328. */
  withClass: Record<ForceEnum, number>
}

export interface FrrRequirementNode {
  id: string
  documentKey: string
  group: string
  subset: string
  name: string
  statement: string | null
  force: ForceEnum | null
  /** Who the rule binds. Schema-required and non-empty on all 246. */
  affects: AffectedParty[]
  /**
   * Rule-specific evidence only — the 5 defaults are NOT merged in here.
   * Empty on the 186 requirements that carry none, which is a real state:
   * they still owe the defaults.
   */
  artifacts: ArtifactRef[]
  classes: ClassKey[]
}

/**
 * Requirement-level `affects` tallies, and the reason this is its own type
 * rather than a bare number: it is the same trap as `ForceDistribution` (D7).
 *
 * A naive recursive walk for `affects` returns 300, because
 * `FRR.<doc>.info.subsets.*` carries `affects` too — as an *applicability*
 * declaration about a whole subset, not an obligation on a requirement. Only
 * the requirement-level field is counted here, and it sums to exactly 246:
 * one party per requirement, none nested inside `varies_by_class`.
 */
export type AffectsDistribution = Partial<Record<AffectedParty, number>>

/**
 * Which certification types an artifact is required for. The schema allows
 * all three; **only `all` occurs in the dataset today**. The other two are
 * carried so a future dataset does not silently drop evidence, but nothing
 * should render a `20x`/`rev5` split that does not exist.
 */
export type ArtifactScope = "all" | "20x" | "rev5"

/**
 * One piece of evidence a rule demands, with enough provenance to say *why*
 * it is owed.
 *
 * `source` is the load-bearing field. `info.default_artifacts.FRR` applies 5
 * boilerplate artifacts to every one of the 246 requirements; only 60 carry
 * anything specific. Merging the two makes the specific evidence burden look
 * roughly 5x larger than it is, so they stay distinguishable all the way to
 * the screen.
 */
export interface ArtifactRef {
  text: string
  scope: ArtifactScope
  /** null when the artifact sits at requirement level, not per-class. */
  class: ClassKey | null
  source: "default" | "requirement"
}

export interface FrrIndex {
  /** Document key -> human name, e.g. "FRC" -> "FedRAMP Certification". */
  documentNames: Map<string, string>
  requirementsById: Map<string, FrrRequirementNode>
  baselinesByClass: Map<BaselineClass, BaselineSet>
  /**
   * The annual-independent-assessment subset (IVV-CSF-AIA). NOT nested:
   * CA-08 is in class b and absent from class c, while FRC-CSF-BSL *is*
   * strictly nested. Always compute set differences against this — never
   * assume containment.
   */
  annualAssessmentByClass: Map<BaselineClass, BaselineSet>
  timeframedEntries: TimeframedEntry[]
  notifications: NotificationItem[]
  painGrids: PainGrid[]
  rolloutCalendar: RolloutEntry[]
  forceDistribution: ForceDistribution
  /** Requirement-level only, and it sums to 246. See AffectsDistribution. */
  affectsDistribution: AffectsDistribution
  /**
   * Control ids that failed to parse. Non-empty fails the build by design —
   * a silently dropped control is an under-scoping error someone acts on.
   */
  parseFailures: { source: string; raw: string }[]
}

export interface FedRampIndex {
  info: {
    title: string
    version: string
    lastUpdated: string
  }
  /**
   * `info.default_artifacts` — 5 artifacts owed by every FRR requirement and
   * 5 by every KSI indicator, stated once at dataset level rather than
   * repeated on each rule.
   */
  defaultArtifacts: { FRR: string[]; KSI: string[] }
  ksiThemes: KsiThemeNode[]
  indicatorsById: Map<string, KsiIndicatorNode>
  /**
   * KSI-edge-only, 209 controls. DO NOT WIDEN to KSI union baseline union
   * CTL — every number on every existing page derives from this set, and the
   * 33 CTL-only controls having no node is load-bearing, not an oversight.
   * Baseline membership lives on `frr.baselinesByClass` instead; coverage is
   * a set intersection against these keys.
   */
  controlsById: Map<string, ControlNode>
  familiesById: Map<string, FamilyNode>
  /**
   * FedRAMP's `CTL` guidance overlay, keyed by canonical `control_id` — the
   * whole of it, including the controls no KSI reaches.
   *
   * This is NOT a widening of `controlsById`: nothing joins against it, and no
   * page is prerendered from it. It exists so the 33 controls that carry
   * FedRAMP-authored guidance and ODP values yet have no page can be COUNTED
   * and named rather than merely missing. The 209/419 split stays a documented
   * refusal; this makes the refusal legible.
   */
  ctlGuidanceById: Map<string, ControlGuidance>
  frdTermsByName: Map<string, FrdDefinition>
  frr: FrrIndex
}
