import { z } from "zod";

// Shapes of the ramprules derived slices this client consumes — validated
// at the edges we rely on, permissive elsewhere. The dataset is upstream's;
// we pin its version, we don't own its schema.

export const SliceEnvelope = z.object({
  dataset_version: z.string(),
  last_updated: z.string(),
  slice: z.string().optional(),
  data: z.unknown().optional(),
});

/**
 * The overlay version a slice payload was derived under, wherever upstream
 * happens to write it. Two spellings are in the published snapshot today —
 * `overlay_version` at the payload root (automation-frontier, aws-evidence) and
 * `overlay.overlay_version` one level down (evidence-plan) — so this reads both
 * rather than assuming the shape we happened to look at first. Returns
 * `undefined` when the slice carries no overlay at all (crosswalk, index),
 * which the loader treats as a refusal only when a pin was declared for it.
 */
export function sliceOverlayVersion(payload: unknown): string | undefined {
  if (payload === null || typeof payload !== "object") return undefined;
  const root = payload as Record<string, unknown>;
  if (typeof root.overlay_version === "string") return root.overlay_version;
  const nested = root.overlay;
  if (nested !== null && typeof nested === "object") {
    const inner = (nested as Record<string, unknown>).overlay_version;
    if (typeof inner === "string") return inner;
  }
  return undefined;
}

export const CrosswalkControl = z.object({
  canonicalId: z.string(),
  displayId: z.string(),
  family: z.string(),
  indicatorIds: z.array(z.string()),
});
export type CrosswalkControl = z.infer<typeof CrosswalkControl>;

export const CrosswalkIndicator = z.object({
  id: z.string(),
  themeKey: z.string(),
  themeName: z.string(),
  name: z.string(),
  statement: z.string().nullable(),
  controls: z.array(
    z.object({
      canonicalId: z.string(),
      displayId: z.string(),
      family: z.string(),
    }),
  ),
});
export type CrosswalkIndicator = z.infer<typeof CrosswalkIndicator>;

/**
 * One uncovered control on ramprules' automation frontier. Upstream's shape,
 * mirrored and not owned: `disposition`/`rationale` are an adjudication of this
 * control and `sourcesConsidered` names the plane that wrote it.
 *
 * **Corrected 2026-08-17 (N1a′-T2).** This comment used to state an invariant —
 * "every reviewed row in the published file carries `sourcesConsidered: ["aws"]`"
 * — which was true of the snapshot pinned when it was written and false of
 * upstream's file by then. Upstream has opened a second plane of its own, named
 * it `pipeline`, and reviewed rows now carry that name instead. So
 * `sourcesConsidered` is READ rather than assumed: `frontier.ts` files each
 * disposition under the source that wrote it, because a reader shown upstream's
 * pipeline reasoning in an AWS column has been told something untrue about who
 * concluded what.
 *
 * rampscan's own adjudications live beside the file in `recipes/adjudications/`,
 * never inside it (N0 decision 1) — this type exists so `rampscan frontier` can
 * read the register it is adjudicating against, under the same version pins as
 * every other slice (`dataset_version` AND the slice's `overlay_version`; see
 * `pins.ts` for why the second one had to be added).
 *
 * Passthrough and mostly optional on purpose: the fields we reason about are
 * validated, the rest travel untouched, because a stricter mirror of someone
 * else's file is a build break waiting for their next release.
 */
export const FrontierControl = z
  .object({
    controlId: z.string(),
    displayId: z.string(),
    family: z.string(),
    ksis: z.array(z.string()).default([]),
    classes: z.array(z.string()).default([]),
    leverage: z.number().optional(),
    // nullable AND optional: the published file writes `null` for a control no
    // upstream pass ever reached, and "the field is absent" and "the field is
    // explicitly nothing" are the same fact to a reader — both mean unreviewed
    /** an upstream plane's disposition, when one reviewed this control */
    disposition: z.string().nullish(),
    rationale: z.string().nullish(),
    /** which upstream plane(s) wrote the disposition above — never assumed */
    sourcesConsidered: z.array(z.string()).default([]),
  })
  .passthrough();
export type FrontierControl = z.infer<typeof FrontierControl>;

// aws-evidence recipes, as published upstream (govcloud not yet renamed —
// that rename is ours and applies to pipeline recipes, not this mirror).
export const AwsRecipe = z
  .object({
    id: z.string(),
    ksi_ids: z.array(z.string()),
    control_ids: z.array(z.string()),
    evidence: z.string(),
    collection: z.object({ kind: z.string() }).passthrough(),
    expected_output: z.string(),
    cadence: z.string(),
    govcloud: z.string(),
    automatable: z.string(),
    notes: z.string(),
  })
  .passthrough();
export type AwsRecipe = z.infer<typeof AwsRecipe>;

/**
 * Upstream's evidence plan, read for one thing only: **which controls upstream
 * has already authored a recipe over, and on which plane**.
 *
 * This slice is the handshake that closes the hole batch 1's audit could not
 * see. Ground rule 10 is enforced against `automation-frontier.json`, which is
 * the UNCOVERED set — so it fires where upstream *adjudicated* a control and is
 * structurally blind where upstream *answered* one, because an answered control
 * leaves the frontier entirely. Three controls (`ia-5.6`, `sa-11`, `si-10`)
 * were being claimed by a recipe on both planes with neither side declaring it,
 * and no check on either side could have noticed: they are on nobody's frontier.
 *
 * The plan is the right file to read rather than upstream's `data/overlays/`
 * source, because it is their *published* surface — the same posture ground
 * rule 2 takes everywhere else. Shape is deliberately minimal and passthrough:
 * a recipe id, the plane that wrote it, and the controls it claims.
 *
 * `provesControls` is scoped per certification class, so the same recipe
 * appears under several classes with the list populated in some and empty in
 * others. The union across classes is the mapping; a single class is not.
 */
export const EvidencePlanItem = z
  .object({
    recipeId: z.string(),
    /** the plane that authored it — `aws` or `pipeline` in the pinned snapshot */
    source: z.string(),
    /** canonical control ids this recipe claims, WITHIN the enclosing class */
    provesControls: z.array(z.string()).default([]),
  })
  .passthrough();
export type EvidencePlanItem = z.infer<typeof EvidencePlanItem>;

/**
 * One evidence plane, with the overlay version it was derived under. Upstream
 * versions its planes independently — `aws` at 1.6.1 and `pipeline` at 0.5.1
 * from one `dataset_version` — which is the same fact that made a single global
 * overlay pin wrong in `pins.ts`, arriving one level further down.
 */
export const EvidencePlanPlane = z
  .object({
    source: z.string(),
    version: z.string().optional(),
  })
  .passthrough();
export type EvidencePlanPlane = z.infer<typeof EvidencePlanPlane>;

export const EvidencePlanData = z
  .object({
    classes: z
      .array(
        z
          .object({
            planes: z.array(EvidencePlanPlane).default([]),
            themes: z
              .array(
                z
                  .object({ items: z.array(EvidencePlanItem).default([]) })
                  .passthrough(),
              )
              .default([]),
          })
          .passthrough(),
      )
      .default([]),
  })
  .passthrough();
export type EvidencePlanData = z.infer<typeof EvidencePlanData>;

/** an upstream recipe claiming a control, and the plane that authored it */
export interface UpstreamRecipeRef {
  recipeId: string;
  plane: string;
}
