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
 * One uncovered control on ramprules' automation frontier (the 121). Upstream's
 * shape, mirrored and not owned: `disposition`/`rationale`/`sourcesConsidered`
 * are the AWS pass's adjudication of this control, and every reviewed row in the
 * published file carries `sourcesConsidered: ["aws"]`. rampscan's own
 * adjudications live beside the file in `recipes/adjudications/`, never inside
 * it (N0 decision 1) — this type exists so `rampscan frontier` can read the
 * register it is adjudicating against, under the same version pin as every
 * other slice.
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
    // nullable AND optional: the published file writes `null` for a control
    // the AWS pass never reached, and "the field is absent" and "the field is
    // explicitly nothing" are the same fact to a reader — both mean unreviewed
    /** the AWS pass's disposition, when it reviewed this control */
    disposition: z.string().nullish(),
    rationale: z.string().nullish(),
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
