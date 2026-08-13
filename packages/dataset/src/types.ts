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
