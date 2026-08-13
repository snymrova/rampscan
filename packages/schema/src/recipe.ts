import { z } from "zod";

// PipelineRecipe mirrors aws-evidence.json's recipe shape field-for-field
// (dataset 2026.07.14.01), with two deliberate deltas per SPEC §10.1:
//   - `govcloud` → `caveats` (generalizing the partition-specific field)
//   - `anchor: "commit"` added — pipeline evidence is commit-anchored
// and `collection.kind` is "pipeline" with a collector reference instead of
// AWS CLI commands.

export const AssertionOp = z.enum([
  "eq",
  "exists",
  "not_exists",
  "in",
  "lte",
  "gte",
  "count_eq",
  "count_lte",
  "max_age_days",
]);
export type AssertionOp = z.infer<typeof AssertionOp>;

const AssertionValue = z.union([
  z.string(),
  z.number(),
  z.boolean(),
  z.array(z.string()),
]);

export const AssertionClause = z.object({
  field: z.string(),
  op: AssertionOp,
  value: AssertionValue.optional(), // exists / not_exists take no value
});

export const RecipeAssertion = AssertionClause.extend({
  where: z.array(AssertionClause).optional(),
  controls: z.array(z.string()).optional(),
  description: z.string(),
});
export type RecipeAssertion = z.infer<typeof RecipeAssertion>;

export const Cadence = z.enum([
  "continuous",
  "daily",
  "weekly",
  "monthly",
  "quarterly",
]);
export type Cadence = z.infer<typeof Cadence>;

export const Automatable = z.enum(["full", "partial", "narrative"]);
export type Automatable = z.infer<typeof Automatable>;

export const PipelineCollection = z.object({
  kind: z.literal("pipeline"),
  collector: z.string(), // collector name whose manifest declares this recipe
  inputs: z.array(z.string()).optional(), // artifacts consumed (e.g. "sbom.cdx.json")
});

export const PipelineRecipe = z.object({
  id: z.string(),
  ksi_ids: z.array(z.string()).min(1),
  control_ids: z.array(z.string()).min(1),
  evidence: z.string(), // what the artifact proves, one sentence
  collection: PipelineCollection,
  expected_output: z.string(),
  assertions: z.array(RecipeAssertion).optional(),
  cadence: Cadence,
  caveats: z.string().optional(), // sole rename: aws-evidence's `govcloud`
  automatable: Automatable,
  notes: z.string().optional(),
  anchor: z.literal("commit"),
});
export type PipelineRecipe = z.infer<typeof PipelineRecipe>;
