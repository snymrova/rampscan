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

/**
 * The plain-language layer (plan K1). Three short paragraphs of operator
 * English per recipe — AUTHORED, never computed. The computed-never-typed rule
 * governs verdicts, counts and states; an explanation of what a check means is
 * exactly the thing a human should write, and the one thing this system has no
 * way to derive.
 *
 * Three fields rather than the one paragraph K1 sketched, because each surface
 * needs a DIFFERENT one of the three: the board answers "what is this row",
 * the queue answers "what do I do about it", and only the evidence page wants
 * all three. One blob would force every surface to print the other two, and
 * would let a recipe answer one question and call itself documented — three
 * slots make a half-written explanation fail the completeness test instead.
 */
export const PlainLanguage = z.object({
  /** what this check looks at, in words an operator who has never read the recipe understands */
  checks: z.string().min(1),
  /** what a violation means in practice — the real-world consequence, not a restatement of the assertion */
  violation: z.string().min(1),
  /** what fixing it looks like: the concrete move, not "resolve the finding" */
  fix: z.string().min(1),
});
export type PlainLanguage = z.infer<typeof PlainLanguage>;

/**
 * What an EMPTY observation set means for this recipe (N0-T2) — the one thing
 * no static test can infer, so the recipe declares it.
 *
 *   "clean"        the collector searched a domain that exists and found
 *                  nothing: gitleaks walked every commit, spectral linted
 *                  every document it found. An empty set is a real result and
 *                  `evidenced` is honest.
 *   "unevidenced"  an empty set means there was nothing to search. The
 *                  collector MUST guard (omit the observation key) or skip
 *                  (state a reason) — it may never emit `[]` and let the
 *                  assertions pass over zero rows.
 *
 * Two values, not three: a domain that exists but was searched incompletely is
 * a `population` fact (AssertionResult.population), not a second kind of
 * emptiness. There is no default, and `catalog.test.ts` refuses a recipe that
 * leaves it unstated — a recipe that cannot say what an empty result means has
 * not decided, and the vacuous pass is what undecided looks like in production.
 */
export const EmptyMeans = z.enum(["clean", "unevidenced"]);
export type EmptyMeans = z.infer<typeof EmptyMeans>;

/**
 * Ground rule 10, at the CATALOG rather than at the record — the arm the
 * adjudication's `citesUpstream` structurally cannot reach.
 *
 * `citesUpstream` is checked against `automation-frontier.json`, which is the
 * UNCOVERED set. So it fires wherever upstream *adjudicated* a control and is
 * blind wherever upstream *answered* one, because an answered control leaves
 * the frontier and takes the fact with it. Three controls had reached that
 * state undetected — `ia-5.6`, `sa-11` and `si-10` each carry a recipe on
 * upstream's `pipeline` plane AND one in this catalog, on nobody's frontier,
 * with neither project saying a word about the other. Risk 7 does not care
 * which file the silence lives in.
 *
 * `relation` is the same two-valued judgement `citesUpstream.agreement` makes,
 * named for recipes rather than verdicts:
 *
 * - `corroborates` — two artifacts, one control, same answer. This is the good
 *   case and the common one, and it is worth *more* than a single claim, not
 *   less: upstream reads the platform's alert store, this plane reads the
 *   committed bytes, and a control answered twice from two evidence paths is
 *   the strongest statement either project can make about it. Left undeclared
 *   it reads instead as two projects duplicating each other.
 * - `contests` — the two artifacts disagree about what the control needs or
 *   about whether this evidence reaches it. A contest must ARGUE, for the same
 *   reason a divergent citation must: an undeclared disagreement leaves a
 *   reader holding both catalogs with two confident claims and no way to choose.
 */
export const UpstreamOverlapRelation = z.enum(["corroborates", "contests"]);
export type UpstreamOverlapRelation = z.infer<typeof UpstreamOverlapRelation>;

export const UpstreamOverlap = z.object({
  /** which of THIS recipe's controls the overlap is on */
  control: z.string(),
  /** upstream's plane that authored the other recipe — their names, not ours */
  plane: z.enum(["aws", "pipeline"]),
  /** upstream's recipe id, so a reader can open both sides */
  recipeId: z.string(),
  relation: UpstreamOverlapRelation,
  /**
   * What the two artifacts are, and why one control needs both — or, on a
   * contest, the argument. A floor rather than a shape, for the reason the
   * divergence notes carry one: a citation short enough to be a label is a
   * label, and the whole failure being guarded is a claim nobody reasoned about.
   */
  note: z.string().min(80),
});
export type UpstreamOverlap = z.infer<typeof UpstreamOverlap>;

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
  /**
   * K1's operator English. OPTIONAL in the shape and REQUIRED in the shipped
   * catalog: the schema mirrors aws-evidence.json's recipe form, which carries
   * no such field, so a recipe imported from that dataset must still parse —
   * while `plain.test.ts` fails CI on any recipe in `recipes/commit/` that
   * lacks one. Shape is schema's job; completeness is policy's.
   */
  plain: PlainLanguage.optional(),
  /**
   * N0's empty-set declaration. OPTIONAL in the shape and REQUIRED in the
   * shipped catalog, for the same reason `plain` is: the recipe shape mirrors
   * aws-evidence.json, which carries no such field, so an imported recipe must
   * still parse — while `catalog.test.ts` fails CI on any recipe in
   * `recipes/commit/` that omits it. Shape is schema's job; completeness is
   * policy's.
   */
  empty_means: EmptyMeans.optional(),
  /**
   * Where upstream has authored a recipe over a control this one claims.
   * OPTIONAL in the shape and REQUIRED-WHEN-APPLICABLE in the catalog, which is
   * a weaker rule than `plain` and `empty_means` carry and deliberately so:
   * those are owed by every recipe, this is owed only by a recipe that overlaps,
   * and whether it overlaps is a fact about UPSTREAM's file rather than about
   * this one. A schema cannot see that file, so `frontier.ts` checks it against
   * the pinned evidence plan — the same split as `citesUpstream`, whose
   * "required on a live record whose control upstream has adjudicated" is
   * likewise enforced where the other file can be read.
   */
  upstream_overlap: z.array(UpstreamOverlap).optional(),
  anchor: z.literal("commit"),
});
export type PipelineRecipe = z.infer<typeof PipelineRecipe>;
