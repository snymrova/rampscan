import { z } from "zod";

// The pipeline adjudication record (SPEC §10.2, plan N1a-T1): one file per
// uncovered frontier control, answering ONE question — can evidence committed
// to a repository discharge this control, in whole or in part?
//
// `automation-frontier.json` carries upstream's uncovered set, and when these
// records were first written it had been adjudicated from exactly one source
// that is not ours: every reviewed row read `sourcesConsidered: ["aws"]` and
// every rationale reasoned about CloudTrail, Config, Access Analyzer, KMS.
// Nobody had asked what a REPOSITORY can answer. These records are that answer.
//
// That is no longer the whole picture and the comment is corrected rather than
// deleted, because the correction is the interesting part: at overlay 0.7.2
// upstream opened a second plane of its own, named it `pipeline`, and thirteen
// frontier rows now carry it. Ours is not the only pass asking this question —
// see N1a′ and ground rule 10, which is why a record cites rather than ignores.
//
// Two structural decisions, both load-bearing and both taken at N0:
//
//   They live in `recipes/adjudications/<control-id>.json`, NOT written back
//   into the frontier — that file is upstream's, behind a version pin the
//   dataset client hard-fails on. Each record carries its own
//   `datasetVersion`, so an upstream re-publish invalidates our reasoning
//   loudly instead of silently re-basing it against controls that moved.
//
//   The field names MIRROR the frontier's own vocabulary, because SPEC §10.2's
//   stated goal is that this overlay be contributable upstream: `recipeIds`
//   sits where the frontier has `coveredBy`, `candidateCollectors` where it
//   has `candidateServices`, and `source` says which pass wrote the row.
//   Mirroring now makes that contribution a merge; diverging now makes it a
//   rewrite.

export const Disposition = z.enum(["automatable", "partial", "narrative"]);
export type Disposition = z.infer<typeof Disposition>;

export const PipelineAdjudication = z
  .object({
    /** canonical control id, as the crosswalk and the frontier key it ("sa-9") */
    controlId: z.string().min(1),
    /** the frontier's display form ("SA-09"), mirrored so a merge needs no lookup */
    displayId: z.string().min(1),
    family: z.string().min(1),
    /**
     * automatable — a repository can discharge this control on its own
     * partial    — a repository answers part of it; `remainder` names the rest
     * narrative  — nothing committable settles it, and the rationale says what
     */
    disposition: Disposition,
    /**
     * The authored paragraph, in the frontier's voice: name the artifact, name
     * why it does or does not settle the control, and where it settles only
     * half, name the half it leaves. A disposition is reasoning, not a label
     * (ground rule 8) — this repository does not ship opinions as evidence,
     * and if the reasoning cannot be written the disposition is not known.
     */
    rationale: z.string().min(1),
    /** which adjudication pass wrote this; ours is always the pipeline */
    source: z.literal("pipeline"),
    /** recipes in `recipes/pipeline/` that discharge it — empty until they exist */
    recipeIds: z.array(z.string()).default([]),
    /** collectors that could evidence it: registered today, or named in Tier 2 */
    candidateCollectors: z.array(z.string()).default([]),
    /**
     * REQUIRED on `partial`, and refused elsewhere. `partial` does not count as
     * covered (N0 decision 3), and the only thing that keeps that honest is a
     * sentence naming the specific thing a repository cannot see. A partial
     * disposition with no remainder is a covered claim wearing a smaller word.
     */
    remainder: z.string().min(1).optional(),
    /**
     * Set when the control this record adjudicates has LEFT the frontier — the
     * frontier is the uncovered set, upstream's file, and it shrinks whenever
     * upstream answers something. The record is kept rather than deleted
     * because deleting it is the silent drop ground rule 10 forbids: a reader
     * holding both overlays would find our paragraph gone and upstream's
     * standing, with no way to tell whether we agreed, disagreed, or never
     * looked. A retirement is a declaration, so it carries a reason in the same
     * voice as the disposition it closes.
     *
     * The original `disposition`, `rationale` and `remainder` stay exactly as
     * they were written. A retired record is a historical claim, and editing
     * one to look better in hindsight is how an overlay stops being evidence.
     */
    retired: z
      .object({
        at: z.string().regex(/^\d{4}-\d{2}-\d{2}$/, "retired.at must be YYYY-MM-DD"),
        /** the upstream overlay version at which the control left the frontier */
        overlayVersion: z.string().min(1),
        /**
         * Why it left, and — where upstream argued with our route rather than
         * merely arriving first — whether we concede or contest. Silence on
         * that is risk 7 arriving through the back door.
         */
        reason: z.string().min(1),
        /** upstream recipes that took it off the frontier, cited by id */
        upstreamRecipeIds: z.array(z.string()).default([]),
      })
      .optional(),
    reviewed: z.string().regex(/^\d{4}-\d{2}-\d{2}$/, "reviewed must be YYYY-MM-DD"),
    /** the frontier version this reasoning was written against */
    datasetVersion: z.string().min(1),
  })
  .superRefine((record, ctx) => {
    if (record.disposition === "partial" && record.remainder === undefined) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["remainder"],
        message:
          `${record.controlId}: a "partial" disposition must name its remainder — ` +
          "the specific thing a repository cannot see. Without it, partial is just covered with a hedge.",
      });
    }
    if (record.disposition !== "partial" && record.remainder !== undefined) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["remainder"],
        message:
          `${record.controlId}: only a "partial" disposition carries a remainder — ` +
          `an "${record.disposition}" record with one is claiming a boundary it did not draw.`,
      });
    }
  });
export type PipelineAdjudication = z.infer<typeof PipelineAdjudication>;
