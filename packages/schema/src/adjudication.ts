import { z } from "zod";

// The commit-plane adjudication record (SPEC §10.2, plan N1a-T1): one file per
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
// WHICH IS WHY `source` READS `commit` AND NO LONGER READS `pipeline` (N1a′-T3,
// decision 6, settled 2026-08-17 as option (b): a third plane, named for the
// ANCHOR rather than the subject). Upstream's plane covers our exact subject
// matter — SAST, dependency, secret, IaC, attestation — and differs in TRUST
// MODEL, not scope: theirs reads a SaaS platform's API, ours reads a checkout
// offline and signs the result. Their schema encodes that assumption in two
// fields REQUIRED on every recipe, and neither has an honest value here:
// `platform` wants the exact offering ("GitHub Enterprise Cloud", "never a bare
// vendor name") and a local CLI is not an offering, while `external_system`
// wants what adopting the platform ADDS to the authorization boundary and our
// answer is the negative one. So filing under their name would have meant
// either writing a `platform` that is not a platform or editing someone else's
// schema. Naming the plane for what distinguishes it costs neither: `anchor:
// z.literal("commit")` in `recipe.ts` is a field their plane has no concept of,
// and it is the property that survives all the way into the signed bundle.
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

export const CommitAdjudication = z
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
    /**
     * Which adjudication pass wrote this; ours is always the commit plane.
     * Upstream's two planes are `aws` and `pipeline`, and a record filed under
     * either of those names would be claiming a pass it did not make — the
     * whole point of the header's decision is that the three names stay
     * distinguishable in a file a reader holds beside upstream's own.
     */
    source: z.literal("commit"),
    /** recipes in `recipes/commit/` that discharge it — empty until they exist */
    recipeIds: z.array(z.string()).default([]),
    /** collectors that could evidence it: registered today, or named in Tier 2 */
    candidateCollectors: z.array(z.string()).default([]),
    /**
     * REQUIRED on `partial`, and refused elsewhere. `partial` does not count as
     * covered (N0 decision 3), and the only thing that keeps that honest is a
     * sentence naming the specific thing a repository cannot see. A partial
     * disposition with no remainder is a covered claim wearing a smaller word.
     *
     * TWO LIMBS, both required, because there are two different boundaries and
     * only one of them is about the control (N1a′-T4, decision 7). `control` is
     * the half this control asks for that a commit cannot show. `boundary` is
     * the half no control asks for and every claim on this plane owes anyway:
     * rampscan enumerates from the checkout it was handed, multi-repo joins are
     * deferred by name, and so nothing here can say the scanned repository is
     * the whole authorization boundary — upstream's own plane card reaches the
     * same conclusion from the other side ("expect `partial`, because the
     * repository set inside the boundary is named by a human").
     *
     * Two limbs rather than one paragraph with a clause in it, because a clause
     * can be forgotten in a rewrite and a required field cannot. Inside
     * `remainder` rather than beside it, because the schema already refuses a
     * `partial` without one and a non-`partial` with one — so the boundary gap
     * inherits that rule instead of needing its own, and no record can carry a
     * boundary sentence while claiming `automatable`. The consequence is worth
     * stating rather than discovering: `automatable` is nearly unreachable on
     * this plane, and the first seven records found it exactly zero times.
     */
    remainder: z
      .object({
        /** the limb of THIS control a commit cannot reach */
        control: z.string().min(1),
        /**
         * the limb no commit reaches on any control: one checkout is not known
         * to be the boundary. Required on a live record, and only on a live
         * one — see `retired`, which freezes a record rather than back-filling
         * a sentence it never carried.
         */
        boundary: z.string().min(1).optional(),
      })
      .optional(),
    /**
     * Ground rule 10, made checkable (N1a′-T5). Where upstream has already
     * adjudicated a control, this record READS that adjudication before writing
     * over it and says which of two things is true.
     *
     * The failure being guarded is not disagreement — it is UNDECLARED
     * disagreement (risk 7). A reader holding both overlays finds two confident
     * paragraphs about one control and no way to choose, which is worse than
     * one paragraph and worse than none. Agreement left silent is the same
     * failure wearing a friendlier face: two passes reaching the same verdict
     * from different evidence is the strongest corroboration either project
     * has, and it is worth nothing if neither says so.
     *
     * Structured rather than a sentence in `rationale`, for the reason T4 chose
     * two limbs over a clause: a citation checked by matching on prose is
     * fragile when the wording moves and gameable when it does not. Here it
     * also buys something a prose check cannot — `disposition` is recounted
     * against upstream's live file, so a citation that was true at the last
     * re-pin and is false now fails loudly instead of ageing quietly.
     *
     * Required on a live record whose control upstream has adjudicated. That
     * condition depends on upstream's file, which this schema cannot see, so it
     * is enforced in `rampscan frontier`'s link checks beside every other
     * cross-file rule rather than here.
     */
    citesUpstream: z
      .object({
        /** which of upstream's planes wrote it — `aws` or `pipeline` */
        source: z.string().min(1),
        /** their disposition, recounted against their file, never remembered */
        disposition: z.string().min(1),
        /**
         * `agrees` — same verdict, and the note says what a commit adds that
         *   their evidence path does not; corroboration is the whole value and
         *   it has to be legible as corroboration.
         * `diverges` — different verdict, and the note ARGUES. This is the case
         *   ground rule 10 exists for; a divergence with a note that merely
         *   restates our own rationale has declared nothing.
         */
        agreement: z.enum(["agrees", "diverges"]),
        note: z.string().min(1),
      })
      .optional(),
    /**
     * What adopting this evidence path adds to the authorization boundary, and
     * on this plane the answer is the NEGATIVE one — which is the single
     * strongest thing this overlay can say that upstream's cannot. Three of the
     * four rationales upstream wrote over controls we also adjudicated end on
     * "the platform … is itself an external system, raising SA-09 and CA-03";
     * their research calls it their sharpest finding, that the plane which
     * would close SA-11 raises SA-09. Ours does not: collectors take no network
     * by decision, execution is local, signing is `node:crypto`. So adopting
     * rampscan to collect evidence does not enlarge the boundary it reports on.
     *
     * A field rather than a habit, because a differentiator stated in four
     * records out of a hundred and nineteen is a differentiator nobody can
     * count. Required on a live record; a retired one is closed.
     */
    externalSystem: z.string().min(1).optional(),
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
    // A RETIRED RECORD IS FROZEN, and that is one rule rather than two
    // exemptions. `retired` already promises the disposition, rationale and
    // remainder stay exactly as they were written, so a field added to this
    // schema afterwards is required of LIVE records only: back-filling
    // `boundary` or `externalSystem` into a closed record would mean writing
    // sentences it never carried and presenting them as what it said at the
    // time, which is the same revision-in-hindsight the freeze exists to stop.
    // The cost is that a retired record is less complete than a live one, and
    // that is the correct trade — it is a historical claim, not a current one.
    if (record.retired !== undefined) return;
    if (record.remainder !== undefined && record.remainder.boundary === undefined) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["remainder", "boundary"],
        message:
          `${record.controlId}: a live "partial" must name the boundary limb too — ` +
          "rampscan reads the checkout it was handed, so no claim here knows the scanned repository " +
          "is the whole authorization boundary. A remainder that names only the control's own gap " +
          "reads as though that gap were the only one.",
      });
    }
    if (record.externalSystem === undefined) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["externalSystem"],
        message:
          `${record.controlId}: every live record states what this evidence path adds to the ` +
          "authorization boundary. On this plane the answer is the negative one, and it is the " +
          "strongest thing this overlay can say that upstream's cannot — a differentiator stated " +
          "on some records and not others is one nobody can count.",
      });
    }
  });
export type CommitAdjudication = z.infer<typeof CommitAdjudication>;
