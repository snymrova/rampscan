/**
 * The versions this checkout is pinned to. Typed deliberately — the pin IS the
 * human decision; every loader hard-fails on a mismatch (ground rule 2).
 * Bumping one is a reviewed change, never a side effect.
 *
 * There are TWO of them, and the second exists because the first did not cover
 * the field that moves. `dataset_version` versions the register: the controls,
 * the crosswalk, the KSIs. `overlay_version` versions the ADJUDICATIONS derived
 * over it — the dispositions and rationales our own records reason against. On
 * 2026-08-17 upstream's automation-frontier moved 0.6.0 → 0.7.2, changing
 * fifteen dispositions and removing two controls from the frontier entirely,
 * while `dataset_version` stayed identical at 2026.07.14.01. The only pin this
 * client checked was the one that had not moved, so every adjudication in
 * `recipes/adjudications/` was keyed to a snapshot the loader could not detect
 * moving (plan N1a′-T1; the plan's risk 4 was already realised when it was
 * written down).
 *
 * It moved AGAIN before the next batch was committed: 0.7.2 → 0.7.5 inside a
 * single day, taking the frontier 119 → 112 as upstream authored seven more
 * recipes on its own plane. So the lesson of N1a′-T1 is not "the second pin was
 * missing", which is now fixed — it is that upstream ships overlay bumps faster
 * than this project closes a batch, and a re-pin is therefore a step at the
 * START of every triage or authoring batch rather than a one-off correction.
 * Re-pinning at the end is re-pinning after the batch has already reasoned
 * against a stale file.
 */
export const DEFAULT_DATASET_PIN = "2026.07.14.01";

/**
 * Overlay pins, keyed by slice file — **per slice, not global**, because
 * `overlay_version` is a property of the overlay a slice was derived from and
 * not of the dataset. The snapshot already proves it: automation-frontier reads
 * 0.6.0 while aws-evidence reads 1.6.1, from the same `dataset_version`. A
 * single global constant would have been wrong on the day it was written.
 *
 * A slice absent from this map is not overlay-versioned and is checked on
 * `dataset_version` alone (crosswalk and index carry no overlay at all). A slice
 * present here must carry the field: a pin against a field nobody reads is the
 * bug this map exists to fix, so the loader refuses rather than passes.
 */
export const DEFAULT_OVERLAY_PINS: Readonly<Record<string, string>> = {
  "automation-frontier.json": "0.7.5",
  "aws-evidence.json": "1.6.1",
};

/**
 * The THIRD pin, and it exists for the same reason as the second: a version we
 * reason against that nothing was checking.
 *
 * `overlay_version` covers the slices that carry one at their root. Upstream's
 * evidence plan carries none — the field was removed there deliberately, because
 * a single page-level stamp over a mixed-plane population is the way a class
 * page prints one version over recipes from two overlays. What it carries
 * instead is one stamp PER PLANE, one level down, and the pipeline plane's stamp
 * is the version every citation written under the new ground-rule-10 arm is
 * keyed to.
 *
 * Pinning it means the loader refuses at exactly the moment upstream authors a
 * new recipe on that plane — which is exactly the moment a control can start
 * being claimed on both planes at once. That is the whole point: the refusal
 * lands when a NEW overlap becomes possible, not after one has shipped
 * undeclared. Batch 1's audit could not have caught `ia-5.6`, `sa-11` or
 * `si-10`, because an answered control is on nobody's frontier.
 *
 * Keyed by plane rather than by file for the reason `DEFAULT_OVERLAY_PINS` is
 * keyed by slice: the planes move independently, and one global constant would
 * have been wrong on the day it was written.
 */
export const DEFAULT_PLANE_PINS: Readonly<Record<string, string>> = {
  pipeline: "0.5.1",
};
