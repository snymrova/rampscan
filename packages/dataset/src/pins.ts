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
  "automation-frontier.json": "0.7.2",
  "aws-evidence.json": "1.6.1",
};
