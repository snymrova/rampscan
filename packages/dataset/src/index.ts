export * from "./client.js";
export * from "./types.js";

/**
 * The dataset version this checkout is pinned to. Typed deliberately — the
 * pin IS the human decision; every loader hard-fails on a mismatch (ground
 * rule 2). Bumping it is a reviewed change, never a side effect.
 */
export const DEFAULT_DATASET_PIN = "2026.07.14.01";
