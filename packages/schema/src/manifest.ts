import { z } from "zod";

// Collector manifest — SPEC §7 (Tool Interfaces): a collector is a program
// plus a manifest declaring inputs, dirty-set depth, the recipe IDs it can
// evidence, and its tool version. Adding a collector is adding a manifest,
// not touching the pipeline. The full format firms up in M1 (C1); the ports
// in @rampscan/core need the type now.

export const CollectorManifest = z.object({
  name: z.string(), // "repo-facts" | "gitleaks" | "syft" | ...
  toolVersion: z.string(), // participates in cache keys and bundle provenance
  recipes: z.array(z.string()), // recipe IDs this collector can evidence
  inputs: z.array(z.string()).optional(), // artifacts consumed from earlier collectors
  outputs: z.array(z.string()).optional(), // artifacts produced (e.g. "sbom.cdx.json")
  dirtySetDepth: z.number().int().min(0).optional(), // blast-radius depth for incremental scans
});
export type CollectorManifest = z.infer<typeof CollectorManifest>;
