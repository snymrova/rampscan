import ts from "typescript";

export * from "./extract.js";
export * from "./entrypoints.js";
export * from "./config.js";
export * from "./db.js";
export * from "./query.js";

/** extractor version — participates in cache keys and bundle provenance */
// 0.2.0: workspace-aware import resolution — monorepo package imports resolve
// to their entry SOURCE file instead of dead-ending on a dependency node (the
// self-scan exposed the dead end as a false not_affected in the SAST gate)
export const GRAPH_VERSION = "0.2.0";

/** tool version string for manifests/bundles: extractor + the parser it rides on */
export function graphToolVersion(): string {
  return `${GRAPH_VERSION}+ts${ts.version}`;
}
