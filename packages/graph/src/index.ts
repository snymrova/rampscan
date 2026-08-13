import ts from "typescript";

export * from "./extract.js";
export * from "./entrypoints.js";
export * from "./config.js";
export * from "./db.js";
export * from "./query.js";

/** extractor version — participates in cache keys and bundle provenance */
export const GRAPH_VERSION = "0.1.0";

/** tool version string for manifests/bundles: extractor + the parser it rides on */
export function graphToolVersion(): string {
  return `${GRAPH_VERSION}+ts${ts.version}`;
}
