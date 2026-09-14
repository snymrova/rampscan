import { z } from "zod";

// The SBOM's declared dependency graph (S1-2, docs/PLAN-SOUNDNESS.md §5-S1):
// CycloneDX `dependencies[].dependsOn`, keyed by npm package name so it joins
// the code graph's dependency nodes, which are npm packages and nothing else.
//
// This graph is a PRESENCE-PROVER ONLY. A package manifest says "lodash
// declares minimist", which is enough to continue a walk that already
// arrived at lodash — and nothing more. It is partial by measurement (34 of
// 173 components carry outgoing edges in this repository's own SBOM), so the
// absence of a chain says nothing, and no caller may read "no SBOM path" as
// "unreachable". `dependencyReachability` upgrades `unknown` to `true`
// through these edges and never downgrades anything.
//
// Keyed by package NAME, not by versioned purl, because that is how the code
// graph's dependency nodes and the OSV join are keyed. Two versions of one
// package therefore collapse to one vertex (this repository's SBOM carries
// postcss@8.4.31 under next and postcss@8.5.26 under vite — 34 edge-carrying
// components by purl, 33 by name), which over-approximates in the one
// direction the over-approximate walk already errs: a chain to ANY version
// makes the advisory count.

const CycloneDxDependencies = z.looseObject({
  components: z
    .array(
      z.looseObject({
        "bom-ref": z.string().optional(),
        name: z.string(),
        purl: z.string().optional(),
      }),
    )
    .optional(),
  dependencies: z
    .array(z.looseObject({ ref: z.string(), dependsOn: z.array(z.string()).optional() }))
    .optional(),
});

export interface SbomDependencyGraph {
  /** npm package name → the npm package names its manifest declares (dependsOn) */
  dependsOn: ReadonlyMap<string, readonly string[]>;
  /** every component in the document, npm or not — what the SBOM was over */
  component_count: number;
  /** npm components that carry at least one outgoing edge — the measure of how partial the graph is */
  components_with_edges: number;
  /** npm → npm dependsOn edges kept */
  edge_count: number;
}

const NPM_PURL = "pkg:npm/";

/**
 * Read the dependsOn edge set out of a CycloneDX document, npm components
 * only: the code graph's dependency nodes are npm packages, so an edge from
 * any other ecosystem could never join the walk and a name collision across
 * ecosystems must not be allowed to look like one.
 */
export function sbomDependencyGraph(doc: unknown): SbomDependencyGraph {
  const parsed = CycloneDxDependencies.parse(doc);
  const nameOfRef = new Map<string, string>();
  for (const c of parsed.components ?? []) {
    const purl = c.purl ?? (c["bom-ref"]?.startsWith("pkg:") ? c["bom-ref"] : undefined);
    if (purl === undefined || !purl.startsWith(NPM_PURL)) continue;
    if (c["bom-ref"] !== undefined) nameOfRef.set(c["bom-ref"], c.name);
  }

  const dependsOn = new Map<string, string[]>();
  let edgeCount = 0;
  for (const d of parsed.dependencies ?? []) {
    const from = nameOfRef.get(d.ref);
    if (from === undefined) continue;
    for (const ref of d.dependsOn ?? []) {
      const to = nameOfRef.get(ref);
      if (to === undefined || to === from) continue;
      const list = dependsOn.get(from);
      if (list === undefined) dependsOn.set(from, [to]);
      else if (!list.includes(to)) list.push(to);
      else continue;
      edgeCount += 1;
    }
  }

  return {
    dependsOn,
    component_count: parsed.components?.length ?? 0,
    components_with_edges: dependsOn.size,
    edge_count: edgeCount,
  };
}
