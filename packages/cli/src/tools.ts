import type { Collector } from "@rampscan/core";
import type { PipelineRecipe } from "@rampscan/schema";
import type { ToolManifest } from "@rampscan/collectors";

// `rampscan tools` (plan J5) — the static map: recipe ↔ collector ↔ tool ↔
// pinned image, and the artifact flow between collectors.
//
// Three questions, three answers, and they are deliberately different tools:
//
//   doctor   can it run?          probes this host right now
//   tools    who feeds whom?      this file — pure derivation over the recipe
//                                 catalog, the collector manifests and
//                                 tools.json, with no host probing at all
//   /runs    what happened?       the signed run record of a scan
//
// Nothing here touches the network, the ledger, or the host: given the same
// three inputs it prints the same map on any machine. That is what makes it
// usable as the answer to "why is this recipe unevidenced" BEFORE a scan —
// a recipe whose collector nobody registered can be seen here without
// running anything.

export interface ToolMapTool {
  name: string;
  /** the version tools.json pins, when it pins one */
  pinnedVersion?: string;
  /** the pinned image a missing binary would run from */
  image?: string;
  /** collectors that ask resolveTool() for this name */
  collectors: string[];
}

export interface ToolMapCollector {
  name: string;
  /** declared in the manifest; empty means pure — reads the repo itself */
  tools: string[];
  /** recipes this collector's manifest says it can evidence */
  recipes: string[];
  /** artifacts consumed from earlier collectors, with who produces each */
  consumes: Array<{ artifact: string; producedBy: string[] }>;
  produces: string[];
  /** manifest-declared recipes the catalog does not hold */
  unknownRecipes: string[];
}

export interface ToolMapRecipe {
  id: string;
  /** the collector the recipe's `collection.collector` names */
  collector: string;
  /** false when no registered collector answers to that name */
  collectorRegistered: boolean;
  /**
   * The collector names this recipe in its manifest too. A recipe pointing at
   * a collector that does not claim it is a one-way link — the scan joins on
   * the recipe's side, so it still runs, but the pair disagrees and that is
   * worth saying out loud rather than rendering as agreement.
   */
  claimedByCollector: boolean;
  /** tools the evidencing collector itself spawns */
  tools: string[];
  /**
   * Tools this recipe's verdict rests on WITHOUT its collector ever spawning
   * one — reached through the artifacts it consumes. `no-reachable-dangerous-code`
   * is evidenced by `sast-reachability`, which spawns nothing and joins
   * semgrep's results against the graph: printing that row as "pure — no
   * external tool" would be true of the collector and a lie about the
   * evidence, which is the exact confusion this command exists to remove.
   */
  viaInputs: Array<{ tool: string; through: string }>;
}

export interface ToolMap {
  recipes: ToolMapRecipe[];
  collectors: ToolMapCollector[];
  tools: ToolMapTool[];
  /** tools.json pins nobody asks for — dead weight, and a pin that rots unnoticed */
  orphanPins: string[];
  /** an input artifact no registered collector produces: the chain is broken here */
  unproducibleInputs: Array<{ collector: string; artifact: string }>;
}

/**
 * The map, derived. Every list is sorted so two runs on two machines print
 * byte-identical output — this is a document people diff.
 */
export function buildToolMap(input: {
  recipes: PipelineRecipe[];
  collectors: Collector[];
  toolManifest: ToolManifest;
}): ToolMap {
  const byName = new Map(input.collectors.map((c) => [c.manifest.name, c]));
  const producerOf = new Map<string, string[]>();
  for (const c of input.collectors) {
    for (const out of c.manifest.outputs ?? []) {
      producerOf.set(out, [...(producerOf.get(out) ?? []), c.manifest.name].sort());
    }
  }
  const catalogIds = new Set(input.recipes.map((r) => r.id));

  /**
   * Every tool reachable from a collector through the artifacts it consumes,
   * transitively — `seen` both terminates a cycle and keeps a diamond
   * (two inputs, one shared producer) from listing the same tool twice.
   */
  function upstreamTools(name: string, seen = new Set<string>()): Array<{ tool: string; through: string }> {
    if (seen.has(name)) return [];
    seen.add(name);
    const collector = byName.get(name);
    if (!collector) return [];
    const out: Array<{ tool: string; through: string }> = [];
    for (const artifact of collector.manifest.inputs ?? []) {
      for (const producer of producerOf.get(artifact) ?? []) {
        if (seen.has(producer)) continue;
        for (const tool of byName.get(producer)?.manifest.tools ?? []) {
          out.push({ tool, through: producer });
        }
        out.push(...upstreamTools(producer, seen));
      }
    }
    return out.sort((a, b) => a.tool.localeCompare(b.tool));
  }

  const recipes: ToolMapRecipe[] = input.recipes
    .map((r) => {
      const collector = r.collection.collector;
      const registered = byName.get(collector);
      return {
        id: r.id,
        collector,
        collectorRegistered: registered !== undefined,
        claimedByCollector: registered?.manifest.recipes.includes(r.id) ?? false,
        tools: [...(registered?.manifest.tools ?? [])].sort(),
        viaInputs: upstreamTools(collector),
      };
    })
    .sort((a, b) => a.id.localeCompare(b.id));

  const collectors: ToolMapCollector[] = input.collectors
    .map((c) => ({
      name: c.manifest.name,
      tools: [...(c.manifest.tools ?? [])].sort(),
      recipes: [...c.manifest.recipes].sort(),
      consumes: [...(c.manifest.inputs ?? [])]
        .sort()
        .map((artifact) => ({ artifact, producedBy: producerOf.get(artifact) ?? [] })),
      produces: [...(c.manifest.outputs ?? [])].sort(),
      unknownRecipes: c.manifest.recipes.filter((id) => !catalogIds.has(id)).sort(),
    }))
    .sort((a, b) => a.name.localeCompare(b.name));

  const askedFor = new Map<string, string[]>();
  for (const c of input.collectors) {
    for (const t of c.manifest.tools ?? []) {
      askedFor.set(t, [...(askedFor.get(t) ?? []), c.manifest.name].sort());
    }
  }
  const tools: ToolMapTool[] = [...askedFor.keys()]
    .sort()
    .map((name) => {
      const spec = input.toolManifest[name];
      return {
        name,
        ...(spec ? { pinnedVersion: spec.version, image: spec.image } : {}),
        collectors: askedFor.get(name) ?? [],
      };
    });

  return {
    recipes,
    collectors,
    tools,
    orphanPins: Object.keys(input.toolManifest)
      .filter((name) => !askedFor.has(name))
      .sort(),
    unproducibleInputs: collectors
      .flatMap((c) =>
        c.consumes
          .filter((i) => i.producedBy.length === 0)
          .map((i) => ({ collector: c.name, artifact: i.artifact })),
      )
      .sort((a, b) => a.collector.localeCompare(b.collector) || a.artifact.localeCompare(b.artifact)),
  };
}

/**
 * The map as text. Three sections in the order a reader asks them: what
 * answers each requirement, what each collector needs, and what each tool
 * pin is. The problems are not a footnote — a broken link is the reason a
 * board cell will read unevidenced, so it renders where the link would be.
 */
export function renderToolMap(map: ToolMap, useColor: boolean): string {
  const paint = (code: string, s: string) => (useColor ? `[${code}m${s}[0m` : s);
  const dim = (s: string) => paint("2", s);
  const red = (s: string) => paint("31", s);
  const lines: string[] = [];

  lines.push(
    dim(
      "the static map — who feeds whom. Nothing here was probed on this host: `pnpm doctor` answers whether a tool can run, `/runs` answers what actually ran.",
    ),
    "",
  );

  lines.push(`RECIPES (${map.recipes.length})`);
  for (const r of map.recipes) {
    const via = r.viaInputs.map((v) => `${v.tool} (via ${v.through})`);
    const tool = !r.collectorRegistered
      ? ""
      : [...r.tools, ...via].length > 0
        ? [...r.tools, ...via].join(", ")
        : dim("pure — no external tool");
    const note = !r.collectorRegistered
      ? red("  ← no collector registered under that name; this recipe can only read unevidenced")
      : !r.claimedByCollector
        ? red("  ← the collector's manifest does not list this recipe")
        : "";
    lines.push(`  ${r.id.padEnd(36)} ${r.collector.padEnd(20)} ${tool}${note}`);
  }
  lines.push("");

  lines.push(`COLLECTORS (${map.collectors.length})`);
  for (const c of map.collectors) {
    lines.push(
      `  ${c.name.padEnd(20)} ${
        c.tools.length > 0 ? c.tools.join(", ") : dim("pure — reads the repo itself")
      }`,
    );
    if (c.recipes.length > 0) lines.push(dim(`      evidences  ${c.recipes.join(", ")}`));
    else lines.push(dim("      evidences  (none — producer only; its output is another collector's input)"));
    for (const i of c.consumes) {
      lines.push(
        i.producedBy.length > 0
          ? dim(`      consumes   ${i.artifact} ← ${i.producedBy.join(", ")}`)
          : `      consumes   ${i.artifact} ${red("← nothing registered produces this")}`,
      );
    }
    if (c.produces.length > 0) lines.push(dim(`      produces   ${c.produces.join(", ")}`));
    for (const id of c.unknownRecipes) {
      lines.push(`      ${red(`declares recipe "${id}", which the catalog does not hold`)}`);
    }
  }
  lines.push("");

  lines.push(`TOOLS (${map.tools.length})`);
  for (const t of map.tools) {
    lines.push(
      `  ${t.name.padEnd(14)} ${
        t.pinnedVersion
          ? `${t.pinnedVersion.padEnd(10)} ${dim(t.image ?? "")}`
          : red("no pin in tools.json — only a binary already on PATH can satisfy this")
      }`,
    );
    lines.push(dim(`      asked for by ${t.collectors.join(", ")}`));
  }
  for (const name of map.orphanPins) {
    lines.push(`  ${name.padEnd(14)} ${dim("pinned in tools.json, asked for by no collector")}`);
  }

  return lines.join("\n");
}

/** the problems the map found, as one list — the CLI's exit code reads this */
export function toolMapProblems(map: ToolMap): string[] {
  const problems: string[] = [];
  for (const r of map.recipes) {
    if (!r.collectorRegistered) {
      problems.push(
        `recipe "${r.id}" names collector "${r.collector}", which is not registered — the recipe can only read unevidenced`,
      );
    } else if (!r.claimedByCollector) {
      problems.push(
        `recipe "${r.id}" names collector "${r.collector}", whose manifest does not list it`,
      );
    }
  }
  for (const c of map.collectors) {
    for (const id of c.unknownRecipes) {
      problems.push(`collector "${c.name}" declares recipe "${id}", which the catalog does not hold`);
    }
  }
  for (const u of map.unproducibleInputs) {
    problems.push(
      `collector "${u.collector}" consumes "${u.artifact}", which no registered collector produces`,
    );
  }
  for (const t of map.tools) {
    if (t.pinnedVersion === undefined) {
      problems.push(
        `tool "${t.name}" has no pin in tools.json — with no binary on PATH there is no image to fall back to`,
      );
    }
  }
  return problems;
}
