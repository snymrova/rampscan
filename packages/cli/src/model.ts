import type { LedgerEntry, RegisterState } from "@rampscan/core";
import type { DatasetClient } from "@rampscan/dataset";
import { createLocalLedger } from "@rampscan/ledger";
import { foldEntries } from "@rampscan/projector";
import { ContractRule, canonicalJson, isEvidenceBundle } from "@rampscan/schema";
import type { Automatable, Cadence, ClaimBasis, PipelineRecipe } from "@rampscan/schema";
import { loadRecipes } from "./recipes.js";
import { buildToolMap } from "./tools.js";
import type { ToolMap } from "./tools.js";

// The repo model (plan L2): ONE canonical-JSON artifact that unifies what this
// system already knows about a scanned world — repos, recipes, controls, KSIs,
// collectors, tools, the declared architecture contract, and the graph each
// gated verdict was walked over — as typed nodes and typed links.
//
// It is deliberately NOT a graph platform. The node-kind list below is closed,
// the link-kind list below is closed, and adding to either is a change to this
// file with a reason, not a config value. `code-review-graph` owns the general
// navigation-graph space; what this artifact carries is the joins that only
// rampscan can make.
//
// Three properties do the load-bearing work:
//
//   1. IT IS A LEDGER DERIVATIVE, NOT A REPO READ. Every node and link here
//      comes from signed statements, the recipe catalog, the pinned crosswalk
//      and the collector manifests — never from the scanned repo's working
//      tree. That is why the contract rules are read from the SIGNED
//      `ClaimBasis.contract_rules` (L1) rather than from today's
//      `rampscan.config.json`: the model states the contract the evidence was
//      checked against, and a model that read the file instead would describe
//      a contract no verdict on the board ever saw.
//   2. IT CARRIES NO CLOCK. There is no `generated_at` field, and nothing here
//      reads a wall clock — so the same ledger always yields byte-identical
//      bytes, and `rampscan model --json` reproduces the artifact a scan
//      attested. The artifact is timeless; its ATTESTATION is dated, by the
//      run record whose subject names it.
//   3. EVERY LINK'S ENDPOINTS ARE NODES. A recipe naming a collector nobody
//      registered produces no dangling link — it produces a stated problem.
//      A model whose links point at nothing would be a drawing of a world that
//      does not exist, which is the failure this shape exists to avoid.

/** the artifact's name — the subject name a run record attests, and the viewer's family key */
export const REPO_MODEL_ARTIFACT = "repo-model.json";

/**
 * The shape version. Bumped when a node or link kind is added or removed, so a
 * reader of an old artifact knows which closed list it was written against.
 */
export const REPO_MODEL_VERSION = 1;

// ---------------------------------------------------------------------------
// nodes — the closed list
// ---------------------------------------------------------------------------

export interface RepoNode {
  kind: "repo";
  /** `repo:<path>` */
  id: string;
  repo: string;
}

export interface RecipeNode {
  kind: "recipe";
  /** `recipe:<id>` */
  id: string;
  recipeId: string;
  /**
   * False when the ledger holds a cell for this recipe but the catalog no
   * longer does. The node exists either way — nothing recorded ever hides —
   * and the catalog-only fields below are simply absent, never guessed.
   */
  inCatalog: boolean;
  cadence?: Cadence;
  automatable?: Automatable;
}

export interface ControlNode {
  kind: "control";
  /** `control:<id>` */
  id: string;
  controlId: string;
}

export interface KsiNode {
  kind: "ksi";
  /** `ksi:<id>` */
  id: string;
  ksiId: string;
}

export interface CollectorNode {
  kind: "collector";
  /** `collector:<name>` */
  id: string;
  collector: string;
  /** spawns no external tool — it reads the repo or an earlier collector's artifact */
  pure: boolean;
}

export interface ToolNode {
  kind: "tool";
  /** `tool:<name>` */
  id: string;
  tool: string;
  pinnedVersion?: string;
  image?: string;
}

export interface ContractRuleNode {
  kind: "contract-rule";
  /** `rule:<repo>:<ruleId>` — rule ids are unique within one repo's contract, not across repos */
  id: string;
  ruleId: string;
  ruleKind: "route-auth" | "boundary";
  repo: string;
  /**
   * The rule exactly as the gate signed it: the canonical JSON of the
   * declaration, lifted verbatim from `ClaimBasis.contract_rules`. Not a
   * paraphrase and not a re-serialization of today's config — the reader is
   * deciding whether a verdict matches what the repository said about itself,
   * and only the signed text can answer that.
   */
  declaration: string;
}

export interface GraphNode {
  kind: "graph";
  /** `graph:<repo>` */
  id: string;
  repo: string;
  commit: string;
  extractorVersion: string;
  nodeCount: number;
  edgeCount: number;
  /** edges matched by name rather than lexically resolved */
  inferredEdgeCount: number;
  entrypoints: string[];
  entrypointSource: string;
  routeRoots?: number;
  /** the live claim whose signed basis this summary was lifted from */
  from: { recipeId: string; bundleDigest: string };
}

export type RepoModelNode =
  | RepoNode
  | RecipeNode
  | ControlNode
  | KsiNode
  | CollectorNode
  | ToolNode
  | ContractRuleNode
  | GraphNode;

export type RepoModelNodeKind = RepoModelNode["kind"];

// ---------------------------------------------------------------------------
// links — the closed list
// ---------------------------------------------------------------------------

/**
 * `state` is the board cell (repo × recipe) and is the only link carrying a
 * computed verdict; everything else is structure. It restates the fold's own
 * register row rather than recomputing anything, so the model and the board
 * cannot come to different conclusions about the same cell.
 */
export interface StateLink {
  kind: "state";
  from: string; // repo node
  to: string; // recipe node
  state: RegisterState;
  /** the live bundle behind the state, when the cell has one */
  bundleDigest?: string;
}

export interface RepoModelEdge {
  kind:
    | "maps-to-ksi" // recipe → ksi (the recipe's own declaration)
    | "maps-to-control" // recipe → control (the recipe's own declaration)
    | "ksi-control" // ksi → control (the pinned crosswalk)
    | "evidenced-by" // recipe → collector (the catalog's collector reference)
    | "spawns" // collector → tool (the collector manifest)
    | "declares" // repo → contract-rule (the signed basis)
    | "checked-by" // contract-rule → recipe (which gate evaluated the rule)
    | "walked"; // repo → graph
  from: string;
  to: string;
}

/** collector → collector, through the artifact the first produces and the second eats */
export interface ConsumesLink {
  kind: "consumes";
  from: string; // consuming collector
  to: string; // producing collector
  artifact: string;
}

export type RepoModelLink = StateLink | RepoModelEdge | ConsumesLink;

export type RepoModelLinkKind = RepoModelLink["kind"];

export interface RepoModel {
  version: number;
  /** the crosswalk pin every `ksi-control` link was read from */
  dataset_version: string;
  nodes: RepoModelNode[];
  links: RepoModelLink[];
  /**
   * What this model could not state, said out loud rather than dropped: a
   * recipe whose collector nobody registered, a signed rule that will not
   * parse, live evidence from two scans disagreeing about the graph. Empty is
   * the healthy case and an empty array is still emitted, so a reader never
   * has to decide whether "absent" meant "clean" or "not checked".
   */
  problems: string[];
}

// ---------------------------------------------------------------------------
// the build
// ---------------------------------------------------------------------------

export interface RepoModelInput {
  /**
   * The ledger's statements. The fold happens HERE rather than being passed
   * in, so the registers and the signed bases can never describe two different
   * ledgers — and the bases are why the entries are needed at all: the
   * projection carries digests, not predicates, and the contract rules and the
   * graph shape live only inside the signed `basis`.
   */
  entries: LedgerEntry[];
  recipes: PipelineRecipe[];
  dataset: DatasetClient;
  toolMap: ToolMap;
}

const repoId = (repo: string): string => `repo:${repo}`;
const recipeNodeId = (id: string): string => `recipe:${id}`;
const controlId = (id: string): string => `control:${id}`;
const ksiId = (id: string): string => `ksi:${id}`;
const collectorId = (name: string): string => `collector:${name}`;
const toolId = (name: string): string => `tool:${name}`;
const ruleNodeId = (repo: string, rule: string): string => `rule:${repo}:${rule}`;
const graphId = (repo: string): string => `graph:${repo}`;

/**
 * The live claim bases for one repo, newest first. "Live" is the fold's own
 * word: the register row's `bundleDigest` is the bundle the board is standing
 * on, so a basis lifted from anywhere else would describe a walk no cell shows.
 */
interface LiveBasis {
  recipeId: string;
  digest: string;
  timestamp: string;
  basis: ClaimBasis;
}

export function buildRepoModel(input: RepoModelInput): RepoModel {
  // The fold instant comes from the ledger's own newest statement rather than
  // a clock: nothing in this model reads it, and a wall clock in a function
  // whose whole contract is "same ledger → same bytes" is a bug waiting for a
  // second scan to expose it.
  const foldInstant =
    [...input.entries]
      .map((e) => e.bundle.predicate.timestamp)
      .sort()
      .at(-1) ?? "1970-01-01T00:00:00.000Z";
  const projection = foldEntries(input.entries, foldInstant, { recipes: input.recipes });

  const byDigest = new Map(input.entries.map((e) => [e.digest, e]));
  const catalogById = new Map(input.recipes.map((r) => [r.id, r]));
  const registeredCollectors = new Set(input.toolMap.collectors.map((c) => c.name));

  const nodes = new Map<string, RepoModelNode>();
  const links: RepoModelLink[] = [];
  const problems: string[] = [];
  const add = (node: RepoModelNode): void => {
    if (!nodes.has(node.id)) nodes.set(node.id, node);
  };

  // --- collectors and tools: the provenance half, straight off J5's map -----
  for (const collector of input.toolMap.collectors) {
    add({
      kind: "collector",
      id: collectorId(collector.name),
      collector: collector.name,
      pure: collector.tools.length === 0,
    });
  }
  for (const tool of input.toolMap.tools) {
    const node: ToolNode = { kind: "tool", id: toolId(tool.name), tool: tool.name };
    if (tool.pinnedVersion !== undefined) node.pinnedVersion = tool.pinnedVersion;
    if (tool.image !== undefined) node.image = tool.image;
    add(node);
  }
  for (const collector of input.toolMap.collectors) {
    for (const tool of collector.tools) {
      links.push({
        kind: "spawns",
        from: collectorId(collector.name),
        to: toolId(tool),
      });
    }
    for (const input_ of collector.consumes) {
      for (const producer of input_.producedBy) {
        links.push({
          kind: "consumes",
          from: collectorId(collector.name),
          to: collectorId(producer),
          artifact: input_.artifact,
        });
      }
    }
  }

  // --- recipes, controls, KSIs, and every board cell -----------------------
  // Driven by the REGISTERS, not by the catalog: the register is the join that
  // already decided which cells exist, and a model built from the catalog
  // alone would silently drop a recipe that left it while its evidence lives.
  const recipeIds = new Set<string>([
    ...input.recipes.map((r) => r.id),
    ...projection.registers.map((row) => row.recipeId),
  ]);
  const ksiIds = new Set<string>();
  const controlIds = new Set<string>();

  for (const id of [...recipeIds].sort()) {
    const recipe = catalogById.get(id);
    const node: RecipeNode = {
      kind: "recipe",
      id: recipeNodeId(id),
      recipeId: id,
      inCatalog: recipe !== undefined,
    };
    if (recipe?.cadence !== undefined) node.cadence = recipe.cadence;
    if (recipe?.automatable !== undefined) node.automatable = recipe.automatable;
    add(node);
  }

  for (const row of projection.registers) {
    add({ kind: "repo", id: repoId(row.repo), repo: row.repo });
    const link: StateLink = {
      kind: "state",
      from: repoId(row.repo),
      to: recipeNodeId(row.recipeId),
      state: row.state,
    };
    if (row.bundleDigest !== undefined) link.bundleDigest = row.bundleDigest;
    links.push(link);
    for (const id of row.ksiIds) ksiIds.add(id);
    for (const id of row.controlIds) controlIds.add(id);
  }
  // a catalog recipe nobody has scanned yet still maps to its controls
  for (const recipe of input.recipes) {
    for (const id of recipe.ksi_ids) ksiIds.add(id);
    for (const id of recipe.control_ids) controlIds.add(id);
  }

  for (const id of [...ksiIds].sort()) add({ kind: "ksi", id: ksiId(id), ksiId: id });
  for (const id of [...controlIds].sort()) {
    add({ kind: "control", id: controlId(id), controlId: id });
  }

  // recipe → ksi / control, from the recipe's own declaration where the
  // catalog holds it and from the register row (which falls back to the live
  // bundle's signed ids) where it does not
  const mappingByRecipe = new Map<string, { ksis: Set<string>; controls: Set<string> }>();
  const mappingFor = (id: string) => {
    let entry = mappingByRecipe.get(id);
    if (!entry) {
      entry = { ksis: new Set(), controls: new Set() };
      mappingByRecipe.set(id, entry);
    }
    return entry;
  };
  for (const recipe of input.recipes) {
    const m = mappingFor(recipe.id);
    for (const id of recipe.ksi_ids) m.ksis.add(id);
    for (const id of recipe.control_ids) m.controls.add(id);
  }
  for (const row of projection.registers) {
    const m = mappingFor(row.recipeId);
    for (const id of row.ksiIds) m.ksis.add(id);
    for (const id of row.controlIds) m.controls.add(id);
  }
  for (const [id, m] of [...mappingByRecipe].sort(([a], [b]) => a.localeCompare(b))) {
    for (const ksi of [...m.ksis].sort()) {
      links.push({ kind: "maps-to-ksi", from: recipeNodeId(id), to: ksiId(ksi) });
    }
    for (const control of [...m.controls].sort()) {
      links.push({ kind: "maps-to-control", from: recipeNodeId(id), to: controlId(control) });
    }
  }

  // ksi → control, from the pinned crosswalk — RESTRICTED to controls this
  // model already holds. A KSI reaches controls no recipe here touches, and
  // pulling them in would grow the artifact without telling the reader
  // anything about this world.
  for (const ksi of [...ksiIds].sort()) {
    for (const control of input.dataset.controlsFor(ksi)) {
      if (!controlIds.has(control)) continue;
      links.push({ kind: "ksi-control", from: ksiId(ksi), to: controlId(control) });
    }
  }

  // recipe → collector. Emitted only when the named collector is registered:
  // a link to a node that does not exist would be a drawing of a world that
  // does not exist, so the broken link becomes a stated problem instead.
  for (const recipe of input.toolMap.recipes) {
    if (!registeredCollectors.has(recipe.collector)) {
      problems.push(
        `recipe "${recipe.id}" names collector "${recipe.collector}", which is not registered — no provenance link could be drawn for it`,
      );
      continue;
    }
    links.push({
      kind: "evidenced-by",
      from: recipeNodeId(recipe.id),
      to: collectorId(recipe.collector),
    });
  }

  // --- the signed bases: the contract, and the graph each walk was over -----
  const basesByRepo = new Map<string, LiveBasis[]>();
  for (const row of projection.registers) {
    if (row.bundleDigest === undefined) continue;
    const entry = byDigest.get(row.bundleDigest);
    if (!entry || !isEvidenceBundle(entry.bundle)) continue;
    const basis = entry.bundle.predicate.basis;
    if (!basis) continue;
    basesByRepo.set(row.repo, [
      ...(basesByRepo.get(row.repo) ?? []),
      {
        recipeId: row.recipeId,
        digest: row.bundleDigest,
        timestamp: entry.bundle.predicate.timestamp,
        basis,
      },
    ]);
  }

  for (const [repo, bases] of [...basesByRepo].sort(([a], [b]) => a.localeCompare(b))) {
    // the declared contract, as the gates signed it
    for (const live of [...bases].sort((a, b) => a.recipeId.localeCompare(b.recipeId))) {
      for (const declaration of live.basis.contract_rules ?? []) {
        const parsed = ContractRule.safeParse(safeJson(declaration));
        if (!parsed.success) {
          problems.push(
            `a contract rule signed into ${live.recipeId}'s basis (bundle ${live.digest.slice(0, 12)}…) does not parse as a rule — it is carried in the ledger and is not rendered here`,
          );
          continue;
        }
        const rule = parsed.data;
        const id = ruleNodeId(repo, rule.id);
        if (!nodes.has(id)) {
          add({
            kind: "contract-rule",
            id,
            ruleId: rule.id,
            ruleKind: rule.kind,
            repo,
            // re-canonicalized from the PARSED rule, so the declaration a
            // reader sees is exactly the text identity was keyed on
            declaration: canonicalJson(rule),
          });
          links.push({ kind: "declares", from: repoId(repo), to: id });
        }
        links.push({ kind: "checked-by", from: id, to: recipeNodeId(live.recipeId) });
      }
    }

    // the graph the gated verdicts were walked over. Live evidence can span
    // scans, so more than one basis may describe a graph; the newest wins and
    // a disagreement is STATED rather than averaged away.
    const withGraph = bases
      .filter((b) => b.basis.graph !== undefined)
      .sort((a, b) => b.timestamp.localeCompare(a.timestamp) || a.recipeId.localeCompare(b.recipeId));
    const newest = withGraph[0];
    if (newest?.basis.graph) {
      const g = newest.basis.graph;
      const node: GraphNode = {
        kind: "graph",
        id: graphId(repo),
        repo,
        commit: g.commit,
        extractorVersion: g.extractor_version,
        nodeCount: g.node_count,
        edgeCount: g.edge_count,
        inferredEdgeCount: g.inferred_edge_count,
        entrypoints: [...newest.basis.entrypoints].sort(),
        entrypointSource: newest.basis.entrypoint_source,
        from: { recipeId: newest.recipeId, bundleDigest: newest.digest },
      };
      if (newest.basis.route_roots !== undefined) node.routeRoots = newest.basis.route_roots;
      add(node);
      links.push({ kind: "walked", from: repoId(repo), to: node.id });

      const disagreeing = withGraph.filter(
        (b) => b.basis.graph!.commit !== g.commit || b.basis.graph!.node_count !== g.node_count,
      );
      if (disagreeing.length > 0) {
        problems.push(
          `${repo}: live evidence spans more than one scan — ${disagreeing
            .map((b) => b.recipeId)
            .sort()
            .join(", ")} rest on a different graph than the newest (${newest.recipeId}), which is the one summarized here`,
        );
      }
    }
  }

  const sortedNodes = [...nodes.values()].sort((a, b) => a.id.localeCompare(b.id));
  const sortedLinks = [...links].sort(
    (a, b) =>
      a.kind.localeCompare(b.kind) || a.from.localeCompare(b.from) || a.to.localeCompare(b.to),
  );

  // the invariant, checked rather than trusted: no link may point at a node
  // this model does not hold
  for (const link of sortedLinks) {
    for (const end of [link.from, link.to]) {
      if (!nodes.has(end)) {
        problems.push(`internal: ${link.kind} link points at "${end}", which is not a node here`);
      }
    }
  }

  return {
    version: REPO_MODEL_VERSION,
    dataset_version: input.dataset.version(),
    nodes: sortedNodes,
    links: sortedLinks,
    problems: [...new Set(problems)].sort(),
  };
}

function safeJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}

/** the artifact's bytes: canonical JSON, newline-terminated — one serialization, everywhere */
export function serializeRepoModel(model: RepoModel): string {
  return canonicalJson(model) + "\n";
}

// ---------------------------------------------------------------------------
// the one hand
// ---------------------------------------------------------------------------

export interface RepoModelOptions {
  ledgerDir: string;
  recipesDir: string;
  dataset: DatasetClient;
  /** the registered collectors, for the provenance half (defaults to none) */
  toolMap: ToolMap;
}

/**
 * The model from a ledger on disk, with no scan — the same posture as
 * `rampscan tools`: this is a derivation, so it needs no run to be current,
 * and `rampscan model` and `scan()` both end up at `buildRepoModel`.
 */
export async function computeRepoModel(options: RepoModelOptions): Promise<RepoModel> {
  const entries = await createLocalLedger(options.ledgerDir).list();
  const recipes = await loadRecipes(options.recipesDir);
  return buildRepoModel({
    entries,
    recipes,
    dataset: options.dataset,
    toolMap: options.toolMap,
  });
}

/**
 * The model as text — the shape at a glance, for a terminal. The JSON is the
 * artifact (`--json`, byte-identical to what a scan attested); this is the
 * reading of it, and it counts nothing it does not list.
 */
export function renderRepoModel(model: RepoModel, useColor: boolean): string {
  const paint = (code: string, s: string) => (useColor ? `[${code}m${s}[0m` : s);
  const dim = (s: string) => paint("2", s);
  const red = (s: string) => paint("31", s);
  const lines: string[] = [];

  lines.push(
    dim(
      `repo model v${model.version} — a derivation of the ledger, the recipe catalog and the pinned crosswalk ${model.dataset_version}. No clock: the same ledger always yields the same bytes (\`rampscan model --json\`).`,
    ),
    "",
  );

  const byKind = new Map<string, RepoModelNode[]>();
  for (const node of model.nodes) {
    byKind.set(node.kind, [...(byKind.get(node.kind) ?? []), node]);
  }
  lines.push(`NODES (${model.nodes.length})`);
  for (const [kind, list] of [...byKind].sort(([a], [b]) => a.localeCompare(b))) {
    lines.push(`  ${kind.padEnd(16)} ${list.length}`);
  }
  lines.push("");

  const linkCounts = new Map<string, number>();
  for (const link of model.links) {
    linkCounts.set(link.kind, (linkCounts.get(link.kind) ?? 0) + 1);
  }
  lines.push(`LINKS (${model.links.length})`);
  for (const [kind, count] of [...linkCounts].sort(([a], [b]) => a.localeCompare(b))) {
    lines.push(`  ${kind.padEnd(16)} ${count}`);
  }
  lines.push("");

  const repos = model.nodes.filter((n): n is RepoNode => n.kind === "repo");
  lines.push(`REPOS (${repos.length})`);
  for (const repo of repos) {
    lines.push(`  ${repo.repo}`);
    const states = model.links.filter(
      (l): l is StateLink => l.kind === "state" && l.from === repo.id,
    );
    const tally = new Map<string, number>();
    for (const s of states) tally.set(s.state, (tally.get(s.state) ?? 0) + 1);
    lines.push(
      dim(
        `      ${states.length} cell(s): ${[...tally]
          .sort(([a], [b]) => a.localeCompare(b))
          .map(([state, n]) => `${n} ${state}`)
          .join(", ")}`,
      ),
    );
    const rules = model.nodes.filter(
      (n): n is ContractRuleNode => n.kind === "contract-rule" && n.repo === repo.repo,
    );
    lines.push(
      rules.length > 0
        ? dim(`      contract  ${rules.map((r) => `${r.ruleId} (${r.ruleKind})`).join(", ")}`)
        : dim("      contract  none declared in any live claim's basis"),
    );
    const graph = model.nodes.find(
      (n): n is GraphNode => n.kind === "graph" && n.repo === repo.repo,
    );
    lines.push(
      graph
        ? dim(
            `      graph     ${graph.nodeCount} nodes, ${graph.edgeCount} edges (${graph.inferredEdgeCount} name-inferred) @ ${graph.commit.slice(0, 12)} — from ${graph.from.recipeId}`,
          )
        : dim("      graph     no live claim here rests on a walk"),
    );
  }

  if (model.problems.length > 0) {
    lines.push("");
    lines.push(red(`PROBLEMS (${model.problems.length})`));
    for (const problem of model.problems) lines.push(`  - ${problem}`);
  }

  return lines.join("\n");
}
