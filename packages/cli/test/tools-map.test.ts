import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { allCollectors, loadToolManifest } from "@rampscan/collectors";
import type { Collector } from "@rampscan/core";
import type { PipelineRecipe } from "@rampscan/schema";
import { buildToolMap, renderToolMap, toolMapProblems } from "../src/tools.js";
import { loadRecipes } from "../src/recipes.js";

// `rampscan tools` (plan J5) — the static map. Two kinds of test here, and
// they answer different questions:
//
//   over the REAL catalog: is this repo's own wiring intact? A recipe naming
//     a collector nobody registers, or a collector eating an artifact nobody
//     produces, is a board cell that will read unevidenced for a reason no
//     scan can explain — and it is checkable without running anything.
//   over SYNTHETIC wiring: does the map actually notice when it is broken?
//     A checker that only ever sees a healthy repo is not a checker.

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "../../..");

async function realMap() {
  return buildToolMap({
    recipes: await loadRecipes(join(REPO_ROOT, "recipes/pipeline")),
    collectors: allCollectors,
    toolManifest: await loadToolManifest(),
  });
}

function fakeCollector(manifest: Partial<Collector["manifest"]> & { name: string }): Collector {
  return {
    manifest: { toolVersion: "1", recipes: [], ...manifest },
    collect: async () => {
      throw new Error("never runs — the map is pure derivation");
    },
  };
}

function fakeRecipe(id: string, collector: string): PipelineRecipe {
  return {
    id,
    ksi_ids: ["KSI-SCR-MIT"],
    control_ids: ["sa-11"],
    evidence: "e",
    collection: { kind: "pipeline", collector },
    expected_output: "o",
    assertions: [],
    cadence: "daily",
    automatable: "full",
    anchor: "commit",
  } as PipelineRecipe;
}

describe("the real wiring holds together", () => {
  it("every recipe in the catalog has a registered collector that claims it", async () => {
    const map = await realMap();
    const orphans = map.recipes.filter((r) => !r.collectorRegistered || !r.claimedByCollector);
    expect(orphans.map((r) => `${r.id} → ${r.collector}`)).toEqual([]);
  });

  it("every consumed artifact has a producer in the same collector set", async () => {
    const map = await realMap();
    expect(map.unproducibleInputs).toEqual([]);
  });

  it("every tool a collector asks for is pinned in tools.json", async () => {
    const map = await realMap();
    expect(map.tools.filter((t) => t.pinnedVersion === undefined).map((t) => t.name)).toEqual([]);
  });

  it("finds no problems at all — the map is green on this repo", async () => {
    expect(toolMapProblems(await realMap())).toEqual([]);
  });

  it("the flagship recipe names semgrep even though its collector spawns nothing", async () => {
    // this is the case the command exists for: sast-reachability is pure, so a
    // map built from `tools` alone would print "no external tool" over a
    // verdict semgrep produced
    const map = await realMap();
    const flagship = map.recipes.find((r) => r.id === "no-reachable-dangerous-code")!;
    expect(flagship.collector).toBe("sast-reachability");
    expect(flagship.tools).toEqual([]);
    expect(flagship.viaInputs).toEqual([{ tool: "semgrep", through: "semgrep" }]);
  });

  it("the advisory recipe reaches syft two artifacts upstream", async () => {
    const map = await realMap();
    const advisories = map.recipes.find((r) => r.id === "no-critical-reachable-advisories")!;
    expect(advisories.viaInputs.map((v) => v.tool)).toEqual(["osv-scanner", "syft"]);
  });

  it("the text map is sorted and stable — this is a document people diff", async () => {
    const map = await realMap();
    const once = renderToolMap(map, false);
    const twice = renderToolMap(await realMap(), false);
    expect(once).toBe(twice);
    expect(once).toContain("RECIPES (15)");
    expect(once).toContain("pure — no external tool");
  });
});

describe("the map notices when the wiring is broken", () => {
  it("a recipe pointing at an unregistered collector is named, not silently pure", () => {
    const map = buildToolMap({
      recipes: [fakeRecipe("orphan", "ghost")],
      collectors: [fakeCollector({ name: "real", recipes: ["orphan"] })],
      toolManifest: {},
    });
    expect(map.recipes[0]!.collectorRegistered).toBe(false);
    expect(map.recipes[0]!.tools).toEqual([]);
    expect(toolMapProblems(map)[0]).toContain("not registered");
    // and the row says so where the tool name would be
    expect(renderToolMap(map, false)).toContain("no collector registered");
  });

  it("a one-way link — recipe names the collector, collector does not claim it — is a problem", () => {
    const map = buildToolMap({
      recipes: [fakeRecipe("a", "c1")],
      collectors: [fakeCollector({ name: "c1", recipes: [] })],
      toolManifest: {},
    });
    expect(map.recipes[0]!.collectorRegistered).toBe(true);
    expect(map.recipes[0]!.claimedByCollector).toBe(false);
    expect(toolMapProblems(map)[0]).toContain("does not list it");
  });

  it("a collector declaring a recipe the catalog does not hold is named", () => {
    const map = buildToolMap({
      recipes: [],
      collectors: [fakeCollector({ name: "c1", recipes: ["gone"] })],
      toolManifest: {},
    });
    expect(map.collectors[0]!.unknownRecipes).toEqual(["gone"]);
    expect(toolMapProblems(map)[0]).toContain("catalog does not hold");
  });

  it("an input nothing produces breaks the chain, and the map says where", () => {
    const map = buildToolMap({
      recipes: [],
      collectors: [fakeCollector({ name: "gate", inputs: ["missing.json"] })],
      toolManifest: {},
    });
    expect(map.unproducibleInputs).toEqual([{ collector: "gate", artifact: "missing.json" }]);
    expect(renderToolMap(map, false)).toContain("nothing registered produces this");
  });

  it("a tool with no pin can only run as a binary already on PATH, and says so", () => {
    const map = buildToolMap({
      recipes: [],
      collectors: [fakeCollector({ name: "c1", tools: ["nmap"] })],
      toolManifest: {},
    });
    expect(map.tools[0]!.pinnedVersion).toBeUndefined();
    expect(toolMapProblems(map)[0]).toContain("no pin in tools.json");
  });

  it("a pin nobody asks for is listed as an orphan, not as a tool in use", () => {
    const map = buildToolMap({
      recipes: [],
      collectors: [fakeCollector({ name: "c1" })],
      toolManifest: { trivy: { version: "0.1", image: "aquasec/trivy:0.1" } },
    });
    expect(map.tools).toEqual([]);
    expect(map.orphanPins).toEqual(["trivy"]);
    // an unused pin is not a broken link — it rots, but nothing depends on it
    expect(toolMapProblems(map)).toEqual([]);
  });

  it("a consumption cycle terminates rather than hanging the command", () => {
    const map = buildToolMap({
      recipes: [fakeRecipe("r", "a")],
      collectors: [
        fakeCollector({ name: "a", recipes: ["r"], inputs: ["y"], outputs: ["x"] }),
        fakeCollector({ name: "b", tools: ["t"], inputs: ["x"], outputs: ["y"] }),
      ],
      toolManifest: { t: { version: "1", image: "i:1" } },
    });
    expect(map.recipes[0]!.viaInputs).toEqual([{ tool: "t", through: "b" }]);
  });

  it("a diamond lists a shared upstream tool once", () => {
    const map = buildToolMap({
      recipes: [fakeRecipe("r", "gate")],
      collectors: [
        fakeCollector({ name: "gate", recipes: ["r"], inputs: ["left", "right"] }),
        fakeCollector({ name: "l", inputs: ["base"], outputs: ["left"] }),
        fakeCollector({ name: "r2", inputs: ["base"], outputs: ["right"] }),
        fakeCollector({ name: "base", tools: ["t"], outputs: ["base"] }),
      ],
      toolManifest: { t: { version: "1", image: "i:1" } },
    });
    expect(map.recipes[0]!.viaInputs).toEqual([{ tool: "t", through: "base" }]);
  });
});
