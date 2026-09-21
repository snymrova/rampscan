import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import { DEFAULT_DATASET_PIN, loadKsiCatalog, loadLocalDataset } from "@rampscan/dataset";
import type { ReachPin } from "@rampscan/schema";
import { DEFAULT_ALLOWLIST_PATH, loadAwsActionAllowlist } from "../src/aws-actions.js";
import { DEFAULT_BINDINGS_PATH, loadAwsLiteralBindings } from "../src/aws-bindings.js";
import { classifyAwsRecipes, windowEnding } from "../src/aws-recipes.js";
import { loadPinnedProwlerFramework, uncoveredKsis } from "../src/prowler-framework.js";
import { buildReachPins } from "../src/reach-pins.js";
import { loadRecipes } from "../src/recipes.js";

// The three pins, over the real three pins (docs/PLAN-REACH.md N0-1). These
// are facts about this checkout — which is why they are asserted against
// the files rather than against a fixture: the day a pin moves, the rung it
// confers moves with it, and this is where that shows first.

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");

let pins: Record<string, ReachPin[]>;
let uncovered: readonly string[];

beforeAll(async () => {
  const dataset = await loadLocalDataset(
    join(REPO_ROOT, "docs/context/ramprules/derived"),
    DEFAULT_DATASET_PIN,
  );
  const catalog = await loadKsiCatalog({
    derivedDir: join(REPO_ROOT, "docs/context/ramprules/derived"),
    rulesFile: join(REPO_ROOT, "docs/context/fedramp-rules/fedramp-consolidated-rules.json"),
    pin: DEFAULT_DATASET_PIN,
  });
  const prowler = await loadPinnedProwlerFramework(REPO_ROOT);
  uncovered = uncoveredKsis(prowler, "aws");
  pins = buildReachPins({
    ksiIds: catalog.ksis.map((k) => k.id),
    recipes: await loadRecipes(join(REPO_ROOT, "recipes/commit")),
    // no `aws` block: every placeholder unbound, which is what CI sees
    aws: classifyAwsRecipes(
      dataset.recipes(),
      await loadAwsActionAllowlist(join(REPO_ROOT, DEFAULT_ALLOWLIST_PATH)),
      await loadAwsLiteralBindings(join(REPO_ROOT, DEFAULT_BINDINGS_PATH)),
      undefined,
      windowEnding(new Date("2026-09-21T00:00:00.000Z"), 30),
      DEFAULT_DATASET_PIN,
    ),
    prowler,
  });
});

const planeOf = (ksi: string, plane: ReachPin["plane"]) => pins[ksi]!.find((p) => p.plane === plane)!;

describe("buildReachPins over the real pins", () => {
  it("every catalog KSI gets exactly the three planes, in the closed order", () => {
    expect(Object.keys(pins).length).toBe(46);
    for (const entry of Object.values(pins)) {
      expect(entry.map((p) => p.plane)).toEqual(["pipeline", "aws", "prowler"]);
    }
  });

  it("the four people-and-money KSIs are observed by nothing on any plane", () => {
    for (const ksi of ["KSI-CED-RAT", "KSI-PIY-RES", "KSI-PIY-RIS", "KSI-SVC-RUD"]) {
      for (const p of pins[ksi]!) {
        expect(p.observes, `${ksi} ${p.plane}`).toEqual([]);
        expect(p.wired, `${ksi} ${p.plane}`).toEqual([]);
      }
    }
  });

  it("a catalog recipe both observes and wires its KSI — wired is what a recipe confers by existing", () => {
    const p = planeOf("KSI-SCR-MIT", "pipeline");
    expect(p.observes.length).toBeGreaterThan(0);
    expect(p.wired).toEqual(p.observes);
    expect(p.observes).toEqual([...p.observes].sort());
  });

  it("an upstream AWS recipe observes; only a runnable one wires", () => {
    // the incident-response KSIs: upstream publishes a recipe, nothing runs it
    for (const ksi of ["KSI-INR-AAR", "KSI-INR-RIR", "KSI-INR-RPI"]) {
      const p = planeOf(ksi, "aws");
      expect(p.observes.length, ksi).toBeGreaterThan(0);
      expect(p.wired, ksi).toEqual([]);
      expect(planeOf(ksi, "pipeline").observes).toEqual([]);
      expect(planeOf(ksi, "prowler").observes).toEqual([]);
    }
    // and one the runner can execute with nothing bound
    const apm = planeOf("KSI-IAM-APM", "aws");
    expect(apm.wired.length).toBeGreaterThan(0);
    for (const id of apm.wired) expect(apm.observes).toContain(id);
  });

  it("the Prowler plane is the framework's AWS checks, empty exactly on the reviewed uncovered set", () => {
    expect(uncovered.length).toBe(13);
    for (const ksi of uncovered) expect(planeOf(ksi, "prowler").observes, ksi).toEqual([]);
    for (const ksi of Object.keys(pins)) {
      const p = planeOf(ksi, "prowler");
      if (uncovered.includes(ksi)) continue;
      expect(p.observes.length, ksi).toBeGreaterThan(0);
      // the adapter is pinned to the framework, so what it observes it wires
      expect(p.wired).toEqual(p.observes);
    }
  });
});
