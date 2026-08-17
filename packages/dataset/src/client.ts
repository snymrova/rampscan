import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import {
  AwsRecipe,
  CrosswalkControl,
  CrosswalkIndicator,
  FrontierControl,
  SliceEnvelope,
} from "./types.js";

/**
 * The dataset client answers three questions against a pinned ramprules
 * dataset: recipe(id), controlsFor(ksi), ksisFor(control).
 *
 * Two modes behind one interface (plan §M0):
 *   dev    — reads the derived-slice snapshot under docs/context/ramprules/derived/
 *   pinned — ramprules' /api/* (stubbed until the appliance work needs it)
 *
 * Both refuse to run when the loaded dataset_version differs from the pin —
 * ground rule 2: the pin is enforced at load, hard failure on mismatch.
 */
export interface DatasetClient {
  version(): string;
  recipe(id: string): AwsRecipe | undefined;
  recipes(): AwsRecipe[];
  /** canonical control ids reached by a KSI indicator, ascending */
  controlsFor(ksiId: string): string[];
  /** KSI indicator ids that reach a control, ascending */
  ksisFor(controlId: string): string[];
  /**
   * The automation frontier: the uncovered controls a KSI reaches, as upstream
   * published them. Read under the same pin as every other slice, so a
   * re-published frontier fails loudly here rather than silently re-basing the
   * adjudications keyed to it (ground rule 2, applied to a new file class).
   */
  frontier(): FrontierControl[];
  /**
   * Upstream's denominator: how many controls any KSI reaches at all (209 in
   * the pinned snapshot). Read from the frontier's own rollup rather than
   * typed anywhere, because it is the divisor under every ceiling figure this
   * repository publishes (ground rule 9).
   */
  ksiReachedControls(): number;
}

export class DatasetVersionMismatchError extends Error {
  constructor(
    readonly expected: string,
    readonly actual: string,
    readonly where: string,
  ) {
    super(
      `dataset_version mismatch in ${where}: pinned ${expected}, loaded ${actual}. ` +
        `Refusing to run — re-pin or refresh the snapshot.`,
    );
    this.name = "DatasetVersionMismatchError";
  }
}

const CrosswalkData = z.object({
  indicators: z.record(z.string(), CrosswalkIndicator),
  controls: z.record(z.string(), CrosswalkControl),
});

const AwsEvidenceData = z.object({
  recipes: z.array(AwsRecipe),
});

const FrontierData = z.object({
  frontier: z.array(FrontierControl),
  rollup: z.object({ ksiReachedControls: z.number() }).passthrough(),
});

async function loadSlice(
  dir: string,
  file: string,
  pin: string,
): Promise<unknown> {
  const raw = JSON.parse(await readFile(join(dir, file), "utf8")) as unknown;
  const envelope = SliceEnvelope.parse(raw);
  if (envelope.dataset_version !== pin) {
    throw new DatasetVersionMismatchError(pin, envelope.dataset_version, file);
  }
  return envelope.data ?? raw;
}

/** Dev-mode client over a local derived-slice directory. */
export async function loadLocalDataset(
  derivedDir: string,
  pin: string,
): Promise<DatasetClient> {
  // index.json carries the snapshot's own version claim; check it first so a
  // wholesale-stale snapshot fails on one file, not partway through.
  await loadSlice(derivedDir, "index.json", pin);
  const crosswalk = CrosswalkData.parse(
    await loadSlice(derivedDir, "crosswalk.json", pin),
  );
  const awsEvidence = AwsEvidenceData.parse(
    await loadSlice(derivedDir, "aws-evidence.json", pin),
  );
  const frontier = FrontierData.parse(
    await loadSlice(derivedDir, "automation-frontier.json", pin),
  );

  const recipesById = new Map(awsEvidence.recipes.map((r) => [r.id, r]));

  return {
    version: () => pin,
    recipe: (id) => recipesById.get(id),
    recipes: () => [...awsEvidence.recipes],
    controlsFor: (ksiId) => {
      const indicator = crosswalk.indicators[ksiId];
      if (!indicator) return [];
      return indicator.controls.map((c) => c.canonicalId).sort();
    },
    ksisFor: (controlId) => {
      const control = crosswalk.controls[controlId];
      if (!control) return [];
      return [...control.indicatorIds].sort();
    },
    frontier: () => [...frontier.frontier],
    ksiReachedControls: () => frontier.rollup.ksiReachedControls,
  };
}

/**
 * Pinned-mode client over ramprules' /api/* — same interface, deferred
 * implementation. Exists now so nothing upstream grows a dependency on the
 * dev loader's file layout.
 */
export function loadPinnedDataset(
  _baseUrl: string,
  _pin: string,
): Promise<DatasetClient> {
  return Promise.reject(
    new Error(
      "pinned-mode dataset client not implemented yet — use loadLocalDataset (dev mode)",
    ),
  );
}
