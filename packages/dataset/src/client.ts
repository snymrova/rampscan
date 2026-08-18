import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import { DEFAULT_OVERLAY_PINS, DEFAULT_PLANE_PINS } from "./pins.js";
import {
  AwsRecipe,
  CrosswalkControl,
  CrosswalkIndicator,
  EvidencePlanData,
  FrontierControl,
  SliceEnvelope,
  type UpstreamRecipeRef,
  sliceOverlayVersion,
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
 * ground rule 2: the pin is enforced at load, hard failure on mismatch. Since
 * N1a′-T1 they refuse on a second pin too: `overlay_version`, per slice, which
 * is the field the adjudications actually move under. See `pins.ts` for why
 * one pin was not enough and why the second one cannot be global.
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
  /**
   * The overlay the frontier's dispositions were derived under. Exposed so
   * `rampscan frontier` can print the version its own reasoning is keyed to
   * rather than only the register's — the two move independently, and the
   * whole of N1a′-T1 is that a reader who sees one of them believes both.
   */
  frontierOverlayVersion(): string | undefined;
  /**
   * Upstream recipes that claim a control, with the plane that authored each.
   *
   * The frontier cannot answer this and never could: it is the UNCOVERED set,
   * so a control upstream has answered has left it. That blind spot is where
   * `ia-5.6`, `sa-11` and `si-10` came to be claimed by a recipe on both planes
   * with neither project declaring it — not a check that failed, a check that
   * was looking at the only file where the fact is structurally absent.
   */
  upstreamRecipesFor(controlId: string): UpstreamRecipeRef[];
  /** the overlay version each upstream plane's recipes were derived under */
  upstreamPlaneVersions(): Readonly<Record<string, string>>;
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

/**
 * The other pin. Kept a distinct class from `DatasetVersionMismatchError`, and
 * both messages name their own field, because the two failures call for
 * different reading: a `dataset_version` move re-bases the control register,
 * an `overlay_version` move re-bases the REASONING about it, and a reader who
 * cannot tell which pin to move from the error will move the wrong one.
 */
export class OverlayVersionMismatchError extends Error {
  constructor(
    readonly expected: string,
    readonly actual: string | undefined,
    readonly where: string,
  ) {
    super(
      actual === undefined
        ? `overlay_version missing from ${where}: pinned ${expected}, but the slice carries no ` +
          `overlay_version. Refusing to run — a pin against a field nobody reads is the bug this ` +
          `check exists to fix; drop the slice's entry from DEFAULT_OVERLAY_PINS or refresh the snapshot.`
        : `overlay_version mismatch in ${where}: pinned ${expected}, loaded ${actual}. ` +
          `Refusing to run — the dispositions moved under an unchanged dataset_version. ` +
          `Re-read the adjudications keyed to this slice, then re-pin.`,
    );
    this.name = "OverlayVersionMismatchError";
  }
}

/**
 * The third pin's failure, and a third class rather than a reuse of the second
 * for the reason the second was not a reuse of the first: the reading it calls
 * for is different again. A `dataset_version` move re-bases the register; an
 * `overlay_version` move re-bases upstream's reasoning about it; a PLANE move
 * means upstream has authored or withdrawn recipes, so the set of controls
 * answered on both planes at once may have changed — and that set is the one
 * ground rule 10's new arm is about. The right response is not to re-read our
 * dispositions but to re-read the CATALOG against upstream's, which is a
 * different job the message has to name or the reader will do the other one.
 */
export class PlaneVersionMismatchError extends Error {
  constructor(
    readonly plane: string,
    readonly expected: string,
    readonly actual: string | undefined,
    readonly where: string,
  ) {
    super(
      actual === undefined
        ? `plane "${plane}" is pinned at ${expected} but ${where} carries no such plane. ` +
          `Refusing to run — either upstream withdrew the plane or the snapshot predates it; ` +
          `drop the entry from DEFAULT_PLANE_PINS or refresh the snapshot.`
        : `plane "${plane}" version mismatch in ${where}: pinned ${expected}, loaded ${actual}. ` +
          `Refusing to run — upstream's recipes on that plane moved, so which controls are ` +
          `claimed on both planes at once may have moved with them. Re-read the CATALOG against ` +
          `upstream's recipes (ground rule 10), then re-pin.`,
    );
    this.name = "PlaneVersionMismatchError";
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
  overlayPins: Readonly<Record<string, string>>,
): Promise<unknown> {
  const raw = JSON.parse(await readFile(join(dir, file), "utf8")) as unknown;
  const envelope = SliceEnvelope.parse(raw);
  if (envelope.dataset_version !== pin) {
    throw new DatasetVersionMismatchError(pin, envelope.dataset_version, file);
  }
  const payload = envelope.data ?? raw;
  const overlayPin = overlayPins[file];
  if (overlayPin !== undefined) {
    const loaded = sliceOverlayVersion(payload);
    if (loaded !== overlayPin) {
      throw new OverlayVersionMismatchError(overlayPin, loaded, file);
    }
  }
  return payload;
}

/** Dev-mode client over a local derived-slice directory. */
export async function loadLocalDataset(
  derivedDir: string,
  pin: string,
  overlayPins: Readonly<Record<string, string>> = DEFAULT_OVERLAY_PINS,
  planePins: Readonly<Record<string, string>> = DEFAULT_PLANE_PINS,
): Promise<DatasetClient> {
  // index.json carries the snapshot's own version claim; check it first so a
  // wholesale-stale snapshot fails on one file, not partway through.
  await loadSlice(derivedDir, "index.json", pin, overlayPins);
  const crosswalk = CrosswalkData.parse(
    await loadSlice(derivedDir, "crosswalk.json", pin, overlayPins),
  );
  const awsEvidence = AwsEvidenceData.parse(
    await loadSlice(derivedDir, "aws-evidence.json", pin, overlayPins),
  );
  const frontierPayload = await loadSlice(
    derivedDir,
    "automation-frontier.json",
    pin,
    overlayPins,
  );
  const frontier = FrontierData.parse(frontierPayload);
  const frontierOverlay = sliceOverlayVersion(frontierPayload);

  // The evidence plan is read for the recipe→control map alone, and it is NOT
  // in `overlayPins`: it carries no root `overlay_version` to pin, by upstream's
  // own deliberate removal. Its versions live one level down, per plane, and
  // `planePins` is what checks them.
  const plan = EvidencePlanData.parse(
    await loadSlice(derivedDir, "evidence-plan.json", pin, overlayPins),
  );
  const planeVersions: Record<string, string> = {};
  // `provesControls` is scoped per certification class, so one recipe appears
  // under several classes with the list populated in some and empty in others.
  // The union across classes is the mapping — reading a single class would
  // under-report, which on a check about undeclared overlap fails silent.
  const upstreamByControl = new Map<string, UpstreamRecipeRef[]>();
  const seen = new Set<string>();
  for (const cls of plan.classes) {
    for (const plane of cls.planes) {
      if (plane.version !== undefined) planeVersions[plane.source] = plane.version;
    }
    for (const theme of cls.themes) {
      for (const item of theme.items) {
        for (const controlId of item.provesControls) {
          const key = `${controlId} ${item.source} ${item.recipeId}`;
          if (seen.has(key)) continue;
          seen.add(key);
          const refs = upstreamByControl.get(controlId) ?? [];
          refs.push({ recipeId: item.recipeId, plane: item.source });
          upstreamByControl.set(controlId, refs);
        }
      }
    }
  }
  for (const [plane, expected] of Object.entries(planePins)) {
    const actual = planeVersions[plane];
    if (actual !== expected) {
      throw new PlaneVersionMismatchError(plane, expected, actual, "evidence-plan.json");
    }
  }

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
    frontierOverlayVersion: () => frontierOverlay,
    upstreamRecipesFor: (controlId) => [...(upstreamByControl.get(controlId) ?? [])],
    upstreamPlaneVersions: () => ({ ...planeVersions }),
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
