import { fileURLToPath } from "node:url";
import { join, dirname } from "node:path";
import { describe, expect, it } from "vitest";
import {
  DEFAULT_OVERLAY_PINS,
  DatasetVersionMismatchError,
  OverlayVersionMismatchError,
  PlaneVersionMismatchError,
  loadLocalDataset,
  loadPinnedDataset,
  sliceOverlayVersion,
} from "../src/index.js";

const derivedDir = join(
  dirname(fileURLToPath(import.meta.url)),
  "../../../docs/context/ramprules/derived",
);
const PIN = "2026.07.14.01";

describe("loadLocalDataset", () => {
  it("answers ksisFor('ac-2.1') correctly against the snapshot", async () => {
    const ds = await loadLocalDataset(derivedDir, PIN);
    // M0 exit test — values verified by hand against crosswalk.json
    expect(ds.ksisFor("ac-2.1")).toEqual(["KSI-IAM-JIT", "KSI-IAM-SUS"]);
  });

  it("controlsFor and ksisFor are mutually consistent", async () => {
    const ds = await loadLocalDataset(derivedDir, PIN);
    for (const ksi of ds.ksisFor("ac-2.1")) {
      expect(ds.controlsFor(ksi)).toContain("ac-2.1");
    }
  });

  it("resolves an aws-evidence recipe by id, with its catalog joins intact", async () => {
    const ds = await loadLocalDataset(derivedDir, PIN);
    const recipe = ds.recipe("iam-credential-report");
    expect(recipe).toBeDefined();
    expect(recipe?.ksi_ids).toContain("KSI-IAM-APM");
    expect(recipe?.control_ids).toContain("ac-2.1");
    expect(ds.recipe("no-such-recipe")).toBeUndefined();
  });

  it("returns [] for unknown ids rather than guessing", async () => {
    const ds = await loadLocalDataset(derivedDir, PIN);
    expect(ds.ksisFor("zz-99")).toEqual([]);
    expect(ds.controlsFor("KSI-ZZZ-ZZZ")).toEqual([]);
  });

  it("refuses to run on a dataset_version mismatch — hard failure at load", async () => {
    await expect(loadLocalDataset(derivedDir, "1999.01.01.01")).rejects.toThrow(
      DatasetVersionMismatchError,
    );
  });

  it("reports its pinned version", async () => {
    const ds = await loadLocalDataset(derivedDir, PIN);
    expect(ds.version()).toBe(PIN);
  });
});

// N1a′-T1. The dataset_version pin above was the only one this client checked,
// and it is not the field the adjudications move under: upstream's frontier went
// 0.6.0 → 0.7.2 on 2026-08-17, changing fifteen dispositions and dropping two
// controls off the frontier entirely, while dataset_version stayed identical.
describe("overlay_version pinning", () => {
  it("refuses a slice whose overlay_version differs from its pin, naming the slice", async () => {
    // 0.6.0 is the pin this checkout moved OFF, and it is the right fixture for
    // the same reason it was the right bug: it is the version the tree held
    // while upstream published 0.7.2, and holding it again must fail rather
    // than quietly re-base the adjudications keyed to the newer file.
    await expect(
      loadLocalDataset(derivedDir, PIN, {
        ...DEFAULT_OVERLAY_PINS,
        "automation-frontier.json": "0.6.0",
      }),
    ).rejects.toThrow(OverlayVersionMismatchError);
    await expect(
      loadLocalDataset(derivedDir, PIN, {
        ...DEFAULT_OVERLAY_PINS,
        "automation-frontier.json": "0.6.0",
      }),
    ).rejects.toThrow(/automation-frontier\.json/);
  });

  it("pins per slice — two slices carry different overlays under one dataset_version", async () => {
    // Not a hypothetical: this is why the pin cannot be a single constant.
    // The shipped snapshot holds automation-frontier at one overlay and
    // aws-evidence at another, both at dataset_version 2026.07.14.01.
    expect(DEFAULT_OVERLAY_PINS["automation-frontier.json"]).not.toBe(
      DEFAULT_OVERLAY_PINS["aws-evidence.json"],
    );
    // and both are satisfied by the same load
    await expect(loadLocalDataset(derivedDir, PIN)).resolves.toBeDefined();
  });

  it("refuses a pin against a slice that carries no overlay_version at all", async () => {
    // A pin nobody reads is the bug this check exists to fix, so declaring one
    // over crosswalk.json — which has no overlay — must fail rather than pass.
    await expect(
      loadLocalDataset(derivedDir, PIN, {
        ...DEFAULT_OVERLAY_PINS,
        "crosswalk.json": "0.6.0",
      }),
    ).rejects.toThrow(/overlay_version missing/);
  });

  it("leaves the dataset_version refusal unchanged, and the two errors are distinguishable", async () => {
    // Which pin to move is the first thing a reader needs, and the two moves
    // call for different reading — one re-bases the register, one re-bases the
    // reasoning about it.
    const datasetFailure = loadLocalDataset(derivedDir, "1999.01.01.01");
    await expect(datasetFailure).rejects.toThrow(DatasetVersionMismatchError);
    await expect(datasetFailure).rejects.not.toThrow(OverlayVersionMismatchError);

    const overlayFailure = loadLocalDataset(derivedDir, PIN, {
      "automation-frontier.json": "9.9.9",
    });
    await expect(overlayFailure).rejects.toThrow(OverlayVersionMismatchError);
    await expect(overlayFailure).rejects.not.toThrow(DatasetVersionMismatchError);
    await expect(overlayFailure).rejects.toThrow(/dispositions moved/);
  });

  it("reads both spellings upstream uses, and reports the frontier's overlay", async () => {
    // automation-frontier and aws-evidence write it at the payload root;
    // evidence-plan writes it one level down under `overlay`.
    expect(sliceOverlayVersion({ overlay_version: "1.2.3" })).toBe("1.2.3");
    expect(sliceOverlayVersion({ overlay: { overlay_version: "1.2.3" } })).toBe("1.2.3");
    expect(sliceOverlayVersion({ rollup: {} })).toBeUndefined();
    expect(sliceOverlayVersion(null)).toBeUndefined();

    const ds = await loadLocalDataset(derivedDir, PIN);
    expect(ds.frontierOverlayVersion()).toBe(DEFAULT_OVERLAY_PINS["automation-frontier.json"]);
  });
});

describe("the plane pin — the third one, over upstream's own recipes", () => {
  it("reads upstream's pipeline recipes by the control each claims", async () => {
    // The map the frontier structurally cannot hold: a control upstream has
    // ANSWERED has left the uncovered set, taking with it the fact that this
    // catalog also claims it. Three controls were in exactly that state.
    const ds = await loadLocalDataset(derivedDir, PIN);
    expect(ds.upstreamRecipesFor("ia-5.6")).toContainEqual({
      plane: "pipeline",
      recipeId: "secret-exposure-detection-and-push-protection",
    });
    expect(ds.upstreamRecipesFor("sa-11")).toContainEqual({
      plane: "pipeline",
      recipeId: "static-analysis-coverage-and-flaw-disposition",
    });
    expect(ds.upstreamRecipesFor("no-such-control")).toEqual([]);
  });

  it("unions provesControls across classes, because one class under-reports", async () => {
    // `provesControls` is scoped per certification class, so the same recipe
    // appears under several classes with the list populated in some and empty
    // in others. Reading one class would silently under-report — and this is a
    // check about undeclared overlap, where under-reporting IS the failure.
    const ds = await loadLocalDataset(derivedDir, PIN);
    const pipeline = ["ia-5.6", "sa-11", "si-10", "si-7.7", "cm-4.2", "sa-10", "cm-3.4", "sr-6", "sr-8"];
    for (const control of pipeline) {
      expect(
        ds.upstreamRecipesFor(control).some((r) => r.plane === "pipeline"),
        `${control} should carry a pipeline recipe`,
      ).toBe(true);
    }
  });

  it("refuses when upstream's plane moves, and says to re-read the catalog rather than the records", async () => {
    // A plane bump means upstream authored or withdrew recipes, so WHICH
    // controls are claimed on both planes may have moved — a different job from
    // the one an overlay_version bump calls for, and the message has to name it
    // or the reader does the other one.
    const moved = loadLocalDataset(derivedDir, PIN, DEFAULT_OVERLAY_PINS, { pipeline: "9.9.9" });
    await expect(moved).rejects.toThrow(PlaneVersionMismatchError);
    await expect(moved).rejects.toThrow(/Re-read the CATALOG/);

    const absent = loadLocalDataset(derivedDir, PIN, DEFAULT_OVERLAY_PINS, { endpoint: "0.1.0" });
    await expect(absent).rejects.toThrow(/carries no such plane/);
  });

  it("reports every plane upstream stamps, read rather than assumed", async () => {
    const ds = await loadLocalDataset(derivedDir, PIN);
    expect(ds.upstreamPlaneVersions()).toMatchObject({ aws: "1.6.1", pipeline: "0.5.1" });
  });
});

describe("loadPinnedDataset", () => {
  it("is stubbed behind the same interface and says so", async () => {
    await expect(
      loadPinnedDataset("https://ramprules.com", PIN),
    ).rejects.toThrow(/not implemented/);
  });
});
