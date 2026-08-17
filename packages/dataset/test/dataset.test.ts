import { fileURLToPath } from "node:url";
import { join, dirname } from "node:path";
import { describe, expect, it } from "vitest";
import {
  DEFAULT_OVERLAY_PINS,
  DatasetVersionMismatchError,
  OverlayVersionMismatchError,
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
    await expect(
      loadLocalDataset(derivedDir, PIN, {
        ...DEFAULT_OVERLAY_PINS,
        "automation-frontier.json": "0.7.2",
      }),
    ).rejects.toThrow(OverlayVersionMismatchError);
    await expect(
      loadLocalDataset(derivedDir, PIN, {
        ...DEFAULT_OVERLAY_PINS,
        "automation-frontier.json": "0.7.2",
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

describe("loadPinnedDataset", () => {
  it("is stubbed behind the same interface and says so", async () => {
    await expect(
      loadPinnedDataset("https://ramprules.com", PIN),
    ).rejects.toThrow(/not implemented/);
  });
});
