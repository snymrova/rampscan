import { fileURLToPath } from "node:url";
import { join, dirname } from "node:path";
import { describe, expect, it } from "vitest";
import {
  DatasetVersionMismatchError,
  loadLocalDataset,
  loadPinnedDataset,
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

describe("loadPinnedDataset", () => {
  it("is stubbed behind the same interface and says so", async () => {
    await expect(
      loadPinnedDataset("https://ramprules.com", PIN),
    ).rejects.toThrow(/not implemented/);
  });
});
