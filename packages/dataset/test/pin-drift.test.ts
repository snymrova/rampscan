import { readFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { DEFAULT_DATASET_PIN, compareDatasetVersions, pinDrift, renderPinDrift } from "../src/index.js";

// P1's last piece: upstream publishes rules on its own schedule, and every pin
// in this repository is a decision taken against a file that has since moved.
// `pinDrift` is the comparison itself — pure, over a version string somebody
// else fetched — so the scheduled job that calls it has no logic of its own and
// the same answer is reachable from a test, from `rampscan doctor` and from CI.
//
// The versions are FedRAMP's own `info.version`, `YYYY.MM.DD.NN`, which orders
// lexically as long as every field is zero-padded. It has been since the first
// release, and a version that is not that shape is refused rather than guessed
// at: a comparison that silently returns "not newer" for an unparseable string
// is a drift check that reports clean while drifting.

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");

describe("compareDatasetVersions", () => {
  it("orders by date then by the release counter within a day", () => {
    expect(compareDatasetVersions("2026.07.14.01", "2026.09.13.02")).toBeLessThan(0);
    expect(compareDatasetVersions("2026.09.13.02", "2026.07.14.01")).toBeGreaterThan(0);
    expect(compareDatasetVersions("2026.09.13.02", "2026.09.13.02")).toBe(0);
    // the counter, which is the field a same-day republish moves
    expect(compareDatasetVersions("2026.09.13.01", "2026.09.13.02")).toBeLessThan(0);
    // and the day, not the string: a zero-padded month must not sort under a bare one
    expect(compareDatasetVersions("2026.09.13.02", "2026.10.01.01")).toBeLessThan(0);
  });

  it("refuses a version it cannot order rather than calling it equal", () => {
    for (const bad of ["2026.09.13", "2026.9.13.02", "v2026.09.13.02", "", "latest"]) {
      expect(() => compareDatasetVersions(bad, DEFAULT_DATASET_PIN), bad).toThrow(/not a dataset version/);
    }
  });
});

describe("pinDrift — what the scheduled check reports", () => {
  it("clean when upstream is at the pin", () => {
    const d = pinDrift(DEFAULT_DATASET_PIN, DEFAULT_DATASET_PIN);
    expect(d).toEqual({ kind: "current", pin: DEFAULT_DATASET_PIN });
    expect(renderPinDrift(d)).toContain("at the pin");
  });

  it("behind when upstream has published newer — the case the job exists for", () => {
    const d = pinDrift(DEFAULT_DATASET_PIN, "2026.11.01.01");
    expect(d).toEqual({ kind: "behind", pin: DEFAULT_DATASET_PIN, upstream: "2026.11.01.01" });
    const text = renderPinDrift(d);
    expect(text).toContain("2026.11.01.01");
    expect(text).toContain(DEFAULT_DATASET_PIN);
    // the message says what a re-pin is, because a drift notice that reads as a
    // version bump invites the side effect ground rule 2 forbids
    expect(text).toMatch(/reviewed change/);
  });

  it("ahead is its own answer, not a clean one: the pin names a file upstream does not publish", () => {
    const d = pinDrift(DEFAULT_DATASET_PIN, "2026.07.14.01");
    expect(d.kind).toBe("ahead");
    expect(renderPinDrift(d)).toMatch(/upstream does not publish/);
  });

  it("the vendored copy is the pin — the two legs of §12.4 cannot disagree about which version this is", async () => {
    const rules = JSON.parse(
      await readFile(join(REPO_ROOT, "docs/context/fedramp-rules/fedramp-consolidated-rules.json"), "utf8"),
    ) as { info: { version: string } };
    expect(rules.info.version).toBe(DEFAULT_DATASET_PIN);
    expect(pinDrift(DEFAULT_DATASET_PIN, rules.info.version).kind).toBe("current");
  });
});
