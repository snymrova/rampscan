import { fileURLToPath } from "node:url";
import { join, dirname } from "node:path";
import { describe, expect, it } from "vitest";
import { loadKsiCatalogFromSlices } from "@rampscan/dataset";
import { renderOwed, renderOwedKsi } from "../src/owed.js";

const derivedDir = join(
  dirname(fileURLToPath(import.meta.url)),
  "../../../docs/context/ramprules/derived",
);
const PIN = "2026.07.14.01";

// The Q1 exit gate, as a test: the owed state for a (KSI, class) pair —
// statement, floor, window, artifact count — every number arriving from the
// catalog port, which read it from the pinned JSON (catalog.test.ts proves
// that leg; this one proves the numbers survive to the text a reader sees).
describe("rampscan owed", () => {
  const load = () => loadKsiCatalogFromSlices(derivedDir, PIN);

  it("prints the register with the class's owed numbers, all 46 rows", async () => {
    const catalog = await load();
    const text = renderOwed(catalog, "b");
    expect(text).toContain("class b (≈ Low) · dataset 2026.07.14.01");
    expect(text).toContain("≥1 automated method per KSI");
    expect(text).toContain("FRC-CSX-VVK (SHOULD)");
    expect(text).toContain("re-validate every 7 days");
    expect(text).toContain("5 default artifacts owed per KSI");
    // one line per KSI — the 46-row invariant reaches the text
    const rows = text.split("\n").filter((l) => /^ {2}KSI-/.test(l));
    expect(rows).toHaveLength(46);
  });

  it("answers a (KSI, class) pair: statement, floor, window, artifacts, crosswalk", async () => {
    const catalog = await load();
    const text = renderOwedKsi(catalog, "c", "KSI-CED-RAT");
    expect(text).toContain("KSI-CED-RAT — Reviewing All Training");
    expect(text).toContain("persistently reviewed"); // the statement itself
    expect(text).toContain("≥2 automated methods per KSI");
    expect(text).toContain("≥6 months of persistent-validation history");
    expect(text).toContain("re-validate every 3 days");
    expect(text).toContain("controls (11): at-2,");
    expect(text).toContain("1. Explanation of measures");
  });

  it("class d says the MVX window is undefined rather than inventing one", async () => {
    const catalog = await load();
    const text = renderOwed(catalog, "d");
    expect(text).toContain("≥4 automated methods per KSI");
    expect(text).toContain("≥18 months");
    expect(text).toContain("none defined — VDR-TFR-MVX carries no entry");
  });

  it("a class-varied statement says so instead of printing one class's words", async () => {
    const catalog = await load();
    const text = renderOwedKsi(catalog, "b", "KSI-SVC-VCM");
    expect(text).toContain("varies by certification class at this pin");
  });

  it("an unknown KSI is undefined, for the caller's nonzero exit", async () => {
    const catalog = await load();
    expect(renderOwedKsi(catalog, "b", "KSI-ZZZ-ZZZ")).toBeUndefined();
  });
});
