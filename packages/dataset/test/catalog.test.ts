import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { join, dirname } from "node:path";
import { describe, expect, it } from "vitest";
import {
  CatalogDivergenceError,
  CatalogSourceError,
  DatasetVersionMismatchError,
  assertCatalogsEquivalent,
  loadKsiCatalogFromRules,
  loadKsiCatalogFromSlices,
  type KsiCatalog,
} from "../src/index.js";

const contextDir = join(dirname(fileURLToPath(import.meta.url)), "../../../docs/context");
const derivedDir = join(contextDir, "ramprules/derived");
const rulesFile = join(contextDir, "fedramp-rules/fedramp-consolidated-rules.json");
const PIN = "2026.07.14.01";

// Q1.3 — the dual-source contract (SPEC §12.4). Path A is the ramprules
// derived-slice snapshot; Path B is fedramp-consolidated-rules.json direct.
// The rules JSON is the canonical upstream ramprules derives from, so this
// test proves the derivation round-trips: every owed fact identical at the
// pin, with the loaders' independent parses cross-validating each other.
//
// The third leg §12.4 names — Paramify's CR26/ OSCAL serialization as a
// cross-check, never a source — waits on that file being vendored; nothing
// here changes when it arrives, it only gains another comparand.
describe("the dual-source equivalence contract", () => {
  it("both paths yield identical KsiCatalog values at the pin", async () => {
    const a = await loadKsiCatalogFromSlices(derivedDir, PIN);
    const b = await loadKsiCatalogFromRules(rulesFile, PIN);
    expect(() => assertCatalogsEquivalent(a, b)).not.toThrow();
    // and the blunt instrument agrees with the walking one
    expect(a).toEqual(b);
  });

  it("names the first differing owed fact rather than diffing two catalogs", async () => {
    const a = await loadKsiCatalogFromSlices(derivedDir, PIN);
    const forged: KsiCatalog = {
      ...a,
      floors: { ...a.floors, c: { ...a.floors.c, minPerKsi: 3 } },
    };
    expect(() => assertCatalogsEquivalent(a, forged)).toThrow(CatalogDivergenceError);
    expect(() => assertCatalogsEquivalent(a, forged)).toThrow(/floors\.c\.minPerKsi/);
  });
});

// The owed numbers below are asserted LITERALLY, against both paths at once
// (equivalence above makes one load representative). These are the load-bearing
// numbers of the pivot — G1/G2's floors, G3's windows, G4's history — verified
// by hand against fedramp-consolidated-rules.json 2026.07.14.01; a re-pin that
// moves one of them is supposed to arrive here as a failing test, because a
// moved owed number is a reviewed change, never a drive-by (ground rule 2).
describe("the owed state at pin 2026.07.14.01", () => {
  const load = () => loadKsiCatalogFromSlices(derivedDir, PIN);

  it("carries 46 KSIs across 10 themes — the board's row set, always", async () => {
    const catalog = await load();
    expect(catalog.ksis).toHaveLength(46);
    expect(catalog.themes).toHaveLength(10);
    // every indicator's theme exists, and ids are canonical (ascending, unique)
    const themeKeys = new Set(catalog.themes.map((t) => t.key));
    const ids = catalog.ksis.map((k) => k.id);
    for (const ksi of catalog.ksis) expect(themeKeys.has(ksi.themeKey)).toBe(true);
    expect(ids).toEqual([...new Set(ids)].sort());
  });

  it("carries every KSI's statement and its controls crosswalk", async () => {
    const catalog = await load();
    // Five indicators' statements the rules vary by class (optional wording
    // at b, mandatory at c); the shared surface is null exactly there — see
    // KsiEntry.statement — and a flat string everywhere else. The list is
    // asserted literally: a re-pin that varies one more statement is an owed
    // change this test should hand to a reviewer, not absorb.
    const variedAtThisPin = [
      "KSI-CNA-EIS",
      "KSI-MLA-ALA",
      "KSI-SVC-PRR",
      "KSI-SVC-RUD",
      "KSI-SVC-VCM",
    ];
    expect(catalog.ksis.filter((k) => k.statement === null).map((k) => k.id)).toEqual(
      variedAtThisPin,
    );
    for (const ksi of catalog.ksis) {
      if (!variedAtThisPin.includes(ksi.id)) {
        expect(ksi.statement, `${ksi.id} statement`).toBeTruthy();
      }
    }
    const rat = catalog.ksis.find((k) => k.id === "KSI-CED-RAT");
    expect(rat?.themeKey).toBe("CED");
    expect(rat?.controls).toContain("at-2");
    expect(rat?.controls).toEqual([...(rat?.controls ?? [])].sort());
  });

  it("owes five default artifacts per KSI", async () => {
    const catalog = await load();
    expect(catalog.defaultArtifacts).toHaveLength(5);
    expect(catalog.defaultArtifacts[0]).toMatch(/Explanation of measures/);
  });

  it("method floors read 1/2/4 for b/c/d and none for a (FRC-CSX-VVK)", async () => {
    const { floors } = await load();
    expect(floors.a).toMatchObject({ minPerKsi: null, force: "MAY" });
    expect(floors.b).toMatchObject({ minPerKsi: 1, force: "SHOULD" });
    expect(floors.c).toMatchObject({ minPerKsi: 2, force: "MUST" });
    expect(floors.d).toMatchObject({ minPerKsi: 4, force: "MUST" });
    for (const f of Object.values(floors)) expect(f.requirementId).toBe("FRC-CSX-VVK");
  });

  it("history floors read 6/18 months for c/d and none for a/b (FRC-CSX-MOT)", async () => {
    const { historyFloors } = await load();
    expect(historyFloors.a).toMatchObject({ months: null, force: "MAY" });
    expect(historyFloors.b).toMatchObject({ months: null, force: "SHOULD" });
    expect(historyFloors.c).toMatchObject({ months: 6, force: "MUST" });
    expect(historyFloors.d).toMatchObject({ months: 18, force: "MUST" });
  });

  it("MVX windows read 1mo/7d/3d for a/b/c, and class d honestly has none", async () => {
    const { windows } = await load();
    expect(windows.a).toMatchObject({ num: 1, unit: "months", force: "SHOULD" });
    expect(windows.b).toMatchObject({ num: 7, unit: "days", force: "MUST" });
    expect(windows.c).toMatchObject({ num: 3, unit: "days", force: "MUST" });
    // SPEC §11 open question 6: VDR-TFR-MVX defines no class-d window. The
    // scheduler refuses class d for exactly this reason (§12.3); the catalog's
    // null is the dataset speaking, not a loader gap.
    expect(windows.d).toBeNull();
  });

  it("the scheduler's typed MVX days agree with the data — until Q3 reads them from here", async () => {
    // packages/scheduler/src/mvx.ts types { b: 7, c: 3 } today; Q3.2 re-keys
    // the clock to read the owed side. Until then this test is the tripwire:
    // if a re-pin moves a window, the typed copy fails HERE, by name.
    const { windows } = await load();
    expect(windows.b).toMatchObject({ num: 7, unit: "days" });
    expect(windows.c).toMatchObject({ num: 3, unit: "days" });
  });

  it("the non-machine clock reads every 3 months (VDR-TFR-NMV)", async () => {
    const { nonMachineWindow } = await load();
    expect(nonMachineWindow).toEqual({
      requirementId: "VDR-TFR-NMV",
      force: "MUST",
      num: 3,
      unit: "months",
    });
  });
});

describe("refusals — the same discipline as the client, on both paths", () => {
  it("Path A refuses a dataset_version mismatch", async () => {
    await expect(loadKsiCatalogFromSlices(derivedDir, "1999.01.01.01")).rejects.toThrow(
      DatasetVersionMismatchError,
    );
  });

  it("Path B refuses a dataset_version mismatch, naming the rules file", async () => {
    const failure = loadKsiCatalogFromRules(rulesFile, "1999.01.01.01");
    await expect(failure).rejects.toThrow(DatasetVersionMismatchError);
    await expect(failure).rejects.toThrow(/fedramp-consolidated-rules\.json/);
  });

  it("a reworded owed sentence is a refusal, not a silent no-floor", async () => {
    // The parsers are deliberately narrow: a re-pin that rewords a MUST
    // statement may have moved the number, so it must arrive as a
    // CatalogSourceError naming the rule — never as minPerKsi: null.
    const rules = JSON.parse(await readFile(rulesFile, "utf8")) as {
      FRR: {
        FRC: {
          data: {
            "20x": { CSX: { "FRC-CSX-VVK": { varies_by_class: { c: { statement: string } } } } };
          };
        };
      };
    };
    rules.FRR.FRC.data["20x"].CSX["FRC-CSX-VVK"].varies_by_class.c.statement =
      "Providers seeking 20x Class C Certification MUST implement a couple of automated methods.";
    const dir = await mkdtemp(join(tmpdir(), "rampscan-catalog-"));
    const forged = join(dir, "fedramp-consolidated-rules.json");
    await writeFile(forged, JSON.stringify(rules));
    const failure = loadKsiCatalogFromRules(forged, PIN);
    await expect(failure).rejects.toThrow(CatalogSourceError);
    await expect(failure).rejects.toThrow(/FRC-CSX-VVK class c/);
    await expect(failure).rejects.toThrow(/owed all the same/);
  });
});
