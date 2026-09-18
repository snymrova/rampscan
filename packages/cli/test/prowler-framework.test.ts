import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { DEFAULT_DATASET_PIN, loadKsiCatalog, optionalKsis } from "@rampscan/dataset";
import { ProwlerUncovered } from "@rampscan/schema";
import {
  PROWLER_FRAMEWORK_DIR,
  PROWLER_FRAMEWORK_FILE,
  PROWLER_FRAMEWORK_PIN,
  PROWLER_UNCOVERED_PATH,
  assertFrameworkMatchesCatalog,
  checksFor,
  loadPinnedProwlerFramework,
  optionalAtClassB,
  parseProwlerKsiFramework,
  uncoveredKsis,
} from "../src/prowler-framework.js";

// P3-0 (docs/RESEARCH-PROWLER-INGEST.md §4d, §6): the fifth pin, and the
// golden test that is the whole reason the pin is worth having.
//
// WHY THIS IS A TEST AND NOT A TABLE. The tempting artifact here was a
// rampscan-owned check→KSI map, and that is the `labels.json` mistake: P1
// deleted `recipes/aws-actions/labels.json` because upstream had begun
// publishing the same mapping and a row that looked current was one upstream
// renumbering away from naming the wrong thing. Prowler publishes the
// KSI→check mapping, so rampscan keeps no second copy of it — it keeps the
// FILE, pinned on its bytes, and a test that re-derives §2's facts from it on
// every run instead of quoting them.
//
// WHAT THE GOLDEN TEST ACTUALLY GUARDS. Two catalogs are about to be joined
// on KSI id, and there are exactly two ways that join can rot:
//
//   1. THE ID SET moves on either side. Checked BOTH WAYS — a KSI in Prowler
//      that rampscan cannot resolve is an ingest that would mint methods for
//      an indicator off the board, and a KSI in rampscan that Prowler does not
//      carry is an indicator the adapter would silently never reach. Neither
//      is allowed to be discovered by a user.
//   2. CLASS APPLICABILITY moves on either side, which is the second and
//      quieter one: the five indicators optional at class b are the
//      denominator every class-b meter divides by (§13.7), and Prowler states
//      them in its own field. Two sources stating one owed fact and disagreeing
//      is a broken join, exactly as `assertCatalogsEquivalent` treats it.
//
// The class-A arm is deliberately NOT compared. Prowler's `ClassApplicability`
// enum has two values and neither mentions class A; the framework states the
// class-A subset in PROSE ("Class A authorizations mandate a subset of seven
// KSIs via FRC-CLA-MFR") and not in a field. Comparing class a would be
// reading a source's silence as a claim, which is the `varies_by_class` trap
// of P2-0 §2a one file over — so the test asserts that the framework says
// nothing about class a, rather than asserting what it says.

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");

const catalog = () =>
  loadKsiCatalog({
    derivedDir: join(REPO_ROOT, "docs/context/ramprules/derived"),
    rulesFile: join(REPO_ROOT, "docs/context/fedramp-rules/fedramp-consolidated-rules.json"),
    pin: DEFAULT_DATASET_PIN,
  });

/** the pinned file, parsed, as a plain object a test may plant a defect into */
async function rawFramework(): Promise<Record<string, unknown>> {
  const bytes = await readFile(join(REPO_ROOT, PROWLER_FRAMEWORK_DIR, PROWLER_FRAMEWORK_FILE));
  return JSON.parse(bytes.toString("utf8")) as Record<string, unknown>;
}

/** write a planted framework into a temp repo root, so the loader reads it through its own path */
async function plant(mutate: (fw: Record<string, unknown>) => void): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "rampscan-prowler-"));
  const fw = await rawFramework();
  mutate(fw);
  await mkdir(join(root, PROWLER_FRAMEWORK_DIR), { recursive: true });
  await writeFile(join(root, PROWLER_FRAMEWORK_DIR, PROWLER_FRAMEWORK_FILE), JSON.stringify(fw));
  return root;
}

describe("P3-0 — the pinned Prowler KSI framework", () => {
  it("loads at its pinned bytes, version and framework name", async () => {
    const fw = await loadPinnedProwlerFramework(REPO_ROOT);
    expect(fw.framework).toBe("FedRAMP-20x-KSI");
    expect(fw.version).toBe(PROWLER_FRAMEWORK_PIN.version);
    expect(fw.requirements).toHaveLength(46);
    // the pin states a size as well as a digest, and a stated number nothing
    // checks is the thing this repository re-pins to avoid
    const bytes = await readFile(join(REPO_ROOT, PROWLER_FRAMEWORK_DIR, PROWLER_FRAMEWORK_FILE));
    expect(bytes.byteLength).toBe(PROWLER_FRAMEWORK_PIN.bytes);
    expect(createHash("sha256").update(bytes).digest("hex")).toBe(PROWLER_FRAMEWORK_PIN.sha256);
  });

  it("refuses bytes that do not match the pin, naming the re-read rather than the file", async () => {
    // A draft artifact republished under an unchanged `version` is exactly the
    // move `packages/dataset/src/pins.ts` exists to complain about, and this
    // one carries no release at all (§10f), so `version` alone pins nothing.
    const root = await plant((fw) => {
      fw["description"] = "edited";
    });
    await expect(loadPinnedProwlerFramework(root)).rejects.toThrow(/pinned bytes/);
  });

  it("refuses a key it has never read, rather than dropping it", async () => {
    // The fedramp-schemas rule, applied to a third-party file: an unrecognised
    // key is an exit, not a pass. A pin whose reader silently ignores a new
    // field is a pin that is re-stamped instead of re-read.
    const fw = await rawFramework();
    (fw["requirements"] as Record<string, unknown>[])[0]!["severity"] = "high";
    expect(() => parseProwlerKsiFramework(fw, "planted")).toThrow(/severity/);
  });

  it("refuses a sixth provider, because AWS-only is a decision and not an oversight", async () => {
    const fw = await rawFramework();
    const first = (fw["requirements"] as Record<string, unknown>[])[0]!;
    (first["checks"] as Record<string, unknown>)["oci"] = [];
    expect(() => parseProwlerKsiFramework(fw, "planted")).toThrow(/oci/);
  });

  it("refuses a ClassApplicability value it cannot interpret", async () => {
    const fw = await rawFramework();
    const first = (fw["requirements"] as Record<string, unknown>[])[0]!;
    (first["attributes"] as Record<string, unknown>)["ClassApplicability"] = "Required for Class D";
    expect(() => parseProwlerKsiFramework(fw, "planted")).toThrow(/Class D/);
  });
});

describe("P3-0 — the both-ways golden test (§2e, §4d)", () => {
  it("every id in the framework resolves at the dataset pin, and every KSI in the catalog appears in the framework", async () => {
    const [fw, cat] = await Promise.all([loadPinnedProwlerFramework(REPO_ROOT), catalog()]);
    const ids = fw.requirements.map((r) => r.id);
    expect(ids).toHaveLength(46);
    expect([...ids].sort()).toEqual(cat.ksis.map((k) => k.id));
    // and through the function the adapter will call, which names both directions
    expect(() => assertFrameworkMatchesCatalog(fw, cat.ksis.map((k) => k.id))).not.toThrow();
  });

  it("refuses a framework carrying an id the pinned catalog does not have — never skips it", async () => {
    // The adapter must not mint a method for an indicator off the board. This
    // is the refusal that makes "no crosswalk" (§2e) safe rather than lucky.
    const [fw, cat] = await Promise.all([loadPinnedProwlerFramework(REPO_ROOT), catalog()]);
    const planted = {
      ...fw,
      requirements: [...fw.requirements, { ...fw.requirements[0]!, id: "KSI-ZZZ-QQQ" }],
    };
    expect(() => assertFrameworkMatchesCatalog(planted, cat.ksis.map((k) => k.id))).toThrow(
      /KSI-ZZZ-QQQ/,
    );
  });

  it("refuses when the catalog carries an indicator the framework does not, naming it", async () => {
    const [fw, cat] = await Promise.all([loadPinnedProwlerFramework(REPO_ROOT), catalog()]);
    const dropped = { ...fw, requirements: fw.requirements.filter((r) => r.id !== "KSI-CED-RAT") };
    expect(() => assertFrameworkMatchesCatalog(dropped, cat.ksis.map((k) => k.id))).toThrow(
      /KSI-CED-RAT/,
    );
  });

  it("agrees with the catalog on the five indicators optional at class b", async () => {
    const [fw, cat] = await Promise.all([loadPinnedProwlerFramework(REPO_ROOT), catalog()]);
    expect(optionalAtClassB(fw)).toEqual([
      "KSI-CNA-EIS",
      "KSI-MLA-ALA",
      "KSI-SVC-PRR",
      "KSI-SVC-RUD",
      "KSI-SVC-VCM",
    ]);
    expect(optionalAtClassB(fw)).toEqual(optionalKsis(cat, "b"));
  });

  it("agrees with the catalog on all 373 KSI→control edges, and on the two indicators that reach none", async () => {
    // Not in the research note, and the strongest arm of the three: §2e
    // established that the ID SETS match both ways, which is what makes the
    // join legal. This says the two catalogs are the same catalog — every
    // row's control mapping is identical, 373 edges against 373.
    //
    // The fold is where the two spellings meet and nothing more: rampscan's
    // dataset canonicalises to `at-2.2`, Prowler keeps upstream's `AT-2.2`,
    // and neither is rewritten in place to make this pass.
    const [fw, cat] = await Promise.all([loadPinnedProwlerFramework(REPO_ROOT), catalog()]);
    const fold = (ids: readonly string[]) => [...ids].map((c) => c.toLowerCase()).sort();
    const disagree: string[] = [];
    let edges = 0;
    for (const req of fw.requirements) {
      const entry = cat.ksis.find((k) => k.id === req.id)!;
      edges += req.nistControls.length;
      if (fold(req.nistControls).join(",") !== fold(entry.controls).join(",")) {
        disagree.push(req.id);
      }
    }
    expect(disagree).toEqual([]);
    expect(edges).toBe(373);
    expect(edges).toBe(cat.ksis.reduce((n, k) => n + k.controls.length, 0));
    // and the two rows that omit the attribute are the two the catalog maps
    // no control to — upstream's optional attribute, used where FedRAMP has
    // nothing to put in it
    expect(fw.requirements.filter((r) => r.nistControls.length === 0).map((r) => r.id)).toEqual([
      "KSI-CNA-OFA",
      "KSI-PIY-RES",
    ]);
    expect(cat.ksis.filter((k) => k.controls.length === 0).map((k) => k.id)).toEqual([
      "KSI-CNA-OFA",
      "KSI-PIY-RES",
    ]);
  });

  it("states nothing about class a, and the test says so rather than comparing it", async () => {
    // FRC-CLA-MFR's seven-KSI subset is in the framework's prose and in no
    // field of any row, so a reader that filtered on ClassApplicability alone
    // would treat class A as class B. Pinned here so a re-pin that starts
    // stating it arrives as a failure to read, not as a silent new claim.
    const fw = await loadPinnedProwlerFramework(REPO_ROOT);
    const values = new Set(fw.requirements.map((r) => r.classApplicability));
    expect([...values].sort()).toEqual(["optional-b-required-c", "required-b-and-c"]);
    expect(fw.description).toMatch(/Class A authorizations mandate a subset of seven KSIs/);
  });
});

describe("P3-0 — the coverage §2c states, recomputed rather than quoted", () => {
  it("AWS reaches 33 of 46 indicators over 459 mappings on 443 distinct checks", async () => {
    const fw = await loadPinnedProwlerFramework(REPO_ROOT);
    const mapped = fw.requirements.filter((r) => checksFor(r, "aws").length > 0);
    const mappings = fw.requirements.reduce((n, r) => n + checksFor(r, "aws").length, 0);
    const distinct = new Set(fw.requirements.flatMap((r) => checksFor(r, "aws")));
    expect(mapped).toHaveLength(33);
    expect(mappings).toBe(459);
    expect(distinct.size).toBe(443);
  });

  it("the AWS-uncovered set is exactly the set no provider covers", async () => {
    const fw = await loadPinnedProwlerFramework(REPO_ROOT);
    expect(uncoveredKsis(fw, "aws")).toEqual(uncoveredKsis(fw));
    expect(uncoveredKsis(fw)).toHaveLength(13);
  });

  it("carries config_requirements on 24 rows, four of them empty — an empty array is not an absence", async () => {
    // §2a's shape listing did not have this key at all; the note is corrected
    // in this change. It matters twice over: it is the framework's own
    // statement of the config thresholds a scan must meet (§10d), and four
    // rows carry `[]`, which a reader that tested truthiness would count as
    // carrying requirements.
    const fw = await loadPinnedProwlerFramework(REPO_ROOT);
    const present = fw.requirements.filter((r) => r.configRequirements !== undefined);
    expect(present).toHaveLength(24);
    expect(present.filter((r) => r.configRequirements!.length === 0).map((r) => r.id)).toEqual([
      "KSI-IAM-SUS",
      "KSI-INR-RIR",
      "KSI-RPL-ARP",
      "KSI-SVC-EIS",
    ]);
  });
});

describe("P3-0 — the reviewed uncovered set (§4d)", () => {
  it("names exactly the thirteen the pinned framework leaves uncovered, with a basis each", async () => {
    const fw = await loadPinnedProwlerFramework(REPO_ROOT);
    const reviewed = ProwlerUncovered.parse(
      JSON.parse(await readFile(join(REPO_ROOT, PROWLER_UNCOVERED_PATH), "utf8")),
    );
    expect(reviewed.rows.map((r) => r.ksi)).toEqual(uncoveredKsis(fw));
    for (const row of reviewed.rows) {
      const req = fw.requirements.find((r) => r.id === row.ksi)!;
      expect(row.name).toBe(req.name);
    }
  });

  it("is pinned to the same bytes the loader is, so it cannot be re-stamped without a re-read", async () => {
    const reviewed = ProwlerUncovered.parse(
      JSON.parse(await readFile(join(REPO_ROOT, PROWLER_UNCOVERED_PATH), "utf8")),
    );
    expect(reviewed.framework_sha256).toBe(PROWLER_FRAMEWORK_PIN.sha256);
    expect(reviewed.framework_version).toBe(PROWLER_FRAMEWORK_PIN.version);
  });
});
