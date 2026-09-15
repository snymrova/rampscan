import { createHash } from "node:crypto";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { allCollectors } from "@rampscan/collectors";
import { DEFAULT_DATASET_PIN, loadKsiCatalog } from "@rampscan/dataset";
import { createLocalLedger } from "@rampscan/ledger";
import { createProjector } from "@rampscan/projector";
import { KsiCrosswalk, isEvidenceBundle, methodOfIngestedBundle } from "@rampscan/schema";
import { ingest, loadSubmissions } from "../src/ingest.js";
import { deriveCatalogMethods, loadRecipes } from "../src/recipes.js";
import { verify } from "../src/verify.js";

// The package adapter (SPEC §12.8, plan S3-1): `rampscan ingest <package.yaml>`
// over a machine-readable assessment package — the shape the only publicly
// assessed 20x package is published in (docs/RESEARCH-PARAMIFY-PILOT.md §2),
// which ships no Evidence/ tree, only the assessed package. What the adapter
// must and must not sign:
//
//   - one submission per (validation KSI × evidence), crosswalked to the
//     pinned catalog when the package's KSI ids are an earlier catalog's —
//     one Phase One indicator can land on two 2026 KSIs, or on none;
//   - no assertion, ever: the package carries a person's reading
//     (`assessmentStatus`, `validationRules: []` — §8.1), which is not a
//     machine assertion the appliance evaluated. Every bundle is
//     `unevidenced`, and the method it derives is NOT automated — the
//     FRC-CSX-VVK numerator moves by zero when a package is ingested,
//     however many of its evidences a script produced;
//   - `point-in-time`, uniformly: an assessment package is a captured state
//     at effectiveDate, whatever produced the capture;
//   - the digested subject is the package file itself — the bytes the
//     appliance actually holds; the artifacts the package names are carried
//     by reference, never given an invented digest.
//
// The fixture is ours (fixtures/ingest-package/README.md): shapes only.

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const PACKAGE = join(REPO_ROOT, "fixtures/ingest-package/synthetic-package.yaml");
const CROSSWALK = join(REPO_ROOT, "recipes/crosswalks/ksi-phase-one-to-2026.07.14.01.json");
const RECIPES_DIR = join(REPO_ROOT, "recipes/commit");
const DATASET_DIR = join(REPO_ROOT, "docs/context/ramprules/derived");
const RULES_FILE = join(REPO_ROOT, "docs/context/fedramp-rules/fedramp-consolidated-rules.json");

const base = {
  path: PACKAGE,
  repo: "synthetic-csp/offering",
  datasetDir: DATASET_DIR,
  rulesFile: RULES_FILE,
  datasetPin: DEFAULT_DATASET_PIN,
  crosswalk: CROSSWALK,
  cadence: "monthly" as const,
};

async function work(): Promise<{ ledgerDir: string; keysDir: string; dir: string }> {
  const dir = await mkdtemp(join(tmpdir(), "rampscan-s31-"));
  return { dir, ledgerDir: join(dir, "ledger"), keysDir: join(dir, "keys") };
}

describe("ingest package adapter — an assessed package becomes ledger citizens (S3-1)", () => {
  it("mints one submission per (crosswalked KSI × evidence), and skips what has no successor", async () => {
    const { submissions, skipped } = await loadSubmissions(PACKAGE, {
      crosswalk: CROSSWALK,
      cadence: "monthly",
      datasetPin: DEFAULT_DATASET_PIN,
    });
    // CNA-01: three evidences → KSI-CNA-RNT; PIY-06: one evidence → two KSIs;
    // IAM-01: one evidence → KSI-IAM-APM; SVC-07: no 2026 successor
    expect(submissions.map((s) => `${s.recipe_id}#${s.ksi}`).sort()).toEqual([
      "idp-authenticator-settings#KSI-IAM-APM",
      "network-acl-console-screenshot#KSI-CNA-RNT",
      "security-budget-memo#KSI-PIY-RES",
      "security-budget-memo#KSI-PIY-RIS",
      "security-group-rules#KSI-CNA-RNT",
      "security-group-rules~2#KSI-CNA-RNT",
    ]);
    expect(skipped).toEqual([
      expect.objectContaining({
        ksi: "SVC-07",
        script: "patch-policy",
        reason: expect.stringMatching(/no 2026\.07\.14\.01 successor.*FRR-VDR/),
      }),
    ]);
  });

  it("signs nothing it did not evaluate: no assertions, point-in-time, not automated, the assessor as signer", async () => {
    const { submissions } = await loadSubmissions(PACKAGE, {
      crosswalk: CROSSWALK,
      cadence: "monthly",
      datasetPin: DEFAULT_DATASET_PIN,
    });
    const packageDigest = createHash("sha256").update(await readFile(PACKAGE)).digest("hex");
    for (const s of submissions) {
      expect(s.assertions).toEqual([]);
      expect(s.evidence_class).toBe("point-in-time");
      expect(s.automated).toBe(false);
      expect(s.cadence).toBe("monthly");
      expect(s.signer_identity).toBe("Synthetic 3PAO: A. Assessor");
      // the package file is the one artifact the appliance holds bytes for
      expect(s.artifacts[0]).toEqual({ name: basename(PACKAGE), sha256: packageDigest });
    }
    const sg = submissions.find((s) => s.recipe_id === "security-group-rules")!;
    // the named artifacts ride by reference — a URL and a file name, no digest
    expect(sg.artifacts.slice(1)).toEqual([
      {
        name: "Untitled Artifact",
        reference: "https://example.invalid/synthetic-csp/evidence/security_groups.sh",
      },
      { name: "Security Groups", reference: "security_groups.json" },
    ]);
    // the run's clock is the latest capture the evidence names
    expect(sg.timestamp).toBe("2026-06-18T00:00:00.000Z");
    expect(sg.reproduce).toMatch(/^1\. aws ec2 describe-security-groups/);
    // an artifact named without a reference or a date: carried by name, and
    // the timestamp falls back to the assessment's own date (6/30/26)
    const idp = submissions.find((s) => s.recipe_id === "idp-authenticator-settings")!;
    expect(idp.artifacts.slice(1)).toEqual([{ name: "IdP Authenticators" }]);
    expect(idp.timestamp).toBe("2026-06-30T00:00:00.000Z");
  });

  it("appends unevidenced bundles whose derived methods are non-automated, and they verify offline", async () => {
    const { ledgerDir, keysDir } = await work();
    const lines: string[] = [];
    const outcome = await ingest({ ...base, ledgerDir, keysDir, log: (l) => lines.push(l) });
    expect(outcome.appended).toHaveLength(6);
    expect(outcome.skipped).toHaveLength(1);
    for (const record of outcome.appended) expect(record.verdict).toBe("unevidenced");

    const ledger = createLocalLedger(ledgerDir);
    for (const record of outcome.appended) {
      const entry = (await ledger.get(record.digest))!;
      if (!isEvidenceBundle(entry.bundle)) throw new Error("not an evidence bundle");
      const method = methodOfIngestedBundle(entry.bundle.predicate);
      expect(method.automated).toBe(false);
      expect(method.clock).toBe("non-machine");
      expect(entry.bundle.predicate.ingest?.automated).toBe(false);
      // subjects are the digested artifacts only — the package file
      expect(entry.bundle.subject).toHaveLength(1);
      expect(entry.bundle.subject[0]!.name).toBe(basename(PACKAGE));
      const report = await verify({ digest: record.digest, ledgerDir, keysDir });
      expect(report.ok).toBe(true);
    }
    expect(lines.at(-1)).toMatch(/6 bundle\(s\) appended, 0 unchanged, 1 skipped/);
    // ingesting the same package again re-signs nothing
    const again = await ingest({ ...base, ledgerDir, keysDir });
    expect(again.appended).toHaveLength(0);
    expect(again.unchanged).toHaveLength(6);
  });

  it("moves the register's method count and not its automated count (FRC-CSX-VVK)", async () => {
    const { dir, ledgerDir, keysDir } = await work();
    const catalog = await loadKsiCatalog({
      derivedDir: DATASET_DIR,
      rulesFile: RULES_FILE,
      pin: DEFAULT_DATASET_PIN,
    });
    const recipes = await loadRecipes(RECIPES_DIR);
    const methods = deriveCatalogMethods(recipes, allCollectors.map((c) => c.manifest));
    const projector = createProjector({
      recipes,
      methods,
      ksiIds: catalog.ksis.map((k) => k.id),
      methodFloor: catalog.floors.b.minPerKsi,
      machineWindow: catalog.windows.b,
      nonMachineWindow: catalog.nonMachineWindow,
    });
    const before = await projector.fold(createLocalLedger(ledgerDir));
    await ingest({ ...base, ledgerDir, keysDir });
    const after = await projector.fold(createLocalLedger(ledgerDir));
    const row = (fold: typeof after, ksi: string) =>
      fold.methodRegisters.find((r) => r.repo === base.repo && r.ksi === ksi);

    // KSI-CNA-RNT gained three methods and zero automated ones
    const cna = row(after, "KSI-CNA-RNT")!;
    const cnaBefore = row(before, "KSI-CNA-RNT");
    expect(cna.methods.length).toBe((cnaBefore?.methods.length ?? 0) + 3);
    expect(cna.automatedMethods).toBe(cnaBefore?.automatedMethods ?? 0);
    const ingested = cna.methods.filter((m) => m.source === "aws-ingested");
    expect(ingested).toHaveLength(3);
    for (const cell of ingested) {
      expect(cell.state).toBe("unevidenced");
      expect(cell.automated).toBe(false);
      expect(cell.clock).toBe("non-machine");
      expect(cell.evidenceClass).toBe("point-in-time");
    }
    // one Phase One indicator, two 2026 KSIs: the same evidence counts on both
    expect(row(after, "KSI-PIY-RES")!.methods.map((m) => m.recipeId)).toContain("security-budget-memo");
    expect(row(after, "KSI-PIY-RIS")!.methods.map((m) => m.recipeId)).toContain("security-budget-memo");
    void dir;
  });

  it("refuses a package it cannot place: no crosswalk for an earlier catalog, a crosswalk to another pin, an indicator the crosswalk does not carry, no cadence", async () => {
    const { ledgerDir, keysDir } = await work();
    await expect(ingest({ ...base, ledgerDir, keysDir, crosswalk: undefined })).rejects.toThrow(
      /does not resolve in dataset[\s\S]*--crosswalk/,
    );
    await expect(ingest({ ...base, ledgerDir, keysDir, cadence: undefined })).rejects.toThrow(
      /--cadence/,
    );
    const raw = JSON.parse(await readFile(CROSSWALK, "utf8")) as KsiCrosswalk;
    const { dir } = await work();
    const { writeFile } = await import("node:fs/promises");
    const otherPin = join(dir, "other-pin.json");
    await writeFile(otherPin, JSON.stringify({ ...raw, to: "1999.01.01.01" }));
    await expect(ingest({ ...base, ledgerDir, keysDir, crosswalk: otherPin })).rejects.toThrow(
      /1999\.01\.01\.01.*2026\.07\.14\.01/,
    );
    const missing = join(dir, "missing.json");
    await writeFile(
      missing,
      JSON.stringify({ ...raw, entries: raw.entries.filter((e) => e.from !== "IAM-01") }),
    );
    await expect(ingest({ ...base, ledgerDir, keysDir, crosswalk: missing })).rejects.toThrow(
      /IAM-01/,
    );
  });
});

describe("the Phase One → 2026.07.14.01 crosswalk is a reviewed artifact", () => {
  it("resolves every successor in the pinned catalog, names each indicator once, and says where the retired ones went", async () => {
    const crosswalk = KsiCrosswalk.parse(JSON.parse(await readFile(CROSSWALK, "utf8")));
    expect(crosswalk.to).toBe(DEFAULT_DATASET_PIN);
    const catalog = await loadKsiCatalog({
      derivedDir: DATASET_DIR,
      rulesFile: RULES_FILE,
      pin: DEFAULT_DATASET_PIN,
    });
    const known = new Set(catalog.ksis.map((k) => k.id));
    const froms = crosswalk.entries.map((e) => e.from);
    expect(new Set(froms).size).toBe(froms.length);
    for (const entry of crosswalk.entries) {
      for (const to of entry.to) expect(known.has(to), `${entry.from} → ${to}`).toBe(true);
      if (entry.to.length === 0) expect(entry.basis).toMatch(/no 2026 KSI states it/);
    }
  });
});
