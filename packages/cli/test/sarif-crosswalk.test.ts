import { readFile, readdir } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import { loadToolManifest } from "@rampscan/collectors";
import { DEFAULT_DATASET_PIN, loadKsiCatalog } from "@rampscan/dataset";
import type { SarifCrosswalk } from "@rampscan/schema";
import { SarifCrosswalk as CrosswalkSchema, sarifCrosswalkName, sarifRuleIndex } from "@rampscan/schema";

// The SARIF crosswalks over the real pins (docs/PLAN-REACH.md N2-2): each is
// named for its tool and version, files only rule ids the pinned version's
// vendored list carries, files each under exactly one catalog KSI, and — for
// the tool rampscan runs itself — is pinned to the image tools.json runs.

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const CROSSWALKS = join(REPO_ROOT, "recipes/crosswalks");

interface RuleList {
  tool: string;
  version: string;
  checks: Array<{ id: string }>;
}

let crosswalks: Array<{ file: string; cw: SarifCrosswalk; rules: RuleList }>;
let ksiIds: Set<string>;

beforeAll(async () => {
  const files = (await readdir(CROSSWALKS)).filter((f) => /^sarif-.+\.json$/.test(f) && !f.endsWith("-rules.json")).sort();
  crosswalks = await Promise.all(
    files.map(async (file) => {
      const cw = CrosswalkSchema.parse(JSON.parse(await readFile(join(CROSSWALKS, file), "utf8")));
      const rules = JSON.parse(
        await readFile(join(CROSSWALKS, file.replace(/\.json$/, "-rules.json")), "utf8"),
      ) as RuleList;
      return { file, cw, rules };
    }),
  );
  const catalog = await loadKsiCatalog({
    derivedDir: join(REPO_ROOT, "docs/context/ramprules/derived"),
    rulesFile: join(REPO_ROOT, "docs/context/fedramp-rules/fedramp-consolidated-rules.json"),
    pin: DEFAULT_DATASET_PIN,
  });
  ksiIds = new Set(catalog.ksis.map((k) => k.id));
});

describe("the SARIF crosswalks over the real pins", () => {
  it("there are two — semgrep (rampscan's own SAST, round-tripped) and zizmor — each named for its tool and version", () => {
    expect(crosswalks.map((c) => c.file)).toEqual(["sarif-semgrep-oss-1.173.0.json", "sarif-zizmor-1.30.1.json"]);
    for (const { file, cw } of crosswalks) expect(`${sarifCrosswalkName(cw)}.json`).toBe(file);
  });

  it("every rule id filed exists in the pinned version's vendored rule list, and is filed once", () => {
    for (const { file, cw, rules } of crosswalks) {
      expect(rules.tool, file).toBe(cw.tool);
      expect(rules.version, file).toBe(cw.version);
      const known = new Set(rules.checks.map((c) => c.id));
      const unknown = cw.entries.filter((e) => !known.has(e.rule)).map((e) => e.rule);
      expect(unknown, `${file}: rule ids the pinned ${cw.tool} does not carry`).toEqual([]);
      expect(() => sarifRuleIndex(cw)).not.toThrow();
    }
  });

  it("zizmor's crosswalk files every audit the pinned version documents — a log carrying an unfiled audit is refused, so none may be left unread", () => {
    const { cw, rules } = crosswalks.find((c) => c.cw.tool === "zizmor")!;
    expect(cw.entries.map((e) => e.rule).sort()).toEqual(rules.checks.map((c) => c.id).sort());
  });

  it("every KSI filed under is in the catalog at this pin, and every crosswalk resolves to it", () => {
    for (const { file, cw } of crosswalks) {
      expect(cw.to, file).toBe(DEFAULT_DATASET_PIN);
      for (const e of cw.entries) expect(ksiIds.has(e.ksi), `${file}: ${e.rule} → ${e.ksi}`).toBe(true);
    }
  });

  it("the semgrep crosswalk is pinned to the image rampscan's own collector runs, and files the vendored ruleset's ids", async () => {
    const manifest = await loadToolManifest();
    const { cw, rules } = crosswalks.find((c) => c.cw.tool === "Semgrep OSS")!;
    expect(cw.version).toBe(manifest["semgrep"]?.version);
    const yaml = await readFile(join(REPO_ROOT, "packages/collectors/semgrep-rules.yaml"), "utf8");
    const ids = [...yaml.matchAll(/^\s*- id:\s*(\S+)/gm)].map((m) => m[1]!).sort();
    expect(rules.checks.map((c) => c.id)).toEqual(ids);
    expect(cw.entries.map((e) => e.rule).sort()).toEqual(ids);
  });

  it("every crosswalk observes the commit plane — a client's log over the checkout is the pipeline's plane, not a second one", () => {
    for (const { cw } of crosswalks) expect(cw.plane).toBe("commit");
  });
});
