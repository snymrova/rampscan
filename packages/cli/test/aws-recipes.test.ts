import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { DEFAULT_DATASET_PIN, loadLocalDataset } from "@rampscan/dataset";
import { AwsConfig } from "@rampscan/schema";
import { DEFAULT_ALLOWLIST_PATH, loadAwsActionAllowlist } from "../src/aws-actions.js";
import { DEFAULT_BINDINGS_PATH, loadAwsLiteralBindings } from "../src/aws-bindings.js";
import { classifyAwsRecipes, loadAwsConfig, renderAwsRecipes, windowEnding } from "../src/aws-recipes.js";

// T1-5 (docs/PLAN-CLOUD-RUNNER.md, #171): `rampscan recipes --aws` prints
// the classification from the classifier itself. The counts here are the
// ones the plan's §1 table is replaced by, in the three readings an operator
// can be in: no config, a config with the account alone, and a config that
// supplies every name the table owes.

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const NOW = new Date("2026-09-15T12:00:00Z");

async function inputs() {
  const ds = await loadLocalDataset(join(REPO_ROOT, "docs/context/ramprules/derived"), DEFAULT_DATASET_PIN);
  return {
    recipes: ds.recipes(),
    list: await loadAwsActionAllowlist(join(REPO_ROOT, DEFAULT_ALLOWLIST_PATH)),
    table: await loadAwsLiteralBindings(join(REPO_ROOT, DEFAULT_BINDINGS_PATH)),
  };
}

const ACCOUNT = AwsConfig.parse({ account_id: "111111111111", partition: "aws", regions: ["us-east-1"] });

describe("T1-5 — rampscan recipes --aws prints the classification, computed (#171)", () => {
  it("no config: 22 of 57 runnable, 18 with assertions; the print names the refused recipes", async () => {
    const { recipes, list, table } = await inputs();
    const report = classifyAwsRecipes(recipes, list, table, undefined, windowEnding(NOW, 30), DEFAULT_DATASET_PIN);
    expect(report.runnable).toBe(22);
    expect(report.runnable_ksis).toBe(17);
    expect(report.runnable_with_assertions).toBe(18);
    expect(report.config).toBeUndefined();
    expect(report.window).toEqual({ start: "2026-08-16T12:00:00.000Z", end: "2026-09-15T12:00:00.000Z" });
    const text = renderAwsRecipes(report);
    expect(text).toContain("runnable  22 of 57 recipes, 17 KSIs — 18 carry upstream assertions and are judged by machine");
    expect(text).toContain("no `aws` block");
    expect(text).toContain("  clock-synchronization-and-timestamps  KSI-MLA-OSM");
    expect(text).toMatch(/refused action ssm send-command: executes a document/);
  });

  it("the account alone binds the reserved names: one more window recipe becomes runnable, and the owed list is upstream's placeholders too", async () => {
    const { recipes, list, table } = await inputs();
    const report = classifyAwsRecipes(recipes, list, table, ACCOUNT, windowEnding(NOW, 30), DEFAULT_DATASET_PIN);
    expect(report.runnable).toBe(23);
    expect(report.recipes.find((r) => r.id === "backup-restore-testing")!.result.kind).toBe("runnable");
    // the window, in ours and in upstream's spellings, is the appliance's
    for (const reserved of ["WINDOW_START", "START_TIME", "T0", "SINCE_EPOCH_MS", "ACCOUNT_ID", "REGION"]) {
      expect(report.owed_params, reserved).not.toContain(reserved);
    }
    // and what is owed is what the recipes actually name — the reviewed
    // table's `SECURITY_GROUP_ID` beside the fifty upstream now publishes
    expect(report.owed_params).toContain("SECURITY_GROUP_ID");
    expect(report.owed_params).toContain("DETECTOR_ID");
    expect(report.owed_params).toContain("TRAIL_NAME");
    expect(report.owed_params.length).toBe(53);
    expect(renderAwsRecipes(report)).toContain("config: account 111111111111 · partition aws · region us-east-1");
  });

  it("every owed name supplied: 54 of 57 run, and the only three left are the ones that would write", async () => {
    const { recipes, list, table } = await inputs();
    const params = Object.fromEntries(
      classifyAwsRecipes(recipes, list, table, ACCOUNT, windowEnding(NOW, 30), DEFAULT_DATASET_PIN).owed_params.map((n) => [n, `v-${n}`]),
    );
    const report = classifyAwsRecipes(recipes, list, table, { ...ACCOUNT, params }, windowEnding(NOW, 30), DEFAULT_DATASET_PIN);
    expect(report.owed_params).toEqual([]);
    expect(report.runnable).toBe(54);
    const manual = report.recipes.filter((r) => r.result.kind === "manual");
    // nothing is manual for a placeholder any more: `owed_params` names every
    // one, so a config that satisfies the print leaves only the refusals
    const reasons = new Set(manual.flatMap((r) => (r.result.kind === "manual" ? r.result.reasons.map((x) => x.kind) : [])));
    expect([...reasons].sort()).toEqual(["refused-action"]);
    expect(manual.map((r) => r.id).sort()).toEqual([
      "acquisition-scanning-and-sbom-inventory",
      "audit-reduction-and-report-generation",
      "clock-synchronization-and-timestamps",
    ]);
  });

  it("loadAwsConfig: absent → undefined, malformed → refused with the path named, valid → the block", async () => {
    const dir = await mkdtemp(join(tmpdir(), "rampscan-t15-"));
    expect(await loadAwsConfig(dir)).toBeUndefined();
    await writeFile(join(dir, "rampscan.config.json"), JSON.stringify({ aws: { account_id: "1", partition: "aws", regions: [] } }));
    await expect(loadAwsConfig(dir)).rejects.toThrow(/aws\.account_id/);
    await writeFile(join(dir, "rampscan.config.json"), JSON.stringify({ aws: { account_id: "111111111111", partition: "aws-us-gov", regions: ["us-gov-west-1"] } }));
    expect(await loadAwsConfig(dir)).toMatchObject({ partition: "aws-us-gov", params: {} });
  });
});
