import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { DEFAULT_DATASET_PIN, loadLocalDataset } from "@rampscan/dataset";
import type { AwsRecipe } from "@rampscan/dataset";
import { AwsConfig } from "@rampscan/schema";
import type { AwsActionAllowlist, AwsLiteralBindings } from "@rampscan/schema";
import { DEFAULT_ALLOWLIST_PATH, loadAwsActionAllowlist } from "../src/aws-actions.js";
import {
  DEFAULT_BINDINGS_PATH,
  applyLiteralBindings,
  bindAwsParams,
  loadAwsLiteralBindings,
  unboundParamsOf,
} from "../src/aws-bindings.js";
import { classifyAwsRecipe, placeholdersOf } from "../src/aws-classify.js";

// T1-3 (docs/PLAN-CLOUD-RUNNER.md, #169): the reviewed literal table is
// golden against the overlay both ways — every row's literal still occurs
// in its recipe (no stale row), and after the rewrite no known example
// literal survives in any command. Then the classifier's count with the
// table applied, which is the number T1-5 prints: what "runnable as
// published" means once a stranger's account id is a placeholder.

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");

let cachedList: AwsActionAllowlist | undefined;
let cachedTable: AwsLiteralBindings | undefined;
async function list(): Promise<AwsActionAllowlist> {
  cachedList ??= await loadAwsActionAllowlist(join(REPO_ROOT, DEFAULT_ALLOWLIST_PATH));
  return cachedList;
}
async function table(): Promise<AwsLiteralBindings> {
  cachedTable ??= await loadAwsLiteralBindings(join(REPO_ROOT, DEFAULT_BINDINGS_PATH));
  return cachedTable;
}
async function recipes(): Promise<AwsRecipe[]> {
  const ds = await loadLocalDataset(join(REPO_ROOT, "docs/context/ramprules/derived"), DEFAULT_DATASET_PIN);
  return ds.recipes();
}
/** the published text of each step — the `run`, the only half a binding rewrites */
const commandsOf = (r: Pick<AwsRecipe, "collection">) => (r.collection.commands ?? []).map((c) => c.run);

/** the tells of an example literal: the documentation's account ids, `my-…`, `EXAMPLE`, an example resource id, a fixed date */
const EXAMPLE_TELLS = [
  /\b123456789012\b/,
  /\b111122223333\b/,
  /\bmy-[a-z-]+\b/,
  /EXAMPLE/,
  /\b(i|sg)-0123456789abcdef0\b/,
  /\b20\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ\b/,
  /\b1[67]\d{8}\b/,
];

const CONFIG = AwsConfig.parse({
  account_id: "111111111111",
  partition: "aws",
  regions: ["us-east-1", "us-west-2"],
  params: { INSTANCE_ARN: "arn:aws:sso:::instance/ssoins-1", CLOUDTRAIL_BUCKET: "acme-trail-logs" },
});
const WINDOW = { start: "2026-08-16T00:00:00Z", end: "2026-09-15T00:00:00Z" };

describe("T1-3 — the reviewed literal table is golden against the overlay (#169)", () => {
  it("no row is stale: every literal still occurs in its recipe's published commands", async () => {
    const t = await table();
    const rs = await recipes();
    const byId = new Map(rs.map((r) => [r.id, r]));
    const unknownRecipe = t.entries.filter((e) => !byId.has(e.recipe)).map((e) => e.recipe);
    expect(unknownRecipe).toEqual([]);
    const stale = rs.flatMap((r) => applyLiteralBindings(r, t).stale.map((row) => `${row.recipe}: ${row.literal}`));
    expect(stale).toEqual([]);
    expect(t.dataset).toBe(DEFAULT_DATASET_PIN);
  });

  it("after the rewrite no example literal survives in any command, and every placeholder is well-formed", async () => {
    const t = await table();
    const rs = await recipes();
    const survivors: string[] = [];
    for (const r of rs) {
      for (const c of commandsOf(applyLiteralBindings(r, t).recipe)) {
        for (const tell of EXAMPLE_TELLS) {
          const m = tell.exec(c);
          if (m) survivors.push(`${r.id}: ${m[0]} in: ${c.slice(0, 80)}`);
        }
        for (const name of placeholdersOf(c)) expect(name).toMatch(/^[A-Za-z][A-Za-z0-9_-]*$/);
      }
    }
    expect(survivors).toEqual([]);
  });

  it("a `becomes` row keeps the fixed text around the variable part", async () => {
    const t = await table();
    const rs = await recipes();
    const ddos = applyLiteralBindings(rs.find((r) => r.id === "ddos-protection-and-rate-limiting")!, t).recipe;
    const waf = commandsOf(ddos).find((c) => c.includes("AWS/WAFV2"))!;
    expect(waf).toContain("Name=Region,Value=<REGION>");
    // Shield's endpoint region is not an example and is left as published
    expect(commandsOf(ddos).filter((c) => c.includes("shield")).every((c) => c.includes("--region us-east-1"))).toBe(true);
    const audit = applyLiteralBindings(rs.find((r) => r.id === "audit-reduction-and-report-generation")!, t).recipe;
    expect(commandsOf(audit).find((c) => c.includes("athena"))).toContain("OutputLocation=<AUDIT_REPORTS_URI>/athena/");
  });

  it("with the table applied and nothing bound, the classifier's count is what T1-5 prints", async () => {
    const l = await list();
    const t = await table();
    const rs = await recipes();
    const runnable = rs.filter((r) => classifyAwsRecipe(applyLiteralBindings(r, t).recipe, l).kind === "runnable");
    // computed, never typed: of 57 recipes, the ones that need no placeholder
    // at all. `patch-and-vulnerability-remediation` is not among them — its
    // example instance id is rewritten to `<INSTANCE_ID>` by the table below
    expect(runnable).toHaveLength(22);
    expect(runnable.map((r) => r.id)).not.toContain("patch-and-vulnerability-remediation");
  });

  // Overlay 4.3.0 publishes placeholders of its own where it used to publish
  // example literals, and it spells the request's window in five ways: ISO
  // 8601 as `START_TIME`/`END_TIME` and as `T0`/`T1`, epoch seconds as
  // `START_EPOCH`/`END_EPOCH` and as `SINCE_EPOCH`, and epoch milliseconds as
  // `SINCE_EPOCH_MS` (GuardDuty's numeric `updatedAt` criterion). They are the
  // appliance's to bind, not the operator's — a config cannot hold the window
  // of a request that has not been made — so they are reserved and derived
  // here. Left to `aws.params` they would be permanently unbound, and a dozen
  // recipes would read as manual for a reason that was really ours.
  it("the window binds upstream's own spellings of it, in seconds and in milliseconds", () => {
    const params = bindAwsParams(CONFIG, WINDOW);
    expect(params).toMatchObject({
      START_TIME: WINDOW.start,
      END_TIME: WINDOW.end,
      T0: WINDOW.start,
      T1: WINDOW.end,
      START_EPOCH: "1786838400",
      END_EPOCH: "1789430400",
      SINCE_EPOCH: "1786838400",
      SINCE_EPOCH_MS: "1786838400000",
    });
    // and none of them is the operator's to set
    for (const name of ["START_TIME", "T1", "SINCE_EPOCH_MS"]) {
      expect(() => AwsConfig.parse({ ...CONFIG, params: { [name]: "x" } }), name).toThrow(/reserved/);
    }
  });

  it("bindAwsParams: reserved names from the account and the window, the rest from aws.params, nothing overridable", () => {
    const params = bindAwsParams(CONFIG, WINDOW);
    expect(params).toMatchObject({
      ACCOUNT_ID: "111111111111",
      PARTITION: "aws",
      REGION: "us-east-1",
      WINDOW_START: WINDOW.start,
      WINDOW_END: WINDOW.end,
      EPOCH_START: "1786838400",
      EPOCH_END: "1789430400",
      INSTANCE_ARN: "arn:aws:sso:::instance/ssoins-1",
    });
    expect(() => AwsConfig.parse({ ...CONFIG, params: { ACCOUNT_ID: "222222222222" } })).toThrow(/reserved/);
    expect(() => AwsConfig.parse({ ...CONFIG, account_id: "12345" })).toThrow();
    expect(() => AwsConfig.parse({ ...CONFIG, region: "us-east-1" })).toThrow();
  });

  it("a recipe whose example account id became <ACCOUNT_ID> runs with the configured account, never the example", async () => {
    const l = await list();
    const t = await table();
    const rs = await recipes();
    const patch = applyLiteralBindings(rs.find((r) => r.id === "patch-and-vulnerability-remediation")!, t).recipe;
    const params = bindAwsParams({ ...CONFIG, params: { INSTANCE_ID: "i-0aaaabbbbccccdddd" } }, WINDOW);
    const c = classifyAwsRecipe(patch, l, params);
    expect(c.kind).toBe("runnable");
    if (c.kind === "runnable") {
      const inspector = c.steps.find((s) => s.argv[1] === "inspector2")!;
      expect(inspector.argv).toEqual(["aws", "inspector2", "batch-get-account-status", "--account-ids", "111111111111"]);
      expect(c.steps.flatMap((s) => s.argv).join(" ")).not.toContain("123456789012");
    }
  });

  it("unboundParamsOf names what the config still owes for the table's non-reserved names", async () => {
    const t = await table();
    const owed = unboundParamsOf(t, bindAwsParams(CONFIG, WINDOW));
    // the window and the region are the appliance's; a resource id is the operator's
    expect(owed).not.toContain("WINDOW_START");
    expect(owed).not.toContain("REGION");
    expect(owed).toContain("SECURITY_GROUP_ID");
    expect(owed).toContain("AUDIT_REPORTS_URI");
  });
});
