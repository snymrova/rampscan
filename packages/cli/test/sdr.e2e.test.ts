import { execFile, execFileSync } from "node:child_process";
import { mkdtemp, mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { beforeAll, describe, expect, it } from "vitest";
import { repoFacts } from "@rampscan/collectors";
import { DEFAULT_DATASET_PIN } from "@rampscan/dataset";
import { scan } from "../src/scan.js";

// R2.1's exit, end to end through the real CLI (docs/PLAN-SDR.md §5, §7):
// a scanned repository declaring an authored artifact 1 gets a schema-valid
// Security Decision Record carrying that body; two runs at the same --as-of
// write the same bytes; `conformance` recognises the file by name; and an
// offering with no package overview address gets no file at all.
//
// KSI-CMT-VTD rather than the plan's KSI-SVC-SIN: repo-facts evidences it in
// this fixture, so the authored body and live evidence meet on one row, the
// same arrangement R1.4's exit gate uses.

const root = join(dirname(fileURLToPath(import.meta.url)), "../../..");
const tsx = join(root, "node_modules/.bin/tsx");
const KSI = "KSI-CMT-VTD";
const ARTIFACT_PATH = "docs/ksi/cmt-vtd-1.md";
const BODY = "## Vulnerability tracking\n\nDependency updates are automated and tested on every merge.\n";
const SDR_FILE = "fedramp-security-decision-record.json";

const gitEnv = {
  ...process.env,
  GIT_AUTHOR_NAME: "r21-test",
  GIT_AUTHOR_EMAIL: "r21@rampscan.invalid",
  GIT_COMMITTER_NAME: "r21-test",
  GIT_COMMITTER_EMAIL: "r21@rampscan.invalid",
};

const offering = {
  providerName: "Example Cloud Inc.",
  serviceName: "Example Evidence Plane",
  serviceAcronym: "EEP",
  serviceDescription: "A CI/CD evidence plane.",
  certificationType: "20x",
  fedRampPackageId: "Example Cloud Inc. (EEP)",
  website: "https://example.com/eep",
  logo: "https://example.com/logo.svg",
  serviceType: ["SaaS"],
  deploymentModel: "Public Cloud",
  contactInformation: [
    { contactType: "Security", contactName: "Security Team" },
    { contactType: "Sales", contactName: "Sales Team" },
  ],
  report: {
    certificationPackageOverviewUri: "https://trust.example.com/cpo.json",
    plannedCertificationDataChanges: { planningHorizonThrough: "2026-12-31", changes: [] },
    acceptedVulnerabilities: "none accepted",
    transformativeChanges: [],
    updatedRecommendations: [],
    activeAgencies: [],
    reportableIncidents: { incidents: [] },
  },
};

let base: string;
let appRoot: string;
let ledgerDir: string;
let asOf: string;

function git(...args: string[]): string {
  return execFileSync("git", args, { cwd: appRoot, env: gitEnv, encoding: "utf8" }).trim();
}

/** run the CLI; a nonzero exit is returned, not thrown — the refusal test wants it */
async function cli(...args: string[]): Promise<{ code: number; stdout: string; stderr: string }> {
  try {
    const { stdout, stderr } = await promisify(execFile)(tsx, ["packages/cli/src/main.ts", ...args], {
      cwd: root,
      env: { ...process.env, NO_COLOR: "1" },
      maxBuffer: 16 * 1024 * 1024,
    });
    return { code: 0, stdout, stderr };
  } catch (cause) {
    const c = cause as { code?: number; stdout?: string; stderr?: string };
    return { code: c.code ?? 1, stdout: c.stdout ?? "", stderr: c.stderr ?? "" };
  }
}

beforeAll(async () => {
  base = await mkdtemp(join(tmpdir(), "rampscan-r21-e2e-"));
  appRoot = join(base, "app");
  ledgerDir = join(base, "ledger");
  await mkdir(join(appRoot, "docs", "ksi"), { recursive: true });
  await mkdir(join(appRoot, ".github", "workflows"), { recursive: true });
  await writeFile(join(appRoot, "package.json"), JSON.stringify({ name: "r21-app", version: "1.0.0" }));
  await writeFile(
    join(appRoot, ".github", "workflows", "ci.yml"),
    ["on: push", "jobs:", "  t:", "    runs-on: ubuntu-latest", "    steps:", "      - run: npm test"].join("\n") + "\n",
  );
  await writeFile(join(appRoot, ARTIFACT_PATH), BODY);
  await writeFile(
    join(appRoot, "rampscan.config.json"),
    JSON.stringify({
      offering,
      artifacts: [
        { ksi: KSI, artifact: 1, path: ARTIFACT_PATH, description: "How vulnerabilities are tracked and remediated." },
      ],
    }),
  );
  git("init", "-q", "-b", "main");
  git("add", "-A");
  git("commit", "-qm", "app with a declared artifact and an offering");

  await scan({
    path: appRoot,
    outDir: join(base, "scan-out"),
    datasetDir: join(root, "docs/context/ramprules/derived"),
    datasetPin: DEFAULT_DATASET_PIN,
    recipesDir: join(root, "recipes/commit"),
    collectors: [repoFacts],
    ledgerDir,
    keysDir: join(base, "keys"),
    trigger: "test",
  });
  asOf = new Date(Date.now() + 60_000).toISOString();
}, 240_000);

describe("rampscan sdr, end to end (R2.1)", () => {
  it("writes a schema-valid record whose KSI row carries the authored body", async () => {
    const out = join(base, "out-a");
    const run = await cli("sdr", appRoot, "--ledger", ledgerDir, "--out", out, "--as-of", asOf);
    expect(run.code, run.stderr).toBe(0);
    expect(run.stdout).toContain(`${SDR_FILE} → schema-valid`);

    const doc = JSON.parse(await readFile(join(out, "exports/fedramp", SDR_FILE), "utf8")) as Record<string, unknown>;
    const row = (doc["keySecurityIndicators"] as Record<string, unknown>[]).find((k) => k["ksiId"] === KSI)!;
    const impl = row["ksiImplementation"] as string[];
    expect(impl[0]).toContain("authored; body sha256");
    expect(impl[0]).toContain(BODY);
    expect((row["ksiEvidence"] as unknown[]).length).toBeGreaterThan(0);
    expect((doc["metadata"] as Record<string, string>)["lastUpdated"]).toBe(asOf);
    expect((doc["x-rampscan"] as Record<string, Record<string, boolean>>)["conformance"]!["valid"]).toBe(true);
  }, 120_000);

  it("writes identical bytes on a second run at the same --as-of", async () => {
    const a = join(base, "out-b1");
    const b = join(base, "out-b2");
    expect((await cli("sdr", appRoot, "--ledger", ledgerDir, "--out", a, "--as-of", asOf)).code).toBe(0);
    expect((await cli("sdr", appRoot, "--ledger", ledgerDir, "--out", b, "--as-of", asOf)).code).toBe(0);
    const [x, y] = await Promise.all([
      readFile(join(a, "exports/fedramp", SDR_FILE), "utf8"),
      readFile(join(b, "exports/fedramp", SDR_FILE), "utf8"),
    ]);
    expect(x).toBe(y);
  }, 120_000);

  it("is recognised by conformance from its filename alone", async () => {
    const out = join(base, "out-c");
    await cli("sdr", appRoot, "--ledger", ledgerDir, "--out", out, "--as-of", asOf);
    const file = join(out, "exports/fedramp", SDR_FILE);
    // strip the stamp so only the filename can name the schema
    const doc = JSON.parse(await readFile(file, "utf8")) as Record<string, Record<string, unknown>>;
    delete doc["x-rampscan"]!["conformance"];
    await writeFile(file, JSON.stringify(doc));
    const run = await cli("conformance", file, "--json");
    expect(run.code, run.stdout + run.stderr).toBe(0);
    expect(JSON.parse(run.stdout).findings[0]).toMatchObject({ schemaSource: "filename", conformant: true });
  }, 120_000);

  it("writes nothing when the offering declares no package overview address, and names the key", async () => {
    const bare = join(base, "bare");
    await mkdir(bare, { recursive: true });
    const { report: _report, ...rest } = offering;
    await writeFile(join(bare, "rampscan.config.json"), JSON.stringify({ offering: rest }));
    const out = join(base, "out-d");
    const run = await cli("sdr", bare, "--ledger", ledgerDir, "--out", out, "--as-of", asOf);
    expect(run.code).toBe(1);
    expect(run.stdout).toMatch(/offering\.report\.certificationPackageOverviewUri/);
    await expect(readdir(join(out, "exports/fedramp"))).rejects.toThrow();
  }, 120_000);
});
