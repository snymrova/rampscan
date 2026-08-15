import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, mkdir, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import { repoFacts } from "@rampscan/collectors";
import { DEFAULT_DATASET_PIN } from "@rampscan/dataset";
import { computeEvidencePackage, scan, tar, verify } from "../src/index.js";
import type { EvidencePackage } from "../src/index.js";

// Export (plan I3e): the per-control evidence package. Built over a REAL
// scanned world (repo-facts only — no external tools, CI-safe), because the
// thing under test is whether the package an auditor downloads actually
// verifies, and a hand-built ledger would prove nothing about that.

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "../../..");
const gitEnv = {
  ...process.env,
  GIT_AUTHOR_NAME: "i3e-test",
  GIT_AUTHOR_EMAIL: "i3e@rampscan.invalid",
  GIT_COMMITTER_NAME: "i3e-test",
  GIT_COMMITTER_EMAIL: "i3e@rampscan.invalid",
};

let appRoot: string;
let ledgerDir: string;
let keysDir: string;
let outDir: string;

// ---------------------------------------------------------------------------
// tar: a fixed 512-byte layout, so pin the bytes
// ---------------------------------------------------------------------------

/** the reference reader: walk the archive back into { name → bytes } */
function untar(bytes: Uint8Array): Map<string, Uint8Array> {
  const out = new Map<string, Uint8Array>();
  const buffer = Buffer.from(bytes);
  for (let offset = 0; offset + 512 <= buffer.length; ) {
    const header = buffer.subarray(offset, offset + 512);
    const name = header.subarray(0, 100).toString("ascii").replace(/\0.*$/, "");
    if (name === "") break; // the terminating zero blocks
    const size = parseInt(header.subarray(124, 135).toString("ascii").trim(), 8);
    // the checksum must be the sum of the header with its own field spaced out
    const stated = parseInt(header.subarray(148, 156).toString("ascii").replace(/\0.*$/, "").trim(), 8);
    const spaced = Buffer.from(header);
    spaced.fill(0x20, 148, 156);
    let sum = 0;
    for (const byte of spaced) sum += byte;
    expect(sum, `checksum for ${name}`).toBe(stated);
    expect(header.subarray(257, 262).toString("ascii")).toBe("ustar");

    const start = offset + 512;
    out.set(name, new Uint8Array(buffer.subarray(start, start + size)));
    offset = start + Math.ceil(size / 512) * 512;
  }
  return out;
}

describe("tar", () => {
  it("round-trips names, bytes and padding, with valid ustar checksums", () => {
    const entries = [
      { name: "MANIFEST.json", bytes: Buffer.from('{"a":1}\n', "utf8") },
      { name: "bundles/deadbeef.envelope.json", bytes: Buffer.from("x".repeat(1000), "utf8") },
      { name: "empty.txt", bytes: new Uint8Array(0) },
    ];
    const archive = tar(entries, 1_700_000_000);

    // every member is a whole number of 512-byte blocks, plus two zero blocks
    expect(archive.length % 512).toBe(0);
    const read = untar(archive);
    expect([...read.keys()]).toEqual(entries.map((e) => e.name));
    for (const entry of entries) {
      expect(Buffer.from(read.get(entry.name)!)).toEqual(Buffer.from(entry.bytes));
    }
  });

  it("is byte-identical for the same entries at the same instant", () => {
    const entries = [{ name: "a.txt", bytes: Buffer.from("hello", "utf8") }];
    expect(Buffer.from(tar(entries, 42))).toEqual(Buffer.from(tar(entries, 42)));
  });

  it("refuses a member name ustar cannot represent rather than truncating it", () => {
    expect(() => tar([{ name: "a/".repeat(60), bytes: new Uint8Array(0) }], 0)).toThrow(
      /exceeds 100 bytes/,
    );
  });
});

// ---------------------------------------------------------------------------
// the evidence package, over a real scan
// ---------------------------------------------------------------------------

beforeAll(async () => {
  const base = await mkdtemp(join(tmpdir(), "rampscan-i3e-"));
  appRoot = join(base, "app");
  ledgerDir = join(base, "ledger");
  keysDir = join(base, "keys");
  outDir = join(base, "out");
  await mkdir(join(appRoot, ".github", "workflows"), { recursive: true });

  await writeFile(
    join(appRoot, "package.json"),
    JSON.stringify({ name: "i3e-app", version: "1.0.0" }, null, 2),
  );
  await writeFile(
    join(appRoot, "package-lock.json"),
    JSON.stringify({ name: "i3e-app", version: "1.0.0", lockfileVersion: 3, packages: {} }, null, 2),
  );
  await writeFile(
    join(appRoot, ".github", "workflows", "ci.yml"),
    ["name: ci", "on: [push]", "jobs:", "  test:", "    runs-on: ubuntu-latest", "    steps:", "      - uses: actions/checkout@v4", ""].join("\n"),
  );

  const git = (...args: string[]) =>
    execFileSync("git", args, { cwd: appRoot, env: gitEnv, encoding: "utf8" }).trim();
  git("init", "-q", "-b", "main");
  git("add", "-A");
  git("commit", "-q", "-m", "i3e fixture");

  await scan({
    path: appRoot,
    outDir,
    datasetDir: join(repoRoot, "docs/context/ramprules/derived"),
    datasetPin: DEFAULT_DATASET_PIN,
    recipesDir: join(repoRoot, "recipes/pipeline"),
    collectors: [repoFacts],
    ledgerDir,
    keysDir,
    now: new Date("2026-08-15T09:00:00.000Z"),
  });
});

async function pkg(overrides: Partial<Parameters<typeof computeEvidencePackage>[0]> = {}): Promise<EvidencePackage> {
  return computeEvidencePackage({
    ledgerDir,
    keysDir,
    recipesDir: join(repoRoot, "recipes/pipeline"),
    artifactsDir: join(outDir, "artifacts"),
    register: "controls",
    // si-7.1 is mapped by three repo-facts recipes with different verdicts —
    // exactly the mixed-state control an auditor samples
    id: "si-7.1",
    now: new Date("2026-08-15T10:00:00.000Z"),
    ...overrides,
  });
}

describe("computeEvidencePackage", () => {
  it("ships every mapped recipe — including the ones with no evidence", async () => {
    const { manifest } = await pkg();
    expect(manifest.id).toBe("si-7.1");
    expect(manifest.rows.length).toBe(manifest.counts.total);
    expect(manifest.rows.length).toBeGreaterThan(1);
    // the gap is part of the record: a package that carried only the good news
    // would be the screenshot folder this product exists to replace
    const states = new Set(manifest.rows.map((r) => r.state));
    expect(states.size).toBeGreaterThan(1);
    for (const row of manifest.rows.filter((r) => r.state === "unevidenced")) {
      expect(row.digest).toBeUndefined();
      expect(row.problems.join(" ")).toMatch(/no evidence bundle/);
    }
  });

  it("carries the ledger's EXACT envelope bytes, and they verify offline", async () => {
    const { bytes, manifest } = await pkg();
    const files = untar(bytes);

    const signed = manifest.rows.filter((r) => r.envelopePath);
    expect(signed.length).toBeGreaterThan(0);
    for (const row of signed) {
      const inPackage = files.get(row.envelopePath!)!;
      expect(inPackage, row.recipeId).toBeDefined();
      // byte-for-byte the object store's file, never a re-serialization
      const onDisk = await readFile(join(ledgerDir, "objects", `${row.digest}.envelope.json`));
      expect(Buffer.from(inPackage)).toEqual(onDisk);

      // and the payload really is the statement at that address
      const envelope = JSON.parse(Buffer.from(inPackage).toString("utf8")) as { payload: string };
      const payload = Buffer.from(envelope.payload, "base64");
      expect(createHash("sha256").update(payload).digest("hex")).toBe(row.digest);
    }

    // the same check rampscan verify runs, on a digest taken from the package
    const report = await verify({ digest: signed[0]!.digest!, ledgerDir, keysDir });
    expect(report.ok, report.lines.join("\n")).toBe(true);
  });

  it("ships the public key so verification needs nothing else from this machine", async () => {
    const files = untar((await pkg()).bytes);
    expect(Buffer.from(files.get("rampscan.pub")!).toString("utf8")).toContain("BEGIN PUBLIC KEY");
    expect(Buffer.from(files.get("VERIFY.md")!).toString("utf8")).toContain("Verify without rampscan");
  });

  it("matches artifacts by DIGEST and ships the bytes that match", async () => {
    const { bytes, manifest } = await pkg();
    const files = untar(bytes);
    const shipped = manifest.rows
      .flatMap((r) => r.artifacts)
      .filter((a) => a.kind === "artifact" && a.path);
    expect(shipped.length).toBeGreaterThan(0);
    for (const artifact of shipped) {
      const inPackage = files.get(artifact.path!)!;
      expect(inPackage, artifact.name).toBeDefined();
      expect(createHash("sha256").update(inPackage).digest("hex")).toBe(artifact.sha256);
    }
  });

  it("refuses a same-named artifact from a later run instead of shipping it", async () => {
    // the scan output dir is overwritten by later runs; a file that merely
    // shares a name is not the artifact that was attested
    const poisoned = join(outDir, "artifacts", "repo-facts", "repo-facts.json");
    const original = await readFile(poisoned);
    await writeFile(poisoned, '{"from":"a later run"}');
    try {
      const { manifest, bytes } = await pkg();
      const facts = manifest.rows
        .flatMap((r) => r.artifacts)
        .filter((a) => a.name === "repo-facts.json");
      expect(facts.length).toBeGreaterThan(0);
      for (const artifact of facts) {
        expect(artifact.path).toBeUndefined();
        expect(artifact.missing).toMatch(/later run/);
      }
      // and nothing under artifacts/ made it into the archive
      expect([...untar(bytes).keys()].some((n) => n.startsWith("artifacts/"))).toBe(false);
    } finally {
      await writeFile(poisoned, original);
    }
  });

  it("names anchors as repo content and does not bundle source", async () => {
    const { manifest, bytes } = await pkg();
    const anchors = manifest.rows.flatMap((r) => r.artifacts).filter((a) => a.kind === "anchor");
    expect(anchors.length).toBeGreaterThan(0);
    for (const anchor of anchors) {
      expect(anchor.path).toBeUndefined();
      expect(anchor.missing).toMatch(/^repo content at commit \w+ — not shipped; `git show /);
    }
    const files = untar(bytes);
    // package.json is an anchor here — it must not be in the archive
    expect([...files.keys()].some((n) => n.endsWith("/package.json"))).toBe(false);
  });

  it("says why artifacts are absent when no scan output dir is configured", async () => {
    const { manifest } = await computeEvidencePackage({
      ledgerDir,
      keysDir,
      recipesDir: join(repoRoot, "recipes/pipeline"),
      register: "controls",
      id: "si-7.1",
      now: new Date("2026-08-15T10:00:00.000Z"),
    });
    const artifacts = manifest.rows.flatMap((r) => r.artifacts).filter((a) => a.kind === "artifact");
    expect(artifacts.length).toBeGreaterThan(0);
    for (const artifact of artifacts) {
      expect(artifact.missing).toMatch(/no scan output dir configured/);
    }
  });

  it("refuses an id the register does not hold, as an answer not a crash", async () => {
    await expect(pkg({ id: "zz-99" })).rejects.toThrow(/no control "zz-99" in the register/);
  });

  it("works the same for a KSI rollup, and the filename dates itself", async () => {
    const { manifest, filename } = await pkg({ register: "ksis", id: "KSI-SCR-MIT" });
    expect(manifest.register).toBe("ksis");
    expect(manifest.rows.length).toBe(manifest.counts.total);
    expect(filename).toBe("rampscan-evidence-ksi-ksi-scr-mit-2026-08-15.tar");
  });

  it("counts in the manifest agree with a recount from its own rows", async () => {
    const { manifest } = await pkg();
    const recount = {
      evidenced: manifest.rows.filter((r) => r.state === "evidenced").length,
      violated: manifest.rows.filter((r) => r.state === "violated").length,
      unevidenced: manifest.rows.filter((r) => r.state === "unevidenced").length,
      notApplicable: manifest.rows.filter((r) => r.state === "notApplicable").length,
      total: manifest.rows.length,
    };
    expect(recount).toEqual(manifest.counts);
  });
});
