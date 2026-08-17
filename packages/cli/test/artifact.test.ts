import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, mkdir, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import { repoFacts } from "@rampscan/collectors";
import { DEFAULT_DATASET_PIN } from "@rampscan/dataset";
import { createLocalLedger } from "@rampscan/ledger";
import { isEvidenceBundle, isScanRun } from "@rampscan/schema";
import {
  ArtifactNotAttestedError,
  REPO_MODEL_ARTIFACT,
  resolveArtifact,
  scan,
} from "../src/index.js";

// Artifact resolution (plan J4), over a REAL scanned world — repo-facts only,
// no external tools, CI-safe — because the thing under test is whether the
// bytes a viewer renders are the bytes a signed statement attested, and a
// hand-built ledger would prove nothing about that.
//
// The property that matters most is the REFUSAL. Serving an artifact by path
// without re-hashing would let a modified file on disk render under a signed
// bundle's digest, which is the exact confusion this architecture exists to
// prevent — so the tamper case below is the load-bearing test in this file.

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "../../..");
const gitEnv = {
  ...process.env,
  GIT_AUTHOR_NAME: "j4-test",
  GIT_AUTHOR_EMAIL: "j4@rampscan.invalid",
  GIT_COMMITTER_NAME: "j4-test",
  GIT_COMMITTER_EMAIL: "j4@rampscan.invalid",
};

let appRoot: string;
let ledgerDir: string;
let keysDir: string;
let outDir: string;
let artifactsDir: string;

/** the repo-facts artifact's attested digest + name, read out of the ledger */
let attested: { name: string; digest: string; bundleDigest: string };
/** an anchor subject: repo content at the scanned commit, never served */
let anchor: { name: string; digest: string };

beforeAll(async () => {
  const base = await mkdtemp(join(tmpdir(), "rampscan-j4-"));
  appRoot = join(base, "app");
  ledgerDir = join(base, "ledger");
  keysDir = join(base, "keys");
  outDir = join(base, "out");
  artifactsDir = join(outDir, "artifacts");
  await mkdir(join(appRoot, ".github", "workflows"), { recursive: true });

  await writeFile(
    join(appRoot, "package.json"),
    JSON.stringify({ name: "j4-app", version: "1.0.0" }, null, 2),
  );
  await writeFile(
    join(appRoot, "package-lock.json"),
    JSON.stringify({ name: "j4-app", version: "1.0.0", lockfileVersion: 3, packages: {} }, null, 2),
  );
  await writeFile(
    join(appRoot, ".github", "workflows", "ci.yml"),
    ["name: ci", "on: [push]", "jobs:", "  test:", "    runs-on: ubuntu-latest", "    steps:", "      - run: npm test", ""].join("\n"),
  );

  const git = (...args: string[]) =>
    execFileSync("git", args, { cwd: appRoot, env: gitEnv, encoding: "utf8" }).trim();
  git("init", "-q", "-b", "main");
  git("add", "-A");
  git("commit", "-q", "-m", "j4 fixture");

  await scan({
    path: appRoot,
    outDir,
    datasetDir: join(repoRoot, "docs/context/ramprules/derived"),
    datasetPin: DEFAULT_DATASET_PIN,
    recipesDir: join(repoRoot, "recipes/commit"),
    collectors: [repoFacts],
    ledgerDir,
    keysDir,
    now: new Date("2026-08-15T09:00:00.000Z"),
  });

  const entries = await createLocalLedger(ledgerDir).list();
  for (const entry of entries) {
    if (!isEvidenceBundle(entry.bundle)) continue;
    const anchorNames = new Set(entry.bundle.predicate.anchor_paths.map((a) => a.path));
    for (const subject of entry.bundle.subject) {
      const digest = subject.digest.sha256!;
      if (anchorNames.has(subject.name)) {
        anchor ??= { name: subject.name, digest };
      } else {
        attested ??= { name: subject.name, digest, bundleDigest: entry.digest };
      }
    }
  }
  expect(attested, "the scan attested at least one artifact").toBeDefined();
  expect(anchor, "the scan attested at least one anchor").toBeDefined();
});

describe("resolveArtifact", () => {
  it("hands back bytes that hash to the digest a signed statement attests", async () => {
    const resolution = await resolveArtifact({ ledgerDir, artifactsDir, digest: attested.digest });

    expect(resolution.name).toBe(attested.name);
    expect(resolution.kind).toBe("artifact");
    expect(resolution.reason).toBeUndefined();
    expect(resolution.bytes).toBeDefined();
    // the check the whole route rests on, made again here from the outside
    expect(createHash("sha256").update(resolution.bytes!).digest("hex")).toBe(attested.digest);
    // provenance: the statement(s) that attest these bytes, named
    expect(resolution.attestedBy).toContain(attested.bundleDigest);
    expect(resolution.commit).toMatch(/^[0-9a-f]{40}$/);
  });

  it("accepts the digest in any case, and answers with the canonical form", async () => {
    const resolution = await resolveArtifact({
      ledgerDir,
      artifactsDir,
      digest: attested.digest.toUpperCase(),
    });
    expect(resolution.digest).toBe(attested.digest);
    expect(resolution.bytes).toBeDefined();
  });

  it("REFUSES a file of the right name whose bytes are from a later run", async () => {
    // the scan output dir is overwritten by later runs — this is the ordinary
    // case on any machine that has scanned since, not an exotic one
    const path = join(artifactsDir, "repo-facts", attested.name);
    const original = await readFile(path);
    await writeFile(path, JSON.stringify({ "a-later-run": true }, null, 2) + "\n");
    try {
      const resolution = await resolveArtifact({ ledgerDir, artifactsDir, digest: attested.digest });
      // the digest is still attested — the BYTES are the problem, and the
      // difference between those two facts is the whole point of the message
      expect(resolution.bytes).toBeUndefined();
      expect(resolution.name).toBe(attested.name);
      expect(resolution.attestedBy).toContain(attested.bundleDigest);
      expect(resolution.reason).toMatch(/from a later run/);
      expect(resolution.reason).toMatch(/does not match the attested digest/);
    } finally {
      await writeFile(path, original);
    }
    // and it resolves again once the real bytes are back — the refusal was
    // about the bytes, and nothing was poisoned by it
    expect((await resolveArtifact({ ledgerDir, artifactsDir, digest: attested.digest })).bytes).toBeDefined();
  });

  it("says `not retained` when no file of that name is under the output dir", async () => {
    const resolution = await resolveArtifact({
      ledgerDir,
      artifactsDir: join(outDir, "no-such-dir"),
      digest: attested.digest,
    });
    expect(resolution.bytes).toBeUndefined();
    expect(resolution.reason).toMatch(/not retained — no file named/);
  });

  it("says so when the console has no scan output dir at all", async () => {
    const resolution = await resolveArtifact({ ledgerDir, digest: attested.digest });
    expect(resolution.bytes).toBeUndefined();
    expect(resolution.reason).toMatch(/no scan output dir configured/);
  });

  it("never serves an anchor — that is the client's source, and `git show` reproduces it", async () => {
    const resolution = await resolveArtifact({ ledgerDir, artifactsDir, digest: anchor.digest });
    expect(resolution.kind).toBe("anchor");
    expect(resolution.bytes).toBeUndefined();
    expect(resolution.reason).toMatch(/^repo content at commit [0-9a-f]{40}/);
    expect(resolution.reason).toMatch(new RegExp(`git show [0-9a-f]{12}:${anchor.name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`));
  });

  // A run record's subjects are the RUN's artifacts. Before L2 nothing was
  // attested by a run record alone — every artifact was also an evidence
  // bundle's subject — so the resolver's "not an evidence bundle → a scoping
  // justification" shortcut had never been wrong out loud. repo-model.json is
  // the first artifact only the run record names, and under that shortcut it
  // refused to serve with a sentence about a scoping event that does not exist.
  it("serves an artifact only the run record attests — a run's own derivation is not a justification", async () => {
    const entries = await createLocalLedger(ledgerDir).list();
    const run = entries.find((e) => isScanRun(e.bundle))!;
    const subject = run.bundle.subject.find((s) => s.name === REPO_MODEL_ARTIFACT)!;
    const digest = subject.digest["sha256"]!;
    // the premise: no evidence bundle names these bytes, so the classification
    // rests entirely on the statement kind
    expect(
      entries.filter((e) => e.bundle.subject.some((s) => s.digest["sha256"] === digest)),
    ).toHaveLength(1);

    const resolution = await resolveArtifact({ ledgerDir, artifactsDir, digest });
    expect(resolution.kind).toBe("artifact");
    expect(resolution.name).toBe(REPO_MODEL_ARTIFACT);
    expect(resolution.attestedBy).toEqual([run.digest]);
    expect(resolution.bytes).toBeDefined();
    expect(createHash("sha256").update(resolution.bytes!).digest("hex")).toBe(digest);
  });

  it("classifies scan-result.json as an artifact too, and says it was not retained", async () => {
    // it lives beside the artifacts dir rather than inside it, so the honest
    // answer is "no file of that name here" — not a sentence about scoping
    const entries = await createLocalLedger(ledgerDir).list();
    const run = entries.find((e) => isScanRun(e.bundle))!;
    const subject = run.bundle.subject.find((s) => s.name === "scan-result.json")!;
    const resolution = await resolveArtifact({
      ledgerDir,
      artifactsDir,
      digest: subject.digest["sha256"]!,
    });
    expect(resolution.kind).toBe("artifact");
    expect(resolution.reason).toMatch(/not retained — no file named scan-result\.json/);
  });

  it("refuses a digest no signed statement attests — this serves artifacts, not files", async () => {
    const unattested = createHash("sha256").update("not in this ledger").digest("hex");
    await expect(
      resolveArtifact({ ledgerDir, artifactsDir, digest: unattested }),
    ).rejects.toThrow(ArtifactNotAttestedError);
    await expect(
      resolveArtifact({ ledgerDir, artifactsDir, digest: unattested }),
    ).rejects.toThrow(/no signed statement in this ledger attests/);
  });

  it("refuses anything that is not a sha256, rather than going looking", async () => {
    for (const bad of ["../../etc/passwd", "deadbeef", "", "g".repeat(64)]) {
      await expect(
        resolveArtifact({ ledgerDir, artifactsDir, digest: bad }),
      ).rejects.toThrow(ArtifactNotAttestedError);
    }
  });
});
