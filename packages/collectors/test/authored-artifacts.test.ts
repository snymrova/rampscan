import { execFileSync } from "node:child_process";
import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { MAX_ARTIFACT_BODY_BYTES } from "@rampscan/schema";
import { collectAuthoredArtifacts, loadDeclaredArtifacts } from "../src/index.js";

// R1.4 — the `authored` source (SPEC §13.3): a repo declares which file IS its
// answer to slot N of KSI Y, and the artifact plane picks it up commit-anchored.
//
// The discipline under test is the ANCHOR. An authored artifact carries the
// commit that last touched its file, not the commit being scanned, because
// §13.5's three-month clock is asking whether the writing has been revisited —
// and a clock that restarted on every scan would answer "yes" forever.

const gitEnv = {
  ...process.env,
  GIT_AUTHOR_NAME: "r14-test",
  GIT_AUTHOR_EMAIL: "r14@rampscan.invalid",
  GIT_COMMITTER_NAME: "r14-test",
  GIT_COMMITTER_EMAIL: "r14@rampscan.invalid",
};

function git(cwd: string, ...args: string[]): string {
  return execFileSync("git", args, { cwd, env: gitEnv, encoding: "utf8" }).trim();
}

async function repoWith(
  files: Record<string, string>,
  config?: unknown,
  opts: { commit?: boolean } = {},
): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "rampscan-r14-"));
  for (const [rel, body] of Object.entries(files)) {
    await mkdir(join(root, rel, ".."), { recursive: true });
    await writeFile(join(root, rel), body);
  }
  if (config !== undefined) {
    await writeFile(join(root, "rampscan.config.json"), JSON.stringify(config, null, 2));
  }
  git(root, "init", "-q", "-b", "main");
  if (opts.commit !== false) {
    git(root, "add", "-A");
    git(root, "commit", "-qm", "declared artifacts");
  }
  return root;
}

const declaration = (overrides: Record<string, unknown> = {}) => ({
  artifacts: [
    {
      ksi: "KSI-SVC-SIN",
      artifact: 1,
      path: "docs/ksi/svc-sin-1.md",
      description: "How service integrity is demonstrated, and by which measures.",
      ...overrides,
    },
  ],
});

const BODY = "## Service integrity\n\nEvery merge to main runs the pinned gate.\n";

describe("declared KSI artifacts (R1.4)", () => {
  it("resolves a declared body, anchored to the commit that last touched it", async () => {
    const root = await repoWith({ "docs/ksi/svc-sin-1.md": BODY }, declaration());
    const head = git(root, "rev-parse", "HEAD");
    const declared = (await loadDeclaredArtifacts(root))!;
    const scan = await collectAuthoredArtifacts(root, declared);

    expect(scan.problems).toEqual([]);
    expect(scan.found).toHaveLength(1);
    const found = scan.found[0]!;
    expect(found.ksi).toBe("KSI-SVC-SIN");
    expect(found.artifact).toBe(1);
    expect(found.body).toBe(BODY);
    expect(found.anchor).toEqual({ commit: head, path: "docs/ksi/svc-sin-1.md" });
    expect(found.validFrom).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });

  it("anchors to the commit that touched THIS file, not to HEAD", async () => {
    const root = await repoWith({ "docs/ksi/svc-sin-1.md": BODY }, declaration());
    const wrote = git(root, "rev-parse", "HEAD");
    // a later commit that changes something else entirely
    await writeFile(join(root, "README.md"), "# unrelated\n");
    git(root, "add", "-A");
    git(root, "commit", "-qm", "unrelated change");
    expect(git(root, "rev-parse", "HEAD")).not.toBe(wrote);

    const scan = await collectAuthoredArtifacts(root, (await loadDeclaredArtifacts(root))!);
    // the artifact was not revisited, so its clock must not have moved — this
    // is the whole reason the anchor is not the scanned commit (§13.5)
    expect(scan.found[0]!.anchor.commit).toBe(wrote);
  });

  it("reports a declaration pointing at nothing, rather than dropping it", async () => {
    const root = await repoWith({ "README.md": "# app\n" }, declaration());
    const scan = await collectAuthoredArtifacts(root, (await loadDeclaredArtifacts(root))!);
    expect(scan.found).toEqual([]);
    expect(scan.problems[0]!.reason).toBe("no file at the declared path");
    expect(scan.problems[0]!.ksi).toBe("KSI-SVC-SIN");
  });

  it("refuses an empty file — an absence with a reason is written, not left blank", async () => {
    const root = await repoWith({ "docs/ksi/svc-sin-1.md": "" }, declaration());
    const scan = await collectAuthoredArtifacts(root, (await loadDeclaredArtifacts(root))!);
    expect(scan.problems[0]!.reason).toBe("the declared file is empty");
  });

  it("refuses a body longer than its own summary, and says where a document belongs", async () => {
    const root = await repoWith(
      { "docs/ksi/svc-sin-1.md": "x".repeat(MAX_ARTIFACT_BODY_BYTES + 1) },
      declaration(),
    );
    const scan = await collectAuthoredArtifacts(root, (await loadDeclaredArtifacts(root))!);
    expect(scan.problems[0]!.reason).toContain("short and simple high-level summaries");
    expect(scan.problems[0]!.reason).toContain("evidenceLocation");
  });

  it("refuses an uncommitted file — it could never die by anchor drift", async () => {
    const root = await repoWith({ "docs/ksi/svc-sin-1.md": BODY }, declaration(), {
      commit: false,
    });
    const scan = await collectAuthoredArtifacts(root, (await loadDeclaredArtifacts(root))!);
    expect(scan.found).toEqual([]);
    expect(scan.problems[0]!.reason).toContain("cannot die by anchor drift");
  });

  it("is honestly absent when nothing is declared — a claim never made", async () => {
    const noBlock = await repoWith({ "README.md": "# app\n" }, { documents: [] });
    expect(await loadDeclaredArtifacts(noBlock)).toBeUndefined();
    const noConfig = await repoWith({ "README.md": "# app\n" });
    expect(await loadDeclaredArtifacts(noConfig)).toBeUndefined();
  });

  it("refuses a mistyped declaration rather than letting it waive itself", async () => {
    for (const bad of [
      { ksi: "KSI-SVC-SIN", artifact: 6, path: "a.md", description: "a".repeat(20) },
      { ksi: "KSI-SVC-SIN", artifact: 1, paths: "a.md", description: "a".repeat(20) },
      { artifact: 1, path: "a.md", description: "a".repeat(20) },
    ]) {
      const root = await repoWith({ "a.md": "x" }, { artifacts: [bad] });
      await expect(loadDeclaredArtifacts(root), JSON.stringify(bad)).rejects.toThrow(
        /must not silently waive itself/,
      );
    }
  });

  it("refuses two declarations for one slot, and two slots for one file", async () => {
    const sameSlot = await repoWith(
      { "a.md": "x", "b.md": "y" },
      {
        artifacts: [
          { ksi: "KSI-SVC-SIN", artifact: 1, path: "a.md", description: "a".repeat(20) },
          { ksi: "KSI-SVC-SIN", artifact: 1, path: "b.md", description: "b".repeat(20) },
        ],
      },
    );
    await expect(loadDeclaredArtifacts(sameSlot)).rejects.toThrow(/same \(KSI, artifact\) slot/);

    const samePath = await repoWith(
      { "a.md": "x" },
      {
        artifacts: [
          { ksi: "KSI-SVC-SIN", artifact: 1, path: "a.md", description: "a".repeat(20) },
          { ksi: "KSI-SVC-SIN", artifact: 3, path: "a.md", description: "b".repeat(20) },
        ],
      },
    );
    await expect(loadDeclaredArtifacts(samePath)).rejects.toThrow(/same path/);
  });
});
