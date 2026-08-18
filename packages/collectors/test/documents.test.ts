import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import type { CollectContext, CollectOutput } from "@rampscan/core";
import { POLICY_RECIPE, SYSTEM_DOCS_RECIPE, documents, repoFacts } from "../src/index.js";
import { copyCheckout } from "./checkout.js";

// The documents gate (plan N1b wave 1), driven on the REAL fixture for the
// passing case and on copies of it for the broken ones.
//
// `vulnerable-app` declares two documents and really has both — it is the one
// plane where that fixture behaves — so the recipes have somewhere to reach
// `evidenced`. Everything that makes a declaration fail needs the repository
// broken in exactly one way, which a copy in a temp directory can be and a
// committed fixture cannot: a declared document deleted, a declared document
// emptied, a block that declares nothing, a block that is not there at all,
// and a block with a misspelled kind.
//
// `bare-app` is the honest-skip case: no config file, so no claim was ever
// made, and the board must say that rather than reporting a failed control.

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "../../..");
const fixtureRoot = join(repoRoot, "fixtures/vulnerable-app");
const bareRoot = join(repoRoot, "fixtures/bare-app");

function ctx(root: string, artifactDir: string): CollectContext {
  return {
    workspace: { root, repo: root, commit: "f".repeat(40) },
    artifactDir,
    inputs: new Map(),
    runId: "run-test",
  };
}

async function run(root: string): Promise<CollectOutput> {
  const dir = await mkdtemp(join(tmpdir(), "rampscan-documents-"));
  return documents.collect(ctx(root, dir));
}

/** a copy of the fixture, for the cases that need it broken one way */
async function fixtureCopy(): Promise<string> {
  return copyCheckout(fixtureRoot, "documents-repo");
}

/** rewrite the copy's documents block, leaving the contract block alone */
async function withDocuments(root: string, declared: unknown): Promise<void> {
  const path = join(root, "rampscan.config.json");
  const config = JSON.parse(await readFile(path, "utf8")) as Record<string, unknown>;
  if (declared === undefined) delete config["documents"];
  else config["documents"] = declared;
  await writeFile(path, `${JSON.stringify(config, null, 2)}\n`);
}

let out: CollectOutput;

beforeAll(async () => {
  out = await run(fixtureRoot);
}, 30_000);

describe("documents on the fixture — the declaration holds", () => {
  it("emits one row per declared document, split by kind", () => {
    expect(out.observations[POLICY_RECIPE]).toEqual([
      {
        document_id: "access-control-policy",
        kind: "access-control-policy",
        path: "docs/access-control-policy.md",
        present: true,
        bytes: expect.any(Number),
        non_empty: true,
      },
    ]);
    expect(out.observations[SYSTEM_DOCS_RECIPE]).toEqual([
      {
        document_id: "admin-guide",
        kind: "system-documentation",
        path: "docs/admin-guide.md",
        present: true,
        bytes: expect.any(Number),
        non_empty: true,
      },
    ]);
  });

  it("anchors each row to the declaration AND to the document it names", () => {
    // both, because either one moving changes what the claim means: an edit to
    // the document changes what was attested, and an edit to the declaration
    // changes which document the claim was about
    const anchored = out.anchors![POLICY_RECIPE]!.map((a) => a.path);
    expect(anchored).toEqual(["rampscan.config.json", "docs/access-control-policy.md"]);
    for (const a of out.anchors![POLICY_RECIPE]!) {
      expect(a.contentHash).toMatch(/^[0-9a-f]{64}$/);
    }
  });

  it("finds nothing wrong and spawns nothing", () => {
    expect(out.findings).toEqual([]);
    expect(out.artifacts).toEqual([]);
    expect(out.skipped).toBeUndefined();
  });
});

describe("documents — a declaration that does not hold", () => {
  it("a declared document that is missing emits present:false and a finding", async () => {
    const root = await fixtureCopy();
    await rm(join(root, "docs/admin-guide.md"));
    const broken = await run(root);
    expect(broken.observations[SYSTEM_DOCS_RECIPE]).toMatchObject([
      { document_id: "admin-guide", present: false, bytes: 0, non_empty: false },
    ]);
    // the negative witness: the row exists so the count assertion has something
    // to count, and the recipe violates rather than passing over zero rows
    expect(broken.findings).toHaveLength(1);
    expect(broken.findings[0]!.summary).toContain("is not in the checkout");
    // the missing file cannot anchor a finding about itself
    expect(broken.findings[0]!.anchor.node).toBe("rampscan.config.json");
  });

  it("a declared document that is empty is present and not non_empty", async () => {
    const root = await fixtureCopy();
    await writeFile(join(root, "docs/admin-guide.md"), "");
    const broken = await run(root);
    expect(broken.observations[SYSTEM_DOCS_RECIPE]).toMatchObject([
      { present: true, bytes: 0, non_empty: false },
    ]);
    expect(broken.findings[0]!.summary).toContain("empty file");
    expect(broken.findings[0]!.anchor.node).toBe("docs/admin-guide.md");
  });

  it("a directory at the declared path is not the document", async () => {
    const root = await fixtureCopy();
    await rm(join(root, "docs/admin-guide.md"));
    const { mkdir } = await import("node:fs/promises");
    await mkdir(join(root, "docs/admin-guide.md"));
    const broken = await run(root);
    expect(broken.observations[SYSTEM_DOCS_RECIPE]).toMatchObject([{ present: false }]);
  });
});

describe("documents — the empty-set discipline", () => {
  it("declaring only one kind GUARDS the other: no key, not an empty array", async () => {
    const root = await fixtureCopy();
    await withDocuments(root, [
      {
        id: "admin-guide",
        kind: "system-documentation",
        path: "docs/admin-guide.md",
        description: "the operator's guide",
      },
    ]);
    const one = await run(root);
    expect(one.observations[SYSTEM_DOCS_RECIPE]).toHaveLength(1);
    // the anti-pattern this guards is `observations[POLICY_RECIPE] = []`, which
    // the join reads as "defined" and the count assertions pass over
    expect(POLICY_RECIPE in one.observations).toBe(false);
  });

  it("a repository with no config file SKIPS with a stated reason", async () => {
    const skipped = await run(bareRoot);
    expect(skipped.observations).toEqual({});
    expect(skipped.skipped?.reason).toContain("no documents declared");
    // the sentence K1 renders under the empty cell has to say why, and "a claim
    // never made" is a different fact from "a claim broken"
    expect(skipped.skipped?.reason).toContain("claim never made");
  });

  it("an EMPTY declaration skips too, and says which of the two it was", async () => {
    const root = await fixtureCopy();
    await withDocuments(root, []);
    const skipped = await run(root);
    expect(skipped.skipped?.reason).toContain("is empty");
  });

  it("no documents key at all skips, leaving the contract block alone", async () => {
    const root = await fixtureCopy();
    await withDocuments(root, undefined);
    const skipped = await run(root);
    expect(skipped.skipped?.reason).toContain("no documents declared");
  });
});

describe("documents — a mistyped declaration is a config error, never a waiver", () => {
  it("an unknown kind refuses to parse", async () => {
    const root = await fixtureCopy();
    await withDocuments(root, [
      {
        id: "incident-response",
        kind: "incident-response-policy",
        path: "docs/admin-guide.md",
        description: "how we respond",
      },
    ]);
    await expect(run(root)).rejects.toThrow(/failed validation/);
  });

  it("a misspelled field refuses to parse rather than declaring nothing", async () => {
    const root = await fixtureCopy();
    await withDocuments(root, [
      {
        id: "admin-guide",
        kind: "system-documentation",
        paths: "docs/admin-guide.md",
        description: "the operator's guide",
      },
    ]);
    await expect(run(root)).rejects.toThrow(/failed validation/);
  });

  it("two declarations naming one path refuse to parse", async () => {
    const root = await fixtureCopy();
    await withDocuments(root, [
      {
        id: "admin-guide",
        kind: "system-documentation",
        path: "docs/admin-guide.md",
        description: "the operator's guide",
      },
      {
        id: "runbook",
        kind: "system-documentation",
        path: "docs/admin-guide.md",
        description: "the same file wearing a second name",
      },
    ]);
    await expect(run(root)).rejects.toThrow(/same path/);
  });

  it("a description stating a verdict refuses to parse", async () => {
    // the rule contract.ts holds declared prose to, inherited: this text renders
    // on our surfaces, and a verdict there would be a typed one
    const root = await fixtureCopy();
    await withDocuments(root, [
      {
        id: "admin-guide",
        kind: "system-documentation",
        path: "docs/admin-guide.md",
        description: "this document is evidenced",
      },
    ]);
    await expect(run(root)).rejects.toThrow(/failed validation/);
  });
});

describe("the disclosure channel witness (repo-facts, RA-05 (11))", () => {
  async function facts(root: string): Promise<CollectOutput> {
    const dir = await mkdtemp(join(tmpdir(), "rampscan-disclosure-"));
    return repoFacts.collect(ctx(root, dir));
  }

  it("finds the fixture's published SECURITY.md", async () => {
    const out = await facts(fixtureRoot);
    expect(out.observations["security-disclosure-published"]).toEqual([
      {
        disclosure_present: true,
        path: "SECURITY.md",
        bytes: expect.any(Number),
        non_empty: true,
      },
    ]);
  });

  it("emits the witness row on a repository that publishes nothing", async () => {
    // Witness, not Guard: the row is always there, so a repo with no channel
    // VIOLATES honestly instead of reading unevidenced — an absent disclosure
    // policy is a real answer, not a missing observation
    const out = await facts(bareRoot);
    expect(out.observations["security-disclosure-published"]).toEqual([
      { disclosure_present: false, path: null, bytes: 0, non_empty: false },
    ]);
  });

  it("a zero-byte channel is present and not non_empty", async () => {
    const root = await fixtureCopy();
    await writeFile(join(root, "SECURITY.md"), "");
    const out = await facts(root);
    expect(out.observations["security-disclosure-published"]).toEqual([
      { disclosure_present: true, path: "SECURITY.md", bytes: 0, non_empty: false },
    ]);
  });

  it("reads .well-known/security.txt when there is no SECURITY.md", async () => {
    const root = await fixtureCopy();
    await rm(join(root, "SECURITY.md"));
    const { mkdir } = await import("node:fs/promises");
    await mkdir(join(root, ".well-known"), { recursive: true });
    await writeFile(
      join(root, ".well-known/security.txt"),
      "Contact: mailto:security@example.invalid\n",
    );
    const out = await facts(root);
    expect(out.observations["security-disclosure-published"]).toMatchObject([
      { disclosure_present: true, path: ".well-known/security.txt", non_empty: true },
    ]);
  });
});
