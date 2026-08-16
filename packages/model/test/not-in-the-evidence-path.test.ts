import { readFile, readdir } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");

async function sources(dir: string): Promise<string[]> {
  const out: string[] = [];
  for (const entry of await readdir(dir, { withFileTypes: true, recursive: true })) {
    if (entry.isFile() && entry.name.endsWith(".ts")) out.push(join(entry.parentPath, entry.name));
  }
  return out;
}

// I4/I5, structurally. "No model output enters the fold" is a claim this
// repository should not have to take on trust from a comment: a scan, a gate,
// a bundle and the projection are all computed by packages that must have no
// way to reach a model at all. The plan's exit criterion asks for a projection
// that is byte-identical with and without a runtime — this is the stronger and
// cheaper form of the same assertion, because a package that cannot import the
// model cannot vary with it.
describe("the model is unreachable from the evidence path", () => {
  const sealed = ["collectors", "projector", "graph", "ledger", "signer", "schema", "dataset", "scheduler"];

  for (const pkg of sealed) {
    it(`packages/${pkg} does not import @rampscan/model`, async () => {
      const files = await sources(join(root, "packages", pkg, "src"));
      const offenders: string[] = [];
      for (const file of files) {
        if ((await readFile(file, "utf8")).includes("@rampscan/model")) offenders.push(file);
      }
      expect(offenders).toEqual([]);
    });
  }

  it("packages/core declares the port but imports no adapter", async () => {
    // The interface lives in core like the other six. The ADAPTER lives in
    // packages/model, and core importing it would put a runtime behind a type.
    const files = await sources(join(root, "packages", "core", "src"));
    for (const file of files) {
      expect(await readFile(file, "utf8")).not.toContain("@rampscan/model");
    }
  });

  it("the CLI does not draft — no scan path touches a model", async () => {
    const files = await sources(join(root, "packages", "cli", "src"));
    const offenders: string[] = [];
    for (const file of files) {
      if ((await readFile(file, "utf8")).includes("@rampscan/model")) offenders.push(file);
    }
    // If a future command wants a draft, this test is the conversation: it
    // fails, and whoever changes it has to say why a signed pipeline needs one.
    expect(offenders).toEqual([]);
  });

  it("exactly one console route reaches the model", async () => {
    const files = await sources(join(root, "console", "web", "app"));
    const importers = [];
    for (const file of files) {
      if ((await readFile(file, "utf8")).includes("@rampscan/model")) importers.push(file);
    }
    expect(importers.map((f) => f.replace(`${root}/`, ""))).toEqual([
      "console/web/app/api/model/draft/route.ts",
    ]);
  });
});
