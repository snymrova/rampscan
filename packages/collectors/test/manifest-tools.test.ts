import { readFile, readdir } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { allCollectors } from "../src/index.js";

// The manifest's `tools` declaration vs the code (plan J5).
//
// `rampscan tools` and the console's chain both read the DECLARATION, and a
// declaration can drift from the call that actually resolves the tool. So the
// declaration is pinned against the source: every `resolveTool("x", …)` a
// collector makes must appear in its manifest, and every declared tool must be
// resolved somewhere in that collector.
//
// This is the difference between a map that is true and a map that was true
// once. A wrong tool name on the chain would put an auditor's question at the
// wrong tool, which is worse than the raw JSON the chain replaced.

const SRC = join(dirname(fileURLToPath(import.meta.url)), "../src");

/** every name passed to resolveTool() in one collector's source */
function resolvedTools(source: string): string[] {
  return [...source.matchAll(/resolveTool\(\s*"([^"]+)"/g)].map((m) => m[1]!).sort();
}

describe("the tools a collector declares are the tools it actually resolves", () => {
  it("every collector's manifest matches its source", async () => {
    const files = (await readdir(SRC)).filter(
      (f) => f.endsWith(".ts") && !["index.ts", "support.ts", "tools.ts", "journal.ts", "osv-report.ts"].includes(f),
    );
    const sources = new Map<string, string>();
    for (const file of files) {
      sources.set(file, await readFile(join(SRC, file), "utf8"));
    }

    const mismatches: string[] = [];
    for (const collector of allCollectors) {
      const name = collector.manifest.name;
      // find the source file that declares this manifest name
      const entry = [...sources.entries()].find(([, src]) =>
        src.includes(`name: "${name}"`),
      );
      if (!entry) {
        mismatches.push(`${name}: no source file declares this manifest name`);
        continue;
      }
      const actual = resolvedTools(entry[1]);
      const declared = [...(collector.manifest.tools ?? [])].sort();
      if (JSON.stringify(actual) !== JSON.stringify(declared)) {
        mismatches.push(
          `${name} (${entry[0]}): declares [${declared.join(", ")}], resolves [${actual.join(", ")}]`,
        );
      }
    }
    expect(mismatches).toEqual([]);
  });

  it("a pure collector declares no tool at all rather than an empty-ish one", () => {
    // repo-facts, graph, reachability and sast-reachability read the repo or
    // earlier artifacts; "pure" is a fact about them, and the console prints
    // it as such instead of as a missing binary
    for (const name of ["repo-facts", "graph", "reachability", "sast-reachability"]) {
      const collector = allCollectors.find((c) => c.manifest.name === name)!;
      expect(collector.manifest.tools ?? []).toEqual([]);
    }
  });

  it("the detector would notice a drifted declaration", () => {
    // guard the guard: the regex must find a resolveTool call in real source
    expect(resolvedTools('const t = await resolveTool("syft", { args: [] });')).toEqual(["syft"]);
    expect(resolvedTools("// resolveTool is described in a comment\n")).toEqual([]);
  });
});
