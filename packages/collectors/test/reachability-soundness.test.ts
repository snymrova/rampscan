import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import type { CollectContext, CollectOutput } from "@rampscan/core";
import { GRAPH_DB_ARTIFACT } from "@rampscan/graph";
import {
  graphCollector,
  reachability,
  OPENVEX_ARTIFACT,
  OSV_RESULTS_ARTIFACT,
  SBOM_ARTIFACT,
} from "../src/index.js";

// S0-3 — the failing test, first (docs/PLAN-SOUNDNESS.md §5, phase S0).
//
// The finding: `reachability.ts:142` reads
//
//     const notAffected = gated && (dep === undefined || !dep.reachable);
//
// and `dep === undefined` means the package has NO NODE in the code graph —
// the absence of evidence — which is treated as a proof of unreachability
// equal in standing to a completed walk that failed to arrive. Dependency
// nodes come only from first-party import specifiers, so any advisory in a
// package the source does not `import` directly becomes a signed
// `not_affected`. That is ground rule 7 (no vacuous passes) in the one place
// `catalog.test.ts` does not reach, because it gates recipe verdicts and this
// failure moved into the collector's gating.
//
// The fixture reproduces the real shape exactly: `minimist` is declared in
// `fixtures/vulnerable-app/package.json` and never imported, so it has no
// node — and the SBOM below carries `lodash → minimist`, where `lodash` IS
// reachable from the entry point. The same relationship holds in this
// repository's own output, where `sbom.cdx.json` carries
// `next@15.5.23 → postcss@8.4.31` while `graph.db` has no `postcss` node and
// `openvex.json` signs four `not_affected` statements about it.
//
// S0 committed this under `it.fails`: against the code at 2801f8c it threw,
// which was S0's exit gate, and the wrapper kept `main` green while the
// finding was recorded rather than fixed. S1-1 (#128) removed the
// `dep === undefined` disjunct and flipped it back to `it`; it is now the
// regression guard for GHSA-7jff-6v53-r56x.

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "../../..");
const fixtureRoot = join(repoRoot, "fixtures/vulnerable-app");

const OSV_REPORT = {
  results: [
    {
      source: { path: "package-lock.json" },
      packages: [
        {
          package: { name: "minimist", version: "1.2.5", ecosystem: "npm" },
          vulnerabilities: [
            {
              id: "GHSA-xvch-5gv4-984h",
              summary: "Prototype pollution in minimist",
              aliases: ["CVE-2021-44906"],
            },
          ],
          groups: [{ ids: ["GHSA-xvch-5gv4-984h", "CVE-2021-44906"], max_severity: "9.8" }],
        },
      ],
    },
  ],
};

// CycloneDX, shaped like syft's real output: `minimist` is not imported by any
// first-party file, and it is a dependency of `lodash`, which is.
const SBOM = {
  bomFormat: "CycloneDX",
  specVersion: "1.7",
  components: [
    { "bom-ref": "pkg:npm/lodash@4.17.15", type: "library", name: "lodash", version: "4.17.15" },
    { "bom-ref": "pkg:npm/minimist@1.2.5", type: "library", name: "minimist", version: "1.2.5" },
  ],
  dependencies: [
    { ref: "pkg:npm/lodash@4.17.15", dependsOn: ["pkg:npm/minimist@1.2.5"] },
    { ref: "pkg:npm/minimist@1.2.5", dependsOn: [] },
  ],
};

function ctx(artifactDir: string, inputs: Map<string, string>): CollectContext {
  return {
    workspace: { root: fixtureRoot, repo: "fixtures/vulnerable-app", commit: "f".repeat(40) },
    artifactDir,
    inputs,
    runId: "run-s0-3",
  };
}

describe("S0-3 — a package absent from the graph is not proof of unreachability", () => {
  let out: CollectOutput;

  beforeAll(async () => {
    const graphDir = await mkdtemp(join(tmpdir(), "rampscan-s0-graph-"));
    const graphOut = await graphCollector.collect(ctx(graphDir, new Map()));
    const graphDbPath = graphOut.artifacts.find((a) => a.name === GRAPH_DB_ARTIFACT)!.path;

    const dir = await mkdtemp(join(tmpdir(), "rampscan-s0-reach-"));
    const osvPath = join(dir, OSV_RESULTS_ARTIFACT);
    const sbomPath = join(dir, SBOM_ARTIFACT);
    await writeFile(osvPath, JSON.stringify(OSV_REPORT));
    await writeFile(sbomPath, JSON.stringify(SBOM));
    out = await reachability.collect(
      ctx(
        dir,
        new Map([
          [OSV_RESULTS_ARTIFACT, osvPath],
          [GRAPH_DB_ARTIFACT, graphDbPath],
          [SBOM_ARTIFACT, sbomPath],
        ]),
      ),
    );
  });

  it("does not sign not_affected for a package the walk never had a node for", async () => {
    const rows = out.observations["no-critical-reachable-advisories"]!;
    const minimist = rows.find((r) => r["package"] === "minimist")!;

    // The whole finding, in one assertion: `minimist` has no node in graph.db,
    // so nothing was walked and nothing may be claimed. Before S1-1 this read
    // `true`, from `dep === undefined` at reachability.ts:142.
    expect(minimist["not_affected"]).toBe(false);

    // And `reachable: "false"` is the same claim in the observation row —
    // it must be anything but a negative verdict the walk did not earn.
    expect(minimist["reachable"]).not.toBe("false");

    // The signed document is where it matters: no `not_affected` statement may
    // rest on an absent node.
    const vexPath = out.artifacts.find((a) => a.name === OPENVEX_ARTIFACT)!.path;
    const vex = JSON.parse(await readFile(vexPath, "utf8")) as {
      statements: Array<Record<string, unknown>>;
    };
    expect(vex.statements.filter((s) => s["status"] === "not_affected")).toHaveLength(0);
  });
});
