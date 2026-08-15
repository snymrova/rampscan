import { basename, dirname, join, posix } from "node:path";
import type { Collector, CollectOutput } from "@rampscan/core";
import { SBOM_ARTIFACT } from "./syft.js";
import { OSV_RESULTS_ARTIFACT } from "./osv-report.js";
import { absentReason, resolveTool } from "./tools.js";

// osv-scanner — known advisories against the SBOM syft produced (plan C2).
// As of M4 this wrapper is a pure PRODUCER: it writes osv-results.json and
// nothing else. The advisory verdict, the findings, and the OpenVEX all
// moved to the `reachability` collector, which joins this artifact against
// the code graph — an advisory only counts once its reachability is known
// (or honestly unknown).

export const osvScanner: Collector = {
  manifest: {
    name: "osv-scanner",
    toolVersion: "resolved-at-run",
    tools: ["osv-scanner"],
    recipes: [], // producer only — the advisories recipe is evidenced by `reachability`
    inputs: [SBOM_ARTIFACT],
    outputs: [OSV_RESULTS_ARTIFACT],
    // keyed on the SBOM it consumes; a cached result can miss advisories
    // published since — the daemon's scheduled full scan is the corrective
    cacheScope: ["@inputs"],
  },

  async collect(ctx): Promise<CollectOutput> {
    const tool = await resolveTool("osv-scanner", {
      args: ["--version"],
      parse: (out) => {
        const m = /osv-scanner version:\s*(\S+)/.exec(out);
        return m ? m[1]! : out.split("\n")[0]!.trim();
      },
    });
    if (!tool) {
      return {
        findings: [],
        artifacts: [],
        observations: {},
        toolVersion: "absent",
        exitCode: -1,
        skipped: { reason: absentReason("osv-scanner") },
      };
    }
    const version = tool.version;
    const sbomPath = ctx.inputs.get(SBOM_ARTIFACT);
    if (!sbomPath) {
      return {
        findings: [],
        artifacts: [],
        observations: {},
        toolVersion: version,
        exitCode: -1,
        skipped: { reason: `no ${SBOM_ARTIFACT} available — syft must run (and succeed) first` },
      };
    }

    const reportPath = join(ctx.artifactDir, OSV_RESULTS_ARTIFACT);
    const reportArg = posix.join(tool.mount(ctx.artifactDir, "rw"), OSV_RESULTS_ARTIFACT);
    const sbomArg = posix.join(tool.mount(dirname(sbomPath), "ro"), basename(sbomPath));
    // exit 0 = clean, 1 = vulnerabilities found; both are results
    const { exitCode, stderr } = await tool.exec([
      "scan",
      "source",
      "--sbom",
      sbomArg,
      "--format",
      "json",
      "--output-file",
      reportArg,
    ]);
    if (exitCode !== 0 && exitCode !== 1) {
      return {
        findings: [],
        artifacts: [],
        observations: {},
        toolVersion: version,
        exitCode,
        skipped: { reason: `osv-scanner failed (exit ${exitCode}, via ${tool.runtime}): ${stderr.slice(0, 300)}` },
      };
    }

    return {
      findings: [],
      artifacts: [{ name: OSV_RESULTS_ARTIFACT, path: reportPath }],
      observations: {},
      toolVersion: version,
      exitCode,
    };
  },
};
