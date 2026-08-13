import { readFile } from "node:fs/promises";
import { basename, dirname, join, posix } from "node:path";
import { z } from "zod";
import type { Collector, CollectOutput } from "@rampscan/core";
import type { Finding } from "@rampscan/schema";
import { SBOM_ARTIFACT } from "./syft.js";
import { fileSha256, makeFinding, sha256 } from "./support.js";
import { absentReason, resolveTool } from "./tools.js";

// osv-scanner — known advisories against the SBOM syft produced (plan C2).
// Until M4's reachability gate, every advisory counts (the recipe's notes say
// so): non-reachability-gated is the honest M1 posture.

const OsvResults = z
  .object({
    results: z
      .array(
        z.object({
          source: z.object({ path: z.string().optional() }).passthrough().optional(),
          packages: z.array(
            z.object({
              package: z.object({
                name: z.string(),
                version: z.string().optional(),
                ecosystem: z.string().optional(),
              }),
              vulnerabilities: z
                .array(
                  z.object({
                    id: z.string(),
                    summary: z.string().optional(),
                    aliases: z.array(z.string()).optional(),
                    database_specific: z.object({ severity: z.string().optional() }).passthrough().optional(),
                  }).passthrough(),
                )
                .optional(),
              groups: z
                .array(
                  z.object({
                    ids: z.array(z.string()),
                    max_severity: z.string().optional(),
                  }).passthrough(),
                )
                .optional(),
            }).passthrough(),
          ),
        }).passthrough(),
      )
      .optional(),
  })
  .passthrough();

/** normalize a CVSS score (as string) or a database severity word to one register */
export function normalizeSeverity(maxScore?: string, dbWord?: string): string {
  const score = maxScore ? Number.parseFloat(maxScore) : Number.NaN;
  if (!Number.isNaN(score)) {
    if (score >= 9) return "CRITICAL";
    if (score >= 7) return "HIGH";
    if (score >= 4) return "MEDIUM";
    return "LOW";
  }
  const word = dbWord?.toUpperCase() ?? "";
  if (["CRITICAL", "HIGH", "MEDIUM", "MODERATE", "LOW"].includes(word)) {
    return word === "MODERATE" ? "MEDIUM" : word;
  }
  return "UNKNOWN";
}

export const osvScanner: Collector = {
  manifest: {
    name: "osv-scanner",
    toolVersion: "resolved-at-run",
    recipes: ["no-critical-reachable-advisories"],
    inputs: [SBOM_ARTIFACT],
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

    const reportPath = join(ctx.artifactDir, "osv-results.json");
    const reportArg = posix.join(tool.mount(ctx.artifactDir, "rw"), "osv-results.json");
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

    const report = OsvResults.parse(JSON.parse(await readFile(reportPath, "utf8")));
    const rows: Array<Record<string, unknown>> = [];
    const provenance = { analyzer: "osv-scanner", version, runId: ctx.runId };
    const findings: Finding[] = [];

    for (const result of report.results ?? []) {
      for (const pkg of result.packages) {
        const byId = new Map(
          (pkg.vulnerabilities ?? []).map((v) => [v.id, v] as const),
        );
        const groups = pkg.groups?.length
          ? pkg.groups
          : (pkg.vulnerabilities ?? []).map((v) => ({ ids: [v.id], max_severity: undefined }));
        for (const group of groups) {
          const primary = group.ids[0]!;
          const vuln = byId.get(primary);
          const severity = normalizeSeverity(group.max_severity, vuln?.database_specific?.severity);
          rows.push({
            advisory: primary,
            aliases: group.ids,
            package: pkg.package.name,
            version: pkg.package.version ?? "unknown",
            ecosystem: pkg.package.ecosystem ?? "unknown",
            severity,
          });
          if (severity === "CRITICAL" || severity === "HIGH") {
            findings.push(
              makeFinding(
                {
                  variable: "advisories",
                  anchorNode: "package.json",
                  anchorContentHash: sha256(`${pkg.package.name}@${pkg.package.version}`),
                  signature: `${primary} ${pkg.package.name}@${pkg.package.version}`,
                  severity: severity === "CRITICAL" ? "blocker" : "high",
                  summary: `${primary}: ${severity} advisory against ${pkg.package.name}@${pkg.package.version}${vuln?.summary ? ` — ${vuln.summary}` : ""}`,
                  failureScenario:
                    "the vulnerable code path ships in the deployed artifact; an exploit for a published advisory is the cheapest attack there is (reachability gating arrives in M4 — until then every advisory counts)",
                  evidence: [
                    {
                      kind: "counterexample",
                      note: `${group.ids.join(", ")} — ${pkg.package.ecosystem ?? ""}:${pkg.package.name}@${pkg.package.version}`,
                    },
                  ],
                  reproduce: `osv-scanner scan source --sbom ${SBOM_ARTIFACT}`,
                  ksiIds: ["KSI-SCR-MON", "KSI-CMT-VTD"],
                  controlIds: ["ra-5", "si-2"],
                },
                provenance,
              ),
            );
          }
        }
      }
    }

    // advisories are about the dependency manifests, same anchors as the SBOM
    const anchorPaths: Array<{ path: string; contentHash: string }> = [];
    for (const rel of ["package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock"]) {
      try {
        anchorPaths.push({ path: rel, contentHash: await fileSha256(join(ctx.workspace.root, rel)) });
      } catch {
        // not present — fine
      }
    }

    return {
      findings,
      artifacts: [{ name: "osv-results.json", path: reportPath }],
      observations: { "no-critical-reachable-advisories": rows },
      anchors: { "no-critical-reachable-advisories": anchorPaths },
      toolVersion: version,
      exitCode,
    };
  },
};
