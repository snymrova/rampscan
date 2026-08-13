import { readFile } from "node:fs/promises";
import { join, posix } from "node:path";
import { z } from "zod";
import type { Collector, CollectOutput } from "@rampscan/core";
import { fileSha256 } from "./support.js";
import { absentReason, resolveTool } from "./tools.js";

// syft — SBOM in CycloneDX JSON (plan C2). The SBOM is the inventory artifact
// downstream collectors consume (osv-scanner reads it by name via the run's
// input map).

export const SBOM_ARTIFACT = "sbom.cdx.json";

const CycloneDx = z
  .object({
    specVersion: z.string(),
    metadata: z.object({ timestamp: z.string().optional() }).passthrough().optional(),
    components: z.array(z.object({}).passthrough()).optional(),
  })
  .passthrough();

const MANIFEST_ANCHORS = [
  "package.json",
  "package-lock.json",
  "pnpm-lock.yaml",
  "yarn.lock",
  "bun.lock",
  "requirements.txt",
  "go.mod",
  "Cargo.lock",
];

export const syft: Collector = {
  manifest: {
    name: "syft",
    toolVersion: "resolved-at-run",
    recipes: ["sbom-exists-and-fresh"],
    outputs: [SBOM_ARTIFACT],
    cacheScope: ["@tree"], // scans the committed tree — any content change re-runs it
  },

  async collect(ctx): Promise<CollectOutput> {
    const tool = await resolveTool("syft", {
      args: ["--version"],
      parse: (out) => out.replace(/^syft\s+/, "").trim(),
    });
    if (!tool) {
      return {
        findings: [],
        artifacts: [],
        observations: {},
        toolVersion: "absent",
        exitCode: -1,
        skipped: { reason: absentReason("syft") },
      };
    }
    const version = tool.version;

    const sbomPath = join(ctx.artifactDir, SBOM_ARTIFACT);
    const sbomArg = posix.join(tool.mount(ctx.artifactDir, "rw"), SBOM_ARTIFACT);
    // Exclude uncommitted trees (installs, build output, .git): they are not
    // commit-anchored, so an SBOM that catalogs them cannot honestly claim to
    // describe the scanned commit — the manifests and lockfiles can.
    const excludes = ["node_modules", ".git", ".next", "dist", "build", "vendor", ".venv"].flatMap(
      (d) => ["--exclude", `./**/${d}/**`, "--exclude", `./${d}/**`],
    );
    const { exitCode, stderr } = await tool.exec([
      "scan",
      `dir:${tool.mount(ctx.workspace.root, "ro")}`,
      "-o",
      `cyclonedx-json=${sbomArg}`,
      "-q",
      ...excludes,
    ]);
    if (exitCode !== 0) {
      return {
        findings: [],
        artifacts: [],
        observations: {},
        toolVersion: version,
        exitCode,
        skipped: { reason: `syft failed (exit ${exitCode}, via ${tool.runtime}): ${stderr.slice(0, 300)}` },
      };
    }

    const sbom = CycloneDx.parse(JSON.parse(await readFile(sbomPath, "utf8")));
    const generatedAt = sbom.metadata?.timestamp ?? new Date().toISOString();

    // the SBOM is *about* the dependency manifests — deps change, SBOM dies
    const anchorPaths: Array<{ path: string; contentHash: string }> = [];
    for (const rel of MANIFEST_ANCHORS) {
      try {
        anchorPaths.push({ path: rel, contentHash: await fileSha256(join(ctx.workspace.root, rel)) });
      } catch {
        // manifest not present in this repo — fine
      }
    }

    return {
      findings: [],
      artifacts: [{ name: SBOM_ARTIFACT, path: sbomPath }],
      observations: {
        "sbom-exists-and-fresh": [
          {
            format: "CycloneDX",
            spec_version: sbom.specVersion,
            component_count: sbom.components?.length ?? 0,
            generated_at: generatedAt,
          },
        ],
      },
      anchors: { "sbom-exists-and-fresh": anchorPaths },
      toolVersion: version,
      exitCode,
    };
  },
};
