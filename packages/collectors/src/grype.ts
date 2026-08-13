import { mkdir, readFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join, posix } from "node:path";
import { z } from "zod";
import type { Collector, CollectOutput } from "@rampscan/core";
import type { Finding } from "@rampscan/schema";
import { fileSha256, makeFinding } from "./support.js";
import { absentReason, resolveTool } from "./tools.js";

// grype — OS-level packages in the container image the repo's Dockerfile
// builds FROM: the vulnerabilities the repo manifest never declares (plan C2).
// M1 scans the base image named by the final FROM, not a locally built image —
// building requires the full app context; the base image is where the OS
// packages live. Graceful skip when there is no Dockerfile.

const GrypeReport = z
  .object({
    matches: z.array(
      z.object({
        vulnerability: z.object({
          id: z.string(),
          severity: z.string().optional(),
          fix: z.object({ state: z.string().optional() }).passthrough().optional(),
        }).passthrough(),
        artifact: z.object({
          name: z.string(),
          version: z.string().optional(),
          type: z.string().optional(),
        }).passthrough(),
      }).passthrough(),
    ),
  })
  .passthrough();

/** the base image of the final stage: last FROM line, alias stripped */
export function finalBaseImage(dockerfile: string): string | undefined {
  const stages = new Map<string, string>(); // alias → image
  let last: string | undefined;
  for (const raw of dockerfile.split("\n")) {
    const m = /^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+[Aa][Ss]\s+(\S+))?/.exec(raw);
    if (!m) continue;
    let image = m[1]!;
    // a FROM that names an earlier stage resolves to that stage's image
    image = stages.get(image.toLowerCase()) ?? image;
    if (m[2]) stages.set(m[2].toLowerCase(), image);
    last = image;
  }
  if (last === "scratch") return undefined;
  return last;
}

export const grype: Collector = {
  manifest: {
    name: "grype",
    toolVersion: "resolved-at-run",
    recipes: ["container-base-image-patched"],
  },

  async collect(ctx): Promise<CollectOutput> {
    const tool = await resolveTool("grype", {
      args: ["--version"],
      parse: (out) => out.replace(/^grype\s+/, "").trim(),
    });
    if (!tool) {
      return {
        findings: [],
        artifacts: [],
        observations: {},
        toolVersion: "absent",
        exitCode: -1,
        skipped: { reason: absentReason("grype") },
      };
    }
    const version = tool.version;

    let dockerfile: string;
    try {
      dockerfile = await readFile(join(ctx.workspace.root, "Dockerfile"), "utf8");
    } catch {
      return {
        findings: [],
        artifacts: [],
        observations: {},
        toolVersion: version,
        exitCode: 0,
        skipped: { reason: "no Dockerfile at the repo root — nothing container-shaped to scan" },
      };
    }
    const image = finalBaseImage(dockerfile);
    if (!image) {
      return {
        findings: [],
        artifacts: [],
        observations: {},
        toolVersion: version,
        exitCode: 0,
        skipped: { reason: "Dockerfile has no scannable base image (FROM scratch or unparseable)" },
      };
    }

    const reportPath = join(ctx.artifactDir, "grype-report.json");
    const reportArg = posix.join(tool.mount(ctx.artifactDir, "rw"), "grype-report.json");
    // Under Docker the container is ephemeral but grype's vulnerability DB
    // (~700MB) must not be: mount a persistent host cache dir for it.
    // A local binary manages its own ~/.cache/grype — leave that alone.
    const env: Record<string, string> = {};
    if (tool.kind === "docker") {
      const dbCache = join(homedir(), ".cache", "rampscan", "grype-db");
      await mkdir(dbCache, { recursive: true });
      env["GRYPE_DB_CACHE_DIR"] = tool.mount(dbCache, "rw");
    }
    // exit 0 regardless of matches unless --fail-on is set; network + DB required
    const { exitCode, stderr } = await tool.exec(["-o", "json", "--file", reportArg, image], {
      timeoutMs: 900_000,
      env,
    });
    if (exitCode !== 0) {
      return {
        findings: [],
        artifacts: [],
        observations: {},
        toolVersion: version,
        exitCode,
        skipped: {
          reason: `grype failed on ${image} (exit ${exitCode}, via ${tool.runtime}) — likely no network or image pull failure: ${stderr.slice(0, 300)}`,
        },
      };
    }

    const report = GrypeReport.parse(JSON.parse(await readFile(reportPath, "utf8")));
    const rows = report.matches.map((m) => ({
      vulnerability: m.vulnerability.id,
      severity: (m.vulnerability.severity ?? "Unknown").toUpperCase(),
      package: m.artifact.name,
      version: m.artifact.version ?? "unknown",
      fix_state: m.vulnerability.fix?.state ?? "unknown",
      image,
    }));

    const dockerfileHash = await fileSha256(join(ctx.workspace.root, "Dockerfile"));
    const criticals = rows.filter((r) => r.severity === "CRITICAL");
    const findings: Finding[] = [];
    if (criticals.length > 0) {
      // one finding summarizing the register, not one per CVE — the artifact
      // holds the full list; hundreds of per-CVE findings would drown the run
      findings.push(
        makeFinding(
          {
            variable: "container",
            anchorNode: "Dockerfile",
            anchorContentHash: dockerfileHash,
            signature: `critical-vulns ${image}`,
            severity: "blocker",
            summary: `base image ${image} carries ${criticals.length} CRITICAL OS-level vulnerabilities (${rows.length} total)`,
            failureScenario:
              "every container built from this base ships exploitable OS packages the application never declares; patching the app changes nothing until the base image moves",
            evidence: [
              {
                kind: "counterexample",
                note: criticals.slice(0, 10).map((c) => `${c.vulnerability} (${c.package}@${c.version})`).join(", ") + (criticals.length > 10 ? ", …" : ""),
              },
            ],
            reproduce: `grype ${image}`,
            ksiIds: ["KSI-SCR-MON", "KSI-CMT-VTD"],
            controlIds: ["ra-5", "si-2"],
          },
          { analyzer: "grype", version, runId: ctx.runId },
        ),
      );
    }

    return {
      findings,
      artifacts: [{ name: "grype-report.json", path: reportPath }],
      observations: { "container-base-image-patched": rows },
      anchors: {
        "container-base-image-patched": [{ path: "Dockerfile", contentHash: dockerfileHash }],
      },
      toolVersion: version,
      exitCode,
    };
  },
};
