import { readdir, writeFile } from "node:fs/promises";
import { join, posix } from "node:path";
import { z } from "zod";
import type { Collector, CollectOutput, ObservationRows } from "@rampscan/core";
import type { Finding } from "@rampscan/schema";
import { exec, fileSha256, makeFinding } from "./support.js";
import { absentReason, resolveTool } from "./tools.js";

// spectral — OpenAPI/Swagger document lint (the API contract plane). Like
// checkov, no graph involvement: a spec file has no call path. Documents are
// found by name in the committed tree; the ruleset is always rampscan's own
// (`extends: spectral:oas`, bundled inside the pinned tool — offline and
// deterministic), never the repo's, so the evidence claim is against a fixed
// baseline rather than whatever the repo chose to silence.

export const SPECTRAL_RESULTS_ARTIFACT = "spectral-results.json";

const SPEC_FILE = /(^|\/)(openapi|swagger)[^/]*\.(ya?ml|json)$/i;

const SEVERITY_NAMES = ["error", "warning", "info", "hint"] as const;

const SpectralResult = z
  .object({
    code: z.union([z.string(), z.number()]),
    message: z.string(),
    severity: z.number(),
    source: z.string().optional(),
    path: z.array(z.union([z.string(), z.number()])).optional(),
    range: z.object({ start: z.object({ line: z.number() }).passthrough() }).passthrough(),
  })
  .passthrough();
const SpectralOutput = z.array(SpectralResult);

/** committed files via git; fs walk as the non-git fallback (unit-test roots) */
async function listCommittedFiles(root: string): Promise<string[]> {
  const res = await exec("git", ["ls-files"], { cwd: root }).catch(() => undefined);
  if (res && res.exitCode === 0) {
    return res.stdout.split("\n").filter((l) => l.length > 0);
  }
  const out: string[] = [];
  async function walk(rel: string): Promise<void> {
    for (const entry of await readdir(join(root, rel), { withFileTypes: true })) {
      if (entry.name === "node_modules" || entry.name === ".git") continue;
      const childRel = rel === "" ? entry.name : `${rel}/${entry.name}`;
      if (entry.isDirectory()) await walk(childRel);
      else out.push(childRel);
    }
  }
  await walk("");
  return out;
}

export function matchSpecFiles(files: string[]): string[] {
  return files.filter((f) => SPEC_FILE.test(f)).sort();
}

export const spectral: Collector = {
  manifest: {
    name: "spectral",
    toolVersion: "resolved-at-run",
    tools: ["spectral"],
    recipes: ["api-spec-lint-clean"],
    outputs: [SPECTRAL_RESULTS_ARTIFACT],
    cacheScope: ["**/openapi*.yaml", "**/openapi*.yml", "**/openapi*.json", "**/swagger*.yaml", "**/swagger*.yml", "**/swagger*.json"],
  },

  async collect(ctx): Promise<CollectOutput> {
    const committed = await listCommittedFiles(ctx.workspace.root);
    const specs = matchSpecFiles(committed);
    if (specs.length === 0) {
      return {
        findings: [],
        artifacts: [],
        observations: {},
        toolVersion: "n/a",
        exitCode: 0,
        skipped: { reason: "no OpenAPI/Swagger documents in the committed tree — nothing API-shaped to lint" },
      };
    }

    const tool = await resolveTool("spectral", {
      args: ["--version"],
      parse: (out) => out.split("\n")[0]!.trim(),
    });
    if (!tool) {
      return {
        findings: [],
        artifacts: [],
        observations: {},
        toolVersion: "absent",
        exitCode: -1,
        skipped: { reason: absentReason("spectral") },
      };
    }
    const version = tool.version;

    // rampscan's ruleset, not the repo's: spectral:oas ships inside the tool
    const rulesetPath = join(ctx.artifactDir, ".spectral.yaml");
    await writeFile(rulesetPath, 'extends: ["spectral:oas"]\n');

    const scanRoot = tool.mount(ctx.workspace.root, "ro");
    const rulesetArg = posix.join(tool.mount(ctx.artifactDir, "rw"), ".spectral.yaml");
    // exit 0 = clean, 1 = results at or above fail-severity; both are results
    const { stdout, exitCode, stderr } = await tool.exec([
      "lint",
      "--ruleset",
      rulesetArg,
      "--format",
      "json",
      ...specs.map((s) => posix.join(scanRoot, s)),
    ]);
    if (exitCode !== 0 && exitCode !== 1) {
      return {
        findings: [],
        artifacts: [],
        observations: {},
        toolVersion: version,
        exitCode,
        skipped: { reason: `spectral failed (exit ${exitCode}, via ${tool.runtime}): ${stderr.slice(0, 300)}` },
      };
    }

    const results = SpectralOutput.parse(JSON.parse(stdout));
    const relativize = (p: string | undefined): string => {
      if (p === undefined) return specs[0]!;
      const root = scanRoot.endsWith("/") ? scanRoot : scanRoot + "/";
      return p.startsWith(root) ? p.slice(root.length) : p;
    };

    const normalizedResults = results
      .map((r) => ({
        code: String(r.code),
        file: relativize(r.source),
        line: r.range.start.line + 1, // spectral ranges are 0-based
        severity: SEVERITY_NAMES[r.severity] ?? String(r.severity),
        message: r.message,
        json_path: (r.path ?? []).join("."),
      }))
      .sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line || a.code.localeCompare(b.code));

    const normalized = {
      tool: "spectral",
      version,
      ruleset: "spectral:oas",
      documents: specs,
      results: normalizedResults,
    };
    const resultsPath = join(ctx.artifactDir, SPECTRAL_RESULTS_ARTIFACT);
    await writeFile(resultsPath, JSON.stringify(normalized, null, 2) + "\n");

    const rows: ObservationRows = normalizedResults.map((r) => ({ ...r }));
    const provenance = { analyzer: "spectral", version, runId: ctx.runId };
    const findings: Finding[] = [];
    for (const r of normalizedResults) {
      if (r.severity !== "error") continue;
      findings.push(
        makeFinding(
          {
            variable: "api-spec",
            anchorNode: r.file,
            anchorContentHash: await fileSha256(join(ctx.workspace.root, r.file)).catch(() => r.file),
            signature: `${r.code} ${r.file} ${r.json_path}`,
            severity: "medium",
            summary: `${r.code}: ${r.message} — ${r.file}:${r.line}`,
            failureScenario:
              "the published API contract is invalid against the OpenAPI standard; every consumer and generated client works from a document that lies",
            evidence: [
              { kind: "counterexample", path: r.file, note: `${r.code} at ${r.json_path || "document root"}: ${r.message}` },
            ],
            reproduce: `spectral lint --ruleset '{"extends":["spectral:oas"]}' ${specs.join(" ")}`,
            ksiIds: ["KSI-SVC-ACM"],
            controlIds: ["sa-5"],
          },
          provenance,
        ),
      );
    }

    const anchorPaths: Array<{ path: string; contentHash: string }> = [];
    for (const rel of specs) {
      try {
        anchorPaths.push({ path: rel, contentHash: await fileSha256(join(ctx.workspace.root, rel)) });
      } catch {
        // committed but absent from the working tree — the row still stands
      }
    }

    return {
      findings,
      artifacts: [{ name: SPECTRAL_RESULTS_ARTIFACT, path: resultsPath }],
      // rows may be EMPTY: spectral linted real documents and objected to
      // nothing — an observation (count_eq 0 passes → evidenced), not an absence
      observations: { "api-spec-lint-clean": rows },
      anchors: { "api-spec-lint-clean": anchorPaths },
      toolVersion: version,
      exitCode,
      reproduce: `spectral lint --ruleset '{"extends":["spectral:oas"]}' ${specs.join(" ")}`,
    };
  },
};
