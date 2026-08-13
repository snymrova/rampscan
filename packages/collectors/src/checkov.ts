import { readdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import type { Collector, CollectOutput, ObservationRows } from "@rampscan/core";
import type { Finding } from "@rampscan/schema";
import { exec, fileSha256, makeFinding } from "./support.js";
import { absentReason, resolveTool } from "./tools.js";

// checkov — IaC misconfiguration scan (the config plane: Dockerfiles, CI
// workflows, Terraform). No graph involvement, deliberately: there is no
// call path to walk in a Dockerfile — this is a pure M1-style collector,
// spawn → parse → rows. Frameworks are limited to what the committed tree
// actually contains, detected up front; a repo with nothing IaC-shaped
// skips honestly instead of reporting a vacuous pass.

export const CHECKOV_RESULTS_ARTIFACT = "checkov-results.json";

interface FrameworkMatch {
  framework: string;
  test: (path: string) => boolean;
}

const FRAMEWORKS: FrameworkMatch[] = [
  { framework: "dockerfile", test: (p) => /(^|\/)Dockerfile([^/]*)?$|\.dockerfile$/.test(p) },
  { framework: "github_actions", test: (p) => /^\.github\/workflows\/[^/]+\.ya?ml$/.test(p) },
  { framework: "terraform", test: (p) => /\.tf$|\.tf\.json$/.test(p) },
];

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

export function matchIacFiles(files: string[]): { frameworks: string[]; files: string[] } {
  const frameworks = new Set<string>();
  const matched: string[] = [];
  for (const file of files) {
    for (const { framework, test } of FRAMEWORKS) {
      if (test(file)) {
        frameworks.add(framework);
        matched.push(file);
        break;
      }
    }
  }
  return { frameworks: [...frameworks].sort(), files: matched.sort() };
}

const CheckovCheck = z
  .object({
    check_id: z.string(),
    check_name: z.string().optional(),
    file_path: z.string(),
    resource: z.string().optional(),
    guideline: z.string().nullable().optional(),
  })
  .passthrough();

const CheckovReport = z
  .object({
    check_type: z.string(),
    results: z
      .object({
        passed_checks: z.array(CheckovCheck).optional(),
        failed_checks: z.array(CheckovCheck).optional(),
      })
      .passthrough(),
  })
  .passthrough();

/** checkov emits one report object for a single framework, an array for several */
const CheckovOutput = z.union([CheckovReport, z.array(CheckovReport)]);

export const checkov: Collector = {
  manifest: {
    name: "checkov",
    toolVersion: "resolved-at-run",
    recipes: ["iac-baseline-clean"],
    outputs: [CHECKOV_RESULTS_ARTIFACT],
    cacheScope: ["**/Dockerfile", "**/Dockerfile.*", "**/*.dockerfile", ".github/workflows/**", "**/*.tf", "**/*.tf.json"],
  },

  async collect(ctx): Promise<CollectOutput> {
    const committed = await listCommittedFiles(ctx.workspace.root);
    const iac = matchIacFiles(committed);
    if (iac.frameworks.length === 0) {
      return {
        findings: [],
        artifacts: [],
        observations: {},
        toolVersion: "n/a",
        exitCode: 0,
        skipped: { reason: "no IaC in the committed tree (Dockerfile, GitHub workflow, Terraform) — nothing config-shaped to scan" },
      };
    }

    const tool = await resolveTool("checkov", {
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
        skipped: { reason: absentReason("checkov") },
      };
    }
    const version = tool.version;

    const scanRoot = tool.mount(ctx.workspace.root, "ro");
    // --skip-download: no external policy or module fetches — the vendored
    // policy set that ships inside the pinned image is the whole baseline,
    // deterministic and offline. No --quiet: it strips passed_checks from
    // the JSON too, and passed_count must be computed, never zeroed by a
    // display flag. Exit 1 means "failed checks" — a result.
    const { stdout, exitCode, stderr } = await tool.exec([
      "-d",
      scanRoot,
      "-o",
      "json",
      "--skip-download",
      "--framework",
      ...iac.frameworks,
    ]);
    if (exitCode !== 0 && exitCode !== 1) {
      return {
        findings: [],
        artifacts: [],
        observations: {},
        toolVersion: version,
        exitCode,
        skipped: { reason: `checkov failed (exit ${exitCode}, via ${tool.runtime}): ${stderr.slice(0, 300)}` },
      };
    }

    const parsed = CheckovOutput.parse(JSON.parse(stdout));
    const reports = Array.isArray(parsed) ? parsed : [parsed];
    const relativize = (p: string): string => {
      const root = scanRoot.endsWith("/") ? scanRoot : scanRoot + "/";
      if (p.startsWith(root)) return p.slice(root.length);
      return p.startsWith("/") ? p.slice(1) : p;
    };

    let passedCount = 0;
    const failed: Array<{
      check_id: string;
      check_name: string;
      framework: string;
      file: string;
      resource: string;
    }> = [];
    for (const report of reports) {
      passedCount += report.results.passed_checks?.length ?? 0;
      for (const c of report.results.failed_checks ?? []) {
        failed.push({
          check_id: c.check_id,
          check_name: c.check_name ?? c.check_id,
          framework: report.check_type,
          file: relativize(c.file_path),
          resource: c.resource ?? "",
        });
      }
    }
    failed.sort(
      (a, b) => a.file.localeCompare(b.file) || a.check_id.localeCompare(b.check_id) || a.resource.localeCompare(b.resource),
    );

    const normalized = {
      tool: "checkov",
      version,
      frameworks: iac.frameworks,
      passed_count: passedCount,
      failed_count: failed.length,
      failed,
    };
    const resultsPath = join(ctx.artifactDir, CHECKOV_RESULTS_ARTIFACT);
    await writeFile(resultsPath, JSON.stringify(normalized, null, 2) + "\n");

    const rows: ObservationRows = failed.map((f) => ({ ...f }));
    const provenance = { analyzer: "checkov", version, runId: ctx.runId };
    const findings: Finding[] = [];
    for (const f of failed) {
      findings.push(
        makeFinding(
          {
            variable: "iac",
            anchorNode: f.file,
            anchorContentHash: await fileSha256(join(ctx.workspace.root, f.file)).catch(() => f.file),
            signature: `${f.check_id} ${f.file} ${f.resource}`,
            severity: "medium",
            summary: `${f.check_id}: ${f.check_name} — ${f.file}${f.resource ? ` (${f.resource})` : ""}`,
            failureScenario:
              "the infrastructure definition ships a configuration checkov's baseline rejects; misconfiguration is deployed exactly as committed",
            evidence: [
              { kind: "counterexample", path: f.file, note: `${f.check_id} (${f.framework}): ${f.check_name}` },
            ],
            reproduce: `checkov -d <repo> --framework ${iac.frameworks.join(" ")}`,
            ksiIds: ["KSI-SVC-ACM"],
            controlIds: ["cm-2", "cm-6"],
          },
          provenance,
        ),
      );
    }

    // the evidence is about every IaC file the baseline judged — a change to
    // any of them changes the answer
    const anchorPaths: Array<{ path: string; contentHash: string }> = [];
    for (const rel of iac.files) {
      try {
        anchorPaths.push({ path: rel, contentHash: await fileSha256(join(ctx.workspace.root, rel)) });
      } catch {
        // committed but absent from the working tree — the row still stands
      }
    }

    return {
      findings,
      artifacts: [{ name: CHECKOV_RESULTS_ARTIFACT, path: resultsPath }],
      // rows may be EMPTY: checkov ran over real IaC and rejected nothing —
      // that is an observation (count_eq 0 passes → evidenced), not an absence
      observations: { "iac-baseline-clean": rows },
      anchors: { "iac-baseline-clean": anchorPaths },
      toolVersion: version,
      exitCode,
    };
  },
};
