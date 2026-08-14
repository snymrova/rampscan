import { readFile, writeFile } from "node:fs/promises";
import { dirname, join, posix } from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import type { Collector, CollectOutput } from "@rampscan/core";
import { exec, sha256 } from "./support.js";
import { absentReason, resolveTool } from "./tools.js";

// semgrep — SAST over the committed sources, pure PRODUCER (same posture as
// osv-scanner after M4): it writes semgrep-results.json and nothing else.
// The verdict, the findings, and the call paths all belong to the
// `sast-reachability` collector, which joins this artifact against graph.db —
// a SAST hit only counts once its reachability is known (or honestly
// unknown).
//
// The artifact is NORMALIZED, not semgrep's raw output: repo-relative paths,
// a minimal field set, sorted rows. Raw semgrep output embeds the scan path
// (host path for a binary run, bind-mount path under Docker) and run-varying
// sections — normalizing keeps the artifact byte-identical across runtimes,
// so evidence identity doesn't re-key on plumbing.

export const SEMGREP_RESULTS_ARTIFACT = "semgrep-results.json";
// `join(dirname(fileURLToPath(...)))`, NOT `new URL("...", import.meta.url)`:
// the console's Next.js routes transpile this package, and webpack rewrites
// the relative-URL pattern into an asset reference that crashes at module
// load — which took the console's server routes down with it
export const SEMGREP_RULES_PATH = join(
  dirname(fileURLToPath(import.meta.url)),
  "../semgrep-rules.yaml",
);

const RawSemgrepOutput = z
  .object({
    version: z.string().optional(),
    results: z.array(
      z
        .object({
          check_id: z.string(),
          path: z.string(),
          start: z.object({ line: z.number() }).passthrough(),
          end: z.object({ line: z.number() }).passthrough(),
          extra: z
            .object({
              severity: z.string(),
              message: z.string(),
            })
            .passthrough(),
        })
        .passthrough(),
    ),
    errors: z.array(z.object({}).passthrough()),
  })
  .passthrough();

export const SemgrepResults = z.object({
  tool: z.literal("semgrep"),
  version: z.string(),
  rules: z.string(), // sha256 of the ruleset that produced these results
  results: z.array(
    z.object({
      check_id: z.string(),
      path: z.string(), // repo-relative
      start_line: z.number(),
      end_line: z.number(),
      severity: z.string(), // ERROR | WARNING | INFO
      message: z.string(),
    }),
  ),
  error_count: z.number(),
});
export type SemgrepResults = z.infer<typeof SemgrepResults>;

/** strip the scan-root prefix from a result path — repo-relative or bust */
export function relativizeResultPath(path: string, scanRoot: string): string {
  const root = scanRoot.endsWith("/") ? scanRoot : scanRoot + "/";
  return path.startsWith(root) ? path.slice(root.length) : path;
}

export const semgrep: Collector = {
  manifest: {
    name: "semgrep",
    toolVersion: "resolved-at-run",
    recipes: [], // producer only — the SAST recipe is evidenced by `sast-reachability`
    outputs: [SEMGREP_RESULTS_ARTIFACT],
    // the sources the rules read; the ruleset content itself rides in the
    // cache salt (cacheKeySalt), like a tool re-pin
    cacheScope: [
      "**/*.ts",
      "**/*.tsx",
      "**/*.mts",
      "**/*.cts",
      "**/*.js",
      "**/*.jsx",
      "**/*.mjs",
      "**/*.cjs",
    ],
  },

  async collect(ctx): Promise<CollectOutput> {
    const tool = await resolveTool("semgrep", {
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
        skipped: { reason: absentReason("semgrep") },
      };
    }
    const version = tool.version;
    const rulesContent = await readFile(SEMGREP_RULES_PATH, "utf8");

    // Committed tree only (the self-scan lesson, same as syft): semgrep scans
    // the filesystem, so untracked + ignored paths — computed from git, not a
    // static list — are excluded before they can leak into commit-anchored
    // evidence.
    const excludes: string[] = [];
    const untracked = await exec("git", ["ls-files", "--others", "--directory"], {
      cwd: ctx.workspace.root,
    });
    if (untracked.exitCode === 0) {
      for (const line of untracked.stdout.split("\n")) {
        if (line === "") continue;
        excludes.push("--exclude", line.endsWith("/") ? line.slice(0, -1) : line);
      }
    }

    const rulesArg = tool.mount(SEMGREP_RULES_PATH, "ro");
    const scanRoot = tool.mount(ctx.workspace.root, "ro");
    const outPath = join(ctx.artifactDir, "semgrep-raw.json");
    const outArg = posix.join(tool.mount(ctx.artifactDir, "rw"), "semgrep-raw.json");
    // --metrics=off: no phoning home; findings are a result, not an error
    // (semgrep exits 0 on findings unless --error is passed — it isn't)
    const { exitCode, stderr } = await tool.exec([
      "scan",
      "--config",
      rulesArg,
      "--json",
      "--output",
      outArg,
      "--metrics=off",
      "--quiet",
      ...excludes,
      scanRoot,
    ]);
    if (exitCode !== 0) {
      return {
        findings: [],
        artifacts: [],
        observations: {},
        toolVersion: version,
        exitCode,
        skipped: { reason: `semgrep failed (exit ${exitCode}, via ${tool.runtime}): ${stderr.slice(0, 300)}` },
      };
    }

    const raw = RawSemgrepOutput.parse(JSON.parse(await readFile(outPath, "utf8")));
    const normalized: SemgrepResults = {
      tool: "semgrep",
      version,
      rules: sha256(rulesContent),
      results: raw.results
        .map((r) => ({
          // semgrep namespaces rule ids with a prefix derived from the CONFIG
          // PATH (host path for a binary, bind-mount path under Docker) — the
          // final segment is the authored id, and the only stable one; rule
          // ids in the vendored set are dot-free so this is lossless
          check_id: r.check_id.split(".").pop()!,
          path: relativizeResultPath(r.path, scanRoot),
          start_line: r.start.line,
          end_line: r.end.line,
          severity: r.extra.severity,
          message: r.extra.message,
        }))
        .sort((a, b) =>
          a.path.localeCompare(b.path) || a.start_line - b.start_line || a.check_id.localeCompare(b.check_id),
        ),
      error_count: raw.errors.length,
    };
    const resultsPath = join(ctx.artifactDir, SEMGREP_RESULTS_ARTIFACT);
    await writeFile(resultsPath, JSON.stringify(normalized, null, 2) + "\n");

    return {
      findings: [],
      artifacts: [{ name: SEMGREP_RESULTS_ARTIFACT, path: resultsPath }],
      observations: {},
      toolVersion: version,
      exitCode,
    };
  },
};
