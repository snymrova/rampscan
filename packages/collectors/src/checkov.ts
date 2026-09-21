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

/**
 * The recipes the crosswalk `recipes/crosswalks/checkov-3.3.11-to-2026.09.13.02.json`
 * derives over this collector's artifact (docs/PLAN-REACH.md N2-1), named
 * here because a manifest is static and the catalog test wants every recipe
 * a collector answers declared by it. `checkov-crosswalk.test.ts` holds this
 * list equal to the crosswalk's rows, so a row added there without a line
 * here fails the build rather than leaving a recipe nobody claims.
 */
export const CHECKOV_DERIVED_RECIPES = [
  "iac-attack-surface-declared",
  "iac-backups-declared",
  "iac-central-logging-declared",
  "iac-encryption-declared",
  "iac-event-logging-declared",
  "iac-logical-networking-declared",
  "iac-service-auth-declared",
  "iac-tls-validation-declared",
  "iac-traffic-restricted-declared",
] as const;

/** a failed check as the normalized artifact and the observation rows carry it */
export interface FailedCheck {
  check_id: string;
  check_name: string;
  framework: string;
  file: string;
  resource: string;
}

/**
 * The observation set of every crosswalk-derived recipe this run (N2-1),
 * pure over what checkov evaluated and what the recipes carry.
 *
 * The soundness rule, and the reason this is a function with a test rather
 * than three lines inside `collect`: a derived recipe's observation set
 * EXISTS only when at least one of its rules was evaluated this run — present
 * in checkov's passed or failed checks over the frameworks the tree
 * contained. A recipe whose rules all target a framework the tree does not
 * have (every terraform rule, on a repository with Dockerfiles only) gets no
 * key, so the join reads it `unevidenced`; emitting `[]` for it would let
 * `count_eq 0` pass over rules that never ran, which is the vacuous pass one
 * level above the one `iac-baseline-clean`'s Skip already guards.
 *
 * When the key exists, its rows are the failed checks whose id the recipe
 * carries — the same rows the base recipe holds, filtered — so the recipe's
 * `where … in` narrows nothing further and the population is the count of
 * failures among its own rules.
 */
export function derivedObservations(
  evaluated: ReadonlySet<string>,
  failed: readonly FailedCheck[],
  recipes: ReadonlyArray<{ id: string; derived_from?: { checks: string[] } | undefined }>,
): Record<string, ObservationRows> {
  const out: Record<string, ObservationRows> = {};
  for (const recipe of recipes) {
    const checks = recipe.derived_from?.checks;
    if (checks === undefined) continue;
    if (!checks.some((id) => evaluated.has(id))) continue;
    const mapped = new Set(checks);
    out[recipe.id] = failed.filter((f) => mapped.has(f.check_id)).map((f) => ({ ...f }));
  }
  return out;
}

interface FrameworkMatch {
  framework: string;
  test: (path: string) => boolean;
}

const FRAMEWORKS: FrameworkMatch[] = [
  { framework: "dockerfile", test: (p) => /(^|\/)Dockerfile([^/]*)?$|\.dockerfile$/.test(p) },
  {
    framework: "github_actions",
    // composite actions included since #23: the same framework, one directory
    // over, and the same secrets when a workflow calls them
    test: (p) => /^\.github\/(workflows\/[^/]+|actions\/.+\/action)\.ya?ml$/.test(p),
  },
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

const CheckovCheck = z.looseObject({
  check_id: z.string(),
  check_name: z.string().optional(),
  file_path: z.string(),
  resource: z.string().optional(),
  guideline: z.string().nullable().optional(),
});

const CheckovReport = z.looseObject({
  check_type: z.string(),
  results: z.looseObject({
    passed_checks: z.array(CheckovCheck).optional(),
    failed_checks: z.array(CheckovCheck).optional(),
  }),
});

/**
 * checkov emits one report object for a single framework, an array for
 * several. Exported for the schema hard-edge pin (#31): loose parsing must
 * retain unknown vendor fields.
 */
export const CheckovOutput = z.union([CheckovReport, z.array(CheckovReport)]);

export const checkov: Collector = {
  manifest: {
    name: "checkov",
    toolVersion: "resolved-at-run",
    tools: ["checkov"],
    recipes: ["iac-baseline-clean", ...CHECKOV_DERIVED_RECIPES],
    outputs: [CHECKOV_RESULTS_ARTIFACT],
    cacheScope: ["**/Dockerfile", "**/Dockerfile.*", "**/*.dockerfile", ".github/workflows/**", "**/*.tf", "**/*.tf.json"],
    // Declared scan scope (SPEC §12.6): the scanned set is enumerated via
    // `git ls-files` — tracked files only, masked paths never walked.
    scope: { population: "checkout", history: false, gitignored: "excluded" },
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
    const failed: FailedCheck[] = [];
    // every rule id checkov evaluated this run, passed or failed — the
    // population a crosswalk-derived recipe's existence is decided against
    const evaluated = new Set<string>();
    for (const report of reports) {
      passedCount += report.results.passed_checks?.length ?? 0;
      for (const c of report.results.passed_checks ?? []) evaluated.add(c.check_id);
      for (const c of report.results.failed_checks ?? []) {
        evaluated.add(c.check_id);
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
      // the rule ids that ran, so the artifact carries the population each
      // derived recipe's existence was judged against (N2-1)
      evaluated_check_ids: [...evaluated].sort(),
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

    // the crosswalk-derived recipes (N2-1): one observation set per recipe
    // whose rules were evaluated this run, none for a recipe whose rules
    // never applied — `derivedObservations` states the rule
    const derived = derivedObservations(evaluated, failed, ctx.recipes ?? []);
    const derivedAnchors = Object.fromEntries(Object.keys(derived).map((id) => [id, anchorPaths]));

    return {
      findings,
      artifacts: [{ name: CHECKOV_RESULTS_ARTIFACT, path: resultsPath }],
      // rows may be EMPTY: checkov ran over real IaC and rejected nothing —
      // that is an observation (count_eq 0 passes → evidenced), not an absence
      observations: { "iac-baseline-clean": rows, ...derived },
      anchors: { "iac-baseline-clean": anchorPaths, ...derivedAnchors },
      toolVersion: version,
      exitCode,
      reproduce: `checkov -d <repo> --framework ${iac.frameworks.join(" ")}`,
    };
  },
};
