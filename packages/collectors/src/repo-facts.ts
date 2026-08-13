import { readFile, readdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { parse as parseYaml } from "yaml";
import type { Collector, CollectOutput, ObservationRows } from "@rampscan/core";
import type { Finding } from "@rampscan/schema";
import { fileSha256, makeFinding } from "./support.js";

// repo-facts — the hand-rolled collector (plan C2, first on purpose): plain
// file checks, no external tool. Evidences the recipes that are pure
// repository state: lockfile pinning, CI action pinning, CI provenance,
// tests-in-CI, dependency-update automation, CODEOWNERS, container user.

export const REPO_FACTS_VERSION = "0.1.0";

const LOCKFILES = [
  "package-lock.json",
  "npm-shrinkwrap.json",
  "pnpm-lock.yaml",
  "yarn.lock",
  "bun.lock",
  "bun.lockb",
];

const PROVENANCE_USES = /slsa-framework\/slsa-github-generator|actions\/attest-build-provenance|sigstore\/|cosign/i;
const PROVENANCE_RUN = /cosign\s+(sign|attest)|--provenance/i;
const TEST_RUN =
  /\b(vitest|jest|mocha|playwright|cypress|pytest|go\s+test|cargo\s+test|mvn\s+test|gradle\s+test|make\s+test)\b|\b(npm|pnpm|yarn|bun)\s+(run\s+)?test\b/i;

async function exists(path: string): Promise<boolean> {
  try {
    await readFile(path);
    return true;
  } catch {
    return false;
  }
}

interface WorkflowStep {
  uses?: string;
  run?: string;
}

interface ParsedWorkflow {
  file: string; // repo-relative
  steps: WorkflowStep[];
}

async function readWorkflows(root: string): Promise<ParsedWorkflow[]> {
  const dir = join(root, ".github", "workflows");
  let names: string[];
  try {
    names = (await readdir(dir)).filter((n) => /\.ya?ml$/.test(n));
  } catch {
    return [];
  }
  const out: ParsedWorkflow[] = [];
  for (const name of names.sort()) {
    const rel = join(".github", "workflows", name);
    const steps: WorkflowStep[] = [];
    try {
      const doc = parseYaml(await readFile(join(root, rel), "utf8")) as {
        jobs?: Record<string, { steps?: unknown[] }>;
      };
      for (const job of Object.values(doc?.jobs ?? {})) {
        for (const raw of job?.steps ?? []) {
          if (raw && typeof raw === "object") {
            const s = raw as Record<string, unknown>;
            const step: WorkflowStep = {};
            if (typeof s["uses"] === "string") step.uses = s["uses"];
            if (typeof s["run"] === "string") step.run = s["run"];
            steps.push(step);
          }
        }
      }
    } catch {
      // unparseable workflow: still counts as a workflow file, zero steps
    }
    out.push({ file: rel, steps });
  }
  return out;
}

/** an action ref is pinned when it names an immutable revision, not a movable tag */
function pinnedToSha(uses: string): boolean {
  if (uses.startsWith("./")) return true; // repo-local: moves with the commit
  if (uses.startsWith("docker://")) return uses.includes("@sha256:");
  const at = uses.lastIndexOf("@");
  if (at === -1) return false;
  return /^[0-9a-f]{40}$/.test(uses.slice(at + 1));
}

function lastUser(dockerfile: string): string {
  let user = "root"; // no USER directive → the image runs as root
  for (const line of dockerfile.split("\n")) {
    const m = /^\s*USER\s+(\S+)/i.exec(line);
    if (m) user = m[1]!;
  }
  return user;
}

export const repoFacts: Collector = {
  manifest: {
    name: "repo-facts",
    toolVersion: REPO_FACTS_VERSION,
    recipes: [
      "lockfile-pinned-deps",
      "ci-actions-pinned",
      "ci-provenance-present",
      "tests-in-ci",
      "dependency-update-automation",
      "codeowners-defined",
      "container-runs-nonroot",
    ],
  },

  async collect(ctx): Promise<CollectOutput> {
    const { root } = ctx.workspace;
    const provenance = {
      analyzer: "repo-facts",
      version: REPO_FACTS_VERSION,
      runId: ctx.runId,
    };
    const observations: Record<string, ObservationRows> = {};
    const anchors: Record<string, Array<{ path: string; contentHash: string }>> = {};
    const findings: Finding[] = [];

    const anchor = async (recipeId: string, relPath: string) => {
      (anchors[recipeId] ??= []).push({
        path: relPath,
        contentHash: await fileSha256(join(root, relPath)),
      });
    };

    // ---- lockfile-pinned-deps ---------------------------------------------
    if (await exists(join(root, "package.json"))) {
      const present: string[] = [];
      for (const lf of LOCKFILES) {
        if (await exists(join(root, lf))) present.push(lf);
      }
      observations["lockfile-pinned-deps"] = [
        {
          manifest: "package.json",
          lockfile: present[0] ?? null,
          lockfile_present: present.length > 0,
        },
      ];
      await anchor("lockfile-pinned-deps", "package.json");
      for (const lf of present) await anchor("lockfile-pinned-deps", lf);
      if (present.length === 0) {
        findings.push(
          makeFinding(
            {
              variable: "repo-facts",
              anchorNode: "package.json",
              anchorContentHash: await fileSha256(join(root, "package.json")),
              signature: "missing-lockfile",
              severity: "high",
              summary: "package.json has no lockfile — dependency versions float",
              failureScenario:
                "a transitive dependency publishes a malicious or breaking version and the next install silently picks it up; the deployed tree is unreproducible",
              evidence: [{ kind: "file", path: "package.json", note: "no lockfile found beside it" }],
              reproduce: `ls ${LOCKFILES.join(" ")}`,
              ksiIds: ["KSI-SCR-MIT"],
              controlIds: ["si-7.1", "sr-5"],
            },
            provenance,
          ),
        );
      }
    }

    // ---- CI workflows: pinning, provenance, tests -------------------------
    const workflows = await readWorkflows(root);
    const usesRows: ObservationRows = [];
    let provenanceSteps = 0;
    let testSteps = 0;
    for (const wf of workflows) {
      for (const step of wf.steps) {
        if (step.uses) {
          const pinned = pinnedToSha(step.uses);
          usesRows.push({
            workflow: wf.file,
            action: step.uses,
            pinned_to_sha: pinned,
          });
          if (PROVENANCE_USES.test(step.uses)) provenanceSteps++;
          if (!pinned) {
            findings.push(
              makeFinding(
                {
                  variable: "repo-facts",
                  anchorNode: wf.file,
                  anchorContentHash: await fileSha256(join(root, wf.file)),
                  signature: `unpinned-action ${step.uses}`,
                  severity: "medium",
                  summary: `CI action "${step.uses}" is pinned to a mutable ref, not a commit SHA`,
                  failureScenario:
                    "the tag is force-moved to a compromised release and the next CI run executes attacker-controlled code with the workflow's credentials",
                  evidence: [{ kind: "file", path: wf.file, note: `uses: ${step.uses}` }],
                  reproduce: `grep -n "uses: *${step.uses.replaceAll('"', "")}" ${wf.file}`,
                  ksiIds: ["KSI-SCR-MIT"],
                  controlIds: ["sr-5", "si-7.1"],
                },
                provenance,
              ),
            );
          }
        }
        if (step.run) {
          if (PROVENANCE_RUN.test(step.run)) provenanceSteps++;
          if (TEST_RUN.test(step.run)) testSteps++;
        }
      }
    }

    if (workflows.length > 0) {
      observations["ci-actions-pinned"] = usesRows;
      for (const wf of workflows) await anchor("ci-actions-pinned", wf.file);
    }

    observations["ci-provenance-present"] = [
      { workflow_count: workflows.length, provenance_step_count: provenanceSteps },
    ];
    observations["tests-in-ci"] = [
      { workflow_count: workflows.length, test_step_count: testSteps },
    ];
    for (const wf of workflows) {
      await anchor("ci-provenance-present", wf.file);
      await anchor("tests-in-ci", wf.file);
    }
    if (workflows.length > 0 && provenanceSteps === 0) {
      const wf = workflows[0]!;
      findings.push(
        makeFinding(
          {
            variable: "repo-facts",
            anchorNode: wf.file,
            anchorContentHash: await fileSha256(join(root, wf.file)),
            signature: "no-provenance-step",
            severity: "medium",
            summary: "no CI workflow generates build provenance or attestations",
            failureScenario:
              "an artifact of unknown origin is deployed; nothing ties the running build to the reviewed commit, so a tampered build is indistinguishable from a real one",
            evidence: workflows.map((w) => ({ kind: "file" as const, path: w.file })),
            reproduce: `grep -rEn "slsa|attest|provenance|cosign" .github/workflows/ || true`,
            ksiIds: ["KSI-SCR-MIT"],
            controlIds: ["sa-15.3", "si-7.1"],
          },
          provenance,
        ),
      );
    }

    // ---- dependency-update-automation -------------------------------------
    let automationConfig: string | null = null;
    for (const cand of [
      ".github/dependabot.yml",
      ".github/dependabot.yaml",
      "renovate.json",
      "renovate.json5",
      ".renovaterc",
      ".renovaterc.json",
      ".github/renovate.json",
    ]) {
      if (await exists(join(root, cand))) {
        automationConfig = cand;
        break;
      }
    }
    const dependabot = automationConfig?.includes("dependabot") ?? false;
    const renovate = automationConfig !== null && !dependabot;
    observations["dependency-update-automation"] = [
      { dependabot, renovate, automated: automationConfig !== null, config: automationConfig },
    ];
    if (automationConfig) await anchor("dependency-update-automation", automationConfig);

    // ---- codeowners-defined -----------------------------------------------
    let codeownersPath: string | null = null;
    for (const cand of ["CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS"]) {
      if (await exists(join(root, cand))) {
        codeownersPath = cand;
        break;
      }
    }
    observations["codeowners-defined"] = [
      { codeowners_present: codeownersPath !== null, path: codeownersPath },
    ];
    if (codeownersPath) await anchor("codeowners-defined", codeownersPath);

    // ---- container-runs-nonroot -------------------------------------------
    if (await exists(join(root, "Dockerfile"))) {
      const content = await readFile(join(root, "Dockerfile"), "utf8");
      const user = lastUser(content);
      const nonroot = user !== "root" && user !== "0";
      observations["container-runs-nonroot"] = [
        { dockerfile: "Dockerfile", final_user: user, nonroot },
      ];
      await anchor("container-runs-nonroot", "Dockerfile");
      if (!nonroot) {
        findings.push(
          makeFinding(
            {
              variable: "repo-facts",
              anchorNode: "Dockerfile",
              anchorContentHash: await fileSha256(join(root, "Dockerfile")),
              signature: "container-runs-as-root",
              severity: "medium",
              summary: "container image runs as root (no USER directive in Dockerfile)",
              failureScenario:
                "any code-execution bug in the app is immediately root-in-container, making container escape and lateral movement dramatically easier",
              evidence: [{ kind: "file", path: "Dockerfile", note: `final user: ${user}` }],
              reproduce: `grep -n "^USER" Dockerfile || echo "no USER directive"`,
              ksiIds: ["KSI-IAM-ELP"],
              controlIds: ["ac-6"],
            },
            provenance,
          ),
        );
      }
    }

    // the facts artifact: everything observed, in one reviewable file
    const artifactPath = join(ctx.artifactDir, "repo-facts.json");
    await writeFile(artifactPath, JSON.stringify(observations, null, 2));

    return {
      findings,
      artifacts: [{ name: "repo-facts.json", path: artifactPath }],
      observations,
      anchors,
      toolVersion: REPO_FACTS_VERSION,
      exitCode: 0,
    };
  },
};
