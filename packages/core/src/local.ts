import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, readFile } from "node:fs/promises";
import { isAbsolute, join, relative, resolve } from "node:path";
import { promisify } from "node:util";
import { Finding } from "@rampscan/schema";
import type {
  Collector,
  RepoSource,
  RunResult,
  Runner,
  Scheduler,
  Workspace,
} from "./ports.js";

const execFileAsync = promisify(execFile);

// Local adapters. Runner and RepoSource are real as of M1; the M2 adapters
// live in their own packages (@rampscan/ledger, @rampscan/signer,
// @rampscan/projector) per plan §M2. Scheduler lands in M5 and remains a loud
// stub so wiring code can depend on the constructor without fake data back.

function notImplemented(port: string, milestone: string): never {
  throw new Error(`${port} local adapter lands in ${milestone} — not implemented yet`);
}

/**
 * Local Runner: executes registered collectors in-process (the collectors
 * themselves spawn their tools). Later: Fargate task per collector.
 *
 * The runner is the Zod boundary (plan C1): findings coming back from a
 * collector are re-parsed here, so a misbehaving wrapper fails loudly instead
 * of leaking malformed findings into the join.
 */
export function createLocalRunner(options: {
  collectors: Collector[];
  /** absolute dir for this run's artifacts; each collector gets a subdir */
  artifactDir: string;
  /** artifacts from earlier collectors in the run: name → absolute path */
  inputs?: Map<string, string>;
  runId: string;
}): Runner {
  const byName = new Map(options.collectors.map((c) => [c.manifest.name, c]));
  const inputs = options.inputs ?? new Map<string, string>();

  return {
    async run(manifest, workspace): Promise<RunResult> {
      const collector = byName.get(manifest.name);
      if (!collector) {
        throw new Error(`no collector registered for manifest "${manifest.name}"`);
      }
      const artifactDir = join(options.artifactDir, manifest.name);
      await mkdir(artifactDir, { recursive: true });

      const out = await collector.collect({
        workspace,
        artifactDir,
        inputs,
        runId: options.runId,
      });

      const findings = out.findings.map((f) => Finding.parse(f));
      const artifacts = await Promise.all(
        out.artifacts.map(async (a) => {
          const abs = isAbsolute(a.path) ? a.path : join(artifactDir, a.path);
          const sha256 = createHash("sha256")
            .update(await readFile(abs))
            .digest("hex");
          // record the new artifact so later collectors can consume it by name
          inputs.set(a.name, abs);
          return { name: a.name, path: relative(options.artifactDir, abs), sha256 };
        }),
      );

      const result: RunResult = {
        findings,
        artifacts,
        observations: out.observations,
        anchors: out.anchors ?? {},
        toolVersion: out.toolVersion,
        exitCode: out.exitCode,
      };
      if (out.skipped) result.skipped = out.skipped;
      return result;
    },
  };
}

export function createLocalScheduler(): Scheduler {
  return {
    ensureCadence: async () => notImplemented("Scheduler", "M5"),
  };
}

/**
 * Local RepoSource: the target is a path to a checkout already on disk; the
 * workspace pins to its current HEAD. Later: GitHub App clone at a ref.
 */
export function createLocalRepoSource(): RepoSource {
  return {
    async fetch(target): Promise<Workspace> {
      const root = resolve(target.repo);
      const ref = target.ref ?? "HEAD";
      let commit: string;
      try {
        const { stdout } = await execFileAsync("git", ["rev-parse", ref], {
          cwd: root,
        });
        commit = stdout.trim();
      } catch (cause) {
        throw new Error(
          `cannot pin workspace: "${root}" is not a git checkout (or ref "${ref}" is unknown) — commit anchoring requires git history`,
          { cause },
        );
      }
      return { root, repo: target.repo, commit };
    },
  };
}
