import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { copyFile, mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { promisify } from "node:util";
import type { CollectorManifest } from "@rampscan/schema";
import type { RunResult, Runner, Workspace } from "./ports.js";

const execFileAsync = promisify(execFile);

// The scan cache (plan G2): incremental scans by content-hash dirty set.
// A Runner decorator — the pipeline composes it around the local runner and
// the collectors never know. Per collector, the cache key is built from the
// manifest's declared cacheScope resolved against the COMMITTED tree:
//
//   glob      → the (path, git blob hash) pairs the pattern matches — the
//               dirty set by content hash, read from `git ls-tree`, no file
//               I/O; a changed file changes its blob hash changes the key
//   "@commit" → the workspace commit (full-history collectors: gitleaks)
//   "@tree"   → the commit's tree hash (whole-committed-tree collectors: syft)
//   "@inputs" → sha256 of the artifacts this collector consumes from earlier
//               collectors in the run (osv-scanner, reachability)
//
// Tool version and a caller salt (the pinned tools.json content) key every
// entry — ground rule 5: tool versions in every cache key. A collector with
// no cacheScope is never cached. Skipped runs are never cached: skip reasons
// are environmental (missing Docker, no Dockerfile) and must re-evaluate.
//
// What the cache can NOT see: the world outside the repo — a new advisory
// published to OSV or grype's DB, a PATH binary upgraded in place. That is
// exactly why the daemon schedules full cache-bypassing scans and diffs them
// against the incremental result: the cache verifies itself, and external
// drift surfaces as a divergence alert instead of silent staleness.

export type CacheMode = "incremental" | "full";
export type CacheOutcome = "hit" | "miss" | "bypass" | "uncachable";

export interface CachingRunnerOptions {
  /** cache root; entries land at <dir>/<collector>/<key>/ */
  dir: string;
  /** incremental: read+write. full: bypass reads, refresh entries. */
  mode: CacheMode;
  /** the run's artifact dir — cached artifacts are restored under it */
  artifactDir: string;
  /** the run's inputs map — restored artifacts register here for later collectors */
  inputs: Map<string, string>;
  /** extra material folded into every key (e.g. the tools.json content hash) */
  keySalt?: string;
  onOutcome?(collector: string, outcome: CacheOutcome): void;
  log?(line: string): void;
}

interface TreeEntry {
  path: string;
  blob: string;
}

async function listTree(root: string): Promise<TreeEntry[]> {
  const { stdout } = await execFileAsync(
    "git",
    ["ls-tree", "-r", "--format=%(objectname) %(path)", "HEAD"],
    { cwd: root, maxBuffer: 64 * 1024 * 1024 },
  );
  return stdout
    .split("\n")
    .filter((line) => line.length > 0)
    .map((line) => {
      const space = line.indexOf(" ");
      return { blob: line.slice(0, space), path: line.slice(space + 1) };
    });
}

async function treeHash(root: string): Promise<string> {
  const { stdout } = await execFileAsync("git", ["rev-parse", "HEAD^{tree}"], { cwd: root });
  return stdout.trim();
}

/** glob → RegExp: `**` crosses directories, `*` and `?` stay inside one segment */
export function globToRegExp(glob: string): RegExp {
  let out = "^";
  for (let i = 0; i < glob.length; i++) {
    const ch = glob[i]!;
    if (ch === "*") {
      if (glob[i + 1] === "*") {
        // `**/` at a boundary also matches zero directories
        if (glob[i + 2] === "/") {
          out += "(?:.*/)?";
          i += 2;
        } else {
          out += ".*";
          i += 1;
        }
      } else {
        out += "[^/]*";
      }
    } else if (ch === "?") {
      out += "[^/]";
    } else {
      out += ch.replace(/[.+^${}()|[\]\\]/g, "\\$&");
    }
  }
  return new RegExp(out + "$");
}

async function sha256File(path: string): Promise<string> {
  return createHash("sha256").update(await readFile(path)).digest("hex");
}

function sha256Hex(text: string): string {
  return createHash("sha256").update(text).digest("hex");
}

async function resolveScope(
  manifest: CollectorManifest,
  workspace: Workspace,
  inputs: ReadonlyMap<string, string>,
  tree: () => Promise<TreeEntry[]>,
): Promise<string[]> {
  const resolved: string[] = [];
  for (const term of manifest.cacheScope ?? []) {
    if (term === "@commit") {
      resolved.push(`@commit:${workspace.commit}`);
    } else if (term === "@tree") {
      resolved.push(`@tree:${await treeHash(workspace.root)}`);
    } else if (term === "@inputs") {
      for (const name of manifest.inputs ?? []) {
        const path = inputs.get(name);
        // an absent input means the producer skipped — key on that fact
        resolved.push(`@input:${name}:${path === undefined ? "absent" : await sha256File(path)}`);
      }
    } else {
      const re = globToRegExp(term);
      for (const entry of await tree()) {
        if (re.test(entry.path)) resolved.push(`${entry.path}:${entry.blob}`);
      }
    }
  }
  return resolved.sort();
}

interface CacheEntry {
  collector: string;
  toolVersion: string;
  key: string;
  cachedAt: string;
  result: RunResult;
}

/**
 * Wrap a Runner with the content-hash scan cache. Reads happen only in
 * "incremental" mode; both modes write, so a full scan refreshes every
 * entry it runs (post-full incremental scans reuse fresh results).
 */
export function createCachingRunner(inner: Runner, options: CachingRunnerOptions): Runner {
  const log = options.log ?? (() => {});
  const onOutcome = options.onOutcome ?? (() => {});

  return {
    async run(manifest, workspace): Promise<RunResult> {
      if (!manifest.cacheScope || manifest.cacheScope.length === 0) {
        onOutcome(manifest.name, "uncachable");
        return inner.run(manifest, workspace);
      }

      let treeCache: Promise<TreeEntry[]> | undefined;
      const tree = () => (treeCache ??= listTree(workspace.root));
      const scope = await resolveScope(manifest, workspace, options.inputs, tree);
      const key = sha256Hex(
        JSON.stringify({
          collector: manifest.name,
          toolVersion: manifest.toolVersion,
          salt: options.keySalt ?? "",
          scope,
        }),
      );
      const entryDir = join(options.dir, manifest.name, key);
      const entryPath = join(entryDir, "entry.json");

      if (options.mode === "incremental") {
        let entry: CacheEntry | undefined;
        try {
          entry = JSON.parse(await readFile(entryPath, "utf8")) as CacheEntry;
        } catch {
          entry = undefined;
        }
        if (entry) {
          // restore artifacts into the run's artifact dir and register them
          // as inputs, exactly as a live run would have
          for (const artifact of entry.result.artifacts) {
            const source = join(entryDir, "files", artifact.path);
            const target = join(options.artifactDir, artifact.path);
            await mkdir(dirname(target), { recursive: true });
            await copyFile(source, target);
            options.inputs.set(artifact.name, target);
          }
          onOutcome(manifest.name, "hit");
          log(`cache hit: ${manifest.name} (key ${key.slice(0, 12)})`);
          return structuredClone(entry.result);
        }
        onOutcome(manifest.name, "miss");
      } else {
        onOutcome(manifest.name, "bypass");
      }

      const result = await inner.run(manifest, workspace);
      if (result.skipped) return result; // environmental — never cache

      // write the entry atomically: stage under a tmp dir, then rename
      const staging = `${entryDir}.tmp-${process.pid}-${Date.now()}`;
      await mkdir(join(staging, "files"), { recursive: true });
      for (const artifact of result.artifacts) {
        const source = join(options.artifactDir, artifact.path);
        const target = join(staging, "files", artifact.path);
        await mkdir(dirname(target), { recursive: true });
        await copyFile(source, target);
      }
      const entry: CacheEntry = {
        collector: manifest.name,
        toolVersion: result.toolVersion,
        key,
        cachedAt: new Date().toISOString(),
        result,
      };
      await writeFile(join(staging, "entry.json"), JSON.stringify(entry, null, 2) + "\n");
      await rm(entryDir, { recursive: true, force: true });
      await mkdir(dirname(entryDir), { recursive: true });
      await rename(staging, entryDir);
      return result;
    },
  };
}
