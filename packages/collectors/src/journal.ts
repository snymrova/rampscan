import { AsyncLocalStorage } from "node:async_hooks";
import { execFile } from "node:child_process";
import { accessSync, constants } from "node:fs";
import { delimiter, dirname, isAbsolute, join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import type { CollectorTelemetry, Runner } from "@rampscan/core";
import type { ToolInvocation, ToolResolution } from "@rampscan/schema";

const execFileAsync = promisify(execFile);

// The exec journal (plan J1). Everything a collector spawns passes through
// `exec()` in support.ts, and every tool a collector asks for passes through
// `resolveTool()`. Those two are the whole seam — so the journal sits there
// and the eleven collectors are untouched.
//
// It rides an AsyncLocalStorage rather than a parameter threaded into
// `collect()`, for one deliberate reason: routing run telemetry through the
// collector contract would make every collector responsible for reporting its
// own provenance — precisely the arrangement where one quietly under-reports.
// The runner opens a journal around `collect()`; whatever spawns inside that
// async context is recorded whether the collector cooperates or not.

const storage = new AsyncLocalStorage<Journal>();

export interface Journal {
  tools: ToolResolution[];
  invocations: ToolInvocation[];
  /** roots whose paths are safe to record verbatim in a signed statement */
  safeRoots: string[];
}

/** Container mount prefix createDockerTool generates — ours, so safe by construction. */
export const CONTAINER_MOUNT_ROOT = "/rampscan";

export function currentJournal(): Journal | undefined {
  return storage.getStore();
}

/**
 * Run `fn` with a fresh journal open. Nothing spawned outside a journal is
 * recorded — `rampscan doctor`, a bare unit test, the digest probes below.
 */
export async function withJournal<T>(
  safeRoots: string[],
  fn: () => Promise<T>,
): Promise<{ value: T; journal: Journal }> {
  const journal: Journal = {
    tools: [],
    invocations: [],
    safeRoots: normalizeRoots(safeRoots),
  };
  const value = await storage.run(journal, fn);
  return { value, journal };
}

function normalizeRoots(roots: string[]): string[] {
  const all = [
    ...roots,
    tmpdir(),
    CONTAINER_MOUNT_ROOT,
    // rampscan's own installed tree: the vendored semgrep ruleset and
    // tools.json are passed to tools by absolute path, and those paths are
    // ours — redacting them would hide provenance without protecting anything
    resolve(dirname(fileURLToPath(import.meta.url)), ".."),
  ];
  return [...new Set(all.filter((r) => r.length > 0).map((r) => resolve(r)))].sort();
}

/** Called by `exec()` — the single choke point for every process collectors spawn. */
export function recordInvocation(
  command: string,
  argv: string[],
  durationMs: number,
  exitCode: number,
): void {
  const journal = storage.getStore();
  if (!journal) return;
  journal.invocations.push({
    command,
    argv: redactArgv(argv, journal.safeRoots),
    duration_ms: Math.round(durationMs),
    exit_code: exitCode,
  });
}

/** Called by `resolveTool()` — records how a tool resolved, including not at all. */
export function recordResolution(resolution: ToolResolution): void {
  storage.getStore()?.tools.push(resolution);
}

// ---------------------------------------------------------------------------
// argv redaction — an ALLOWLIST, deliberately
//
// A signed statement is permanent: a secret recorded in one cannot be taken
// back, only re-keyed around. So a token is written verbatim only when it
// matches a shape that is known-safe, and everything else becomes
// `<redacted:N bytes>` — the fact that an argument was there survives, its
// content does not. The tempting version is a denylist of secret patterns
// (gitleaks-style), and that is the version that eventually leaks: it fails
// open on every shape nobody thought of.

/** `-x`, `--long-flag` */
const FLAG = /^--?[A-Za-z][A-Za-z0-9-]*$/;

/**
 * An environment variable NAME, which is uppercase by convention and is the
 * one place uppercase is expected. Only ever matched on the left of an `=` —
 * the value on the right still has to pass the same allowlist as anything
 * else, so `HOME=/tmp` survives readable and `GITHUB_TOKEN=…` does not.
 */
const ENV_NAME = /^[A-Z][A-Z0-9_]*$/;

/**
 * A bare vocabulary word: subcommand, output format, version, tool name.
 * Lowercase only and NO underscore — `ghp_…`, `sk_live_…`, `AKIA…` and
 * base64url all die on one of those two, and no subcommand needs either.
 */
const WORD = /^[a-z0-9.][a-z0-9.@+-]*$/;

/**
 * A relative path or glob. Underscore is allowed HERE and only here, because
 * `node_modules` is a real directory and refusing it would redact half of
 * every exclude list — but a token only reaches this rule by containing a
 * `/`, and every one of its segments has to be short enough to be a path
 * segment rather than an opaque blob. An absolute path is deliberately NOT
 * matched: it earns its way in by being under a root this run owns (the rule
 * above), never by looking tidy.
 */
const PATH_LIKE = /^[a-z0-9._*][a-z0-9._@+/*-]*$/;
const MAX_PATH_SEGMENT = 64;

/** Docker bind-mount modes — the only bare words a `-v` value may end with. */
const MOUNT_MODES = new Set(["ro", "rw"]);

/**
 * Above this, a token with no `/` in it is redacted whatever its shape. Long
 * opaque strings are what API keys look like; long safe things (paths, globs,
 * image refs) have separators.
 */
const MAX_OPAQUE_TOKEN = 40;

function underSafeRoot(token: string, roots: string[]): boolean {
  if (!isAbsolute(token)) return false;
  const path = resolve(token);
  return roots.some((root) => path === root || path.startsWith(root.endsWith("/") ? root : root + "/"));
}

export function isSafeArgvToken(token: string, roots: string[]): boolean {
  if (token === "") return true;
  // a real path under a dir this run owns: verbatim, whatever characters it holds
  if (underSafeRoot(token, roots)) return true;
  if (FLAG.test(token)) return true;

  // `--flag=value` / `key=value`: the value half must stand on its own
  const eq = token.indexOf("=");
  if (eq > 0) {
    const left = token.slice(0, eq);
    if (
      (FLAG.test(left) || WORD.test(left) || ENV_NAME.test(left)) &&
      isSafeArgvToken(token.slice(eq + 1), roots)
    ) {
      return true;
    }
  }

  // colon-joined compounds: `dir:/abs/path`, `host:/container:ro`, `image:tag`.
  // Segments hold no colon, so this recursion cannot re-enter here.
  if (token.includes(":")) {
    const parts = token.split(":");
    if (parts.length <= 4 && parts.every((p) => MOUNT_MODES.has(p) || isSafeArgvToken(p, roots))) {
      return true;
    }
  }

  if (token.includes("/")) {
    return (
      PATH_LIKE.test(token) &&
      token.split("/").every((segment) => segment.length <= MAX_PATH_SEGMENT)
    );
  }
  return WORD.test(token) && token.length <= MAX_OPAQUE_TOKEN;
}

function placeholder(token: string): string {
  return `<redacted:${Buffer.byteLength(token, "utf8")} bytes>`;
}

export function redactArgv(argv: string[], roots: string[]): string[] {
  return argv.map((token) => {
    if (isSafeArgvToken(token, roots)) return token;
    // `--flag=<secret>` / `ENV_NAME=<secret>`: keep the name, hide only the
    // value — WHICH option or variable carried something unrecordable is
    // itself provenance worth having, and it names where to go look
    const eq = token.indexOf("=");
    if (eq > 0 && (FLAG.test(token.slice(0, eq)) || ENV_NAME.test(token.slice(0, eq)))) {
      return `${token.slice(0, eq)}=${placeholder(token.slice(eq + 1))}`;
    }
    return placeholder(token);
  });
}

// ---------------------------------------------------------------------------
// binary path + docker image digest resolution

/** Where on PATH a binary resolves — provenance a bare name does not carry. */
export function resolveBinaryPath(name: string): string | undefined {
  if (name.includes("/")) return isExecutable(name) ? resolve(name) : undefined;
  for (const dir of (process.env["PATH"] ?? "").split(delimiter)) {
    if (dir.length === 0) continue;
    const candidate = join(dir, name);
    if (isExecutable(candidate)) return candidate;
  }
  return undefined;
}

function isExecutable(path: string): boolean {
  try {
    accessSync(path, constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

/**
 * What a pinned tag actually resolved to. `tools.json` pins tags, and a tag is
 * a moving pointer — quoting one as if it were a digest would be inventing
 * provenance. So the digest is asked for, and when Docker cannot answer, the
 * record says null and states why (J1 decision 5; this also delivers the
 * image-digest pinning the H phase deferred).
 *
 * Deliberately spawned with execFile rather than support.ts's `exec`: this
 * probe must never appear in the journal it is filling in, and structuring it
 * so it *cannot* beats remembering not to.
 */
const digestProbes = new Map<string, Promise<{ digest: string | null; reason?: string }>>();

export function resolveImageDigest(
  image: string,
): Promise<{ digest: string | null; reason?: string }> {
  let probe = digestProbes.get(image);
  if (!probe) {
    probe = execFileAsync(
      "docker",
      ["image", "inspect", "--format", "{{index .RepoDigests 0}}", image],
      { timeout: 30_000 },
    )
      .then(({ stdout }) => {
        const line = stdout.trim();
        const at = line.lastIndexOf("@sha256:");
        if (at === -1) {
          return {
            digest: null,
            reason: `docker reported no repo digest for ${image} (built locally, or never pulled from a registry)`,
          };
        }
        return { digest: line.slice(at + 1) };
      })
      .catch((error: unknown) => ({
        digest: null,
        reason: `docker image inspect ${image} failed: ${
          error instanceof Error ? error.message.split("\n")[0] : String(error)
        }`,
      }));
    digestProbes.set(image, probe);
  }
  return probe;
}

/** test seam: forget memoized digest probes between worlds */
export function resetImageDigestProbes(): void {
  digestProbes.clear();
}

async function fillImageDigests(journal: Journal): Promise<void> {
  for (const resolution of journal.tools) {
    if (resolution.runtime.kind !== "docker") continue;
    const { digest, reason } = await resolveImageDigest(resolution.runtime.image);
    resolution.runtime.digest = digest;
    if (reason !== undefined) resolution.runtime.digest_reason = reason;
  }
}

/**
 * The Runner decorator that opens a journal per collector (plan J1's capture
 * point). Composed INSIDE the scan cache, so a cache hit records no
 * invocations this run — the telemetry rides the cached RunResult instead,
 * and the run record's `cache.state` is what tells a reader which run those
 * invocations belong to.
 */
export function createJournaledRunner(
  inner: Runner,
  options: { safeRoots: string[] },
): Runner {
  return {
    async run(manifest, workspace) {
      const started = Date.now();
      const { value: result, journal } = await withJournal(
        [...options.safeRoots, workspace.root],
        () => inner.run(manifest, workspace),
      );
      // Digests resolve AFTER the collector ran: the pinned image may only
      // have been pulled by the invocation we just watched.
      await fillImageDigests(journal);
      const telemetry: CollectorTelemetry = {
        durationMs: Date.now() - started,
        tools: journal.tools,
        invocations: journal.invocations,
      };
      return { ...result, telemetry };
    },
  };
}
