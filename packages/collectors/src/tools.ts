import { readFile } from "node:fs/promises";
import { dirname, join, posix } from "node:path";
import { fileURLToPath } from "node:url";
import type { ToolRuntime } from "@rampscan/schema";
import { recordResolution, resolveBinaryPath } from "./journal.js";
import { exec, toolVersion } from "./support.js";
import type { ExecResult } from "./support.js";

// Tool resolution (Docker-first policy): a wrapper never spawns its tool
// directly — it resolves it here. Order:
//
//   1. binary already on PATH  → use it (whatever version is installed)
//   2. Docker available        → run the PINNED image from tools.json;
//                                nothing is ever installed on the host
//   3. neither                 → the wrapper skips with the honest reason
//
// Docker runs are path-mapped: the wrapper asks `tool.mount(hostPath)` for
// the path to put in the tool's args, and gets the host path back for a
// binary or a bind-mount path for a container. Containers run as the calling
// uid:gid so artifacts land owned by the user, with HOME=/tmp so git inside
// (gitleaks) behaves.

export interface ToolSpec {
  version: string;
  image: string;
  /**
   * Docker --entrypoint override. Two reasons to set it: an image that ships
   * no entrypoint (semgrep — the CLI name must lead the args), and an image
   * whose entrypoint does more than run the tool (spectral's launches a
   * telemetry side-process; overriding to the bare binary keeps scans from
   * phoning home).
   */
  entrypoint?: string;
}
export type ToolManifest = Record<string, ToolSpec>;

let manifestCache: Promise<ToolManifest> | undefined;
export function loadToolManifest(): Promise<ToolManifest> {
  // path via dirname(fileURLToPath(...)), not `new URL("...", import.meta.url)`
  // — webpack (the console's Next routes transpile this package) rewrites the
  // relative-URL pattern into an asset reference that breaks at runtime
  return (manifestCache ??= readFile(
    join(dirname(fileURLToPath(import.meta.url)), "../tools.json"),
    "utf8",
  ).then((raw) => (JSON.parse(raw) as { tools: ToolManifest }).tools));
}

let dockerProbe: Promise<boolean> | undefined;
export function dockerAvailable(): Promise<boolean> {
  return (dockerProbe ??= exec("docker", ["version", "--format", "{{.Server.Version}}"], {
    timeoutMs: 15_000,
  })
    .then((r) => r.exitCode === 0)
    .catch(() => false));
}

export interface ToolExecOptions {
  env?: Record<string, string>;
  timeoutMs?: number;
}

export interface ResolvedTool {
  kind: "binary" | "docker";
  version: string;
  /** for provenance/log lines: "syft" or the image ref */
  runtime: string;
  /** path to use in the tool's args for this host path; registers a bind mount under docker */
  mount(hostPath: string, mode?: "ro" | "rw"): string;
  exec(args: string[], opts?: ToolExecOptions): Promise<ExecResult>;
}

interface Mount {
  host: string;
  container: string;
  mode: "ro" | "rw";
}

/** pure: the `docker run` argv for one tool invocation — unit-testable */
export function buildDockerRunArgs(
  image: string,
  mounts: Mount[],
  args: string[],
  env: Record<string, string> = {},
  user?: string,
  entrypoint?: string,
): string[] {
  return [
    "run",
    "--rm",
    ...(user ? ["-u", user] : []),
    ...(entrypoint ? ["--entrypoint", entrypoint] : []),
    "-e",
    "HOME=/tmp",
    ...Object.entries(env).flatMap(([k, v]) => ["-e", `${k}=${v}`]),
    ...mounts.flatMap((m) => ["-v", `${m.host}:${m.container}${m.mode === "ro" ? ":ro" : ""}`]),
    image,
    ...args,
  ];
}

export function createDockerTool(name: string, spec: ToolSpec): ResolvedTool {
  const mounts: Mount[] = [];
  return {
    kind: "docker",
    // report the pinned version bare, same shape the binary reports — the
    // runtime is provenance detail, not a different tool version, and a
    // "(docker)" suffix would re-key otherwise-identical evidence
    version: spec.version,
    runtime: spec.image,
    mount(hostPath, mode = "ro") {
      const existing = mounts.find((m) => m.host === hostPath);
      if (existing) {
        if (mode === "rw") existing.mode = "rw";
        return existing.container;
      }
      const container = posix.join("/rampscan", `m${mounts.length}`);
      mounts.push({ host: hostPath, container, mode });
      return container;
    },
    exec(args, opts = {}) {
      const uid = process.getuid?.();
      const user = uid === undefined ? undefined : `${uid}:${process.getgid!()}`;
      return exec(
        "docker",
        buildDockerRunArgs(spec.image, mounts, args, opts.env ?? {}, user, spec.entrypoint),
        { timeoutMs: opts.timeoutMs ?? 600_000 },
      );
    },
  };
}

function createBinaryTool(name: string, version: string): ResolvedTool {
  return {
    kind: "binary",
    version,
    runtime: name,
    mount: (hostPath) => hostPath,
    exec: (args, opts = {}) => exec(name, args, opts),
  };
}

export interface VersionProbe {
  args: string[];
  parse: (out: string) => string;
}

/** test seam: override the environment probes without touching PATH or a daemon */
export interface ResolveOverrides {
  manifest?: ToolManifest;
  docker?: boolean;
  /** a version string forces "binary present"; null forces "binary absent" */
  binaryVersion?: string | null;
}

export async function resolveTool(
  name: string,
  probe: VersionProbe,
  overrides: ResolveOverrides = {},
): Promise<ResolvedTool | undefined> {
  const binVersion =
    overrides.binaryVersion === null
      ? undefined
      : (overrides.binaryVersion ?? (await toolVersion(name, probe.args, probe.parse)));
  if (binVersion) {
    // provenance the bare name does not carry: WHICH binary on PATH answered
    const path = resolveBinaryPath(name);
    const runtime: ToolRuntime =
      path === undefined ? { kind: "binary" } : { kind: "binary", path };
    recordResolution({ tool: name, version: binVersion, runtime });
    return createBinaryTool(name, binVersion);
  }

  const manifest = overrides.manifest ?? (await loadToolManifest());
  const spec = manifest[name];
  const docker = overrides.docker ?? (await dockerAvailable());
  if (spec && docker) {
    // digest stays null here and is filled after the run — the pinned image
    // may only get pulled by the invocation that is about to happen
    recordResolution({
      tool: name,
      version: spec.version,
      runtime: { kind: "docker", image: spec.image, digest: null },
    });
    return createDockerTool(name, spec);
  }
  recordResolution({
    tool: name,
    runtime: {
      kind: "absent",
      reason: spec
        ? `${name} is not on PATH and Docker is unavailable, so the pinned image ${spec.image} could not run`
        : `${name} is not on PATH and tools.json pins no image for it`,
    },
  });
  return undefined;
}

/** the honest skip reason when a tool resolves to nothing */
export function absentReason(name: string): string {
  return `${name} is not installed and Docker is unavailable — install Docker (missing tools then run pinned images automatically, nothing installs on the host) or install ${name} (see \`pnpm run doctor\`)`;
}
