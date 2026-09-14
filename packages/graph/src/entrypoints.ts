import { readFile } from "node:fs/promises";
import { join, posix } from "node:path";
import { listManifests, resolveRelative, type TreeMode } from "./extract.js";

// Entry point detection — plan §M4: package.json bins/exports (+ main),
// config-assisted where detection falls short. Declared server routes are
// entry points too, but they come from the extracted graph, not from here.
//
// Application roots (S1-3) live here too, because they are the other half of
// the same question: entry points say where a walk STARTS, application roots
// say what the tree contains that a walk could have started in. A negative
// claim ("not reachable from any entry point") is only as wide as the set of
// roots those entry points cover, and the reader is owed that width.

export type EntrypointSource = "config" | "package.json" | "framework" | "fallback" | "none";

/**
 * How detection found an entry point (S1-4): read off a manifest field, or
 * off a framework's file conventions where the manifest declares nothing —
 * a Next.js app has no `main`, `bin` or `exports`, and is exactly the
 * application the self-scan's config left outside every walk.
 */
export type DetectionVia = "package.json" | "scripts" | "next" | "pocketbase" | "fallback";

export interface DetectedEntrypoint {
  /** repo-relative file, present in the walked source set */
  file: string;
  via: DetectionVia;
  /** the application root it was found under; "." for the tree root */
  root: string;
}

/**
 * A place the tree declares as a unit that runs or is consumed on its own — a
 * directory holding its own `package.json` — that also owns source files.
 * Ownership is by nearest manifest: a file belongs to the deepest package.json
 * above it, so a monorepo root claims only the files no member package does.
 * A manifest with no source of its own (a docs folder with a package.json) is
 * not a root — there is nothing under it a walk could have missed.
 *
 * Deliberately NOT a heuristic over `bin`, `scripts.start` or framework
 * markers: the self-scan's second application (`console/web`, a Next.js app)
 * declares none of those, and a definition that missed it would miss exactly
 * the case the definition exists for.
 */
export interface ApplicationRoot {
  /** repo-relative directory; "." for the tree root */
  dir: string;
  /** the manifest's `name`, when it has one */
  name?: string;
}

/** the deepest of `dirs` that contains `rel`; undefined when none does */
export function nearestRoot(rel: string, dirs: readonly string[]): string | undefined {
  let best: string | undefined;
  for (const dir of dirs) {
    const inside = dir === "." || rel.startsWith(dir + "/");
    if (!inside) continue;
    if (best === undefined || dir.length > best.length) best = dir;
  }
  return best;
}

/**
 * Every application root in the tree, sorted by directory. The roots are read
 * from the same tree the source walk is over (`mode`), so a dry run over the
 * worktree sees the manifests the developer just added.
 */
export async function detectApplicationRoots(
  root: string,
  fileSet: ReadonlySet<string>,
  mode: TreeMode = "committed",
): Promise<ApplicationRoot[]> {
  const manifests = await listManifests(root, mode);
  const byDir = new Map<string, ApplicationRoot>();
  for (const rel of manifests) {
    const dir = posix.dirname(rel);
    const entry: ApplicationRoot = { dir };
    try {
      const parsed = JSON.parse(await readFile(join(root, rel), "utf8")) as { name?: unknown };
      if (typeof parsed.name === "string" && parsed.name !== "") entry.name = parsed.name;
    } catch {
      // unparseable or unreadable manifest — still a declared root, just nameless
    }
    byDir.set(dir, entry);
  }
  const dirs = [...byDir.keys()];
  const owned = new Set<string>();
  for (const file of fileSet) {
    const dir = nearestRoot(file, dirs);
    if (dir !== undefined) owned.add(dir);
  }
  return dirs
    .filter((dir) => owned.has(dir))
    .sort()
    .map((dir) => byDir.get(dir)!);
}

export interface Entrypoints {
  /** repo-relative files that exist in the walked source set */
  files: string[];
  source: EntrypointSource;
  /** configured/declared entries that did not resolve to a walked file */
  unresolved: string[];
  /**
   * What detection found across every application root, whether or not the
   * config was honoured over it (S1-4). Config still decides where the walk
   * starts; this is what it decided against.
   */
  detected: DetectedEntrypoint[];
  /**
   * The detected entries the config left out — narrowing, made visible. Empty
   * unless `source` is "config". Declaring one entry point to quiet a warning
   * used to convert the rest of a repository into not-affected territory with
   * nothing said about it; now the rest is named, and the gate reads it.
   */
  excluded: DetectedEntrypoint[];
}

/** resolve a manifest-style spec ("./src/x", "src/x.js") under a root dir */
function resolveSpec(spec: string, fileSet: ReadonlySet<string>, dir = "."): string | undefined {
  const clean = posix.normalize(spec.replace(/^\.\//, ""));
  const rel = dir === "." ? clean : posix.join(dir, clean);
  if (fileSet.has(rel)) return rel;
  // reuse relative resolution rooted at the manifest's own directory
  return resolveRelative(posix.join(dir, "package.json"), "./" + clean, fileSet);
}

function stringsIn(exportsField: unknown): string[] {
  if (typeof exportsField === "string") return [exportsField];
  if (Array.isArray(exportsField)) return exportsField.flatMap(stringsIn);
  if (exportsField && typeof exportsField === "object") {
    return Object.entries(exportsField)
      .filter(([key]) => key !== "types")
      .flatMap(([, value]) => stringsIn(value));
  }
  return [];
}

const FALLBACK_BASES = ["index", "src/index", "main", "src/main", "server", "src/server", "app", "src/app"];

// Next.js file conventions: every one of these is a module the framework
// loads on its own — there is no `main` that imports them, which is why a
// manifest-only detector reads a Next.js app as having no entry point at all.
const NEXT_CONFIG = /^next\.config\.(js|mjs|cjs|ts|mts)$/;
const NEXT_APP_FILES = new Set([
  "page", "layout", "route", "template", "default", "error", "global-error", "loading", "not-found",
]);
const NEXT_ROOT_FILES = /^(middleware|instrumentation|proxy)\.(ts|tsx|js|jsx|mjs|cjs|mts|cts)$/;

function basenameSansExt(rel: string): string {
  const base = posix.basename(rel);
  return base.replace(/\.(tsx?|jsx?|mts|cts|mjs|cjs)$/, "");
}

/** the files a Next.js app under `dir` loads by convention, when it is one */
function nextEntrypoints(dir: string, fileSet: ReadonlySet<string>): string[] {
  const prefix = dir === "." ? "" : dir + "/";
  const under = [...fileSet].filter((f) => f.startsWith(prefix));
  const isNext = under.some((f) => f.slice(prefix.length).split("/").length === 1 && NEXT_CONFIG.test(f.slice(prefix.length)));
  if (!isNext) return [];
  const out: string[] = [];
  for (const f of under) {
    const inner = f.slice(prefix.length);
    if (NEXT_ROOT_FILES.test(inner)) {
      out.push(f);
      continue;
    }
    // app router under app/ or src/app/; pages router under pages/ or src/pages/
    const m = /^(?:src\/)?(app|pages)\/(.+)$/.exec(inner);
    if (!m) continue;
    if (m[1] === "pages") out.push(f);
    else if (NEXT_APP_FILES.has(basenameSansExt(f))) out.push(f);
  }
  return out.sort();
}

// PocketBase loads every `pb_hooks/*.pb.js` and `pb_migrations/*.js` on start;
// nothing imports them, and the directory name is the whole convention — the
// self-scan's workspace root owns twenty migrations and no manifest field
// could ever name them.
const POCKETBASE_FILE = /(^|\/)(pb_hooks\/[^/]+\.pb\.js|pb_migrations\/[^/]+\.js)$/;

/** the files PocketBase under `dir` loads by convention */
function pocketbaseEntrypoints(dir: string, fileSet: ReadonlySet<string>): string[] {
  const prefix = dir === "." ? "" : dir + "/";
  return [...fileSet].filter((f) => f.startsWith(prefix) && POCKETBASE_FILE.test(f.slice(prefix.length))).sort();
}

// a source file named on a `scripts` command line is a place the program
// starts that no `main`/`bin` field records — the self-scan's own CLI is run
// as `"rampscan": "tsx packages/cli/src/main.ts"` from the workspace root and
// declares no bin, which is why config had to name it and detection could not
const SCRIPT_PATH_TOKEN = /^[^\s"'`$|&;<>()-][^\s"'`$|&;<>()]*\.(m?[jt]sx?|c[jt]s)$/;

/** the source files a manifest's `scripts` name, resolved under `dir` */
function scriptEntrypoints(pkg: Record<string, unknown>, fileSet: ReadonlySet<string>, dir: string): string[] {
  const scripts = pkg["scripts"];
  if (!scripts || typeof scripts !== "object") return [];
  const out = new Set<string>();
  for (const command of Object.values(scripts as Record<string, unknown>)) {
    if (typeof command !== "string") continue;
    for (const token of command.split(/\s+/)) {
      if (!SCRIPT_PATH_TOKEN.test(token)) continue;
      const hit = resolveSpec(token, fileSet, dir);
      if (hit) out.add(hit);
    }
  }
  return [...out].sort();
}

/** what a manifest declares as its entry files: main, module, bin, exports */
function declaredSpecs(pkg: Record<string, unknown>): string[] {
  const declared: string[] = [];
  if (typeof pkg["main"] === "string") declared.push(pkg["main"]);
  if (typeof pkg["module"] === "string") declared.push(pkg["module"]);
  const bin = pkg["bin"];
  if (typeof bin === "string") declared.push(bin);
  else if (bin && typeof bin === "object") {
    declared.push(...Object.values(bin).filter((v): v is string => typeof v === "string"));
  }
  declared.push(...stringsIn(pkg["exports"]));
  return declared;
}

/**
 * Detection over every application root: each root's manifest fields, then
 * the framework conventions the root follows. Before S1-4 only the tree
 * root's package.json was read, which on a monorepo declares nothing — so
 * detection found nothing, config was the only way to start a walk, and what
 * config left out was never counted.
 */
async function detect(
  root: string,
  fileSet: ReadonlySet<string>,
  dirs: readonly string[],
): Promise<{ detected: DetectedEntrypoint[]; unresolved: string[] }> {
  const detected = new Map<string, DetectedEntrypoint>();
  const unresolved: string[] = [];
  for (const dir of dirs) {
    let pkg: Record<string, unknown> | undefined;
    try {
      const rel = dir === "." ? "package.json" : posix.join(dir, "package.json");
      pkg = JSON.parse(await readFile(join(root, rel), "utf8")) as Record<string, unknown>;
    } catch {
      pkg = undefined;
    }
    if (pkg) {
      for (const spec of declaredSpecs(pkg)) {
        const hit = resolveSpec(spec, fileSet, dir);
        if (hit) {
          if (!detected.has(hit)) detected.set(hit, { file: hit, via: "package.json", root: dir });
        } else {
          unresolved.push(dir === "." ? spec : `${dir}/${spec.replace(/^\.\//, "")}`);
        }
      }
    }
    if (pkg) {
      for (const file of scriptEntrypoints(pkg, fileSet, dir)) {
        if (!detected.has(file)) detected.set(file, { file, via: "scripts", root: dir });
      }
    }
    for (const file of nextEntrypoints(dir, fileSet)) {
      if (!detected.has(file)) detected.set(file, { file, via: "next", root: dir });
    }
    for (const file of pocketbaseEntrypoints(dir, fileSet)) {
      if (!detected.has(file)) detected.set(file, { file, via: "pocketbase", root: dir });
    }
  }
  return { detected: [...detected.values()].sort((a, b) => a.file.localeCompare(b.file)), unresolved };
}

/**
 * Where the walk starts. Config wins when present — a repository that says
 * where its entry points are is believed — but detection runs regardless, over
 * `applicationRoots` when given (the S1-3 roots) and the tree root otherwise,
 * and everything detection found that config left out is returned as
 * `excluded`, so the narrowing is a recorded fact rather than a silence.
 */
export async function detectEntrypoints(
  root: string,
  fileSet: ReadonlySet<string>,
  configEntrypoints?: string[],
  applicationRoots?: readonly ApplicationRoot[],
): Promise<Entrypoints> {
  const dirs = applicationRoots && applicationRoots.length > 0 ? applicationRoots.map((r) => r.dir) : ["."];
  const found = await detect(root, fileSet, dirs);

  if (configEntrypoints && configEntrypoints.length > 0) {
    const files: string[] = [];
    const unresolved: string[] = [];
    for (const spec of configEntrypoints) {
      const hit = resolveSpec(spec, fileSet);
      if (hit) files.push(hit);
      else unresolved.push(spec);
    }
    const chosen = new Set(files);
    return {
      files: [...chosen].sort(),
      source: "config",
      unresolved,
      detected: found.detected,
      excluded: found.detected.filter((d) => !chosen.has(d.file)),
    };
  }

  if (found.detected.length > 0) {
    const source: EntrypointSource = found.detected.some((d) => d.via === "package.json" || d.via === "scripts")
      ? "package.json"
      : "framework";
    return {
      files: found.detected.map((d) => d.file),
      source,
      unresolved: found.unresolved,
      detected: found.detected,
      excluded: [],
    };
  }

  const fallback = FALLBACK_BASES.map((base) => resolveSpec(base, fileSet)).filter(
    (f): f is string => f !== undefined,
  );
  if (fallback.length > 0) {
    const files = [...new Set(fallback)].sort();
    return {
      files,
      source: "fallback",
      unresolved: [],
      detected: files.map((file) => ({ file, via: "fallback", root: "." })),
      excluded: [],
    };
  }
  return { files: [], source: "none", unresolved: [], detected: [], excluded: [] };
}
