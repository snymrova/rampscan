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

export type EntrypointSource = "config" | "package.json" | "fallback" | "none";

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
}

function resolveSpec(spec: string, fileSet: ReadonlySet<string>): string | undefined {
  const clean = posix.normalize(spec.replace(/^\.\//, ""));
  if (fileSet.has(clean)) return clean;
  // reuse relative resolution rooted at the repo top ("" as the from-file dir)
  return resolveRelative("package.json", "./" + clean, fileSet);
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

export async function detectEntrypoints(
  root: string,
  fileSet: ReadonlySet<string>,
  configEntrypoints?: string[],
): Promise<Entrypoints> {
  if (configEntrypoints && configEntrypoints.length > 0) {
    const files: string[] = [];
    const unresolved: string[] = [];
    for (const spec of configEntrypoints) {
      const hit = resolveSpec(spec, fileSet);
      if (hit) files.push(hit);
      else unresolved.push(spec);
    }
    return { files: [...new Set(files)].sort(), source: "config", unresolved };
  }

  let pkg: Record<string, unknown> | undefined;
  try {
    pkg = JSON.parse(await readFile(join(root, "package.json"), "utf8")) as Record<string, unknown>;
  } catch {
    pkg = undefined;
  }

  if (pkg) {
    const declared: string[] = [];
    if (typeof pkg["main"] === "string") declared.push(pkg["main"]);
    if (typeof pkg["module"] === "string") declared.push(pkg["module"]);
    const bin = pkg["bin"];
    if (typeof bin === "string") declared.push(bin);
    else if (bin && typeof bin === "object") {
      declared.push(...Object.values(bin).filter((v): v is string => typeof v === "string"));
    }
    declared.push(...stringsIn(pkg["exports"]));

    if (declared.length > 0) {
      const files: string[] = [];
      const unresolved: string[] = [];
      for (const spec of declared) {
        const hit = resolveSpec(spec, fileSet);
        if (hit) files.push(hit);
        else unresolved.push(spec);
      }
      if (files.length > 0) {
        return { files: [...new Set(files)].sort(), source: "package.json", unresolved };
      }
    }
  }

  const fallback = FALLBACK_BASES.map((base) => resolveSpec(base, fileSet)).filter(
    (f): f is string => f !== undefined,
  );
  if (fallback.length > 0) {
    return { files: [...new Set(fallback)].sort(), source: "fallback", unresolved: [] };
  }
  return { files: [], source: "none", unresolved: [] };
}
