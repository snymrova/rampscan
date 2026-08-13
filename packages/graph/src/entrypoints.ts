import { readFile } from "node:fs/promises";
import { join, posix } from "node:path";
import { resolveRelative } from "./extract.js";

// Entry point detection — plan §M4: package.json bins/exports (+ main),
// config-assisted where detection falls short. Declared server routes are
// entry points too, but they come from the extracted graph, not from here.

export type EntrypointSource = "config" | "package.json" | "fallback" | "none";

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
