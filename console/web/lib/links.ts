// One canonical URL per entity (U0, docs/PLAN-CONSOLE-DEPTH.md U-R1). Every
// link to a KSI, check, bundle, artifact, run or control is built here and
// nowhere else — test/links.test.ts fails the build on a hand-written one.
// That is what lets U1 give the KSI its own page, and U3 the check, by
// changing one function each instead of every page that mentions them.

const q = (entries: Record<string, string | undefined>): string => {
  const params = new URLSearchParams();
  for (const [k, v] of Object.entries(entries)) if (v !== undefined && v !== "") params.set(k, v);
  const s = params.toString();
  return s ? `?${s}` : "";
};

/** L2 — until U1, the board row itself, opened and scrolled to */
export function ksiHref(ksi: string): string {
  return `/${q({ ksi })}`;
}

/** L3 — until U3, the recipe register's row for this (repo, recipe) cell */
export function checkHref(recipe: string, repo: string): string {
  return `/recipes${q({ repo, recipe })}`;
}

/** L4 — one signed bundle */
export function evidenceHref(digest: string): string {
  return `/evidence/${digest}`;
}

/** L5 — one signed artifact statement */
export function artifactHref(digest: string): string {
  return `/artifacts/${digest}`;
}

/** a control in the auditor's crosswalk register */
export function controlHref(id: string): string {
  return `/controls${q({ reg: "controls", id })}`;
}

/** the KSI rollup in the controls register — the auditor's CSV home (D3 retires it as a destination) */
export function ksiRollupHref(id: string): string {
  return `/controls${q({ reg: "ksis", id })}`;
}

/**
 * A scan run. `scan` names the run that produced something; `repo` asks for
 * the newest recorded scan of that repo (the unevidenced hop, J3).
 */
export function runHref(target: { scan?: string; repo?: string; collector?: string }): string {
  return `/runs${q({ scan: target.scan, repo: target.scan ? undefined : target.repo, collector: target.collector })}`;
}

/** Carry the repo scope (U-R5) onto an in-console path. `null` is the default scope and adds nothing. */
export function withScope(href: string, repo: string | null): string {
  const [path, query = ""] = href.split("?", 2) as [string, string?];
  const params = new URLSearchParams(query);
  if (repo === null) params.delete("repo");
  else params.set("repo", repo);
  const s = params.toString();
  return s ? `${path}?${s}` : path;
}

/** A repo reads as its basename; the full path belongs in `title` and in print. */
export function repoLabel(repo: string): string {
  const parts = repo.split(/[\\/]+/).filter(Boolean);
  return parts[parts.length - 1] ?? repo;
}

/**
 * The scope a reader lands in: the repo with the newest scan, because that is
 * the one they just ran. With no run recorded, the first repo by name.
 */
export function defaultRepo(
  runs: ReadonlyArray<{ repo: string; run_timestamp: string }>,
  repos: readonly string[],
): string | null {
  let newest: { repo: string; run_timestamp: string } | undefined;
  for (const r of runs) if (!newest || r.run_timestamp > newest.run_timestamp) newest = r;
  if (newest) return newest.repo;
  return [...repos].sort()[0] ?? null;
}

/** Where sign-in returns to: a path on this console, never another origin, never the login card. */
export function safeNext(next: string | null): string {
  if (!next || !next.startsWith("/") || next.startsWith("//") || next.startsWith("/\\")) return "/";
  if (next === "/login" || next.startsWith("/login?")) return "/";
  return next;
}
