"use client";

import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { createContext, useCallback, useContext, useMemo, type ReactNode } from "react";
import { defaultRepo, withScope } from "./links";
import { useAuth, useCollection } from "./pb";
import type { ScanRunRecord } from "./types";

// The repo is a scope, not a column (U-R5). One selector in the nav, carried
// in the URL as `?repo=` so a pasted link lands where it was copied from, and
// kept across navigation by the nav's own links. With no `?repo=` the scope
// is the repo with the newest scan, the one the reader most likely just ran.
// `?repo=all` is the explicit "every repo" scope, the only one in which a row
// has to say which repo it belongs to.

export const ALL_REPOS = "all";

export interface RepoScope {
  /** the repo every page reads, or `null` for all repos */
  repo: string | null;
  /** the `?repo=` value as written, or null when the default is in force */
  explicit: string | null;
  /** every repo with a recorded scan, by name */
  repos: string[];
  /** the repo with the newest scan: the scope when none is written */
  fallback: string | null;
  /** move the whole console to another scope, keeping the page and its other parameters */
  setRepo: (repo: string | null) => void;
  /** carry the scope onto an in-console path */
  scoped: (href: string) => string;
}

const ScopeContext = createContext<RepoScope | null>(null);

export function ScopeProvider({ children }: { children: ReactNode }) {
  const params = useSearchParams();
  const pathname = usePathname();
  const router = useRouter();
  const { user } = useAuth();
  // scan_runs is small (the projection keeps the newest N) and names every
  // repo a register row can belong to, because every row came from a scan
  const runs = useCollection<ScanRunRecord>("scan_runs", { enabled: user !== null });

  const explicit = params.get("repo");
  const repos = useMemo(() => {
    const set = new Set(runs.records.map((r) => r.repo));
    // a pasted link can name a repo whose runs have aged out of the projection
    if (explicit && explicit !== ALL_REPOS) set.add(explicit);
    return [...set].sort();
  }, [runs.records, explicit]);
  const fallback = useMemo(() => defaultRepo(runs.records, repos), [runs.records, repos]);
  const repo = explicit === ALL_REPOS ? null : (explicit ?? fallback);

  const setRepo = useCallback(
    (next: string | null) => {
      const here = `${pathname}${params.size > 0 ? `?${params.toString()}` : ""}`;
      router.push(withScope(here, next ?? ALL_REPOS));
    },
    [pathname, params, router],
  );
  const scoped = useCallback((href: string) => withScope(href, explicit), [explicit]);

  const value = useMemo(
    () => ({ repo, explicit, repos, fallback, setRepo, scoped }),
    [repo, explicit, repos, fallback, setRepo, scoped],
  );
  return <ScopeContext.Provider value={value}>{children}</ScopeContext.Provider>;
}

export function useRepoScope(): RepoScope {
  const scope = useContext(ScopeContext);
  if (!scope) throw new Error("useRepoScope outside ScopeProvider");
  return scope;
}
