"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { repoLabel } from "../lib/links";
import { useAuth } from "../lib/pb";
import { ALL_REPOS, useRepoScope } from "../lib/scope";

// The top bar: the repo scope first (it governs every page), then the
// lenses in their groups (Plan U, D1). The levels themselves live on the
// depth rail; the board keeps a link here because it is where work starts.
const GROUPS: Array<{ label: string; links: Array<{ href: string; label: string }> }> = [
  { label: "", links: [{ href: "/", label: "Board" }] },
  {
    label: "Work",
    links: [
      { href: "/queue", label: "Queue" },
      { href: "/approvals", label: "Approvals" },
    ],
  },
  {
    label: "Time",
    links: [
      { href: "/clock", label: "Clock" },
      { href: "/drift", label: "Drift" },
    ],
  },
  {
    label: "Record",
    links: [
      { href: "/recipes", label: "Recipes" },
      { href: "/runs", label: "Runs" },
      { href: "/scoping", label: "Scoping" },
    ],
  },
  { label: "Audit", links: [{ href: "/controls", label: "Controls" }] },
];

export function Nav() {
  const pathname = usePathname();
  const { user, ready } = useAuth();
  const { scoped } = useRepoScope();

  return (
    <nav className="nav" aria-label="console">
      {ready && user && <RepoScopeSelect />}
      <div className="nav-groups">
        {GROUPS.map((group) => (
          <div key={group.label || "home"} className="nav-group">
            {group.label && <span className="nav-group-label">{group.label}</span>}
            {group.links.map((link) => (
              <Link
                key={link.href}
                href={scoped(link.href)}
                className={`nav-link ${pathname === link.href ? "active" : ""}`}
                aria-current={pathname === link.href ? "page" : undefined}
              >
                {link.label}
              </Link>
            ))}
          </div>
        ))}
      </div>
    </nav>
  );
}

/**
 * The one repo selector (U-R5). Option values are the full paths the scan
 * recorded, so a link or a test can name a repo exactly; the labels are
 * basenames, which is what a reader recognises.
 */
function RepoScopeSelect() {
  const { repo, explicit, repos, fallback, setRepo } = useRepoScope();
  if (repos.length === 0) return null;
  return (
    <label className="nav-scope" title={`repo scope: ${repo ?? "every scanned repo"}`}>
      <span className="nav-scope-label">repo</span>
      <select
        aria-label="repo scope"
        value={repo ?? ALL_REPOS}
        onChange={(e) => setRepo(e.target.value === ALL_REPOS ? null : e.target.value)}
      >
        {repos.map((r) => (
          <option key={r} value={r}>
            {repoLabel(r)}
            {explicit === null && r === fallback ? " · newest scan" : ""}
          </option>
        ))}
        {repos.length > 1 && <option value={ALL_REPOS}>all repos</option>}
      </select>
    </label>
  );
}
