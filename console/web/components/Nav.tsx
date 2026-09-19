"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { repoLabel } from "../lib/links";
import { useAuth } from "../lib/pb";
import { ALL_REPOS, useRepoScope } from "../lib/scope";

const LINKS = [
  { href: "/", label: "Board" },
  { href: "/recipes", label: "Recipes" },
  { href: "/queue", label: "Queue" },
  { href: "/controls", label: "Controls" },
  { href: "/scoping", label: "Scoping" },
  { href: "/clock", label: "Clock" },
  { href: "/drift", label: "Drift" },
  { href: "/runs", label: "Runs" },
  { href: "/approvals", label: "Approvals" },
];

export function Nav() {
  const pathname = usePathname();
  const { user, ready, signOut } = useAuth();
  const { scoped } = useRepoScope();

  return (
    <nav className="nav">
      <Link href={scoped("/")} className="nav-brand">
        ramp<span>scan</span>
      </Link>
      {LINKS.map((link) => (
        <Link
          key={link.href}
          href={scoped(link.href)}
          className={`nav-link ${pathname === link.href ? "active" : ""}`}
        >
          {link.label}
        </Link>
      ))}
      <div className="nav-spacer" />
      {ready && user && <RepoScopeSelect />}
      {ready && user && (
        <span className="nav-user">
          <b>{user.email}</b> · {user.role || "no role"} ·{" "}
          <a href="/login" onClick={signOut}>
            sign out
          </a>
        </span>
      )}
      {ready && !user && (
        <span className="nav-user">
          <Link href="/login">sign in</Link>
        </span>
      )}
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
