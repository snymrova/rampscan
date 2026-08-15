"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useAuth } from "../lib/pb";

const LINKS = [
  { href: "/", label: "Board" },
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

  return (
    <nav className="nav">
      <Link href="/" className="nav-brand">
        ramp<span>scan</span>
      </Link>
      {LINKS.map((link) => (
        <Link
          key={link.href}
          href={link.href}
          className={`nav-link ${pathname === link.href ? "active" : ""}`}
        >
          {link.label}
        </Link>
      ))}
      <div className="nav-spacer" />
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
