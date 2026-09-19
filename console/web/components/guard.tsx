"use client";

import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useEffect, type ReactNode } from "react";
import { useAuth } from "../lib/pb";

/**
 * The registers are for console identities only — viewer or approver. A
 * signed-out reader is sent to the login card with where they were going,
 * so a pasted deep link survives the sign-in (U0).
 */
export function RequireAuth({ children }: { children: ReactNode }) {
  const { user, ready } = useAuth();
  const router = useRouter();
  const pathname = usePathname();
  const params = useSearchParams();

  useEffect(() => {
    if (ready && !user) {
      const here = `${pathname}${params.size > 0 ? `?${params.toString()}` : ""}`;
      router.replace(here === "/" ? "/login" : `/login?next=${encodeURIComponent(here)}`);
    }
  }, [ready, user, router, pathname, params]);

  if (!ready) return <p className="muted">loading…</p>;
  if (!user) return null;
  return <>{children}</>;
}
