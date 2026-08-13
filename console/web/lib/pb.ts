"use client";

import PocketBase from "pocketbase";
import { useEffect, useMemo, useRef, useState } from "react";

// One PocketBase client per browser session. The console only ever READS the
// projection collections — its single write surface is `proposals`, and an
// approved proposal becomes a signed ledger event before any register moves.

export const PB_URL = process.env.NEXT_PUBLIC_PB_URL ?? "http://127.0.0.1:8090";

let singleton: PocketBase | undefined;

export function getPb(): PocketBase {
  if (!singleton) {
    singleton = new PocketBase(PB_URL);
    singleton.autoCancellation(false);
  }
  return singleton;
}

export interface AuthUser {
  id: string;
  email: string;
  role: "viewer" | "approver" | "";
}

export function useAuth(): { user: AuthUser | null; ready: boolean; signOut: () => void } {
  const pb = getPb();
  const [ready, setReady] = useState(false);
  const [user, setUser] = useState<AuthUser | null>(null);

  useEffect(() => {
    const read = () => {
      const record = pb.authStore.record;
      setUser(
        pb.authStore.isValid && record
          ? { id: record.id, email: (record["email"] as string) ?? "", role: (record["role"] as AuthUser["role"]) ?? "" }
          : null,
      );
      setReady(true);
    };
    read();
    return pb.authStore.onChange(read);
  }, [pb]);

  return { user, ready, signOut: () => pb.authStore.clear() };
}

/**
 * Live view of a whole collection: full list plus a realtime subscription
 * that refetches (debounced — the projector rebuilds collections wholesale,
 * so per-record patching would be noise).
 */
export function useCollection<T extends { id: string }>(
  name: string,
  options: { sort?: string; enabled?: boolean } = {},
): { records: T[]; loading: boolean; error: string | null; refetch: () => void } {
  const pb = getPb();
  const enabled = options.enabled ?? true;
  const sort = options.sort;
  const [records, setRecords] = useState<T[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [nonce, setNonce] = useState(0);
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);

  useEffect(() => {
    if (!enabled) return;
    let cancelled = false;
    setLoading(true);
    pb.collection(name)
      .getFullList<T & { id: string }>({ batch: 500, ...(sort ? { sort } : {}) })
      .then((items) => {
        if (!cancelled) {
          setRecords(items as unknown as T[]);
          setError(null);
        }
      })
      .catch((e: unknown) => {
        if (!cancelled) setError(e instanceof Error ? e.message : String(e));
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    const unsubscribe = pb.collection(name).subscribe("*", () => {
      clearTimeout(timer.current);
      timer.current = setTimeout(() => setNonce((n) => n + 1), 300);
    });
    return () => {
      cancelled = true;
      clearTimeout(timer.current);
      void unsubscribe.then((fn) => fn()).catch(() => {});
    };
  }, [pb, name, sort, enabled, nonce]);

  return useMemo(
    () => ({ records, loading, error, refetch: () => setNonce((n) => n + 1) }),
    [records, loading, error],
  );
}
