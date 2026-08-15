"use client";

import { useEffect, useState } from "react";
import { getPb } from "./pb";
import type {
  AsOfRegisterRow,
  AsOfRollupRow,
  BoardAsOfResponse,
  RegisterRecord,
  RollupRecord,
} from "./types";

// The as-of selector's client side (I3d), shared by the board and the
// control register so the two pages can never fetch the past differently.
// The fold itself runs server-side — computeBoardAsOf, the same hand
// `rampscan board --as-of` calls — this file only fetches and renames.

/**
 * Fetch the as-of fold whenever an instant is selected. Refetched when the
 * live projection moves (projectedAt) — the ledger is append-only, so the
 * as-of answer can only change when the ledger gained entries.
 */
export function useAsOfBoard(
  asOf: string | null,
  projectedAt: string | undefined,
): BoardAsOfResponse | null {
  const [data, setData] = useState<BoardAsOfResponse | null>(null);

  useEffect(() => {
    if (!asOf) {
      setData(null);
      return;
    }
    let cancelled = false;
    setData(null);
    fetch(`/api/board/asof?at=${encodeURIComponent(asOf)}`, {
      headers: { Authorization: getPb().authStore.token },
    })
      .then((r) => r.json())
      .then((response: BoardAsOfResponse) => {
        if (!cancelled) setData(response);
      })
      .catch((e: unknown) => {
        if (!cancelled) setData({ error: e instanceof Error ? e.message : String(e) });
      });
    return () => {
      cancelled = true;
    };
  }, [asOf, projectedAt]);

  return data;
}

/**
 * The projector's as-of register row in the live collection's record shape —
 * mechanical field renaming so the board renders both worlds through one
 * component, never a recomputation. The synthesized id is the cell key.
 */
export function asOfRegisterRecord(row: AsOfRegisterRow): RegisterRecord {
  return {
    id: `${row.repo} ${row.recipeId}`,
    repo: row.repo,
    recipe_id: row.recipeId,
    ksi_ids: row.ksiIds,
    control_ids: row.controlIds,
    state: row.state,
    cadence: row.cadence ?? "",
    collector: row.collector ?? "",
    plain: row.plain ?? null,
    run_id: row.runId ?? "",
    bundle_digest: row.bundleDigest ?? "",
    fresh_as_of: row.freshAsOf ?? "",
    commit_sha: row.commit ?? "",
    pointers: row.pointers ?? null,
    introduced_at: row.introducedAt ?? "",
    introducing_commit: row.introducingCommit ?? "",
    scoping: row.scoping ?? null,
  };
}

/** Same renaming for a rollup row (controls / ksis). */
export function asOfRollupRecord(row: AsOfRollupRow): RollupRecord {
  return {
    id: `${row.repo} ${row.id}`,
    repo: row.repo,
    rollup_id: row.id,
    state: row.state,
    recipe_ids: row.recipeIds,
    counts: row.counts,
  };
}

/** ISO instant → the local-time value a datetime-local input edits. */
export function toLocalInputValue(iso: string): string {
  const d = new Date(iso);
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}
