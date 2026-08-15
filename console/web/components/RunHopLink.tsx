"use client";

import Link from "next/link";
import { runHop } from "../lib/runs";
import type { RegisterRecord } from "../lib/types";

// The board hop (plan J3): one link per register row from the conclusion to
// the machinery that produced it. The href is computed in lib/runs.ts — this
// component only renders it, and renders NOTHING when there is nothing honest
// to point at (a scoped-out cell, or a recipe that left the catalog).
//
// stopPropagation, like every in-row link since I3a: the row itself opens the
// evidence page, and a hop that swallowed that click would trade one
// navigation for another rather than adding one.

export function RunHopLink({
  row,
  historical = false,
}: {
  row: RegisterRecord;
  /**
   * An as-of row (I3d). `/runs` reads the LIVE projection, so a hop from a
   * historical fold would leave the chosen instant without saying so — the
   * same reason the as-of board suppresses propose-N/A.
   */
  historical?: boolean;
}) {
  if (historical) return null;
  const hop = runHop(row);
  if (!hop) return null;
  return (
    <Link
      className="runhop"
      href={hop.href}
      title={hop.title}
      onClick={(e) => e.stopPropagation()}
    >
      {hop.label}
    </Link>
  );
}
