"use client";

import Link from "next/link";
import { usePathname, useSearchParams } from "next/navigation";
import { type CSSProperties, useEffect, useState } from "react";
import { depthOf, LEVELS, railEntity } from "../lib/depth";
import { useAuth } from "../lib/pb";
import { useRepoScope } from "../lib/scope";

// The depth rail: the console's spine. Six stops, L0 posture at the surface
// to L5 bytes at the floor, and one lit band (the thermocline) at the level
// the page is on. A lens page (Queue, Clock, …) cuts across the levels, so the
// band withdraws and the rail says which lens is reading. The band is the one
// moving thing in the console: it slides to the new depth on navigation.

export function DepthRail() {
  const pathname = usePathname();
  const params = useSearchParams();
  const { scoped } = useRepoScope();
  const { user, ready, signOut } = useAuth();
  const depth = depthOf(pathname, new URLSearchParams(params.toString()));
  const index = depth.kind === "level" ? depth.index : -1;
  // the band is placed on the first render and slides only on later moves
  const [settled, setSettled] = useState(false);
  useEffect(() => setSettled(true), []);

  return (
    <aside className={`rail ${depth.kind === "lens" ? "lens" : ""} ${settled ? "settled" : ""}`} aria-label="depth">
      <Link href={scoped("/")} className="rail-brand">
        ramp<span>scan</span>
      </Link>
      <ol className="rail-stops" style={{ "--depth": Math.max(index, 0) } as CSSProperties}>
        <li className={`rail-band ${index < 0 ? "off" : ""}`} aria-hidden="true" />
        {LEVELS.map((level, i) => {
          const here = i === index;
          const above = index >= 0 && i < index;
          const body = (
            <>
              <span className="rail-code">{level.code}</span>
              <span className="rail-name">{level.name}</span>
              {here && depth.kind === "level" && depth.entity && (
                <span className="rail-entity" title={depth.entity} data-entity="here">
                  {railEntity(depth.entity)}
                </span>
              )}
            </>
          );
          return (
            <li
              key={level.key}
              className={`rail-stop ${here ? "here" : ""} ${above ? "above" : ""}`}
              aria-current={here ? "location" : undefined}
              title={level.question}
            >
              {/* the surface is always reachable; a deeper stop is an entity
                  and has no page of its own until you are at one */}
              {i === 0 ? (
                <Link href={scoped("/")} className="rail-hit">
                  {body}
                </Link>
              ) : (
                <span className="rail-hit">{body}</span>
              )}
            </li>
          );
        })}
      </ol>
      {depth.kind !== "none" && (
      <div className="rail-readout" aria-live="polite">
        {depth.kind === "level" ? (
          <>
            <span className="rail-readout-label">depth</span>
            <span className="rail-readout-value">{LEVELS[depth.index].code}</span>
            <span className="rail-readout-note">{LEVELS[depth.index].question}</span>
          </>
        ) : depth.kind === "lens" ? (
          <>
            <span className="rail-readout-label">lens</span>
            <span className="rail-readout-value lens">{depth.lens}</span>
            <span className="rail-readout-note">cuts across every level</span>
          </>
        ) : null}
      </div>
      )}
      {ready && (
        <div className="rail-user">
          {user ? (
            <>
              <b title={user.email}>{user.email}</b>
              <span>
                <span className="nav-role">{user.role || "no role"}</span> ·{" "}
                <a href="/login" onClick={signOut}>
                  sign out
                </a>
              </span>
            </>
          ) : (
            <Link href="/login">sign in</Link>
          )}
        </div>
      )}
    </aside>
  );
}
