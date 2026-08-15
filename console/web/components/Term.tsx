"use client";

import { useState } from "react";
import type { ReactNode } from "react";
import { lookupTerm } from "../lib/glossary";

// Glossary-on-hover (plan K1). Wraps a word this console uses as jargon and
// shows what it means on hover, on keyboard focus, or on click — the last one
// so a touch device is not left out of the explanation.
//
// The load-bearing behaviour is the NEGATIVE one: a term with no glossary
// entry renders its children and nothing else — no wrapper, no dotted
// underline, no empty popover. A tooltip that opens onto nothing is worse than
// a word the reader has to look up, because it costs a click to learn that.

export function Term({
  children,
  name,
}: {
  children: ReactNode;
  /** the glossary key, when the visible text is not it (`<Term name="notApplicable">n/a</Term>`) */
  name?: string;
}) {
  const [open, setOpen] = useState(false);
  const key = name ?? (typeof children === "string" ? children : "");
  const entry = lookupTerm(key);
  if (!entry) return <>{children}</>;

  return (
    <span
      className="term"
      tabIndex={0}
      role="button"
      aria-label={`${entry.term}: ${entry.definition}`}
      onMouseEnter={() => setOpen(true)}
      onMouseLeave={() => setOpen(false)}
      onFocus={() => setOpen(true)}
      onBlur={() => setOpen(false)}
      onClick={(e) => {
        // the row underneath is often a link to the evidence page; asking what
        // a word means is not asking to navigate
        e.stopPropagation();
        // OPEN, never toggle. A pointer that clicks has already hovered, and a
        // toggle would read the hover-open as "already open" and close the
        // definition on the very click that asked for it. Closing is what
        // leaving, blurring and Escape are for.
        setOpen(true);
      }}
      onKeyDown={(e) => {
        if (e.key === "Escape") setOpen(false);
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          setOpen((v) => !v);
        }
      }}
    >
      {children}
      {open && (
        <span className="termtip" role="tooltip">
          <b>{entry.term}</b> — {entry.definition}
        </span>
      )}
    </span>
  );
}
