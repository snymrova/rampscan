"use client";

import Link from "next/link";
import type { CSSProperties, ReactNode } from "react";
import {
  artifactHref,
  checkHref,
  controlHref,
  evidenceHref,
  ksiHref,
  repoLabel,
  runHref,
  withScope,
} from "../lib/links";
import { useRepoScope } from "../lib/scope";

// Every entity mention is a link (U-R2). A KSI id, recipe, digest, run,
// commit or control id is rendered through this one component, so a reader
// can always go one level down from wherever the id appears, and the smoke's
// walk can tell a mention from a bare string by asking for `data-entity`.
//
// The click never bubbles: most of these sit inside a row that opens
// something else on click, and a link that also toggled its row would trade
// one navigation for two.

export type Entity =
  /** `repo`, when the mention belongs to one repo (a proposal, a clock row), opens the board there */
  | { kind: "ksi"; id: string; repo?: string }
  | { kind: "check"; recipe: string; repo: string }
  | { kind: "evidence"; digest: string }
  | { kind: "artifact"; digest: string }
  | { kind: "run"; scan: string; collector?: string }
  | { kind: "commit"; sha: string; scan?: string }
  /** `repo`, as for a KSI: the mention belongs to one repo's register */
  | { kind: "control"; id: string; repo?: string };

const short = (digest: string) => (digest.length > 16 ? `${digest.slice(0, 12)}…` : digest);

function target(entity: Entity, scoped: (href: string) => string): { href: string | null; text: string; title: string } {
  switch (entity.kind) {
    case "ksi":
      return {
        href: entity.repo ? withScope(ksiHref(entity.id), entity.repo) : scoped(ksiHref(entity.id)),
        text: entity.id,
        title: `open ${entity.id} on the board`,
      };
    case "check":
      return {
        href: checkHref(entity.recipe, entity.repo),
        text: entity.recipe,
        title: `open ${entity.recipe} on ${entity.repo}`,
      };
    case "evidence":
      return { href: evidenceHref(entity.digest), text: short(entity.digest), title: `signed bundle ${entity.digest}` };
    case "artifact":
      return { href: artifactHref(entity.digest), text: short(entity.digest), title: `signed artifact ${entity.digest}` };
    case "run":
      return {
        href: runHref({ scan: entity.scan, collector: entity.collector }),
        text: entity.scan,
        title: `open run ${entity.scan}${entity.collector ? ` at the ${entity.collector} collector` : ""}`,
      };
    case "commit":
      // a commit has no page of its own; the scan that read it is where it is recorded
      return {
        href: entity.scan ? runHref({ scan: entity.scan }) : null,
        text: entity.sha.slice(0, 12),
        title: entity.scan ? `commit ${entity.sha}, scanned by ${entity.scan}` : `commit ${entity.sha}`,
      };
    case "control":
      return {
        href: entity.repo ? withScope(controlHref(entity.id), entity.repo) : scoped(controlHref(entity.id)),
        text: entity.id,
        title: `open control ${entity.id}`,
      };
  }
}

export function EntityLink({
  children,
  className = "mono",
  style,
  title,
  ...entity
}: Entity & { children?: ReactNode; className?: string; style?: CSSProperties; title?: string }) {
  const { scoped } = useRepoScope();
  const t = target(entity as Entity, scoped);
  if (title !== undefined) t.title = title;
  // a commit with no known scan is the one entity with nowhere to go; it is
  // still marked, so the walk knows it was considered and not forgotten
  if (t.href === null) {
    return (
      <span className={className} style={style} title={t.title} data-entity={entity.kind}>
        {children ?? t.text}
      </span>
    );
  }
  return (
    <Link
      href={t.href}
      className={className}
      style={style}
      title={t.title}
      data-entity={entity.kind}
      onClick={(e) => e.stopPropagation()}
    >
      {children ?? t.text}
    </Link>
  );
}

/** A repo by its basename, the full path in the title and on paper (U-R5). */
export function RepoName({ repo, className = "" }: { repo: string; className?: string }) {
  return (
    <span className={`repo-name ${className}`} title={repo} data-full={repo}>
      {repoLabel(repo)}
    </span>
  );
}
