// The six levels of zoom (docs/PLAN-CONSOLE-DEPTH.md §2), as the depth rail
// draws them. Every console URL sits at one level, or is read through a lens
// that cuts across them. Pure, so the rail and its test agree on where a page
// is without rendering it.

export interface DepthLevel {
  key: "posture" | "theme" | "ksi" | "check" | "evidence" | "bytes";
  code: string;
  name: string;
  question: string;
}

export const LEVELS: readonly DepthLevel[] = [
  { key: "posture", code: "L0", name: "Posture", question: "how are we doing" },
  { key: "theme", code: "L1", name: "Theme", question: "which indicators need me" },
  { key: "ksi", code: "L2", name: "KSI", question: "why this state, what is owed" },
  { key: "check", code: "L3", name: "Check", question: "what this check says over time" },
  { key: "evidence", code: "L4", name: "Evidence", question: "what exactly was claimed" },
  { key: "bytes", code: "L5", name: "Bytes", question: "the signed thing itself" },
];

export type Lens = "Work" | "Time" | "Record" | "Audit";

export type Depth =
  | { kind: "level"; index: number; entity: string | null }
  | { kind: "lens"; lens: Lens }
  | { kind: "none" };

const LENSES: Record<string, Lens> = {
  "/queue": "Work",
  "/approvals": "Work",
  "/clock": "Time",
  "/drift": "Time",
  "/runs": "Record",
  "/scoping": "Record",
  "/recipes": "Record",
  "/controls": "Audit",
};

/** where a console URL sits: a level (with the entity it names) or a lens */
export function depthOf(pathname: string, params: URLSearchParams): Depth {
  if (pathname === "/") {
    const ksi = params.get("ksi");
    if (ksi) return { kind: "level", index: 2, entity: ksi };
    const theme = params.get("theme");
    if (theme) return { kind: "level", index: 1, entity: theme };
    return { kind: "level", index: 0, entity: null };
  }
  const ksiPage = /^\/ksi\/([^/]+)/.exec(pathname);
  if (ksiPage) return { kind: "level", index: 2, entity: decodeURIComponent(ksiPage[1]) };
  const checkPage = /^\/check\/([^/]+)/.exec(pathname);
  if (checkPage) return { kind: "level", index: 3, entity: decodeURIComponent(checkPage[1]) };
  // a recipe cell named on the flat register is the check, one level down
  if (pathname === "/recipes" && params.get("recipe")) {
    return { kind: "level", index: 3, entity: params.get("recipe") };
  }
  const evidence = /^\/evidence\/([0-9a-f]+)/.exec(pathname);
  if (evidence) return { kind: "level", index: 4, entity: evidence[1] };
  const bytes = /^\/artifacts\/([0-9a-f]+)/.exec(pathname);
  if (bytes) return { kind: "level", index: 5, entity: bytes[1] };
  const lens = LENSES[pathname];
  if (lens) return { kind: "lens", lens };
  return { kind: "none" };
}

/** an entity as the rail prints it: digests shorten, ids stay whole */
export function railEntity(entity: string): string {
  return /^[0-9a-f]{64}$/.test(entity) ? `${entity.slice(0, 12)}…` : entity;
}
