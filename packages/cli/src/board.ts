import type { Projection, RegisterChange, RegisterChangeKind } from "@rampscan/core";
import { CHANGE_KIND_SEVERITY } from "@rampscan/projector";
import type { BoardDiffOutcome } from "./board-diff.js";

// `rampscan board` — the projection as text (the visual console is
// `rampscan serve`). As of M3 the projection joins the recipe catalog, so the
// full registers render here: evidenced / violated / unevidenced (the honest
// default, never hidden) / notApplicable (two-key scoped), then the
// graveyard with causes — drift must be readable before it is clickable.

export function renderBoard(projection: Projection, useColor: boolean): string {
  const paint = (code: string, s: string) => (useColor ? `[${code}m${s}[0m` : s);
  const green = (s: string) => paint("32", s);
  const red = (s: string) => paint("31", s);
  const yellow = (s: string) => paint("33", s);
  const dim = (s: string) => paint("2", s);

  const lines: string[] = [];
  const byState = (state: string) => projection.registers.filter((r) => r.state === state);

  const sections: Array<{ title: string; color: (s: string) => string; state: string }> = [
    { title: "EVIDENCED", color: green, state: "evidenced" },
    { title: "VIOLATED", color: red, state: "violated" },
    { title: "UNEVIDENCED", color: yellow, state: "unevidenced" },
    { title: "NOT APPLICABLE", color: dim, state: "notApplicable" },
  ];
  for (const section of sections) {
    const rows = byState(section.state);
    lines.push(`${section.color(section.title)} (${rows.length})`);
    for (const row of rows) {
      const detail =
        row.state === "notApplicable"
          ? `scoped by ${row.scoping?.approvedBy ?? "?"}`
          : row.state === "unevidenced"
            ? dim("no live evidence in the ledger")
            : `fresh ${row.freshAsOf ?? "?"} ${dim(row.bundleDigest?.slice(0, 12) ?? "")}`;
      lines.push(`  ${row.recipeId.padEnd(36)} ${dim(row.repo.padEnd(28))} ${detail}`);
    }
    if (rows.length === 0) lines.push(dim("  (none)"));
    lines.push("");
  }

  const dead = projection.rows.filter((r) => r.status.state === "dead");
  lines.push(`DEAD EVIDENCE (${dead.length})`);
  for (const row of dead) {
    if (row.status.state !== "dead") continue;
    const killer = row.status.killingCommit ? ` by ${row.status.killingCommit.slice(0, 12)}` : "";
    lines.push(
      `  ${red(row.status.cause).padEnd(useColor ? 21 : 12)} ${row.recipeId.padEnd(36)} ` +
        `was ${row.verdict}, killed${killer} ${dim(row.bundleDigest?.slice(0, 12) ?? "")}`,
    );
  }
  if (dead.length === 0) lines.push(dim("  (none)"));

  lines.push("", dim(`dataset ${projection.datasetVersion} · projected ${projection.projectedAt}`));
  return lines.join("\n");
}

// `rampscan board --since` (I2d): what moved between a prior scan's board and
// this one. State-level by design — refreshed evidence with a held state is
// "unchanged" here; the drift view narrates bundle movement.

const KIND_LABEL: Record<RegisterChangeKind, string> = {
  "newly-violated": "NEWLY VIOLATED",
  "evidence-lapsed": "EVIDENCE LAPSED",
  unscoped: "UNSCOPED",
  removed: "ROWS REMOVED",
  appeared: "ROWS APPEARED",
  scoped: "SCOPED N/A",
  "newly-evidenced": "NEWLY EVIDENCED",
  resolved: "RESOLVED",
};

export function renderBoardDiff(outcome: BoardDiffOutcome, useColor: boolean): string {
  const paint = (code: string, s: string) => (useColor ? `[${code}m${s}[0m` : s);
  const green = (s: string) => paint("32", s);
  const red = (s: string) => paint("31", s);
  const yellow = (s: string) => paint("33", s);
  const dim = (s: string) => paint("2", s);
  const colorFor: Record<RegisterChangeKind, (s: string) => string> = {
    "newly-violated": red,
    "evidence-lapsed": red,
    unscoped: yellow,
    removed: yellow,
    appeared: yellow,
    scoped: dim,
    "newly-evidenced": green,
    resolved: green,
  };

  const { diff } = outcome;
  const label = outcome.baselineIsScan ? "a prior scan's board" : "an as-of fold at that instant";
  const lines: string[] = [
    `SINCE ${diff.baseline} — the board diffed against ${label}, both refolded from the ledger`,
    "",
  ];
  if (diff.changes.length === 0) {
    lines.push(dim(`  no register moved since the baseline (${diff.unchanged} cell(s) held their state)`));
    return lines.join("\n");
  }

  const describe = (change: RegisterChange): string => {
    const arrow =
      change.from === undefined
        ? `new row → ${change.to}`
        : change.to === undefined
          ? `was ${change.from}, row removed`
          : `${change.from} → ${change.to}`;
    const pointers = (change.pointers ?? [])
      .map((p) => [p.file, p.line].filter((x) => x !== undefined).join(":") || p.check || p.call_path)
      .filter((s): s is string => !!s)
      .slice(0, 3)
      .join("  ");
    const since = change.introducedAt
      ? ` (violating since ${change.introducedAt}${change.introducingCommit ? ` at ${change.introducingCommit.slice(0, 12)}` : ""})`
      : "";
    return `${arrow}${pointers ? `  ${pointers}` : ""}${since}`;
  };

  for (const kind of CHANGE_KIND_SEVERITY) {
    const changes = diff.changes.filter((c) => c.kind === kind);
    if (changes.length === 0) continue;
    lines.push(`${colorFor[kind](KIND_LABEL[kind])} (${changes.length})`);
    for (const change of changes) {
      lines.push(`  ${change.recipeId.padEnd(36)} ${dim(change.repo.padEnd(28))} ${describe(change)}`);
    }
    lines.push("");
  }
  lines.push(dim(`unchanged: ${diff.unchanged} cell(s) held their state`));
  return lines.join("\n");
}
