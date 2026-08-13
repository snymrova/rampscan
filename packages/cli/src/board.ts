import type { Projection } from "@rampscan/core";

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
