import type { Projection } from "@rampscan/core";

// `rampscan board` — the projection as text (plan M2; the visual console is
// M3). Live evidence first, then the graveyard with causes: drift must be
// readable before it is clickable. Unevidenced recipes never reach the
// ledger, so this board only shows recorded evidence — the full three
// registers stay in `rampscan scan`'s summary until the M3 console joins
// projection × recipe set.

export function renderBoard(projection: Projection, useColor: boolean): string {
  const paint = (code: string, s: string) => (useColor ? `[${code}m${s}[0m` : s);
  const green = (s: string) => paint("32", s);
  const red = (s: string) => paint("31", s);
  const dim = (s: string) => paint("2", s);

  const live = projection.rows.filter((r) => r.status.state === "live");
  const dead = projection.rows.filter((r) => r.status.state === "dead");
  const lines: string[] = [];

  lines.push(`LIVE EVIDENCE (${live.length})`);
  for (const row of [...live].sort((a, b) => (a.freshAsOf ?? "").localeCompare(b.freshAsOf ?? ""))) {
    const verdict = row.verdict === "evidenced" ? green(row.verdict) : red(row.verdict);
    lines.push(
      `  ${verdict.padEnd(useColor ? 19 : 10)} ${row.recipeId.padEnd(36)} ` +
        `fresh ${row.freshAsOf ?? "?"} ${dim(row.bundleDigest?.slice(0, 12) ?? "")}`,
    );
  }
  if (live.length === 0) lines.push(dim("  (none)"));

  lines.push("", `DEAD EVIDENCE (${dead.length})`);
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
