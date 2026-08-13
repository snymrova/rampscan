import type { RecipeResult, ScanResult } from "@rampscan/schema";

// The three-register terminal summary (plan C5): evidenced / violated /
// unevidenced, the same registers the console will show. Unevidenced is the
// honest default and is never hidden.

const RESET = "[0m";
const BOLD = "[1m";
const DIM = "[2m";
const GREEN = "[32m";
const RED = "[31m";
const YELLOW = "[33m";

function color(enabled: boolean, code: string, text: string): string {
  return enabled ? `${code}${text}${RESET}` : text;
}

function renderRow(r: RecipeResult, useColor: boolean): string[] {
  const lines = [
    `  ${color(useColor, BOLD, r.recipe_id)} ${color(useColor, DIM, `[${r.ksi_ids.join(", ")}] [${r.control_ids.join(", ")}]`)}`,
  ];
  if (r.verdict === "violated") {
    for (const a of r.assertions.filter((a) => !a.passed)) {
      lines.push(`      ✗ ${a.description}${a.detail ? ` — ${a.detail}` : ""}`);
    }
  } else if (r.verdict === "unevidenced" && r.reason) {
    lines.push(`      ${color(useColor, DIM, r.reason)}`);
  }
  return lines;
}

export function renderSummary(result: ScanResult, useColor = process.stdout.isTTY ?? false): string {
  const registers: Array<{ title: string; verdict: RecipeResult["verdict"]; code: string }> = [
    { title: "EVIDENCED", verdict: "evidenced", code: GREEN },
    { title: "VIOLATED", verdict: "violated", code: RED },
    { title: "UNEVIDENCED", verdict: "unevidenced", code: YELLOW },
  ];

  const lines: string[] = [
    "",
    `${color(useColor, BOLD, "rampscan")} ${result.repo} @ ${result.commit.slice(0, 12)}`,
    color(useColor, DIM, `run ${result.run_id} · dataset ${result.dataset_version}`),
    "",
  ];
  for (const reg of registers) {
    const rows = result.recipes.filter((r) => r.verdict === reg.verdict);
    lines.push(color(useColor, reg.code + BOLD, `${reg.title} (${rows.length})`));
    for (const row of rows) lines.push(...renderRow(row, useColor));
    lines.push("");
  }
  if (result.skipped_collectors.length > 0) {
    lines.push(color(useColor, DIM, "skipped collectors:"));
    for (const s of result.skipped_collectors) {
      lines.push(color(useColor, DIM, `  ${s.collector}: ${s.reason}`));
    }
    lines.push("");
  }
  const { evidenced, violated, unevidenced } = result.summary;
  lines.push(
    `${color(useColor, GREEN, `${evidenced} evidenced`)} · ${color(useColor, RED, `${violated} violated`)} · ${color(useColor, YELLOW, `${unevidenced} unevidenced`)} · ${result.findings.length} findings`,
  );
  return lines.join("\n");
}
