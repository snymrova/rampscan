import type {
  RegisterRecord,
  RollupRecord,
  ScopingRegisterRow,
} from "./types";

// Register CSV export (plan I3e). Pure functions over the records the page is
// ALREADY rendering — filters, as-of instant and all — because the exit test
// is "exported row count equals the on-screen register", and a CSV built from
// a second query would be a different answer that merely looks like the same
// one.
//
// Provenance rides every row (`folded_at`) rather than a preamble block: a
// preamble breaks strict CSV parsers and makes "row count" ambiguous, and a
// single row lifted out of the file should still say when it was true. The
// filename carries the same instant for the human.

/** RFC 4180: quote when the value carries a comma, quote, CR or LF. */
export function csvCell(value: string): string {
  return /[",\r\n]/.test(value) ? `"${value.replaceAll('"', '""')}"` : value;
}

export function toCsv(headers: string[], rows: string[][]): string {
  return [headers, ...rows].map((row) => row.map(csvCell).join(",")).join("\r\n") + "\r\n";
}

/** arrays render as one cell, semicolon-separated — legible in a spreadsheet */
function list(values: string[] | null | undefined): string {
  return (values ?? []).join("; ");
}

export function registerCsv(rows: RegisterRecord[], foldedAt: string): string {
  return toCsv(
    [
      "repo",
      "recipe_id",
      "state",
      "ksi_ids",
      "control_ids",
      "cadence",
      "bundle_digest",
      "commit",
      "fresh_as_of",
      "introduced_at",
      "introducing_commit",
      "pointers",
      "scoped_out_by",
      "scoping_justification",
      "folded_at",
    ],
    rows.map((r) => [
      r.repo,
      r.recipe_id,
      r.state,
      list(r.ksi_ids),
      list(r.control_ids),
      r.cadence ?? "",
      r.bundle_digest ?? "",
      r.commit_sha ?? "",
      r.fresh_as_of ?? "",
      r.introduced_at ?? "",
      r.introducing_commit ?? "",
      list(
        (r.pointers ?? []).map((p) =>
          [p.check, p.file && p.line ? `${p.file}:${p.line}` : p.file, p.call_path]
            .filter(Boolean)
            .join(" "),
        ),
      ),
      r.scoping?.approvedBy ?? "",
      r.scoping?.justification ?? "",
      foldedAt,
    ]),
  );
}

export function rollupCsv(rows: RollupRecord[], foldedAt: string): string {
  return toCsv(
    [
      "repo",
      "id",
      "state",
      "mapped_recipes",
      "evidenced",
      "violated",
      "unevidenced",
      "not_applicable",
      "recipe_ids",
      "folded_at",
    ],
    rows.map((r) => [
      r.repo,
      r.rollup_id,
      r.state,
      String(r.counts.total),
      String(r.counts.evidenced),
      String(r.counts.violated),
      String(r.counts.unevidenced),
      String(r.counts.notApplicable),
      list(r.recipe_ids),
      foldedAt,
    ]),
  );
}

export function scopingCsv(rows: ScopingRegisterRow[], foldedAt: string): string {
  return toCsv(
    [
      "decision",
      "repo",
      "recipe_id",
      "ksi_ids",
      "control_ids",
      "proposed_by",
      "decided_by",
      "timestamp",
      "digest",
      "signature",
      "justification",
      "problems",
      "folded_at",
    ],
    rows.map((r) => [
      r.decision,
      r.repo,
      r.recipeId,
      list(r.ksiIds),
      list(r.controlIds),
      r.proposedBy,
      r.decidedBy,
      r.timestamp,
      r.digest ?? "",
      r.signature ?? "",
      r.justification,
      list(r.problems),
      foldedAt,
    ]),
  );
}

/**
 * `rampscan-<view>-<instant>.csv` — the instant in the name is the same one
 * every row carries, so a file separated from its rows still dates itself.
 */
export function csvFilename(view: string, foldedAt: string): string {
  const stamp = foldedAt.replaceAll(/[:.]/g, "-");
  return `rampscan-${view}-${stamp}.csv`;
}

/**
 * Hand the browser a file. Client-only (it touches document/URL); the caller
 * is always a click handler in a "use client" page.
 */
export function downloadText(filename: string, text: string, mime = "text/csv"): void {
  const url = URL.createObjectURL(new Blob([text], { type: `${mime};charset=utf-8` }));
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}
