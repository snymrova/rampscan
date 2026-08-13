import { z } from "zod";

// osv-results.json parsing, shared by the osv-scanner producer and the M4
// reachability gate. One parser, one severity normalization — the two
// collectors must never disagree about what an advisory row is.

export const OSV_RESULTS_ARTIFACT = "osv-results.json";

export const OsvResults = z
  .object({
    results: z
      .array(
        z.object({
          source: z.object({ path: z.string().optional() }).passthrough().optional(),
          packages: z.array(
            z.object({
              package: z.object({
                name: z.string(),
                version: z.string().optional(),
                ecosystem: z.string().optional(),
              }),
              vulnerabilities: z
                .array(
                  z.object({
                    id: z.string(),
                    summary: z.string().optional(),
                    aliases: z.array(z.string()).optional(),
                    database_specific: z.object({ severity: z.string().optional() }).passthrough().optional(),
                  }).passthrough(),
                )
                .optional(),
              groups: z
                .array(
                  z.object({
                    ids: z.array(z.string()),
                    max_severity: z.string().optional(),
                  }).passthrough(),
                )
                .optional(),
            }).passthrough(),
          ),
        }).passthrough(),
      )
      .optional(),
  })
  .passthrough();
export type OsvResults = z.infer<typeof OsvResults>;

/** normalize a CVSS score (as string) or a database severity word to one register */
export function normalizeSeverity(maxScore?: string, dbWord?: string): string {
  const score = maxScore ? Number.parseFloat(maxScore) : Number.NaN;
  if (!Number.isNaN(score)) {
    if (score >= 9) return "CRITICAL";
    if (score >= 7) return "HIGH";
    if (score >= 4) return "MEDIUM";
    return "LOW";
  }
  const word = dbWord?.toUpperCase() ?? "";
  if (["CRITICAL", "HIGH", "MEDIUM", "MODERATE", "LOW"].includes(word)) {
    return word === "MODERATE" ? "MEDIUM" : word;
  }
  return "UNKNOWN";
}

export interface AdvisoryRow {
  advisory: string;
  aliases: string[];
  package: string;
  version: string;
  ecosystem: string;
  severity: string;
  summary?: string;
}

/** one row per advisory group — the shape every downstream assertion reads */
export function advisoryRows(report: OsvResults): AdvisoryRow[] {
  const rows: AdvisoryRow[] = [];
  for (const result of report.results ?? []) {
    for (const pkg of result.packages) {
      const byId = new Map((pkg.vulnerabilities ?? []).map((v) => [v.id, v] as const));
      const groups = pkg.groups?.length
        ? pkg.groups
        : (pkg.vulnerabilities ?? []).map((v) => ({ ids: [v.id], max_severity: undefined }));
      for (const group of groups) {
        const primary = group.ids[0]!;
        const vuln = byId.get(primary);
        const row: AdvisoryRow = {
          advisory: primary,
          aliases: group.ids,
          package: pkg.package.name,
          version: pkg.package.version ?? "unknown",
          ecosystem: pkg.package.ecosystem ?? "unknown",
          severity: normalizeSeverity(group.max_severity, vuln?.database_specific?.severity),
        };
        if (vuln?.summary !== undefined) row.summary = vuln.summary;
        rows.push(row);
      }
    }
  }
  return rows;
}
