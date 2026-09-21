import { z } from "zod";

// The SARIF reader (docs/PLAN-REACH.md N2-2): a SARIF 2.1.0 log becomes one
// document the adapter can join against a per-tool crosswalk. Loose parsing
// (the vendor's fields are kept), strict about the four facts the adapter's
// refusals turn on: the tool and its version, whether the invocation
// finished, which rules the tool DECLARED it ran, and each result's rule,
// level, kind and suppression state.
//
// Two SARIF facts this reader takes at the spec's word rather than guessing:
//
//   - a result with no `level` is `warning` unless its rule's
//     `defaultConfiguration.level` says otherwise (§3.27.10) — Semgrep writes
//     no level on results and puts ERROR/WARNING on the rule, so reading the
//     result alone would demote every Semgrep error to a warning;
//   - a result with no `kind` is `fail` (§3.27.9).
//
// What SARIF does NOT carry is why the adapter needs the client's word for
// the rest: no exit code (`invocations[].executionSuccessful` is the nearest
// thing, and is optional), no signer, no cadence, and no population beyond
// the rules the driver lists.

export const SARIF_VERSION = "2.1.0";

export const SarifLevel = z.enum(["none", "note", "warning", "error"]);
export type SarifLevel = z.infer<typeof SarifLevel>;
export const SarifKind = z.enum(["notApplicable", "pass", "fail", "review", "open", "informational"]);
export type SarifKind = z.infer<typeof SarifKind>;

const RawRule = z.looseObject({
  id: z.string().min(1),
  defaultConfiguration: z.looseObject({ level: SarifLevel.optional() }).optional(),
});

const RawResult = z.looseObject({
  ruleId: z.string().min(1).optional(),
  rule: z.looseObject({ id: z.string().min(1).optional() }).optional(),
  level: SarifLevel.optional(),
  kind: SarifKind.optional(),
  suppressions: z.array(z.looseObject({})).optional(),
  message: z.looseObject({ text: z.string().optional() }).optional(),
  locations: z
    .array(
      z.looseObject({
        physicalLocation: z
          .looseObject({
            artifactLocation: z.looseObject({ uri: z.string().optional() }).optional(),
            region: z.looseObject({ startLine: z.number().int().optional() }).optional(),
          })
          .optional(),
      }),
    )
    .optional(),
});

const RawRun = z.looseObject({
  tool: z.looseObject({
    driver: z.looseObject({
      name: z.string().min(1),
      version: z.string().optional(),
      semanticVersion: z.string().optional(),
      rules: z.array(RawRule).optional(),
    }),
  }),
  invocations: z
    .array(z.looseObject({ executionSuccessful: z.boolean(), endTimeUtc: z.string().optional() }))
    .optional(),
  results: z.array(RawResult).optional(),
});

/** exported for the hard-edge pin: loose parsing must retain unknown vendor fields */
export const RawSarifLog = z.looseObject({
  $schema: z.string().optional(),
  version: z.string(),
  runs: z.array(RawRun).min(1),
});

/** one result, normalized to the fields the adapter's assertion reads */
export interface SarifResult {
  ruleId: string;
  level: SarifLevel;
  kind: SarifKind;
  /** `suppressions[]` present and non-empty — counted, never waived (the Prowler mute rule) */
  suppressed: boolean;
  file?: string;
  line?: number;
  message: string;
}

export interface SarifDocument {
  tool: { name: string; version: string };
  /**
   * `invocations[].executionSuccessful`, every invocation true; null when the
   * log records no invocation at all — the tool did not say, and the adapter
   * refuses to read silence as success.
   */
  executionSuccessful: boolean | null;
  /** the latest `invocations[].endTimeUtc`, when any invocation wrote one — the run's own clock */
  endedAt: string | null;
  /** the rule ids the driver DECLARED (`tool.driver.rules`), sorted — the population a zero-result rule can cite */
  declaredRules: string[];
  results: SarifResult[];
  /** how many runs the log carried — all by one driver, or the reader refuses */
  runCount: number;
}

export class SarifReadError extends Error {}

/** is this JSON a SARIF log? sniffed on content, never on the file name */
export function looksLikeSarif(raw: unknown): boolean {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) return false;
  const o = raw as Record<string, unknown>;
  if (!Array.isArray(o["runs"])) return false;
  const schema = typeof o["$schema"] === "string" ? o["$schema"] : "";
  return /sarif/i.test(schema) || o["version"] === SARIF_VERSION;
}

export function parseSarif(raw: unknown, origin: string): SarifDocument {
  const parsed = RawSarifLog.safeParse(raw);
  if (!parsed.success) {
    throw new SarifReadError(
      `${origin} is not a SARIF log this reader can join: ${parsed.error.issues
        .slice(0, 3)
        .map((i) => `${i.path.join(".") || "(root)"}: ${i.message}`)
        .join("; ")}`,
    );
  }
  const log = parsed.data;
  if (log.version !== SARIF_VERSION) {
    throw new SarifReadError(
      `${origin} is SARIF ${log.version}; the reader is written against ${SARIF_VERSION} and refuses another version rather than guessing its field meanings`,
    );
  }
  const names = new Set(log.runs.map((r) => r.tool.driver.name));
  if (names.size !== 1) {
    throw new SarifReadError(
      `${origin} carries runs from ${names.size} different tools (${[...names].join(", ")}) — one crosswalk joins one tool, so ingest one tool's log at a time`,
    );
  }
  const first = log.runs[0]!.tool.driver;
  const versions = new Set(log.runs.map((r) => r.tool.driver.semanticVersion ?? r.tool.driver.version));
  const version = [...versions][0];
  if (versions.size !== 1 || version === undefined) {
    throw new SarifReadError(
      `${origin}: the driver states ${versions.size === 0 || version === undefined ? "no" : "more than one"} version (semanticVersion/version) — a crosswalk is pinned to one, so the log must say which`,
    );
  }

  const declared = new Set<string>();
  const levelByRule = new Map<string, SarifLevel>();
  let invocations = 0;
  let allSucceeded = true;
  let endedAt: string | null = null;
  const results: SarifResult[] = [];
  for (const run of log.runs) {
    for (const rule of run.tool.driver.rules ?? []) {
      declared.add(rule.id);
      const level = rule.defaultConfiguration?.level;
      if (level !== undefined) levelByRule.set(rule.id, level);
    }
    for (const inv of run.invocations ?? []) {
      invocations++;
      if (!inv.executionSuccessful) allSucceeded = false;
      if (inv.endTimeUtc !== undefined && !Number.isNaN(Date.parse(inv.endTimeUtc))) {
        const iso = new Date(inv.endTimeUtc).toISOString();
        if (endedAt === null || iso > endedAt) endedAt = iso;
      }
    }
    (run.results ?? []).forEach((r, i) => {
      const ruleId = r.ruleId ?? r.rule?.id;
      if (ruleId === undefined) {
        throw new SarifReadError(
          `${origin}: results[${i}] names no rule (neither ruleId nor rule.id) — a finding that belongs to no rule cannot be filed under any indicator`,
        );
      }
      const loc = r.locations?.[0]?.physicalLocation;
      const result: SarifResult = {
        ruleId,
        level: r.level ?? levelByRule.get(ruleId) ?? "warning",
        kind: r.kind ?? "fail",
        suppressed: (r.suppressions?.length ?? 0) > 0,
        message: r.message?.text ?? "",
      };
      if (loc?.artifactLocation?.uri !== undefined) result.file = loc.artifactLocation.uri;
      if (loc?.region?.startLine !== undefined) result.line = loc.region.startLine;
      results.push(result);
    });
  }
  return {
    tool: { name: first.name, version },
    executionSuccessful: invocations === 0 ? null : allSucceeded,
    endedAt,
    declaredRules: [...declared].sort(),
    results,
    runCount: log.runs.length,
  };
}
