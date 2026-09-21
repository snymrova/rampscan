import { z } from "zod";
import { PipelineRecipe, PlainLanguage } from "./recipe.js";

// The checkov rule → KSI crosswalk (docs/PLAN-REACH.md N2-1).
//
// `iac-baseline-clean` evidences one KSI with the whole checkov result set.
// checkov's rules already separate network, exposure, logging, backup,
// encryption and identity concerns, so a reviewed, version-pinned crosswalk
// derives ONE RECIPE PER KSI over the same artifact — each with its own
// assertion (`count_eq 0` where `check_id in <the KSI's rules>`) and its own
// empty-set discipline. What every derived row proves is stated on the row:
// DECLARED state, what the committed definitions say, never the account's.
//
// The derived recipes are generated files in `recipes/commit/` rather than
// values conjured at load, so every catalog invariant (plain prose on disk,
// manifest ↔ file agreement, the empty-set declaration) holds for them the
// way it holds for a hand-written one; `checkov-crosswalk.test.ts` fails the
// build when a file on disk stops equalling its derivation.

export const CheckovFramework = z.enum(["dockerfile", "github_actions", "terraform"]);
export type CheckovFramework = z.infer<typeof CheckovFramework>;

/** one admitted rule, filed under exactly one KSI with the reviewer's reason */
export const CheckovCrosswalkEntry = z.strictObject({
  check: z.string().regex(/^CKV2?_[A-Z]+_\d+$/),
  framework: CheckovFramework,
  ksi: z.string().regex(/^KSI-[A-Z]{3}-[A-Z]{3}$/),
  /** the reviewer's reason — long enough to be an argument, not a label */
  basis: z.string().min(60),
  /** what a pass proves; the only value, and stated per row so a reader never infers it */
  proves: z.literal("declared-state"),
});
export type CheckovCrosswalkEntry = z.infer<typeof CheckovCrosswalkEntry>;

/** the recipe a KSI's entries derive: its id, controls and authored prose */
export const CheckovCrosswalkRow = z.strictObject({
  ksi: z.string().regex(/^KSI-[A-Z]{3}-[A-Z]{3}$/),
  /** the derived recipe's id, in the catalog's naming: what it declares, and that it is declared */
  recipe: z.string().regex(/^iac-[a-z0-9-]+-declared$/),
  controls: z.array(z.string()).min(1),
  /** the auditor sentence, one clause */
  evidence: z.string().min(60),
  plain: PlainLanguage,
  /** the remainder — what the declaration cannot see */
  caveats: z.string().min(60),
});
export type CheckovCrosswalkRow = z.infer<typeof CheckovCrosswalkRow>;

export const CheckovCrosswalk = z.strictObject({
  _type: z.literal("https://rampscan.dev/checkov-crosswalk/v1"),
  tool: z.literal("checkov"),
  /** the checkov version the rule ids were read from — pinned in tools.json */
  version: z.string().regex(/^\d+\.\d+\.\d+$/),
  /** the dataset version the KSI ids resolve against */
  to: z.string().min(1),
  reviewed: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
  /** the recipe every derived row shares its artifact with */
  derived_from: z.string().min(1),
  rule: z.string().min(200),
  rows: z.array(CheckovCrosswalkRow).min(1),
  entries: z.array(CheckovCrosswalkEntry).min(1),
});
export type CheckovCrosswalk = z.infer<typeof CheckovCrosswalk>;

/** the crosswalk's own name, the way a derived recipe cites it */
export function crosswalkName(crosswalk: Pick<CheckovCrosswalk, "tool" | "version" | "to">): string {
  return `${crosswalk.tool}-${crosswalk.version}-to-${crosswalk.to}`;
}

/**
 * The derivation: one recipe per row, over the base recipe's collector and
 * cadence, asserting zero failed checks among the row's rules. Pure, and
 * refusing the four ways a crosswalk goes wrong quietly:
 *
 *   - an entry filed under a KSI that has no row would derive a rule into
 *     nothing;
 *   - a row with no entries would derive a recipe that asserts over an empty
 *     rule set — the vacuous pass, one level up;
 *   - a rule filed under two KSIs would count one observation twice;
 *   - a base recipe that is not the crosswalk's `derived_from`, or that runs a
 *     different collector, would derive rows over an artifact they never read.
 *
 * `empty_means: clean` with the Guard pattern, and the notes say what the
 * guard is: the collector emits a derived recipe's observation set only when
 * at least one of its rules was EVALUATED this run (present in checkov's
 * passed or failed checks), so a tree where none of them applied stays
 * unevidenced. That is the soundness rule the plan names — empty means clean
 * only when the rules were there to fail.
 */
export function deriveCheckovRecipes(
  crosswalk: CheckovCrosswalk,
  base: PipelineRecipe,
): PipelineRecipe[] {
  if (base.id !== crosswalk.derived_from) {
    throw new Error(
      `crosswalk ${crosswalkName(crosswalk)} derives from "${crosswalk.derived_from}", and the base recipe handed in is "${base.id}"`,
    );
  }
  if (base.collection.collector !== "checkov") {
    throw new Error(
      `crosswalk ${crosswalkName(crosswalk)}: base recipe "${base.id}" runs collector "${base.collection.collector}", not checkov — the derived rows would assert over an artifact they never read`,
    );
  }
  const rowByKsi = new Map(crosswalk.rows.map((r) => [r.ksi, r]));
  const checksByKsi = new Map<string, string[]>();
  const filed = new Map<string, string>();
  for (const entry of crosswalk.entries) {
    if (!rowByKsi.has(entry.ksi)) {
      throw new Error(
        `crosswalk ${crosswalkName(crosswalk)}: ${entry.check} is filed under ${entry.ksi}, which has no row — a rule derived into no recipe`,
      );
    }
    const already = filed.get(entry.check);
    if (already !== undefined) {
      throw new Error(
        `crosswalk ${crosswalkName(crosswalk)}: ${entry.check} is filed under both ${already} and ${entry.ksi} — one observation would count twice`,
      );
    }
    filed.set(entry.check, entry.ksi);
    (checksByKsi.get(entry.ksi) ?? checksByKsi.set(entry.ksi, []).get(entry.ksi)!).push(entry.check);
  }
  const name = crosswalkName(crosswalk);
  return crosswalk.rows.map((row) => {
    const checks = [...(checksByKsi.get(row.ksi) ?? [])].sort();
    if (checks.length === 0) {
      throw new Error(
        `crosswalk ${name}: row ${row.ksi} (${row.recipe}) has no entries — a recipe asserting over no rules passes vacuously`,
      );
    }
    const recipe: PipelineRecipe = {
      id: row.recipe,
      ksi_ids: [row.ksi],
      control_ids: [...row.controls],
      evidence: row.evidence,
      collection: { ...base.collection },
      expected_output:
        `the same checkov-results.json ${base.id} reads (frameworks scanned, passed/failed counts, evaluated check ids, failed checks sorted), ` +
        `plus one observation row per failed check whose id the crosswalk ${name} maps to ${row.ksi}: check_id, check_name, framework, file, resource`,
      assertions: [
        {
          field: "check_id",
          op: "count_eq",
          value: 0,
          where: [{ field: "check_id", op: "in", value: checks }],
          controls: [...row.controls],
          description:
            `Zero failed checks among the ${checks.length} checkov rule(s) the crosswalk maps to ${row.ksi} — ` +
            "the committed infrastructure declares the state this indicator asks for, at the scanned commit.",
        },
      ],
      cadence: base.cadence,
      caveats: row.caveats,
      automatable: "full",
      notes:
        `Derived from ${base.id} by the crosswalk recipes/crosswalks/${name}.json: the same collector, the same artifact, ` +
        `and ${checks.length} of its rules filed under ${row.ksi} with a reviewed basis each. What a pass proves is DECLARED state — ` +
        "what the committed definitions say — and the register prints `declared` beside this method for that reason; it corroborates " +
        "the cloud plane and never replaces it. Empty-set discipline — Guard: the collector emits this recipe's observation set only " +
        `when at least one of its ${checks.length} mapped rules was evaluated in this run (present in checkov's passed or failed checks ` +
        "over every file of every detected framework); a tree where none of them applied gets no observation and the recipe stays " +
        "unevidenced, so an empty set here is an exhaustively searched clean result over the whole of the mapped rules the run evaluated.",
      plain: { ...row.plain },
      empty_means: "clean",
      derived_from: {
        recipe: base.id,
        crosswalk: name,
        proves: "declared-state",
        checks,
      },
      anchor: "commit",
    };
    return recipe;
  });
}
