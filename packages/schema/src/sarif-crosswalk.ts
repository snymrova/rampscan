import { z } from "zod";

// A SARIF tool's rule → KSI crosswalk (docs/PLAN-REACH.md N2-2), the shape
// the checkov crosswalk has for a tool whose output arrives as a client's
// SARIF log rather than as a collector's run. Pinned to the tool version
// whose rule ids it names: a rule id absent from the pinned version's list
// fails `sarif-crosswalk.test.ts`, and a log from another version is refused
// by the adapter rather than joined against ids that may have moved.
//
// `plane` is what the tool observed — the checkout (`commit`) for every SARIF
// tool admitted so far. It rides onto the submission and the bundle so the
// reach ladder counts a client's SAST beside rampscan's own pipeline as ONE
// plane (that plan's ground rule 3: two SARIF tools over the same checkout is
// one), never as the second plane an account observation would be.

export const SARIF_CROSSWALK_TYPE = "https://rampscan.dev/sarif-crosswalk/v1" as const;

export const EvidencePlane = z.enum(["commit", "cloud"]);
export type EvidencePlane = z.infer<typeof EvidencePlane>;

export const SarifCrosswalkEntry = z.strictObject({
  /** the rule id exactly as the tool writes `result.ruleId` */
  rule: z.string().min(1),
  ksi: z.string().regex(/^KSI-[A-Z]{3}-[A-Z]{3}$/),
  /** the reviewer's reason — an argument, not a label */
  basis: z.string().min(60),
});
export type SarifCrosswalkEntry = z.infer<typeof SarifCrosswalkEntry>;

export const SarifCrosswalk = z.strictObject({
  _type: z.literal(SARIF_CROSSWALK_TYPE),
  /** the driver name exactly as the tool writes `tool.driver.name` */
  tool: z.string().min(1),
  /** the version the rule ids were read from — `tool.driver.semanticVersion` or `version` */
  version: z.string().min(1),
  /** the dataset version the KSI ids resolve against */
  to: z.string().min(1),
  reviewed: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
  plane: EvidencePlane,
  /** how a client reproduces the log this crosswalk joins, in one line */
  reproduce: z.string().min(20),
  rule: z.string().min(200),
  entries: z.array(SarifCrosswalkEntry).min(1),
});
export type SarifCrosswalk = z.infer<typeof SarifCrosswalk>;

/** the crosswalk's own name, the way a file and a note cite it */
export function sarifCrosswalkName(cw: Pick<SarifCrosswalk, "tool" | "version">): string {
  return `sarif-${cw.tool.toLowerCase().replace(/[^a-z0-9]+/g, "-")}-${cw.version}`;
}

/**
 * The entries by rule id, refusing a rule filed under two KSIs — the same
 * refusal the checkov derivation makes, for the same reason: one finding
 * counted under two indicators is one observation counted twice.
 */
export function sarifRuleIndex(cw: SarifCrosswalk): Map<string, SarifCrosswalkEntry> {
  const index = new Map<string, SarifCrosswalkEntry>();
  for (const entry of cw.entries) {
    const already = index.get(entry.rule);
    if (already !== undefined) {
      throw new Error(
        `crosswalk ${sarifCrosswalkName(cw)}: ${entry.rule} is filed under both ${already.ksi} and ${entry.ksi} — one finding would count twice`,
      );
    }
    index.set(entry.rule, entry);
  }
  return index;
}
