import { z } from "zod";

// The reviewed record of what the pinned Prowler KSI framework does NOT cover
// (P3-0, docs/RESEARCH-PROWLER-INGEST.md §4d).
//
// The mapping itself is upstream's and is never copied here — the vendored
// file is the join table and `packages/cli/src/prowler-framework.ts` reads it.
// What upstream does not publish, and what this file is, is the JUDGEMENT
// beside the gap: "no automated check exists for this indicator on any
// provider at this pin" is a fact about the artifact, and *why* no scanner can
// see it is a reading a person did.
//
// It exists because of what the gap is worth. Prowler reaches 33 of the 46
// indicators; the thirteen it leaves are twelve periodic human activities and
// one data-lifecycle claim, and they are exactly the indicators rampscan's
// attestation and artifact planes exist to price. A gap that valuable is not
// left as a number recomputed in passing — it is named, row by row, and
// re-read when the pin moves rather than re-stamped.
//
// The `rows` are checked against the framework on every test run: the set must
// equal the computed uncovered set, both ways, and each row's `name` must be
// the name upstream gives the indicator. So this file cannot drift into
// describing a framework it no longer matches — it can only fail.

export const PROWLER_UNCOVERED_TYPE = "https://rampscan.dev/prowler-uncovered/v1" as const;

export const ProwlerUncoveredRow = z.strictObject({
  /** the indicator, mnemonic form — must resolve at the dataset pin */
  ksi: z.string().regex(/^KSI-[A-Z]{3}-[A-Z]{3}$/),
  /** the framework's own name for it, so a re-pin that renames a row fails here */
  name: z.string().min(1),
  /** the reviewer's line on why no cloud scanner sees this — the judgement */
  basis: z.string().min(1),
});
export type ProwlerUncoveredRow = z.infer<typeof ProwlerUncoveredRow>;

export const ProwlerUncovered = z.strictObject({
  _type: z.literal(PROWLER_UNCOVERED_TYPE),
  reviewed: z.string().min(1),
  /** the framework version and bytes this reading was made against */
  framework_version: z.string().min(1),
  framework_sha256: z.string().regex(/^[0-9a-f]{64}$/),
  rule: z.string().min(1),
  /** ascending by ksi, and equal to the computed uncovered set */
  rows: z.array(ProwlerUncoveredRow).min(1),
});
export type ProwlerUncovered = z.infer<typeof ProwlerUncovered>;
