import { z } from "zod";

// The shared finding schema — code-graph doc §5, extended with ksi_ids /
// control_ids so a finding can name what it implicates. Every collector —
// a file check, a wrapped scanner, later a model — emits this shape.

export const EvidenceItem = z.object({
  kind: z.enum(["command", "file", "counterexample", "trace", "screenshot"]),
  // command evidence: the invocation and what it returned
  command: z.string().optional(),
  exitCode: z.number().int().optional(),
  output: z.string().optional(),
  // file evidence: a path within the scanned workspace
  path: z.string().optional(),
  note: z.string().optional(),
});
export type EvidenceItem = z.infer<typeof EvidenceItem>;

export const FindingAnchor = z.object({
  node: z.string(), // graph node id; pre-graph (M1–M3) this is a repo-relative path
  span: z.tuple([z.number().int(), z.number().int()]).optional(),
  contentHash: z.string(), // what it was about, so drift is detectable
});
export type FindingAnchor = z.infer<typeof FindingAnchor>;

export const Finding = z.object({
  id: z.string(), // stable across runs: hash(anchor + variable + signature)
  variable: z.string(), // "secrets" | "advisories" | "sbom" | "repo-facts" | ...
  anchor: FindingAnchor,
  severity: z.enum(["blocker", "high", "medium", "low", "info"]),
  confidence: z.number().min(0).max(1), // tier 1 is 1.0 and says so
  verdict: z.enum(["CONFIRMED", "PLAUSIBLE"]).optional(), // tier 3 only; absent = deterministic
  summary: z.string().min(1),
  failureScenario: z.string().min(1), // no scenario, no finding
  evidence: z.array(EvidenceItem),
  reproduce: z.string(), // the exact command a human can paste
  fix: z
    .object({ patch: z.string(), verifiedBy: z.array(z.string()) })
    .optional(),
  provenance: z.object({
    analyzer: z.string(),
    version: z.string(), // tool version — participates in cache keys and bundles
    runId: z.string(),
    costTokens: z.number().int().optional(),
  }),
  lifecycle: z.enum(["new", "persisting", "fixed", "suppressed"]),
  suppression: z
    .object({
      reason: z.string().min(1), // never a bare ignore
      by: z.string(),
      until: z.string().optional(),
    })
    .optional(),
  // rampscan extension: what this finding implicates in the catalog
  ksi_ids: z.array(z.string()),
  control_ids: z.array(z.string()),
});
export type Finding = z.infer<typeof Finding>;
