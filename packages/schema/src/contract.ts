import { z } from "zod";

// The Architecture Contract (plan L1): the `contract` block of the scanned
// repo's rampscan.config.json. A repo DECLARES architecture intent here — the
// routes that must reach an auth check, the modules only named importers may
// touch — and the contract gate checks the declaration against the code graph
// and signs the result. This is the normative layer: rampscan attests
// architecture rules the same way it attests security rules.
//
// Two deliberate hard edges, both aimed at the same failure — a typo that
// silently waives a rule:
//
//   1. An unknown rule `kind` is a CONFIG ERROR, never a skip. The union below
//      is closed, so `"kind": "boundry"` refuses to parse instead of parsing
//      to nothing; the collector surfaces the refusal loudly and both contract
//      recipes read unevidenced with the refusal as their reason.
//   2. Rule objects are strict. A misspelled field (`allowedImporter`) would
//      change what the rule means while looking like it declared something —
//      strict parsing makes it a stated error instead.
//
// `description` is the rule's plain-language seed, written by the repo that
// declares the rule. It is AUTHORED prose and is held to the same rule as K1's
// paragraphs and the glossary: it may say what the rule intends, and it may
// not state a verdict — a description that says "violated" would put a typed
// verdict on every surface that renders the rule. Enforced structurally here,
// not just by a CI grep, because this prose is written outside this
// repository.

const VERDICT_WORDS = /\b(violated|evidenced|unevidenced|notApplicable)\b/i;

const ruleDescription = z
  .string()
  .min(1)
  .refine((text) => !VERDICT_WORDS.test(text), {
    message:
      "a rule description may say what the rule intends; it may not state a verdict (violated/evidenced/unevidenced/notApplicable are computed, never typed)",
  });

/**
 * "These routes must reach an authentication check." Promotes the existing
 * route-auth heuristic to declared intent: `route-auth-coverage` observes
 * every route against a name pattern; a declared rule scopes which routes
 * MUST pass, and a breach of it is a violation of the repo's own statement.
 */
export const RouteAuthRule = z
  .object({
    kind: z.literal("route-auth"),
    /** unique within the contract; how the rule is named everywhere it renders */
    id: z.string().min(1),
    /**
     * Glob over route paths ("/admin/*", "/*"): `*` matches within one path
     * segment, `**` crosses segments. Matched against the path the graph
     * recorded for each declared route, method-independent.
     */
    routes: z.string().min(1),
    description: ruleDescription,
  })
  .strict();
export type RouteAuthRule = z.infer<typeof RouteAuthRule>;

/**
 * "Only these importers may import this module." The guarded module and the
 * allow-list are repo-relative path prefixes; a file is inside one when its
 * path equals the prefix, sits under it as a directory, or is the prefix plus
 * an extension ("src/billing" guards src/billing.js and src/billing/*).
 */
export const BoundaryRule = z
  .object({
    kind: z.literal("boundary"),
    id: z.string().min(1),
    /** the guarded module, as a repo-relative path prefix */
    module: z.string().min(1),
    /** path prefixes whose files may import the module; empty = nobody may */
    allowedImporters: z.array(z.string().min(1)),
    description: ruleDescription,
  })
  .strict();
export type BoundaryRule = z.infer<typeof BoundaryRule>;

/** exactly two rule kinds — a third kind is a schema change, not a config value */
export const ContractRule = z.discriminatedUnion("kind", [RouteAuthRule, BoundaryRule]);
export type ContractRule = z.infer<typeof ContractRule>;

export const ContractConfig = z
  .object({
    rules: z.array(ContractRule),
  })
  .strict()
  .refine(
    (contract) => new Set(contract.rules.map((r) => r.id)).size === contract.rules.length,
    { message: "contract rule ids must be unique" },
  );
export type ContractConfig = z.infer<typeof ContractConfig>;
