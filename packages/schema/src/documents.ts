import { z } from "zod";
import { declaredDescription } from "./contract.js";

// The declared documents block (plan N1b, wave 1): the `documents` array of the
// scanned repo's rampscan.config.json. A repo NAMES the governing documents it
// keeps under version control — where each one lives and which subject it
// answers — and the `documents` collector checks the declaration against the
// checkout and signs the result.
//
// Same normative shape as the architecture contract, for the same reason: a
// document-existence check with no declaration behind it either invents a
// filename convention nobody agreed to, or passes on any repository that
// happens to contain a markdown file. The declaration is what makes an
// evidenced row mean something and a missing file a violation rather than a
// silence.
//
// What this can and cannot carry is settled here rather than left to the
// recipes: the collector reads a path, a size and a content hash. It does not
// read the document. So a declaration is the repo's claim about what a file IS,
// and the evidence is that the file the repo named exists, is not empty, and
// has not moved since it was attested — which is the existence-and-integrity
// half of a documentation control and never the adequacy half. Both
// adjudication records that ride this (AC-01, SA-05) say exactly that in their
// remainders, and neither recipe may claim more than they concede.
//
// `kind` is a CLOSED enum, and narrowly named on purpose. A generic "policy"
// value would let a repo declare its incident-response policy and collect
// AC-01 evidence for it — the over-claim the batch-1 audit caught twice. A
// third subject is therefore a schema change, a new recipe and a new
// adjudication link, not a string somebody types into a config file.

export const DocumentKind = z.enum(["access-control-policy", "system-documentation"]);
export type DocumentKind = z.infer<typeof DocumentKind>;

/**
 * One declared document. Strict, like the contract rules and for the same
 * reason: a misspelled field (`paths`, `type`) would change what the
 * declaration means while looking like it declared something.
 */
export const DeclaredDocument = z
  .object({
    /** unique within the block; how the document is named everywhere it renders */
    id: z.string().min(1),
    kind: DocumentKind,
    /** repo-relative path, no globs — a declaration names a file, not a pattern */
    path: z.string().min(1),
    description: declaredDescription,
  })
  .strict();
export type DeclaredDocument = z.infer<typeof DeclaredDocument>;

/**
 * The block itself: a plain array, unlike `contract`'s `{ rules: [...] }`.
 * There is nothing else to configure here — no walk to tune, no approximation
 * direction to state — and an object wrapper with one key would be a slot
 * reserved for a decision nobody has taken.
 */
export const DocumentsConfig = z
  .array(DeclaredDocument)
  .refine((docs) => new Set(docs.map((d) => d.id)).size === docs.length, {
    message: "declared document ids must be unique",
  })
  .refine((docs) => new Set(docs.map((d) => d.path)).size === docs.length, {
    message:
      "two declarations name the same path — one file cannot answer for two documents, and a duplicate is a copy-paste that would count one artifact twice",
  });
export type DocumentsConfig = z.infer<typeof DocumentsConfig>;
