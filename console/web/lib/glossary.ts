// The glossary (plan K1). Every page in this console is dense with vocabulary
// an operator never chose — KSI, DSSE, anchor, cadence, notApplicable — and a
// reader who cannot decode a column heading cannot audit what is under it.
//
// Three rules hold this honest:
//
//   1. A term with NO entry renders as plain text. Never a broken tooltip,
//      never an empty popover, and never a definition improvised at render
//      time from the term itself.
//   2. Definitions describe the SYSTEM, not the data on screen. Nothing here
//      may state a count, a verdict or a repository's condition — this file is
//      typed prose, and typed prose that made a claim about a repo would be
//      exactly the thing every other surface refuses to do.
//   3. One definition per term, reused everywhere. A word that means one thing
//      on the board and another on the evidence page is worse than an
//      undefined one.

export interface GlossaryEntry {
  /** the term as it should read in the tooltip's heading — canonical spelling */
  term: string;
  /** what it means, in operator English: one or two sentences, no jargon of its own */
  definition: string;
}

/**
 * Normalizes the many spellings one term arrives in. `not_affected`,
 * `not affected` and `Not Affected` are one entry; `notApplicable` and `n/a`
 * are one entry. camelCase splits on the case boundary so a term lifted
 * straight out of a record key (`notApplicable`) finds its entry without the
 * caller transcribing it.
 */
export function normalizeTerm(raw: string): string {
  return raw
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .toLowerCase()
    .replace(/[_\-/]+/g, " ")
    .replace(/[^a-z0-9 .]+/g, "")
    .replace(/\s+/g, " ")
    .trim();
}

const ENTRIES: GlossaryEntry[] = [
  {
    term: "KSI",
    definition:
      "Key Security Indicator — FedRAMP 20x's unit of security outcome, like KSI-SCR-MIT. One indicator is answered by evidence from several recipes at once.",
  },
  {
    term: "control",
    definition:
      "A NIST 800-53 requirement, like si-7.1 — the older and finer-grained framework each recipe also maps to, so one piece of evidence answers both frameworks at the same time.",
  },
  {
    term: "recipe",
    definition:
      "One machine-checkable question about a repository, defined in the catalog: what to collect and which assertions decide the answer. Every board row is one recipe against one repository.",
  },
  {
    term: "ledger",
    definition:
      "The append-only file of signed statements this system writes. Nothing in it is ever edited or deleted — a later statement supersedes an earlier one and both stay, so history cannot be quietly rewritten.",
  },
  {
    term: "projection",
    definition:
      "A read-only view folded out of the ledger. Every page here renders one, which is why nothing on screen is authoritative on its own: it can always be recomputed from the signed statements underneath.",
  },
  {
    term: "bundle",
    definition:
      "One signed statement about one recipe at one commit — the thing an auditor actually verifies. It carries the verdict, the assertions behind it, and the digest of every artifact it rests on.",
  },
  {
    term: "DSSE",
    definition:
      "Dead Simple Signing Envelope — the signature format wrapping every statement. Checking one needs the envelope, the public key and a SHA-256 implementation; it does not need rampscan to be installed or running.",
  },
  {
    term: "digest",
    definition:
      "A SHA-256 hash used as an address. The same bytes always hash to the same digest, so a digest that still matches is proof the bytes did not change.",
  },
  {
    term: "anchor",
    definition:
      "What a claim is pinned to. Evidence here is commit-anchored: it says something about the repository at one exact commit and deliberately says nothing about any other.",
  },
  {
    term: "anchor drift",
    definition:
      "The anchor moved on: the commit a bundle was made about is no longer the current one. The evidence is still true about its own commit — it has simply stopped describing today.",
  },
  {
    term: "evidenced",
    definition:
      "A recipe ran at the scanned commit and every assertion passed. It is a statement about that commit, not a promise about the next one.",
  },
  {
    term: "violated",
    definition:
      "A recipe ran and at least one assertion failed. This is a fact about the repository — not a tooling problem, and not a warning that can be turned down.",
  },
  {
    term: "unevidenced",
    definition:
      "Nothing has answered this cell: no collector ran it, or what ran could not answer. It is the honest default — an empty row is never counted as a pass.",
  },
  {
    term: "notApplicable",
    definition:
      "Scoped out by a recorded decision — one person proposed that this recipe does not apply to this repository and a second approved it. The signed justification stays on the row forever.",
  },
  {
    term: "MVX window",
    definition:
      "Minimum viable expiry — how long a piece of evidence counts as fresh before its cadence has to refresh it. Past the window the evidence is not wrong, it is stale.",
  },
  {
    term: "not_affected",
    definition:
      "A vulnerability exists in a component, but nothing in this repository can reach the affected code, so it cannot be exploited here. Claimed only when the code graph shows no path — never assumed.",
  },
  {
    term: "two-key write",
    definition:
      "Nothing is scoped out on one person's say-so: a proposal from one account and an approval from a different one, both signed and recorded, before any cell moves.",
  },
  {
    term: "collector",
    definition:
      "The part of rampscan that runs one tool and turns its raw output into observations — syft, semgrep, checkov and so on. A single collector can evidence several recipes.",
  },
  {
    term: "cadence",
    definition:
      "How often a recipe is meant to be re-evidenced: daily, weekly, quarterly. Missing the cadence does not make the evidence wrong, it makes it old.",
  },
  {
    term: "scan run",
    definition:
      "The signed record of one scan: which collectors were dispatched, how each tool resolved, how long each took, what each produced, and what it could not do and why.",
  },
  {
    term: "artifact",
    definition:
      "A file a tool produced during a scan — an inventory, a results document. Bundles attest artifacts by digest, so any of them can be re-checked byte for byte later.",
  },
  {
    term: "assertion",
    definition:
      "One machine-checked clause of a recipe: a field, a comparison, a value. A verdict is what the assertions came out as — never a judgement someone typed.",
  },
];

/**
 * Extra spellings that mean an existing entry. Written out rather than guessed
 * at, because a near-miss ("scan runs" → "scan run") is cheap to list and an
 * automatic stemmer would eventually match two terms that are not the same
 * thing.
 */
const ALIASES: Record<string, string> = {
  "key security indicator": "KSI",
  ksis: "KSI",
  controls: "control",
  "nist control": "control",
  recipes: "recipe",
  "n a": "notApplicable", // "n/a" after normalization
  "not applicable": "notApplicable",
  scoped: "notApplicable",
  "not affected": "not_affected",
  "two key": "two-key write",
  "two key write": "two-key write",
  mvx: "MVX window",
  "minimum viable expiry": "MVX window",
  drift: "anchor drift",
  "commit anchor": "anchor",
  "commit anchored": "anchor",
  envelope: "DSSE",
  sha256: "digest",
  "scan runs": "scan run",
  run: "scan run",
  artifacts: "artifact",
  assertions: "assertion",
  collectors: "collector",
  bundles: "bundle",
};

const BY_TERM = new Map<string, GlossaryEntry>(
  ENTRIES.map((entry) => [normalizeTerm(entry.term), entry]),
);

/**
 * The entry for a term, or null when there is none — the caller renders plain
 * text on null. Never throws and never invents: an unknown word simply is not
 * in the glossary yet, which is a gap to fill in this file rather than
 * something for a component to paper over.
 */
export function lookupTerm(raw: string): GlossaryEntry | null {
  const key = normalizeTerm(raw);
  if (key === "") return null;
  const direct = BY_TERM.get(key);
  if (direct) return direct;
  const alias = ALIASES[key];
  if (alias) return BY_TERM.get(normalizeTerm(alias)) ?? null;
  return null;
}

/** Every defined term, for the tests that pin coverage and for a glossary view. */
export function glossaryEntries(): GlossaryEntry[] {
  return [...ENTRIES].sort((a, b) => a.term.localeCompare(b.term));
}
