import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";

// K1 — the glossary, tested through the console's own copy in the standard
// twin posture (loaded by path: console/web is not a workspace package, and a
// static import would emit compiled duplicates into console/web/lib — I3e's
// lesson).
//
// The load-bearing behaviour is the NEGATIVE one. `lookupTerm` returning null
// is what makes the Term component render bare text, so every way a caller can
// hand it something it does not know — an empty string, a word nobody defined,
// a value read straight out of a record — has to come back null rather than
// throw or invent. A glossary that guessed would put a confident wrong
// definition under a word, which is worse than leaving the word undefined.

interface GlossaryEntry {
  term: string;
  definition: string;
}

interface GlossaryModule {
  normalizeTerm(raw: string): string;
  lookupTerm(raw: string): GlossaryEntry | null;
  glossaryEntries(): GlossaryEntry[];
}

const consoleLib = join(
  dirname(fileURLToPath(import.meta.url)),
  "../../../console/web/lib/glossary.ts",
);

let M: GlossaryModule;

beforeAll(async () => {
  M = (await import(consoleLib)) as GlossaryModule;
});

describe("normalizeTerm: one entry, many spellings", () => {
  it("splits camelCase so a term lifted out of a record key finds its entry", () => {
    // `row.state` is literally "notApplicable" — the caller should not have to
    // transcribe it into prose to look it up
    expect(M.normalizeTerm("notApplicable")).toBe("not applicable");
    expect(M.normalizeTerm("not_affected")).toBe("not affected");
  });

  it("folds case, underscores, hyphens and slashes to one shape", () => {
    const shapes = ["two-key write", "TWO_KEY WRITE", "Two-Key  Write", "two/key/write"];
    const [first, ...rest] = shapes.map((s) => M.normalizeTerm(s));
    for (const shape of rest) expect(shape).toBe(first);
  });

  it("drops punctuation that is not part of the term", () => {
    expect(M.normalizeTerm("n/a")).toBe("n a");
    expect(M.normalizeTerm("  KSI:  ")).toBe("ksi");
  });
});

describe("lookupTerm: an unknown term is null, never a guess", () => {
  it("returns null for a word with no entry", () => {
    expect(M.lookupTerm("kubernetes")).toBeNull();
    expect(M.lookupTerm("Repo")).toBeNull();
  });

  it("returns null for nothing at all rather than throwing", () => {
    // the component passes children through when they are not a string, so
    // "" is a real call site, not a hypothetical
    expect(M.lookupTerm("")).toBeNull();
    expect(M.lookupTerm("   ")).toBeNull();
    expect(M.lookupTerm("!!!")).toBeNull();
  });

  it("does not stem or fuzzy-match its way to a wrong entry", () => {
    // "controller" is not "control", and a glossary that thought so would put
    // a NIST control's definition under a piece of application code
    expect(M.lookupTerm("controller")).toBeNull();
    expect(M.lookupTerm("anchoring")).toBeNull();
    expect(M.lookupTerm("recipient")).toBeNull();
  });
});

describe("lookupTerm: the vocabulary the console actually renders", () => {
  it("resolves each of the four register states, including the camelCase one", () => {
    for (const state of ["evidenced", "violated", "unevidenced", "notApplicable"]) {
      const entry = M.lookupTerm(state);
      expect(entry, state).not.toBeNull();
      expect(entry!.definition.length, state).toBeGreaterThan(40);
    }
  });

  it("resolves the pill's visible text as well as its record value", () => {
    // the notApplicable pill READS "n/a" — the reader hovers what they see
    expect(M.lookupTerm("n/a")?.term).toBe("notApplicable");
    expect(M.lookupTerm("notApplicable")?.term).toBe("notApplicable");
  });

  it("resolves the aliases the pages hand it", () => {
    expect(M.lookupTerm("KSIs")?.term).toBe("KSI");
    expect(M.lookupTerm("Controls")?.term).toBe("control");
    expect(M.lookupTerm("MVX window")?.term).toBe("MVX window");
    expect(M.lookupTerm("mvx")?.term).toBe("MVX window");
    expect(M.lookupTerm("not affected")?.term).toBe("not_affected");
    expect(M.lookupTerm("two-key")?.term).toBe("two-key write");
  });
});

describe("the definitions themselves", () => {
  it("every entry is a real definition, not a restatement of the term", () => {
    for (const entry of M.glossaryEntries()) {
      expect(entry.definition.length, entry.term).toBeGreaterThan(60);
      expect(entry.definition.trim(), entry.term).toBe(entry.definition);
      expect(entry.definition, entry.term).toMatch(/[.?]$/);
      // a definition whose first clause is the term itself explains nothing
      expect(
        entry.definition.toLowerCase().startsWith(`${entry.term.toLowerCase()} is`),
        `${entry.term} defines itself`,
      ).toBe(false);
    }
  });

  it("no definition states a fact about any repository or a count of anything", () => {
    // Same rule the recipes' prose is held to: this file is typed English, and
    // typed English that made a claim about a scan would be the one thing
    // every computed surface in this console refuses to do.
    for (const entry of M.glossaryEntries()) {
      expect(entry.definition, entry.term).not.toMatch(
        /\b\d+\s+(findings?|violations?|recipes?|repositor(y|ies))\b/i,
      );
      expect(entry.definition, entry.term).not.toMatch(/\bcurrently\b/i);
    }
  });

  it("every term resolves through its own canonical spelling", () => {
    for (const entry of M.glossaryEntries()) {
      expect(M.lookupTerm(entry.term)?.term, entry.term).toBe(entry.term);
    }
  });

  it("no two entries collapse onto the same normalized key", () => {
    const keys = M.glossaryEntries().map((e) => M.normalizeTerm(e.term));
    expect(new Set(keys).size).toBe(keys.length);
  });
});
