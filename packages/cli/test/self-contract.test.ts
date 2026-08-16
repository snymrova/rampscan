import { readFile, stat } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { ContractConfig } from "@rampscan/schema";

// L3b — rampscan declares its own architecture contract, and this test holds the
// declaration to the same standard the gate holds a customer's.
//
// The LIVE check is `rampscan check .` (L3a) and `rampscan scan .` (the self
// scan): both walk the real graph and are what proved these two rules hold. What
// a fast unit test can add is the part that would otherwise rot silently — a rule
// whose module path no longer exists still PARSES, and L1 makes it violate rather
// than pass, which means a stale rule turns into a red board row nobody can fix
// by editing code. Catching it here names the file to edit instead.
//
// Dogfooding this contract is also what found the two real bugs L3b is worth:
//   1. the gate CRASHED on this repository — phantom file nodes (unresolved
//      imports) have no `path`, and the boundary walk read `path` unguarded;
//   2. `module: "packages/signer/src"` flagged the package's OWN tests as
//      outside importers, because a package's tests live beside `src/` and not
//      inside it. A boundary in a monorepo names the PACKAGE.

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "../../..");

async function exists(rel: string): Promise<boolean> {
  try {
    await stat(join(repoRoot, rel));
    return true;
  } catch {
    return false;
  }
}

describe("rampscan's own architecture contract", () => {
  it("parses under the real schema — the same refusal a scanned repo gets", async () => {
    const raw = JSON.parse(await readFile(join(repoRoot, "rampscan.config.json"), "utf8")) as {
      contract?: unknown;
    };
    expect(raw.contract).toBeDefined();
    const parsed = ContractConfig.parse(raw.contract);
    expect(parsed.rules.length).toBeGreaterThan(0);
  });

  it("declares only rule kinds this repo's graph can actually check", async () => {
    const raw = JSON.parse(await readFile(join(repoRoot, "rampscan.config.json"), "utf8")) as {
      contract: unknown;
    };
    const { rules } = ContractConfig.parse(raw.contract);
    // No route-auth rule, deliberately: this repo's HTTP surface is the
    // console's Next.js route handlers, which the extractor does not detect as
    // route nodes (it detects express-style `app.get(...)`). L1 makes a rule
    // that matches nothing VIOLATE — correctly — so declaring one here would
    // buy a permanent red row that says nothing about this repository's
    // architecture. The absence is a decision, and this test is where it is
    // written down.
    expect(rules.every((r) => r.kind === "boundary")).toBe(true);
  });

  it("guards modules that exist — a rule guarding nothing must fail here, not on the board", async () => {
    const raw = JSON.parse(await readFile(join(repoRoot, "rampscan.config.json"), "utf8")) as {
      contract: unknown;
    };
    const { rules } = ContractConfig.parse(raw.contract);
    for (const rule of rules) {
      if (rule.kind !== "boundary") continue;
      expect(await exists(rule.module), `declared module ${rule.module} is gone`).toBe(true);
      for (const importer of rule.allowedImporters) {
        expect(await exists(importer), `allowed importer ${importer} is gone`).toBe(true);
      }
    }
  });
});
