import { cp, mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";

/**
 * A writable copy of a fixture CHECKOUT, for the cases that need the repository
 * broken in exactly one way — which a temp copy can be and a committed fixture
 * cannot.
 *
 * `.git` is excluded, and that is a flake fix rather than a micro-optimisation.
 * The generated fixtures carry a nested `.git` of 51 files that is 372K of
 * `vulnerable-app`'s 460K, and `fs.cp` over it measures a 346ms median with a
 * 2.7s TAIL on an idle machine, against 137ms median / 173ms max without it.
 * Thirteen copies in one file, any of which can hit that tail, under parallel
 * suite load, against vitest's 5s default, is how `documents.test.ts` came to
 * fail eight tests on one run of the suite and pass on the next. The collectors
 * themselves are not the cost and never were: `documents` measures 7.5ms and
 * `repo-facts` 10.3ms on the same fixture, so the wave-1 note asking whether
 * this was a product question as well as a test one is answered — it was a test
 * one.
 *
 * Excluding it is also the more honest copy. No collector on this plane reads
 * git history metadata — the batch-1 audit established that by cutting the
 * currency limb from AC-01, RA-05 (11) and SA-05 — so a copy carrying history
 * carries something no assertion here can see, and the tests that use this
 * helper break the WORKING TREE: a document deleted, a document emptied, a
 * declaration rewritten. A test that needs the history belongs to a collector
 * that reads one, and there is not one yet.
 */
export async function copyCheckout(fixtureRoot: string, label: string): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), `rampscan-${label}-`));
  const root = join(dir, "repo");
  await cp(fixtureRoot, root, { recursive: true, filter: (src) => basename(src) !== ".git" });
  return root;
}
