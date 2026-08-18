// Builds the two fixture repos exactly once per test run. Individual test
// files must NOT rebuild them — each builder rm -rf's its fixture, and parallel
// test files racing that teardown produce flaky reads.
//
// bare-app joined this list with N0: the vacuous-pass check (catalog-bare.e2e)
// needs a repository that LACKS things, and the property this repo has already
// written down twice — anything reachable only from an empty row is testable
// only on bare-app — now holds for the catalog itself and not just the
// console's affordances.
//
// The temp root joined it with N1b″, for the second flake this file has been
// the right place to fix. Twenty-nine test files call `mkdtemp` at about eighty
// sites and NOT ONE of them removes what it made: a single day of running this
// suite had left 3,035 `rampscan-*` directories and 615 MB in the system temp
// directory, and every `mkdtemp` after them was creating an entry in a
// directory holding thousands. Cleaning up at eighty call sites is eighty
// chances to forget; `os.tmpdir()` reads `TMPDIR` on every call, so one root
// per run — created here, inherited by every forked worker, removed when the
// run ends — fixes all of them at once and cannot be forgotten by the next
// test that needs a scratch directory.
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export default function setup() {
  const root = dirname(dirname(fileURLToPath(import.meta.url)));
  execFileSync("node", [join(root, "fixtures/build-vulnerable-app.mjs")], { stdio: "pipe" });
  execFileSync("node", [join(root, "fixtures/build-bare-app.mjs")], { stdio: "pipe" });

  // Short on purpose: a unix socket path is capped near 104 bytes and the
  // daemon e2e binds one under the temp root, so this prefix stays as close to
  // the system default as a per-run directory can be.
  const runTmp = mkdtempSync(join(tmpdir(), "rs-run-"));
  process.env.TMPDIR = runTmp;
  return () => {
    rmSync(runTmp, { recursive: true, force: true });
  };
}
