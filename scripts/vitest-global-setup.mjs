// Builds the two fixture repos exactly once per test run. Individual test
// files must NOT rebuild them — each builder rm -rf's its fixture, and parallel
// test files racing that teardown produce flaky reads.
//
// bare-app joined this list with N0: the vacuous-pass check (catalog-bare.e2e)
// needs a repository that LACKS things, and the property this repo has already
// written down twice — anything reachable only from an empty row is testable
// only on bare-app — now holds for the catalog itself and not just the
// console's affordances.
import { execFileSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export default function setup() {
  const root = dirname(dirname(fileURLToPath(import.meta.url)));
  execFileSync("node", [join(root, "fixtures/build-vulnerable-app.mjs")], { stdio: "pipe" });
  execFileSync("node", [join(root, "fixtures/build-bare-app.mjs")], { stdio: "pipe" });
}
