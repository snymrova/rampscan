// Builds fixtures/vulnerable-app exactly once per test run. Individual test
// files must NOT rebuild it — the builder rm -rf's the fixture, and parallel
// test files racing that teardown produce flaky reads.
import { execFileSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export default function setup() {
  const root = dirname(dirname(fileURLToPath(import.meta.url)));
  execFileSync("node", [join(root, "fixtures/build-vulnerable-app.mjs")], { stdio: "pipe" });
}
