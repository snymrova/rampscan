// The smoke's one entry point: prepare the scratch world, THEN start
// `rampscan serve` on it. One strictly-ordered command, because Playwright
// launches the webServer BEFORE global setup — a setup file that wipes
// e2e/.smoke would delete the very ledger a just-started serve is watching
// (the fs.watch dies with the directory, the re-fold sees an empty ledger,
// and the projection truncates to zero mid-test — found the hard way).
import { execFileSync, spawn } from "node:child_process";
import { existsSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const smokeDir = join(root, "e2e/.smoke");
const tsx = join(root, "node_modules/.bin/tsx");

/** flagship recipe (M4): reachable lodash CRITICAL with path src/index.js » lodash/merge */
const FLAGSHIP = "no-critical-reachable-advisories";

const PB_PORT = process.env.SMOKE_PB_PORT ?? "8098";
const WEB_PORT = process.env.SMOKE_WEB_PORT ?? "3098";

const pbBin = join(root, "console/pocketbase/bin/pocketbase");
if (!existsSync(pbBin)) {
  console.error(`PocketBase binary missing at ${pbBin} — run \`pnpm fetch-pocketbase\` first`);
  process.exit(1);
}

rmSync(smokeDir, { recursive: true, force: true });

// deterministic fixture repo (fixed timestamps/identity → stable SHAs)
execFileSync("node", [join(root, "fixtures/build-vulnerable-app.mjs")], {
  cwd: root,
  stdio: "inherit",
});

// a REAL scan — the board the smoke reads is a fold of this ledger, nothing canned
execFileSync(
  tsx,
  [
    "packages/cli/src/main.ts",
    "scan",
    "fixtures/vulnerable-app",
    "--ledger", "e2e/.smoke/ledger",
    "--keys", "e2e/.smoke/keys",
    "--out", "e2e/.smoke/out",
  ],
  { cwd: root, stdio: "inherit" },
);

// Fail here, legibly, rather than let the board tests fail confusingly: if
// the flagship recipe is not violated, the scan tools are missing or broken
// (they live in ~/.local/bin locally; `pnpm doctor` names them).
const result = JSON.parse(readFileSync(join(smokeDir, "out/scan-result.json"), "utf8"));
const flagship = result.recipes.find((r) => r.recipe_id === FLAGSHIP);
if (flagship?.verdict !== "violated") {
  console.error(
    `fixture scan did not violate ${FLAGSHIP} (got: ${flagship?.verdict ?? "no row"}) — ` +
      "the smoke needs syft + osv-scanner (plus gitleaks/grype for the other registers) " +
      "on PATH; run `pnpm doctor` (locally the tools live in ~/.local/bin)",
  );
  process.exit(1);
}

const serve = spawn(
  tsx,
  [
    "packages/cli/src/main.ts",
    "serve",
    "--ledger", "e2e/.smoke/ledger",
    "--keys", "e2e/.smoke/keys",
    "--out", "e2e/.smoke/out",
    "--pb-data", "e2e/.smoke/pb-data",
    "--pb-port", PB_PORT,
    "--web-port", WEB_PORT,
  ],
  { cwd: root, stdio: "inherit" },
);
serve.on("exit", (code, signal) => {
  // next dev stamps its distDir into next-env.d.ts; restore the committed
  // .next reference so a smoke run never leaves the working tree dirty
  const nextEnv = join(root, "console/web/next-env.d.ts");
  try {
    const stamped = readFileSync(nextEnv, "utf8");
    const restored = stamped.replace("./.next-smoke/types/routes.d.ts", "./.next/types/routes.d.ts");
    if (restored !== stamped) writeFileSync(nextEnv, restored);
  } catch {
    // best-effort — a missing file is not the smoke's problem
  }
  process.exit(signal ? 0 : (code ?? 1));
});
for (const sig of ["SIGINT", "SIGTERM"]) {
  process.on(sig, () => serve.kill(sig));
}
