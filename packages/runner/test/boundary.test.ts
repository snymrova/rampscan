import { readFile, readdir } from "node:fs/promises";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

// T3-5 (docs/PLAN-CLOUD-RUNNER.md, #180): ground rule 1, enforced by a
// test and not by a sentence. The appliance never holds an AWS credential
// or makes an AWS call: no package but the runner may spawn `aws`, declare
// an AWS SDK, or read an AWS_* variable. And the runner may not sign: no
// value import of a rampscan package, no runtime dependency at all — the
// runner has an AWS role and no ledger key; the appliance the reverse.

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");

async function walk(dir: string, out: string[] = []): Promise<string[]> {
  for (const e of await readdir(dir, { withFileTypes: true })) {
    if (e.name === "node_modules" || e.name === "dist" || e.name === ".next") continue;
    const p = join(dir, e.name);
    if (e.isDirectory()) await walk(p, out);
    else if (/\.(ts|tsx|mts|mjs|js)$/.test(e.name)) out.push(p);
  }
  return out;
}

async function sourcesOutsideRunner(): Promise<string[]> {
  const files: string[] = [];
  for (const pkg of await readdir(join(REPO_ROOT, "packages"))) {
    if (pkg === "runner") continue;
    files.push(...(await walk(join(REPO_ROOT, "packages", pkg, "src"))));
  }
  files.push(...(await walk(join(REPO_ROOT, "console", "web", "lib"))));
  files.push(...(await walk(join(REPO_ROOT, "console", "web", "app"))));
  return files;
}

describe("T3-5 — the boundary: the appliance touches no AWS, the runner signs nothing (#180)", () => {
  it("no package but the runner spawns aws or reads an AWS_* variable", async () => {
    const offenders: string[] = [];
    for (const f of await sourcesOutsideRunner()) {
      const src = await readFile(f, "utf8");
      if (/\b(spawn|spawnSync|exec|execSync|execFile|execFileSync)\s*\(\s*["'`]aws\b/.test(src)) offenders.push(`${relative(REPO_ROOT, f)}: spawns aws`);
      if (/process\.env(?:\.|\[["'])AWS_/.test(src)) offenders.push(`${relative(REPO_ROOT, f)}: reads AWS_*`);
    }
    expect(offenders).toEqual([]);
  });

  it("no package declares an AWS SDK — the runner included, which declares nothing at all", async () => {
    const offenders: string[] = [];
    const roots = [...(await readdir(join(REPO_ROOT, "packages"))).map((p) => join("packages", p)), "console/web", "."];
    for (const r of roots) {
      const pkg = JSON.parse(await readFile(join(REPO_ROOT, r, "package.json"), "utf8")) as Record<string, Record<string, string> | undefined>;
      for (const field of ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"]) {
        for (const name of Object.keys(pkg[field] ?? {})) {
          if (/^(@aws-sdk\/|aws-sdk$|@aws-cdk\/|aws-cdk)/.test(name)) offenders.push(`${r}: ${field} ${name}`);
        }
      }
    }
    expect(offenders).toEqual([]);
    const runner = JSON.parse(await readFile(join(REPO_ROOT, "packages/runner/package.json"), "utf8")) as { dependencies?: Record<string, string> };
    expect(runner.dependencies ?? {}).toEqual({});
  });

  it("the runner imports no rampscan package by value — types only, erased at build — and nothing that can sign", async () => {
    const offenders: string[] = [];
    for (const f of await walk(join(REPO_ROOT, "packages/runner/src"))) {
      const src = await readFile(f, "utf8");
      for (const m of src.matchAll(/^import\s+(?!type\b)[^;]*?from\s+["']([^"']+)["']/gm)) {
        const spec = m[1]!;
        if (spec.startsWith("@rampscan/")) offenders.push(`${relative(REPO_ROOT, f)}: value import of ${spec}`);
        if (!spec.startsWith("node:") && !spec.startsWith("./") && !spec.startsWith("../")) offenders.push(`${relative(REPO_ROOT, f)}: third-party import ${spec}`);
      }
      if (/@rampscan\/(ledger|signer|projector|cli|core)/.test(src)) offenders.push(`${relative(REPO_ROOT, f)}: mentions a package that can sign or fold`);
    }
    expect(offenders).toEqual([]);
  });
});
