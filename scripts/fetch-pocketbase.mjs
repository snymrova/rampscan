#!/usr/bin/env node
// Fetch the pinned PocketBase binary into console/pocketbase/bin/ (plan M3
// E1). The pin — version + per-platform sha256 from the release's official
// checksums.txt — lives in console/pocketbase/version.json; this script
// downloads the matching zip, verifies the hash BEFORE unzipping, and
// extracts the single `pocketbase` binary. Nothing global is installed.
//
// Usage: node scripts/fetch-pocketbase.mjs   (or: pnpm fetch-pocketbase)

import { createHash } from "node:crypto";
import { chmod, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const PB_DIR = join(ROOT, "console/pocketbase");
const BIN = join(PB_DIR, "bin/pocketbase");

const pin = JSON.parse(await readFile(join(PB_DIR, "version.json"), "utf8"));

const platform = { linux: "linux", darwin: "darwin" }[process.platform];
const arch = { x64: "amd64", arm64: "arm64" }[process.arch];
if (!platform || !arch) {
  console.error(`unsupported platform ${process.platform}/${process.arch}`);
  process.exit(1);
}
const key = `${platform}_${arch}`;
const expected = pin.sha256[key];
if (!expected) {
  console.error(`no pinned sha256 for ${key} in version.json`);
  process.exit(1);
}

if (existsSync(BIN)) {
  try {
    const current = execFileSync(BIN, ["--version"], { encoding: "utf8" }).trim();
    if (current.includes(pin.version)) {
      console.log(`pocketbase ${pin.version} already present at ${BIN}`);
      process.exit(0);
    }
    console.log(`replacing ${current} with pinned ${pin.version}`);
  } catch {
    // unreadable/broken binary — refetch
  }
}

const name = `pocketbase_${pin.version}_${key}.zip`;
const url = `https://github.com/pocketbase/pocketbase/releases/download/v${pin.version}/${name}`;
console.log(`fetching ${url}`);
const res = await fetch(url, { redirect: "follow" });
if (!res.ok) {
  console.error(`download failed: HTTP ${res.status}`);
  process.exit(1);
}
const zip = Buffer.from(await res.arrayBuffer());

const actual = createHash("sha256").update(zip).digest("hex");
if (actual !== expected) {
  console.error(`sha256 MISMATCH for ${name}:\n  expected ${expected}\n  got      ${actual}\nrefusing to unpack.`);
  process.exit(1);
}
console.log(`sha256 verified: ${actual}`);

await mkdir(join(PB_DIR, "bin"), { recursive: true });
const zipPath = join(PB_DIR, "bin", name);
await writeFile(zipPath, zip);
try {
  execFileSync("unzip", ["-o", zipPath, "pocketbase", "-d", join(PB_DIR, "bin")], {
    stdio: "pipe",
  });
} finally {
  await rm(zipPath, { force: true });
}
await chmod(BIN, 0o755);
console.log(`pocketbase ${pin.version} → ${BIN}`);
