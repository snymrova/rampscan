import { execFile } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { afterEach, describe, expect, it } from "vitest";
import { startPocketBase, type PocketBaseHandle } from "../src/pocketbase.js";

// #219: the superuser password is base64url, so one in 64 begins with "-".
// PocketBase's CLI read that as a flag, printed "unknown shorthand flag" and
// exited 0 without saving anyone — so serve came up with no superuser and the
// projector's auth 400'd. The smoke mints fresh credentials every run, which
// made console-smoke fail at random; a real `rampscan serve` that drew such a
// password persisted it and failed the same way on every start after.
// Gated on the vendored binary: run `pnpm fetch-pocketbase` to enable.

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const PB_BIN = join(ROOT, "console/pocketbase/bin/pocketbase");
const HAVE_PB = existsSync(PB_BIN);

const PORT = 8096; // test-only, away from serve (8090), the projector test (8097) and the smoke (8098)

let handle: PocketBaseHandle | undefined;
let dataDir: string | undefined;

afterEach(async () => {
  const child = handle?.child;
  handle = undefined;
  // wait for the port to be released, or the next test's health check reaches this one
  if (child && child.exitCode === null) {
    await new Promise((done) => {
      child.once("exit", done);
      child.kill();
    });
  }
  if (dataDir) await rm(dataDir, { recursive: true, force: true });
  dataDir = undefined;
});

async function withCredentials(password: string): Promise<string> {
  dataDir = await mkdtemp(join(tmpdir(), "rampscan-pb-su-"));
  await writeFile(
    join(dataDir, ".rampscan-superuser.json"),
    JSON.stringify({ email: "projector@rampscan.local", password }),
  );
  return dataDir;
}

describe.skipIf(!HAVE_PB)("startPocketBase's superuser (#219)", () => {
  it("authenticates when the stored password begins with a dash", async () => {
    const dir = await withCredentials("-Xk3a_b-cdefghijklmnopqr");
    handle = await startPocketBase({ binPath: PB_BIN, dataDir: dir, port: PORT });
    // auth happens inside startPocketBase; a collection read proves the token is a superuser's
    await expect(handle.admin.request("GET", "/api/collections/users")).resolves.toBeDefined();
  });

  it("refuses to start, naming PocketBase's own error, when the upsert saves no one", async () => {
    // a binary that exits 0 without saving is exactly what #219 was; stand one in
    const dir = await withCredentials("fine-password-123456");
    const fake = join(dir, "fake-pocketbase");
    await writeFile(fake, '#!/bin/sh\necho "Error: something PocketBase refused" >&2\nexit 0\n', {
      mode: 0o755,
    });
    await expect(startPocketBase({ binPath: fake, dataDir: dir, port: PORT })).rejects.toThrow(
      /superuser upsert.*something PocketBase refused/s,
    );
  });

  it("the vendored binary still exits 0 on a flag-parse error (why exit status is not trusted)", async () => {
    // pins the upstream behaviour the fix works around; if this starts failing,
    // PocketBase now exits non-zero and the output check is belt-and-braces
    const dir = await withCredentials("unused");
    const { stdout, stderr } = await promisify(execFile)(PB_BIN, [
      "superuser", "upsert", "projector@rampscan.local", "-Xflaglike", "--dir", dir,
    ]);
    expect(`${stdout}${stderr}`).toMatch(/unknown shorthand flag/);
  });
});
