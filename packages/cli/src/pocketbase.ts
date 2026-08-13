import { execFile, spawn, type ChildProcess } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync } from "node:fs";
import { chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { promisify } from "node:util";
import { PocketBaseAdmin, PROPOSALS_COLLECTION } from "@rampscan/projector";

const execFileAsync = promisify(execFile);

// PocketBase lifecycle for `rampscan serve` (plan M3 E1/E2): the vendored,
// pin-verified binary under console/pocketbase/bin, a superuser identity that
// belongs to the projector (generated once, stored 0600 next to the data
// dir), the console's auth surface (users with viewer/approver roles, demo
// accounts for the local prototype), and the proposals collection — the one
// console-writable surface, whose approved rows always land in the ledger
// before any register moves.

export const DEMO_USERS = [
  { email: "viewer@rampscan.local", role: "viewer" },
  { email: "approver@rampscan.local", role: "approver" },
] as const;
export const DEMO_PASSWORD = "rampscan-demo";

export interface PocketBaseHandle {
  url: string;
  child: ChildProcess;
  superuser: { email: string; password: string };
  admin: PocketBaseAdmin;
}

export interface StartPocketBaseOptions {
  binPath: string; // console/pocketbase/bin/pocketbase
  dataDir: string; // console/pocketbase/data
  port: number;
  log?: (line: string) => void;
}

async function loadOrCreateSuperuser(
  dataDir: string,
): Promise<{ email: string; password: string }> {
  const credPath = join(dataDir, ".rampscan-superuser.json");
  try {
    return JSON.parse(await readFile(credPath, "utf8"));
  } catch {
    const creds = {
      email: "projector@rampscan.local",
      password: randomBytes(18).toString("base64url"),
    };
    await mkdir(dataDir, { recursive: true });
    await writeFile(credPath, JSON.stringify(creds, null, 2), { flag: "wx" });
    await chmod(credPath, 0o600);
    return creds;
  }
}

export async function startPocketBase(options: StartPocketBaseOptions): Promise<PocketBaseHandle> {
  const log = options.log ?? (() => {});
  if (!existsSync(options.binPath)) {
    throw new Error(
      `PocketBase binary missing at ${options.binPath} — run \`pnpm fetch-pocketbase\` ` +
        `(downloads the pinned release and verifies its sha256; nothing is installed globally)`,
    );
  }

  const superuser = await loadOrCreateSuperuser(options.dataDir);
  // idempotent: creates on first run, resets the password to ours on later runs
  await execFileAsync(options.binPath, [
    "superuser", "upsert", superuser.email, superuser.password,
    "--dir", options.dataDir,
  ]);

  const url = `http://127.0.0.1:${options.port}`;
  const child = spawn(
    options.binPath,
    ["serve", `--http=127.0.0.1:${options.port}`, "--dir", options.dataDir],
    { stdio: ["ignore", "pipe", "pipe"] },
  );
  child.stderr?.on("data", (chunk: Buffer) => {
    const line = chunk.toString().trim();
    if (line) log(`pocketbase: ${line}`);
  });

  const admin = new PocketBaseAdmin(url);
  for (let i = 0; i < 100; i++) {
    if (child.exitCode !== null) {
      throw new Error(`pocketbase exited with code ${child.exitCode} before becoming healthy`);
    }
    if (await admin.health()) break;
    await new Promise((r) => setTimeout(r, 100));
  }
  if (!(await admin.health())) throw new Error("pocketbase did not become healthy in 10s");
  await admin.auth(superuser.email, superuser.password);
  log(`pocketbase ${url} up (data: ${options.dataDir})`);
  return { url, child, superuser, admin };
}

/** users.role (viewer|approver), demo accounts, and the proposals collection. */
export async function bootstrapConsole(pb: PocketBaseAdmin, log: (line: string) => void): Promise<void> {
  const users = (await pb.request("GET", "/api/collections/users")) as {
    fields: Array<{ name: string }>;
  };
  if (!users.fields.some((f) => f.name === "role")) {
    await pb.request("PATCH", "/api/collections/users", {
      fields: [
        ...users.fields,
        { name: "role", type: "select", maxSelect: 1, values: ["viewer", "approver"] },
      ],
    });
    log("users collection: added role field (viewer | approver)");
  }

  await pb.ensureCollection(PROPOSALS_COLLECTION);

  for (const user of DEMO_USERS) {
    try {
      await pb.create("users", {
        email: user.email,
        password: DEMO_PASSWORD,
        passwordConfirm: DEMO_PASSWORD,
        role: user.role,
        verified: true,
        emailVisibility: true,
      });
      log(`demo user created: ${user.email} (${user.role}) / password: ${DEMO_PASSWORD}`);
    } catch {
      // already exists — the demo accounts are stable across restarts
    }
  }
}
