import { watch } from "node:fs";
import { existsSync } from "node:fs";
import { mkdir } from "node:fs/promises";
import { join } from "node:path";
import { spawn, type ChildProcess } from "node:child_process";
import {
  DAEMON_EVENTS_COLLECTION,
  DAEMON_STATUS_COLLECTION,
  createProjector,
  writeProjectionPocketBase,
} from "@rampscan/projector";
import type { ProjectionSettings } from "@rampscan/projector";
import { createLocalLedger } from "@rampscan/ledger";
import type { CertClass } from "@rampscan/core";
import { windowMsFor } from "@rampscan/scheduler";
import { DAEMON_STATUS_FILE } from "./daemon.js";
import { mirrorDaemonStatus, tailDaemonEvents } from "./events.js";
import { loadRecipes } from "./recipes.js";
import { DEMO_PASSWORD, DEMO_USERS, bootstrapConsole, startPocketBase } from "./pocketbase.js";

// `rampscan serve` (plan M3 E2): PocketBase + the Next.js console, locally.
// The wiring enforces the architecture instead of trusting it:
//
//   ledger ──fold──► projector ──writes──► PocketBase ──realtime──► console
//      ▲                                                              │
//      └────────── signed writes (scan CLI, approve route) ◄──────────┘
//
// The console never writes a register. Its one write surface is the
// proposals collection; approving a proposal appends a signed scoping event
// to the LEDGER, and the ledger watcher below re-folds — the register moves
// because the record moved. Kill the projection any time: `rampscan rebuild`
// restores it from the ledger and proves the equality.

export interface ServeOptions {
  repoRoot: string;
  ledgerDir: string;
  keysDir: string;
  recipesDir: string;
  datasetDir: string;
  datasetPin: string;
  /** scan/daemon output dir — serve tails outDir/daemon-events.jsonl into the console */
  outDir: string;
  certClass: CertClass;
  pbPort: number;
  webPort: number;
  /** spawn the Next.js dev server (disable for headless smoke tests) */
  web: boolean;
  log?: (line: string) => void;
}

export async function serve(options: ServeOptions): Promise<void> {
  const log = options.log ?? (() => {});
  const pbDir = join(options.repoRoot, "console/pocketbase");
  const webDir = join(options.repoRoot, "console/web");

  const pb = await startPocketBase({
    binPath: join(pbDir, "bin/pocketbase"),
    dataDir: join(pbDir, "data"),
    port: options.pbPort,
    log,
  });
  await bootstrapConsole(pb.admin, log);

  const recipes = await loadRecipes(options.recipesDir);
  const projector = createProjector({ recipes, windowMs: windowMsFor(options.certClass) });
  const settings: ProjectionSettings = {
    certClass: options.certClass,
    reproduceCommand: "pnpm rampscan scan <repo-path>",
  };

  let projecting = false;
  let dirty = false;
  async function project(reason: string): Promise<void> {
    if (projecting) {
      dirty = true;
      return;
    }
    projecting = true;
    try {
      do {
        dirty = false;
        const ledger = createLocalLedger(options.ledgerDir);
        const entries = await ledger.list();
        const projection = await projector.fold(ledger);
        await writeProjectionPocketBase(projection, entries, pb.admin, settings);
        log(
          `projected (${reason}): ${projection.registers.length} register cell(s), ` +
            `${projection.rows.length} evidence row(s), ${projection.drift.length} drift event(s)`,
        );
      } while (dirty);
    } finally {
      projecting = false;
    }
  }

  await project("startup");

  // the daemon's event stream, mirrored so the console can see the machinery
  // (divergence alerts, skip reasons for the action queue, cadence warnings).
  // The jsonl file stays the record; the mirror rebuilds from it on start.
  await pb.admin.ensureCollection(DAEMON_EVENTS_COLLECTION);
  const eventsTail = await tailDaemonEvents({
    path: join(options.outDir, "daemon-events.jsonl"),
    sink: {
      truncate: () => pb.admin.truncate(DAEMON_EVENTS_COLLECTION.name),
      insert: (row) => pb.admin.create(DAEMON_EVENTS_COLLECTION.name, { ...row }),
    },
    log,
  });

  // the daemon's heartbeat snapshot (plan I2b): daemon-status.json is
  // overwritten each tick, so the mirror holds at most one row and is
  // replaced wholesale — the board's status strip reads it to call the
  // daemon alive or stale out loud. No file → empty mirror → the strip
  // says "no daemon" instead of trusting a leftover heartbeat.
  await pb.admin.ensureCollection(DAEMON_STATUS_COLLECTION);
  const statusMirror = await mirrorDaemonStatus({
    path: join(options.outDir, DAEMON_STATUS_FILE),
    sink: {
      replace: async (row) => {
        await pb.admin.truncate(DAEMON_STATUS_COLLECTION.name);
        if (row) await pb.admin.create(DAEMON_STATUS_COLLECTION.name, { ...row });
      },
    },
    log,
  });

  // the ledger is the record: any append re-projects, so a `rampscan scan`
  // in another terminal moves the board live (PocketBase realtime does the rest)
  await mkdir(options.ledgerDir, { recursive: true });
  let debounce: NodeJS.Timeout | undefined;
  const watcher = watch(options.ledgerDir, (_event, filename) => {
    if (filename !== "index.jsonl") return;
    clearTimeout(debounce);
    debounce = setTimeout(() => void project("ledger append").catch((e) => log(`projection failed: ${e}`)), 400);
  });

  let web: ChildProcess | undefined;
  if (options.web) {
    const nextBin = join(webDir, "node_modules/.bin/next");
    if (!existsSync(nextBin)) {
      throw new Error(`console/web is not installed — run \`pnpm install\` first (missing ${nextBin})`);
    }
    web = spawn(nextBin, ["dev", "--port", String(options.webPort)], {
      cwd: webDir,
      stdio: ["ignore", "pipe", "pipe"],
      env: {
        ...process.env,
        NEXT_PUBLIC_PB_URL: pb.url,
        NEXT_PUBLIC_CERT_CLASS: options.certClass,
        RAMPSCAN_PB_URL: pb.url,
        RAMPSCAN_PB_SUPERUSER_EMAIL: pb.superuser.email,
        RAMPSCAN_PB_SUPERUSER_PASSWORD: pb.superuser.password,
        RAMPSCAN_LEDGER_DIR: options.ledgerDir,
        RAMPSCAN_KEYS_DIR: options.keysDir,
        RAMPSCAN_RECIPES_DIR: options.recipesDir,
        RAMPSCAN_DATASET_DIR: options.datasetDir,
        RAMPSCAN_DATASET_PIN: options.datasetPin,
      },
    });
    const forward = (chunk: Buffer) => {
      const line = chunk.toString().trimEnd();
      if (line) log(`next: ${line}`);
    };
    web.stdout?.on("data", forward);
    web.stderr?.on("data", forward);
  }

  const demo = DEMO_USERS.map((u) => `${u.email} (${u.role})`).join(", ");
  console.log(
    [
      "",
      `  console   http://127.0.0.1:${options.webPort}  (class ${options.certClass})`,
      `  pocketbase ${pb.url}  (superuser: projector-owned)`,
      `  sign in    ${demo} — password: ${DEMO_PASSWORD}`,
      "",
      "  scan in another terminal and watch the board move:",
      `    pnpm rampscan scan <repo-path> --ledger ${options.ledgerDir} --keys ${options.keysDir}`,
      "",
    ].join("\n"),
  );

  await new Promise<void>((resolvePromise) => {
    const shutdown = () => {
      watcher.close();
      eventsTail.close();
      statusMirror.close();
      web?.kill("SIGTERM");
      pb.child.kill("SIGTERM");
      resolvePromise();
    };
    process.once("SIGINT", shutdown);
    process.once("SIGTERM", shutdown);
    pb.child.once("exit", (code) => {
      log(`pocketbase exited (${code})`);
      shutdown();
    });
  });
}
