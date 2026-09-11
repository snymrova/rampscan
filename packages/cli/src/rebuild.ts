import { createProjector, readProjectionSqlite, writeProjectionSqlite } from "@rampscan/projector";
import {
  PocketBaseAdmin,
  readProjectionPocketBase,
  writeProjectionPocketBase,
} from "@rampscan/projector";
import type { ProjectionSettings } from "@rampscan/projector";
import { createLocalLedger } from "@rampscan/ledger";
import type { Projection } from "@rampscan/core";
import { canonicalJson } from "@rampscan/schema";
import type { ValidationMethod } from "@rampscan/schema";
import { loadRecipes } from "./recipes.js";

// `rampscan rebuild` (plan M3 E1): the projection is rebuildable from the
// ledger at any time, and this command PROVES it rather than asserting it —
// fold the ledger fresh, drop-and-refill each projection store, read the
// store back, and require byte equality with the fold. If a store and the
// ledger ever disagree, the ledger wins and this is the command that makes
// it so.

export interface RebuildOptions {
  ledgerDir: string;
  recipesDir: string;
  /** SQLite projection path; always written */
  dbPath: string;
  /** MVX window in ms — when present, the fold carries the cadence-gap history (I1d) */
  windowMs?: number;
  /**
   * The KSI pivot's fold inputs (Q2), passed exactly as `serve` passes them
   * so the byte-equality proof covers the method register too: the derived
   * methods, the owed catalog's KSI ids, and the class floor. Omit them and
   * the rebuilt projection simply carries an empty register — but then the
   * proof is over less than the projection serve writes, so `main.ts` wires
   * them for every real invocation.
   */
  methods?: ValidationMethod[];
  ksiIds?: string[];
  methodFloor?: number | null;
  historyFloorMonths?: number | null;
  /** PocketBase target; rebuilt too when provided and healthy */
  pocketbase?: {
    url: string;
    email: string;
    password: string;
    settings: ProjectionSettings;
  };
  now?: () => Date;
  log?: (line: string) => void;
}

export interface RebuildReport {
  ok: boolean;
  lines: string[];
  projection: Projection;
}

function equal(a: Projection, b: Projection): boolean {
  return canonicalJson(a) === canonicalJson(b);
}

export async function rebuild(options: RebuildOptions): Promise<RebuildReport> {
  const lines: string[] = [];
  const ledger = createLocalLedger(options.ledgerDir);
  const recipes = await loadRecipes(options.recipesDir);
  const projectorOptions: Parameters<typeof createProjector>[0] = { recipes };
  if (options.now) projectorOptions.now = options.now;
  if (options.windowMs !== undefined) projectorOptions.windowMs = options.windowMs;
  if (options.methods !== undefined) projectorOptions.methods = options.methods;
  if (options.ksiIds !== undefined) projectorOptions.ksiIds = options.ksiIds;
  if (options.methodFloor !== undefined) projectorOptions.methodFloor = options.methodFloor;
  if (options.historyFloorMonths !== undefined)
    projectorOptions.historyFloorMonths = options.historyFloorMonths;
  const projector = createProjector(projectorOptions);

  const entries = await ledger.list();
  const projection = await projector.fold(ledger);
  lines.push(
    `ledger    ${entries.length} statement(s) → ${projection.rows.length} evidence row(s), ` +
      `${projection.registers.length} register cell(s), ${projection.drift.length} drift event(s)`,
  );

  await writeProjectionSqlite(projection, options.dbPath);
  const sqliteBack = readProjectionSqlite(options.dbPath);
  const sqliteOk = equal(projection, sqliteBack);
  lines.push(
    sqliteOk
      ? `sqlite    ok — ${options.dbPath} reads back identical to the fold (projection ≡ ledger)`
      : `sqlite    MISMATCH — ${options.dbPath} does not read back what the ledger folds to`,
  );

  let pbOk = true;
  if (options.pocketbase) {
    const pb = new PocketBaseAdmin(options.pocketbase.url);
    if (await pb.health()) {
      await pb.auth(options.pocketbase.email, options.pocketbase.password);
      await writeProjectionPocketBase(projection, entries, pb, options.pocketbase.settings);
      const pbBack = await readProjectionPocketBase(pb);
      pbOk = equal(projection, pbBack);
      lines.push(
        pbOk
          ? `pocketbase ok — ${options.pocketbase.url} reads back identical to the fold`
          : `pocketbase MISMATCH — ${options.pocketbase.url} does not read back the fold`,
      );
    } else {
      lines.push(`pocketbase skipped — ${options.pocketbase.url} not reachable`);
    }
  }

  return { ok: sqliteOk && pbOk, lines, projection };
}
