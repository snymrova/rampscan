import { mkdir } from "node:fs/promises";
import { dirname } from "node:path";
import { DatabaseSync } from "node:sqlite";
import type { Projection } from "@rampscan/core";

// SQLite persistence for the projection (plan M2: "plain SQLite this
// milestone — PocketBase arrives with the console"). The database is
// disposable by design: every write drops and refills, because the ledger is
// the record and the projection must stay rebuildable (`rampscan rebuild`
// proves it in M3).

export async function writeProjectionSqlite(
  projection: Projection,
  dbPath: string,
): Promise<void> {
  await mkdir(dirname(dbPath), { recursive: true });
  const db = new DatabaseSync(dbPath);
  try {
    db.exec("BEGIN");
    db.exec("DROP TABLE IF EXISTS coverage");
    db.exec("DROP TABLE IF EXISTS meta");
    db.exec(`
      CREATE TABLE coverage (
        repo            TEXT NOT NULL,
        recipe_id       TEXT NOT NULL,
        ksi_ids         TEXT NOT NULL, -- JSON array
        control_ids     TEXT NOT NULL, -- JSON array
        verdict         TEXT NOT NULL,
        bundle_digest   TEXT,
        state           TEXT NOT NULL, -- live | dead
        cause           TEXT,          -- anchor-drift | superseded (dead only)
        killing_commit  TEXT,
        fresh_as_of     TEXT
      )
    `);
    db.exec(`
      CREATE TABLE meta (
        dataset_version TEXT NOT NULL,
        projected_at    TEXT NOT NULL
      )
    `);
    const insert = db.prepare(
      `INSERT INTO coverage
         (repo, recipe_id, ksi_ids, control_ids, verdict, bundle_digest, state, cause, killing_commit, fresh_as_of)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    );
    for (const row of projection.rows) {
      insert.run(
        row.repo,
        row.recipeId,
        JSON.stringify(row.ksiIds),
        JSON.stringify(row.controlIds),
        row.verdict,
        row.bundleDigest ?? null,
        row.status.state,
        row.status.state === "dead" ? row.status.cause : null,
        row.status.state === "dead" ? (row.status.killingCommit ?? null) : null,
        row.freshAsOf ?? null,
      );
    }
    db.prepare("INSERT INTO meta (dataset_version, projected_at) VALUES (?, ?)").run(
      projection.datasetVersion,
      projection.projectedAt,
    );
    db.exec("COMMIT");
  } catch (error) {
    db.exec("ROLLBACK");
    throw error;
  } finally {
    db.close();
  }
}
