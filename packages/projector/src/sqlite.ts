import { mkdir } from "node:fs/promises";
import { dirname } from "node:path";
import { DatabaseSync } from "node:sqlite";
import type {
  CadenceGap,
  CoverageRow,
  DriftEvent,
  Projection,
  RegisterRow,
  RollupRow,
} from "@rampscan/core";

// SQLite persistence for the projection. The database is disposable by
// design: every write drops and refills, because the ledger is the record and
// the projection must stay rebuildable — `rampscan rebuild` writes it fresh,
// reads it back with readProjectionSqlite, and proves the round trip is
// lossless (plan M3 E1).

export async function writeProjectionSqlite(
  projection: Projection,
  dbPath: string,
): Promise<void> {
  await mkdir(dirname(dbPath), { recursive: true });
  const db = new DatabaseSync(dbPath);
  try {
    db.exec("BEGIN");
    for (const table of ["coverage", "registers", "drift", "controls", "ksis", "gaps", "meta"]) {
      db.exec(`DROP TABLE IF EXISTS ${table}`);
    }
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
      CREATE TABLE registers (
        repo               TEXT NOT NULL,
        recipe_id          TEXT NOT NULL,
        ksi_ids            TEXT NOT NULL, -- JSON array
        control_ids        TEXT NOT NULL, -- JSON array
        state              TEXT NOT NULL, -- evidenced | violated | unevidenced | notApplicable
        cadence            TEXT,
        bundle_digest      TEXT,
        fresh_as_of        TEXT,
        commit_sha         TEXT,
        scoping_digest     TEXT,
        scoping_just       TEXT,
        scoping_proposed   TEXT,
        scoping_approved   TEXT,
        scoping_timestamp  TEXT
      )
    `);
    db.exec(`
      CREATE TABLE drift (
        at              TEXT NOT NULL,
        repo            TEXT NOT NULL,
        recipe_id       TEXT NOT NULL,
        kind            TEXT NOT NULL, -- born | died | verdict-flipped | scoped
        cause           TEXT,
        killing_commit  TEXT,
        from_verdict    TEXT,
        to_verdict      TEXT,
        bundle_digest   TEXT NOT NULL
      )
    `);
    for (const table of ["controls", "ksis"]) {
      db.exec(`
        CREATE TABLE ${table} (
          repo        TEXT NOT NULL,
          id          TEXT NOT NULL,
          state       TEXT NOT NULL, -- evidenced | violated | unevidenced | notApplicable
          recipe_ids  TEXT NOT NULL, -- JSON array
          counts      TEXT NOT NULL  -- JSON object
        )
      `);
    }
    db.exec(`
      CREATE TABLE gaps (
        repo           TEXT NOT NULL,
        recipe_id      TEXT NOT NULL,
        bundle_digest  TEXT NOT NULL,
        gap_start      TEXT NOT NULL,
        gap_end        TEXT NOT NULL,
        duration_ms    INTEGER NOT NULL,
        ongoing        INTEGER NOT NULL -- 0 | 1
      )
    `);
    db.exec(`
      CREATE TABLE meta (
        dataset_version TEXT NOT NULL,
        projected_at    TEXT NOT NULL
      )
    `);

    const insertCoverage = db.prepare(
      `INSERT INTO coverage
         (repo, recipe_id, ksi_ids, control_ids, verdict, bundle_digest, state, cause, killing_commit, fresh_as_of)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    );
    for (const row of projection.rows) {
      insertCoverage.run(
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

    const insertRegister = db.prepare(
      `INSERT INTO registers
         (repo, recipe_id, ksi_ids, control_ids, state, cadence, bundle_digest, fresh_as_of, commit_sha,
          scoping_digest, scoping_just, scoping_proposed, scoping_approved, scoping_timestamp)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    );
    for (const row of projection.registers) {
      insertRegister.run(
        row.repo,
        row.recipeId,
        JSON.stringify(row.ksiIds),
        JSON.stringify(row.controlIds),
        row.state,
        row.cadence ?? null,
        row.bundleDigest ?? null,
        row.freshAsOf ?? null,
        row.commit ?? null,
        row.scoping?.digest ?? null,
        row.scoping?.justification ?? null,
        row.scoping?.proposedBy ?? null,
        row.scoping?.approvedBy ?? null,
        row.scoping?.timestamp ?? null,
      );
    }

    const insertDrift = db.prepare(
      `INSERT INTO drift
         (at, repo, recipe_id, kind, cause, killing_commit, from_verdict, to_verdict, bundle_digest)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    );
    for (const event of projection.drift) {
      insertDrift.run(
        event.at,
        event.repo,
        event.recipeId,
        event.kind,
        event.cause ?? null,
        event.killingCommit ?? null,
        event.from ?? null,
        event.to ?? null,
        event.bundleDigest,
      );
    }

    for (const [table, rollupRows] of [
      ["controls", projection.controls],
      ["ksis", projection.ksis],
    ] as const) {
      const insertRollup = db.prepare(
        `INSERT INTO ${table} (repo, id, state, recipe_ids, counts) VALUES (?, ?, ?, ?, ?)`,
      );
      for (const row of rollupRows) {
        insertRollup.run(
          row.repo,
          row.id,
          row.state,
          JSON.stringify(row.recipeIds),
          JSON.stringify(row.counts),
        );
      }
    }

    const insertGap = db.prepare(
      `INSERT INTO gaps (repo, recipe_id, bundle_digest, gap_start, gap_end, duration_ms, ongoing)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    );
    for (const gap of projection.gaps) {
      insertGap.run(
        gap.repo,
        gap.recipeId,
        gap.bundleDigest,
        gap.start,
        gap.end,
        gap.durationMs,
        gap.ongoing ? 1 : 0,
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

/** Read a stored projection back — `rampscan rebuild` compares this against a fresh fold. */
export function readProjectionSqlite(dbPath: string): Projection {
  const db = new DatabaseSync(dbPath, { readOnly: true });
  try {
    const rows: CoverageRow[] = (db.prepare("SELECT * FROM coverage").all() as any[]).map(
      (r) => {
        const row: CoverageRow = {
          repo: r.repo,
          recipeId: r.recipe_id,
          ksiIds: JSON.parse(r.ksi_ids),
          controlIds: JSON.parse(r.control_ids),
          verdict: r.verdict,
          status:
            r.state === "live"
              ? { state: "live" }
              : { state: "dead", cause: r.cause, ...(r.killing_commit ? { killingCommit: r.killing_commit } : {}) },
        };
        if (r.bundle_digest) row.bundleDigest = r.bundle_digest;
        if (r.fresh_as_of) row.freshAsOf = r.fresh_as_of;
        return row;
      },
    );
    const registers: RegisterRow[] = (db.prepare("SELECT * FROM registers").all() as any[]).map(
      (r) => {
        const row: RegisterRow = {
          repo: r.repo,
          recipeId: r.recipe_id,
          ksiIds: JSON.parse(r.ksi_ids),
          controlIds: JSON.parse(r.control_ids),
          state: r.state,
        };
        if (r.cadence) row.cadence = r.cadence;
        if (r.bundle_digest) row.bundleDigest = r.bundle_digest;
        if (r.fresh_as_of) row.freshAsOf = r.fresh_as_of;
        if (r.commit_sha) row.commit = r.commit_sha;
        if (r.scoping_digest) {
          row.scoping = {
            digest: r.scoping_digest,
            justification: r.scoping_just,
            proposedBy: r.scoping_proposed,
            approvedBy: r.scoping_approved,
            timestamp: r.scoping_timestamp,
          };
        }
        return row;
      },
    );
    const drift: DriftEvent[] = (db.prepare("SELECT * FROM drift").all() as any[]).map((r) => {
      const event: DriftEvent = {
        at: r.at,
        repo: r.repo,
        recipeId: r.recipe_id,
        kind: r.kind,
        bundleDigest: r.bundle_digest,
      };
      if (r.cause) event.cause = r.cause;
      if (r.killing_commit) event.killingCommit = r.killing_commit;
      if (r.from_verdict) event.from = r.from_verdict;
      if (r.to_verdict) event.to = r.to_verdict;
      return event;
    });
    const readRollup = (table: string): RollupRow[] =>
      (db.prepare(`SELECT * FROM ${table}`).all() as any[]).map((r) => ({
        repo: r.repo,
        id: r.id,
        state: r.state,
        recipeIds: JSON.parse(r.recipe_ids),
        counts: JSON.parse(r.counts),
      }));
    const gaps: CadenceGap[] = (db.prepare("SELECT * FROM gaps").all() as any[]).map((r) => ({
      repo: r.repo,
      recipeId: r.recipe_id,
      bundleDigest: r.bundle_digest,
      start: r.gap_start,
      end: r.gap_end,
      durationMs: Number(r.duration_ms),
      ongoing: r.ongoing === 1,
    }));
    const meta = db.prepare("SELECT * FROM meta").get() as any;
    return {
      rows,
      registers,
      drift,
      controls: readRollup("controls"),
      ksis: readRollup("ksis"),
      gaps,
      datasetVersion: meta?.dataset_version ?? "",
      projectedAt: meta?.projected_at ?? "",
    };
  } finally {
    db.close();
  }
}
