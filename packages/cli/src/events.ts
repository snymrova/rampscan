import { watch, type FSWatcher } from "node:fs";
import { readFile } from "node:fs/promises";
import { basename, dirname } from "node:path";

// Tail daemon-events.jsonl into a sink (plan I2a/I2b): `rampscan serve` uses
// this to mirror the daemon's event stream into the console-readable
// `daemon_events` collection. The FILE remains the record — the mirror is
// rebuilt from its tail on every start, and a truncated or rotated file
// triggers a full re-ingest, never a merge. An operator who cannot see the
// daemon's events owns a silently rotting board; this is how they see them.

export interface DaemonEventRow {
  at: string;
  kind: string;
  repo: string;
  /** the whole parsed event line — nothing is dropped in the mirror */
  payload: Record<string, unknown>;
}

export interface DaemonEventSink {
  /** drop the mirror — called before every (re-)backfill */
  truncate(): Promise<void>;
  insert(row: DaemonEventRow): Promise<void>;
}

export interface TailOptions {
  /** the daemon's events file (outDir/daemon-events.jsonl) — may not exist yet */
  path: string;
  sink: DaemonEventSink;
  /**
   * Backfill cap: only the newest N complete lines are mirrored on start.
   * The queue and status strip need the recent tail; the file keeps history.
   */
  tailLimit?: number;
  log?: (line: string) => void;
}

export interface TailHandle {
  /** ingest whatever the file holds beyond the last-read offset (the watcher calls this) */
  ingestNew(): Promise<void>;
  close(): void;
}

const DEFAULT_TAIL_LIMIT = 500;

function parseRow(
  line: string,
  log: (l: string) => void,
  label = "daemon-events",
): DaemonEventRow | undefined {
  try {
    const event = JSON.parse(line) as Record<string, unknown>;
    return {
      at: typeof event.at === "string" ? event.at : "",
      kind: typeof event.kind === "string" ? event.kind : "",
      repo: typeof event.repo === "string" ? event.repo : "",
      payload: event,
    };
  } catch {
    log(`${label}: unparseable line skipped: ${line.slice(0, 120)}`);
    return undefined;
  }
}

export interface DaemonStatusSink {
  /** replace the mirror's single row — undefined clears it (no status file, no daemon claim) */
  replace(row: DaemonEventRow | undefined): Promise<void>;
}

export interface MirrorStatusOptions {
  /** the daemon's heartbeat snapshot (outDir/daemon-status.json) — may not exist */
  path: string;
  sink: DaemonStatusSink;
  log?: (line: string) => void;
}

/**
 * Mirror daemon-status.json into the console (plan I2b). Unlike the events
 * tail this is a SNAPSHOT mirror: the file is overwritten each tick, so the
 * mirror holds at most one row and is replaced wholesale on every change. A
 * missing file clears the mirror — a stale heartbeat from a previous run must
 * never masquerade as a live daemon. A half-written file (the overwrite is
 * not atomic) keeps the previous row; the watcher fires again on completion.
 */
export async function mirrorDaemonStatus(options: MirrorStatusOptions): Promise<TailHandle> {
  const log = options.log ?? (() => {});

  async function refresh(): Promise<void> {
    let raw: string | undefined;
    try {
      raw = await readFile(options.path, "utf8");
    } catch {
      await options.sink.replace(undefined);
      return;
    }
    const row = parseRow(raw.trim(), log, "daemon-status");
    if (row) await options.sink.replace(row);
  }

  await refresh();

  let chain = Promise.resolve();
  const schedule = (work: () => Promise<void>): void => {
    chain = chain.then(work).catch((e) => log(`daemon-status: mirror failed: ${e}`));
  };
  let watcher: FSWatcher | undefined;
  try {
    watcher = watch(dirname(options.path), (_event, filename) => {
      if (filename !== basename(options.path)) return;
      schedule(() => refresh());
    });
  } catch (e) {
    log(`daemon-status: not watching ${dirname(options.path)}: ${e}`);
  }

  return {
    ingestNew: () => {
      schedule(() => refresh());
      return chain;
    },
    close: () => watcher?.close(),
  };
}

export async function tailDaemonEvents(options: TailOptions): Promise<TailHandle> {
  const log = options.log ?? (() => {});
  const tailLimit = options.tailLimit ?? DEFAULT_TAIL_LIMIT;
  // byte offset of the next unread character — only ever advanced past
  // COMPLETE lines, so a partially-written line is read on the next pass
  let offset = 0;

  async function content(): Promise<Buffer> {
    try {
      return await readFile(options.path);
    } catch {
      return Buffer.alloc(0); // the daemon has not written yet — an empty tail
    }
  }

  async function backfill(): Promise<void> {
    await options.sink.truncate();
    offset = 0;
    const buf = await content();
    const complete = buf.subarray(0, buf.lastIndexOf(0x0a) + 1); // through the last "\n"
    offset = complete.length;
    const lines = complete.toString("utf8").split("\n").filter((l) => l.trim().length > 0);
    const dropped = Math.max(0, lines.length - tailLimit);
    if (dropped > 0) log(`daemon-events: mirroring newest ${tailLimit} of ${lines.length} events (the file keeps all)`);
    for (const line of lines.slice(dropped)) {
      const row = parseRow(line, log);
      if (row) await options.sink.insert(row);
    }
  }

  async function ingestNew(): Promise<void> {
    const buf = await content();
    if (buf.length < offset) {
      // shrunk — truncated or rotated: the file is the record, start over
      await backfill();
      return;
    }
    const fresh = buf.subarray(offset);
    const complete = fresh.subarray(0, fresh.lastIndexOf(0x0a) + 1);
    if (complete.length === 0) return;
    offset += complete.length;
    for (const line of complete.toString("utf8").split("\n")) {
      if (line.trim().length === 0) continue;
      const row = parseRow(line, log);
      if (row) await options.sink.insert(row);
    }
  }

  await backfill();

  // watch the directory, not the file: the file may not exist yet, and the
  // daemon recreates it freely. Ingestion is serialized on a promise chain.
  let chain = Promise.resolve();
  const schedule = (work: () => Promise<void>): void => {
    chain = chain.then(work).catch((e) => log(`daemon-events: ingest failed: ${e}`));
  };
  let watcher: FSWatcher | undefined;
  try {
    watcher = watch(dirname(options.path), (_event, filename) => {
      if (filename !== basename(options.path)) return;
      schedule(() => ingestNew());
    });
  } catch (e) {
    // the out dir itself may not exist — the mirror stays at its backfill
    log(`daemon-events: not watching ${dirname(options.path)}: ${e}`);
  }

  return {
    ingestNew: () => {
      schedule(() => ingestNew());
      return chain;
    },
    close: () => watcher?.close(),
  };
}
