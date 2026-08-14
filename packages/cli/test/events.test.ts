import { appendFile, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { mirrorDaemonStatus, tailDaemonEvents } from "../src/events.js";
import type { DaemonEventRow } from "../src/events.js";

// I2a — the daemon-events tail that `rampscan serve` runs: the jsonl FILE is
// the record, the sink is a rebuildable mirror. Ingestion is exercised via
// the handle's ingestNew() (what the fs watcher calls), so the tests are
// deterministic instead of racing watch timing.

function makeSink() {
  const rows: DaemonEventRow[] = [];
  let truncates = 0;
  return {
    rows,
    truncateCount: () => truncates,
    sink: {
      truncate: async () => {
        truncates += 1;
        rows.length = 0;
      },
      insert: async (row: DaemonEventRow) => {
        rows.push(row);
      },
    },
  };
}

const line = (at: string, kind: string, extra: Record<string, unknown> = {}) =>
  JSON.stringify({ at, kind, repo: "/repo", ...extra }) + "\n";

let cleanup: Array<() => Promise<void>> = [];
afterEach(async () => {
  for (const fn of cleanup) await fn();
  cleanup = [];
});

async function setup(initial?: string) {
  const dir = await mkdtemp(join(tmpdir(), "rampscan-events-"));
  cleanup.push(() => rm(dir, { recursive: true, force: true }));
  const path = join(dir, "daemon-events.jsonl");
  if (initial !== undefined) await writeFile(path, initial);
  return { dir, path };
}

describe("tailDaemonEvents", () => {
  it("backfills the existing file into a truncated mirror, keeping the whole event as payload", async () => {
    const { path } = await setup(
      line("2026-08-14T00:00:00Z", "registered") +
        line("2026-08-14T00:01:00Z", "scan-recorded", { mode: "incremental", cacheHits: 3 }),
    );
    const { rows, sink, truncateCount } = makeSink();
    const tail = await tailDaemonEvents({ path, sink });
    cleanup.push(async () => tail.close());

    expect(truncateCount()).toBe(1);
    expect(rows.map((r) => r.kind)).toEqual(["registered", "scan-recorded"]);
    expect(rows[1]!.repo).toBe("/repo");
    expect(rows[1]!.payload).toMatchObject({ mode: "incremental", cacheHits: 3 });
  });

  it("caps the backfill at tailLimit, newest last — the file keeps the full history", async () => {
    const all = Array.from({ length: 10 }, (_, i) =>
      line(`2026-08-14T00:0${i}:00Z`, `k${i}`),
    ).join("");
    const { path } = await setup(all);
    const { rows, sink } = makeSink();
    const tail = await tailDaemonEvents({ path, sink, tailLimit: 4 });
    cleanup.push(async () => tail.close());

    expect(rows.map((r) => r.kind)).toEqual(["k6", "k7", "k8", "k9"]);
  });

  it("ingests appended lines and holds a partial line until its newline arrives", async () => {
    const { path } = await setup(line("2026-08-14T00:00:00Z", "registered"));
    const { rows, sink } = makeSink();
    const tail = await tailDaemonEvents({ path, sink });
    cleanup.push(async () => tail.close());
    expect(rows).toHaveLength(1);

    const partial = JSON.stringify({ at: "2026-08-14T00:03:00Z", kind: "warn-expiring", repo: "/repo" });
    await appendFile(
      path,
      line("2026-08-14T00:02:00Z", "scan-recorded") + partial.slice(0, 20),
    );
    await tail.ingestNew();
    expect(rows.map((r) => r.kind)).toEqual(["registered", "scan-recorded"]);

    await appendFile(path, partial.slice(20) + "\n");
    await tail.ingestNew();
    expect(rows.map((r) => r.kind)).toEqual(["registered", "scan-recorded", "warn-expiring"]);
  });

  it("a shrunken (truncated/rotated) file triggers a full re-ingest, never a merge", async () => {
    const { path } = await setup(
      line("2026-08-14T00:00:00Z", "a") + line("2026-08-14T00:01:00Z", "b"),
    );
    const { rows, sink, truncateCount } = makeSink();
    const tail = await tailDaemonEvents({ path, sink });
    cleanup.push(async () => tail.close());
    expect(rows).toHaveLength(2);

    await writeFile(path, line("2026-08-14T01:00:00Z", "fresh-start"));
    await tail.ingestNew();
    expect(truncateCount()).toBe(2);
    expect(rows.map((r) => r.kind)).toEqual(["fresh-start"]);
  });

  it("a missing file is an empty tail, not an error — events appear once the daemon writes", async () => {
    const { path } = await setup();
    const { rows, sink } = makeSink();
    const tail = await tailDaemonEvents({ path, sink });
    cleanup.push(async () => tail.close());
    expect(rows).toHaveLength(0);

    await writeFile(path, line("2026-08-14T00:00:00Z", "registered"));
    await tail.ingestNew();
    expect(rows.map((r) => r.kind)).toEqual(["registered"]);
  });

  it("an unparseable line is skipped with a log, the rest still ingest", async () => {
    const { path } = await setup(
      line("2026-08-14T00:00:00Z", "a") + "not json at all\n" + line("2026-08-14T00:01:00Z", "b"),
    );
    const { rows, sink } = makeSink();
    const logs: string[] = [];
    const tail = await tailDaemonEvents({ path, sink, log: (l) => logs.push(l) });
    cleanup.push(async () => tail.close());

    expect(rows.map((r) => r.kind)).toEqual(["a", "b"]);
    expect(logs.some((l) => l.includes("unparseable"))).toBe(true);
  });
});

// I2b — the heartbeat snapshot mirror: unlike the events tail, the status
// file is OVERWRITTEN each tick, so the mirror is replaced wholesale and a
// missing file clears it — a leftover heartbeat from a dead run must never
// masquerade as a live daemon.

function makeStatusSink() {
  const replacements: Array<DaemonEventRow | undefined> = [];
  return {
    replacements,
    current: () => replacements.at(-1),
    sink: {
      replace: async (row: DaemonEventRow | undefined) => {
        replacements.push(row);
      },
    },
  };
}

const tick = (at: string, extra: Record<string, unknown> = {}) =>
  JSON.stringify({ at, kind: "tick", repo: "/repo", checkIntervalMs: 300_000, ...extra }) + "\n";

describe("mirrorDaemonStatus", () => {
  it("mirrors the snapshot on start and replaces it wholesale on overwrite", async () => {
    const dir = await mkdtemp(join(tmpdir(), "rampscan-status-"));
    cleanup.push(() => rm(dir, { recursive: true, force: true }));
    const path = join(dir, "daemon-status.json");
    await writeFile(path, tick("2026-08-14T00:00:00Z", { scanDue: false }));

    const { replacements, current, sink } = makeStatusSink();
    const mirror = await mirrorDaemonStatus({ path, sink });
    cleanup.push(async () => mirror.close());

    expect(current()).toMatchObject({ kind: "tick", repo: "/repo" });
    expect(current()!.payload).toMatchObject({ checkIntervalMs: 300_000, scanDue: false });

    await writeFile(path, tick("2026-08-14T00:05:00Z", { scanDue: true, reason: "cadence" }));
    await mirror.ingestNew();
    expect(current()!.at).toBe("2026-08-14T00:05:00Z");
    // every refresh replaces wholesale — no row ever merges with a prior one
    expect(replacements.every((r) => r === undefined || r.kind === "tick")).toBe(true);
  });

  it("a missing file clears the mirror — no heartbeat, no daemon claim", async () => {
    const dir = await mkdtemp(join(tmpdir(), "rampscan-status-"));
    cleanup.push(() => rm(dir, { recursive: true, force: true }));
    const path = join(dir, "daemon-status.json");

    const { current, sink } = makeStatusSink();
    const mirror = await mirrorDaemonStatus({ path, sink });
    cleanup.push(async () => mirror.close());
    expect(current()).toBeUndefined();

    await writeFile(path, tick("2026-08-14T00:00:00Z"));
    await mirror.ingestNew();
    expect(current()).toMatchObject({ at: "2026-08-14T00:00:00Z" });

    await rm(path);
    await mirror.ingestNew();
    expect(current()).toBeUndefined();
  });

  it("a half-written snapshot keeps the previous row — the watcher fires again on completion", async () => {
    const dir = await mkdtemp(join(tmpdir(), "rampscan-status-"));
    cleanup.push(() => rm(dir, { recursive: true, force: true }));
    const path = join(dir, "daemon-status.json");
    await writeFile(path, tick("2026-08-14T00:00:00Z"));

    const { current, sink } = makeStatusSink();
    const logs: string[] = [];
    const mirror = await mirrorDaemonStatus({ path, sink, log: (l) => logs.push(l) });
    cleanup.push(async () => mirror.close());

    const full = tick("2026-08-14T00:05:00Z");
    await writeFile(path, full.slice(0, 25)); // caught mid-overwrite
    await mirror.ingestNew();
    expect(current()!.at).toBe("2026-08-14T00:00:00Z"); // previous row survives
    expect(logs.some((l) => l.includes("daemon-status"))).toBe(true);

    await writeFile(path, full);
    await mirror.ingestNew();
    expect(current()!.at).toBe("2026-08-14T00:05:00Z");
  });
});
