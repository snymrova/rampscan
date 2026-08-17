import { execFileSync } from "node:child_process";
import { appendFile, mkdir, mkdtemp, readFile, readdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import { repoFacts } from "@rampscan/collectors";
import { DEFAULT_DATASET_PIN } from "@rampscan/dataset";
import { startDaemon } from "../src/index.js";
import type { DaemonEvent, DaemonHandle } from "../src/index.js";

// The M5 exit test, compressed to a fake clock (plan §M5 "done when"): the
// daemon produces fresh evidence on cadence, flags a near-expiry before the
// window closes, re-scans when HEAD moves, and its scheduled full scan
// catches a poisoned cache as a divergence. repo-facts only — CI-safe.
//
// With fullEvery=3, full (cache-bypassing) scans are scans 3 and 6. The
// choreography, in fake-window time:
//   t=0.0  scan 1  startup, no evidence          (incremental, all misses)
//   t=0.2  tick    fresh — quiet
//   t=0.6  scan 2  cadence: identical evidence REFRESHED, collectors from cache
//   t=0.8  tick    fresh again (clock reset by the refresh) — quiet
//   t=1.2  scan 3  scheduled FULL scan verifies the clean cache
//   t=2.0  scan 4  the daemon "slept": warn-expiring fires BEFORE the refresh
//          — then the cache is poisoned —
//   t=2.6  scan 5  incremental: serves the poisoned entry (the lie lands)
//   t=3.2  scan 6  FULL: the cache verifies itself → DIVERGENCE alert
//   then   scan 7  a moved HEAD re-scans with fresh evidence

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "../../..");

const gitEnv = {
  ...process.env,
  GIT_AUTHOR_NAME: "m5-test",
  GIT_AUTHOR_EMAIL: "m5@rampscan.invalid",
  GIT_COMMITTER_NAME: "m5-test",
  GIT_COMMITTER_EMAIL: "m5@rampscan.invalid",
};

function git(cwd: string, ...args: string[]): string {
  return execFileSync("git", args, { cwd, env: gitEnv, encoding: "utf8" }).trim();
}

const WINDOW = 10_000; // ms — the fake class-b window
const T0 = Date.parse("2026-08-13T00:00:00.000Z");

let appRoot: string;
let base: string;
let events: DaemonEvent[];
let now: number;
let daemon: DaemonHandle;

function eventsOf<K extends DaemonEvent["kind"]>(kind: K): Array<DaemonEvent & { kind: K }> {
  return events.filter((e): e is DaemonEvent & { kind: K } => e.kind === kind);
}

beforeAll(async () => {
  base = await mkdtemp(join(tmpdir(), "rampscan-m5-"));
  appRoot = join(base, "app");
  await mkdir(join(appRoot, ".github", "workflows"), { recursive: true });
  await writeFile(
    join(appRoot, "package.json"),
    JSON.stringify({ name: "m5-app", version: "1.0.0" }, null, 2),
  );
  await writeFile(
    join(appRoot, "package-lock.json"),
    JSON.stringify({ name: "m5-app", version: "1.0.0", lockfileVersion: 3, packages: {} }, null, 2),
  );
  await writeFile(
    join(appRoot, ".github", "workflows", "ci.yml"),
    [
      "on: push",
      "jobs:",
      "  test:",
      "    runs-on: ubuntu-latest",
      "    steps:",
      `      - uses: actions/checkout@${"0".repeat(40)}`,
      "      - run: npm test",
    ].join("\n") + "\n",
  );
  git(appRoot, "init", "-q", "-b", "main");
  git(appRoot, "add", "-A");
  git(appRoot, "commit", "-qm", "app");

  events = [];
  now = T0;
  daemon = await startDaemon({
    path: appRoot,
    outDir: join(base, "out"),
    ledgerDir: join(base, "ledger"),
    keysDir: join(base, "keys"),
    datasetDir: join(repoRoot, "docs/context/ramprules/derived"),
    datasetPin: DEFAULT_DATASET_PIN,
    recipesDir: join(repoRoot, "recipes/commit"),
    collectors: [repoFacts],
    certClass: "b",
    cacheDir: join(base, "cache"),
    checkIntervalMs: 60_000_000, // ticks are driven manually
    fullEvery: 3,
    windowMs: { b: WINDOW },
    clock: () => now,
    onEvent: (e) => events.push(e),
  });
}, 120_000);

describe("M5: the clock runs itself", () => {
  it("scan 1 (startup): no evidence → immediate scan, evidence appended", () => {
    expect(daemon.scanCount()).toBe(1);
    const recorded = eventsOf("scan-recorded");
    expect(recorded).toHaveLength(1);
    expect(recorded[0]!.mode).toBe("incremental");
    expect(recorded[0]!.appended).toBeGreaterThan(0);
  });

  it("fresh evidence: the next tick does nothing", async () => {
    now = T0 + WINDOW * 0.2;
    await daemon.scheduler.tick();
    expect(daemon.scanCount()).toBe(1);
  });

  it("scan 2 (cadence): past 0.5 of the window the daemon re-scans; identical evidence is REFRESHED (a new attestation — the MVX clock records the re-verification) and collectors come from cache", async () => {
    now = T0 + WINDOW * 0.6;
    await daemon.scheduler.tick();
    expect(daemon.scanCount()).toBe(2);
    const recorded = eventsOf("scan-recorded")[1]!;
    expect(recorded.refreshed).toBeGreaterThan(0); // re-signed, fresh timestamps
    expect(recorded.appended).toBe(0); // nothing actually changed
    expect(recorded.cacheHits).toBeGreaterThan(0); // dirty set empty → reused
  });

  it("the refresh reset the clock: the following tick is quiet", async () => {
    now = T0 + WINDOW * 0.8; // 0.2 windows after the refresh at 0.6
    await daemon.scheduler.tick();
    expect(daemon.scanCount()).toBe(2);
    expect(eventsOf("warn-expiring")).toHaveLength(0);
  });

  it("scan 3 (full): the scheduled full scan verifies the clean cache", async () => {
    now = T0 + WINDOW * 1.2; // 0.6 windows after the refresh
    await daemon.scheduler.tick();
    expect(daemon.scanCount()).toBe(3);
    expect(eventsOf("scan-recorded")[2]!.mode).toBe("full");
    expect(eventsOf("cache-verified")).toHaveLength(1);
    expect(eventsOf("divergence")).toHaveLength(0);
  });

  it("scan 4: near-expiry warns BEFORE the window closes — a daemon that slept past 0.75 warns, then refreshes", async () => {
    // the daemon "sleeps" from 1.2 to 2.0: evidence from scan 3 is now 0.8
    // windows old — expiring, not yet expired
    now = T0 + WINDOW * 2.0;
    await daemon.scheduler.tick();
    const warnings = eventsOf("warn-expiring");
    expect(warnings.length).toBeGreaterThan(0);
    expect(warnings[0]!.remainingMs).toBeGreaterThan(0); // before, not after
    expect(eventsOf("warn-expired")).toHaveLength(0);
    expect(daemon.scanCount()).toBe(4); // and the refresh followed

    // the warning landed before the scan in the event order
    const kinds = events.map((e) => e.kind);
    expect(kinds.indexOf("warn-expiring")).toBeLessThan(kinds.lastIndexOf("scan-started"));
  });

  it("scans 5+6: a poisoned cache entry rides one incremental scan, then the scheduled full scan catches the divergence and writes the report", async () => {
    // poison every cached repo-facts entry: flip the lockfile observation
    const cacheRoot = join(base, "cache", "repo-facts");
    let poisoned = 0;
    for (const key of await readdir(cacheRoot)) {
      const entryPath = join(cacheRoot, key, "entry.json");
      const entry = JSON.parse(await readFile(entryPath, "utf8")) as {
        result: { observations: Record<string, Array<Record<string, unknown>>> };
      };
      const rows = entry.result.observations["lockfile-pinned-deps"];
      if (rows?.[0] !== undefined) {
        rows[0] = { ...rows[0], lockfile_present: false, pinned: false };
        await writeFile(entryPath, JSON.stringify(entry, null, 2) + "\n");
        poisoned += 1;
      }
    }
    expect(poisoned).toBeGreaterThan(0);

    now = T0 + WINDOW * 2.6; // 0.6 past the refresh at 2.0 — due
    await daemon.scheduler.tick(); // scan 5: incremental — serves the lie
    expect(daemon.scanCount()).toBe(5);
    expect(eventsOf("scan-recorded")[4]!.mode).toBe("incremental");

    now = T0 + WINDOW * 3.2;
    await daemon.scheduler.tick(); // scan 6: full — the cache verifies itself
    expect(daemon.scanCount()).toBe(6);
    expect(eventsOf("scan-recorded")[5]!.mode).toBe("full");

    const divergences = eventsOf("divergence");
    expect(divergences).toHaveLength(1);
    const diverged = divergences[0]!.comparison.divergences.map((d) => d.recipeId);
    expect(diverged).toContain("lockfile-pinned-deps");

    const report = JSON.parse(
      await readFile(join(base, "out", "divergence-report.json"), "utf8"),
    ) as { divergences: Array<{ recipeId: string }> };
    expect(report.divergences.some((d) => d.recipeId === "lockfile-pinned-deps")).toBe(true);
  });

  it("scan 7: a moved HEAD triggers a re-scan even with fresh evidence", async () => {
    await appendFile(join(appRoot, ".github", "workflows", "ci.yml"), "# touched\n");
    git(appRoot, "add", "-A");
    git(appRoot, "commit", "-qm", "touch workflow");

    now = T0 + WINDOW * 3.3; // evidence is fresh (scan 6 refreshed at 3.2)
    await daemon.scheduler.tick();
    expect(daemon.scanCount()).toBe(7);
    const recorded = eventsOf("scan-recorded")[6]!;
    expect(recorded.commit).toBe(git(appRoot, "rev-parse", "HEAD"));
  });

  it("the daemon's event log is a computed record: every scan and warning is in daemon-events.jsonl — and the tick heartbeat stays OUT of it", async () => {
    // awaited: stop() drains the append chain. Before it did, this read raced
    // the last write and the count below came up one short under load.
    await daemon.stop();
    const lines = (await readFile(join(base, "out", "daemon-events.jsonl"), "utf8"))
      .trim()
      .split("\n")
      .map((l) => JSON.parse(l) as { kind: string });
    const kinds = new Set(lines.map((l) => l.kind));
    expect(kinds.has("scan-recorded")).toBe(true);
    expect(kinds.has("warn-expiring")).toBe(true);
    expect(kinds.has("cache-verified")).toBe(true);
    expect(kinds.has("divergence")).toBe(true);
    expect(lines.filter((l) => l.kind === "scan-recorded")).toHaveLength(daemon.scanCount());
    // the drain stated as an invariant rather than as a count that happens to
    // match: onEvent fires synchronously and completely, so after stop() the
    // mirror holds EVERY non-tick event the daemon announced, in order
    expect(lines.map((l) => l.kind)).toEqual(
      events.filter((e) => e.kind !== "tick").map((e) => e.kind),
    );
    // one heartbeat per check interval would drown the events mirror's tail
    // (and a standing divergence with it) — ticks live in the snapshot file
    expect(kinds.has("tick")).toBe(false);
  });

  it("the tick heartbeat is a snapshot (I2b): daemon-status.json holds exactly the LAST tick's assessment", async () => {
    const status = JSON.parse(
      await readFile(join(base, "out", "daemon-status.json"), "utf8"),
    ) as Record<string, unknown>;
    expect(status.kind).toBe("tick");
    expect(status.repo).toBe(resolve(appRoot));
    expect(status.at).toBe(new Date(T0 + WINDOW * 3.3).toISOString()); // the last tick
    expect(status.checkIntervalMs).toBe(60_000_000);
    expect(status.windowMs).toBe(WINDOW);
    // the last tick's assessment saw the moved HEAD and decided to scan
    expect(status.scanDue).toBe(true);
    expect(status.reason).toBe("head-moved");
    // ticks were emitted to the listener too — one per driven assessment
    expect(eventsOf("tick").length).toBeGreaterThan(0);
  });

  it("resolves paths consistently: the recorded repo is the resolved target", () => {
    expect(eventsOf("scan-recorded")[0]!.repo).toBe(resolve(appRoot));
  });
});
