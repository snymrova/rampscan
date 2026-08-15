import type { ClaimBasisRecord, CollectorRunRecord, ScanRunRecord } from "./types";

// The provenance chain (plan J5) and the gate basis (I3f) — pure derivations
// over what is already signed: the evidence predicate and the run record of
// the run that produced it.
//
// The chain answers one question in five hops:
//
//   recipe → collector → tool@version(runtime) → artifact digest → bundle
//
// and every hop is a fact somebody signed, never a guess. Where a hop cannot
// be drawn, this module produces the REASON in the hop's own slot rather than
// dropping it: a chain with a silent gap reads as a chain with no gap, and the
// gaps are exactly what an auditor is looking for.
//
// Two of those reasons are load-bearing and predate this file:
//   - the projection keeps the newest N runs, so evidence older than the cap
//     names a run this console does not hold (J3's rule, same words);
//   - run records began at J1, so evidence minted before then names a run
//     nothing ever wrote down.

export type ChainHopKind = "recipe" | "collector" | "tool" | "artifact" | "bundle";

export interface ChainHop {
  kind: ChainHopKind;
  /** the thing itself, as it is named in the record */
  label: string;
  /** one clause on what this hop is */
  detail?: string;
  /** where the reader goes next; absent when this hop is a dead end on purpose */
  href?: string;
  /** why this hop could not be drawn — rendered in its place, never swallowed */
  missing?: string;
  /** the digest this hop is addressed by, when it has one */
  digest?: string;
}

export interface ChainInput {
  recipeId: string;
  /** the producing collector, straight off the predicate; "" on pre-J5 bundles */
  collector: string;
  runId: string;
  repo: string;
  digest: string;
  controlIds: string[];
  /** the subjects of this bundle, so the chain can say which artifacts it attests */
  subjects: Array<{ name: string; sha256: string; isAnchor: boolean }>;
  /** the run record for runId, when the projection holds it */
  run: ScanRunRecord | null;
  /** false while the run collection is still loading — silence is not absence */
  runsLoaded: boolean;
  /** how many runs the projection holds at all (J3's two different absences) */
  runCount: number;
}

/** the collector row for this bundle's collector inside its run record */
export function collectorRunOf(
  run: ScanRunRecord | null,
  collector: string,
): CollectorRunRecord | null {
  if (!run || collector === "") return null;
  return run.collectors.find((c) => c.collector === collector) ?? null;
}

/**
 * The tools a collector's verdict rests on — its own, plus the ones reached
 * through the artifacts it consumed from earlier collectors of the SAME run.
 *
 * The second half is the whole point. `sast-reachability` spawns nothing: it
 * reads semgrep's results and the graph. A chain built from its `tools` alone
 * would print "no external tool" over a verdict semgrep produced, which is
 * true about the collector and false about the evidence.
 */
export interface ToolBehind {
  tool: string;
  version?: string;
  runtime: string;
  /** the collector whose output carried this tool's answer into the verdict */
  through?: string;
  /** the artifact that carried it */
  artifact?: string;
}

export function toolsBehind(
  run: ScanRunRecord,
  collector: string,
  seen = new Set<string>(),
): ToolBehind[] {
  if (seen.has(collector)) return [];
  seen.add(collector);
  const row = run.collectors.find((c) => c.collector === collector);
  if (!row) return [];

  const out: ToolBehind[] = row.tools.map((t) => ({
    tool: t.tool,
    ...(t.version !== undefined ? { version: t.version } : {}),
    runtime:
      t.runtime.kind === "docker"
        ? t.runtime.image
        : t.runtime.kind === "binary"
          ? (t.runtime.path ?? "on PATH")
          : `absent — ${t.runtime.reason}`,
  }));

  for (const artifact of row.consumes ?? []) {
    const producer = run.collectors.find((c) => c.artifacts.some((a) => a.name === artifact));
    if (!producer || seen.has(producer.collector)) continue;
    for (const t of toolsBehind(run, producer.collector, seen)) {
      out.push({ ...t, through: t.through ?? producer.collector, artifact: t.artifact ?? artifact });
    }
  }
  return out;
}

/**
 * The chain's BACK edge (J5): what each collector of a run actually produced,
 * keyed `runId\ncollector`. This is what makes the line clickable in both
 * directions — from a bundle you reach the run that produced it, and from a
 * run you reach the bundles it produced.
 *
 * The line this must not cross: these are facts about the RUN — which signed
 * statements it emitted, addressed by digest — and never a state. No verdict,
 * no register state and no coverage number is read here or rendered from it,
 * because a /runs that showed verdicts would be a second source of truth about
 * a board that is folded from evidence and scoping alone.
 */
export interface ProducedEvidence {
  recipeId: string;
  digest: string;
}

export function producedByRun(
  bundles: Array<{ digest: string; statement: { predicateType: string; predicate: Record<string, unknown> } }>,
): Map<string, ProducedEvidence[]> {
  const out = new Map<string, ProducedEvidence[]>();
  for (const b of bundles) {
    if (b.statement.predicateType !== "https://rampscan.dev/evidence/v1") continue;
    const runId = b.statement.predicate["run_id"];
    const collector = b.statement.predicate["collector"];
    // a bundle minted before J5 names no collector: it belongs to no
    // collector row, and attaching it to one by guessing from tool names is
    // the exact shortcut J3 refused
    if (typeof runId !== "string" || typeof collector !== "string" || collector === "") continue;
    const key = `${runId}\n${collector}`;
    out.set(key, [
      ...(out.get(key) ?? []),
      { recipeId: String(b.statement.predicate["recipe_id"]), digest: b.digest },
    ]);
  }
  for (const list of out.values()) list.sort((a, b) => a.recipeId.localeCompare(b.recipeId));
  return out;
}

/** the reason the run record for a bundle is not on screen — J3's two facts, one hand */
export function missingRunReason(runId: string, runCount: number): string {
  return runCount === 0
    ? `no scan has appended a run record to this projection yet, so run ${runId} was never written down — evidence minted before run records existed names a run that does not exist. Re-scanning produces one.`
    : `run ${runId} is older than the newest ${runCount} run${runCount === 1 ? "" : "s"} this projection keeps. The ledger still holds it, and this bundle verifies offline exactly as before.`;
}

export function provenanceChain(input: ChainInput): ChainHop[] {
  const hops: ChainHop[] = [];

  hops.push({
    kind: "recipe",
    label: input.recipeId,
    detail:
      input.controlIds.length > 0
        ? `the check this evidence answers — mapped to ${input.controlIds.join(", ")}`
        : "the check this evidence answers",
    ...(input.controlIds[0]
      ? { href: `/controls?reg=controls&id=${encodeURIComponent(input.controlIds[0])}` }
      : {}),
  });

  if (input.collector === "") {
    hops.push({
      kind: "collector",
      label: "not recorded",
      missing:
        "this bundle was minted before the producing collector was signed into the predicate, so the chain cannot name it. The catalog would name one, but that is what the catalog says TODAY, not what produced this — a re-scan records it.",
    });
  } else {
    hops.push({
      kind: "collector",
      label: input.collector,
      detail: "the collector that produced this evidence, as the signed predicate names it",
      href: `/runs?scan=${encodeURIComponent(input.runId)}&collector=${encodeURIComponent(input.collector)}`,
    });
  }

  // hop 3 — the tools, from the run record. Every absence here is one of the
  // two J3 facts or a collector the run never dispatched.
  if (!input.runsLoaded) {
    hops.push({ kind: "tool", label: "…", detail: "reading the run record" });
  } else if (!input.run) {
    hops.push({
      kind: "tool",
      label: "run record not held",
      missing: missingRunReason(input.runId, input.runCount),
    });
  } else {
    const row = collectorRunOf(input.run, input.collector);
    if (!row) {
      hops.push({
        kind: "tool",
        label: "not in this run",
        missing:
          input.collector === ""
            ? "with no collector named, there is no row of the run record to read tools from."
            : `run ${input.runId} recorded no row for "${input.collector}" — it was not in that run's collector set, which is a different fact from a collector that ran and skipped.`,
      });
    } else {
      const tools = toolsBehind(input.run, input.collector);
      if (tools.length === 0) {
        hops.push({
          kind: "tool",
          label: "no external tool",
          detail:
            "this collector reads the repo itself and consumed nothing from another collector — a fact about the collector, not a missing binary",
        });
      } else {
        for (const t of tools) {
          hops.push({
            kind: "tool",
            label: `${t.tool}${t.version ? `@${t.version}` : ""}`,
            detail: t.through
              ? `${t.runtime} — reached through ${t.artifact}, produced by ${t.through} in this run`
              : t.runtime,
            href: `/runs?scan=${encodeURIComponent(input.runId)}&collector=${encodeURIComponent(t.through ?? input.collector)}`,
          });
        }
      }
    }
  }

  // hop 4 — the artifacts this statement actually attests. Anchors are named
  // but never counted as artifacts: an anchor is the client's own source at
  // the scanned commit, and this system does not serve it (J4).
  const artifacts = input.subjects.filter((s) => !s.isAnchor);
  if (artifacts.length === 0) {
    const anchors = input.subjects.length;
    hops.push({
      kind: "artifact",
      label: "none attested",
      detail:
        anchors > 0
          ? `this verdict rests on ${anchors} anchor file${anchors === 1 ? "" : "s"} rather than a produced artifact — the gate's answer is the observation itself, and the anchors are what drift kills it by`
          : "this statement attests no subject at all",
    });
  } else {
    for (const a of artifacts) {
      hops.push({
        kind: "artifact",
        label: a.name,
        detail: "attested by digest — the viewer re-hashes the bytes before drawing a row",
        digest: a.sha256,
      });
    }
  }

  hops.push({
    kind: "bundle",
    label: "this bundle",
    detail: "the signed statement you are reading — its payload hashes to this address",
    digest: input.digest,
  });

  return hops;
}

/**
 * A call path split into hops with each edge's resolution attached (I3f).
 * Marking every edge is the point: a path is only as strong as its weakest
 * hop, and an unmarked path asks the reader to trust a name match as much as
 * a resolved import.
 *
 * When the marks do not describe this path — a pre-I3f pointer, or a length
 * that disagrees — every edge reads "unmarked" rather than borrowing a
 * neighbour's resolution.
 */
export interface CallPathHop {
  node: string;
  /** the edge that ARRIVES at this node; absent on the root */
  resolution?: "exact" | "inferred" | "unmarked";
}

export function callPathHops(
  callPath: string,
  resolutions?: Array<"exact" | "inferred">,
): CallPathHop[] {
  const nodes = callPath.split(" » ");
  const usable = resolutions !== undefined && resolutions.length === nodes.length - 1;
  return nodes.map((node, i) =>
    i === 0
      ? { node }
      : { node, resolution: usable ? resolutions![i - 1]! : ("unmarked" as const) },
  );
}

/**
 * Tooling health (plan J5): how each tool resolved across the recorded runs,
 * newest first. "When did semgrep stop resolving as a binary?" has a date
 * because every run signed the answer, and this walks them.
 *
 * Strictly historical. The live half — can it run RIGHT NOW — is `doctor`'s
 * job and is not guessed at here: a console that inferred present-tense tool
 * health from the last recorded run would be reporting a probe it never ran.
 */
export interface ToolHealth {
  tool: string;
  /** how it resolved in the newest run that asked for it */
  latest: { runtime: string; version?: string; at: string; runId: string };
  /**
   * The previous DIFFERENT resolution, and the OLDEST recorded run that
   * already showed the current one — which is as precisely as the record can
   * date a change. Dating it at the newest run would claim it happened later
   * than the evidence supports; dating it at the older run would claim the
   * change had already happened when that run still showed the old answer.
   */
  changedAt?: { from: string; since: string; sinceRunId: string };
  /** collectors that asked for it in the newest run that did */
  askedBy: string[];
  /** runs in which it resolved to nothing at all */
  absentRuns: number;
}

function runtimeOf(t: {
  runtime:
    | { kind: "binary"; path?: string }
    | { kind: "docker"; image: string; digest: string | null }
    | { kind: "absent"; reason: string };
}): string {
  if (t.runtime.kind === "docker") return `docker ${t.runtime.image}`;
  if (t.runtime.kind === "binary") return `binary ${t.runtime.path ?? "on PATH"}`;
  return "absent";
}

export function toolHealth(runs: ScanRunRecord[]): ToolHealth[] {
  // newest first, so the first sighting of a tool IS its latest resolution
  const ordered = [...runs].sort(
    (a, b) => b.run_timestamp.localeCompare(a.run_timestamp) || b.run_id.localeCompare(a.run_id),
  );
  const health = new Map<string, ToolHealth>();
  // the oldest run walked so far that still shows the tool's current runtime
  const unchangedSince = new Map<string, { at: string; runId: string }>();
  for (const run of ordered) {
    for (const c of run.collectors) {
      for (const t of c.tools) {
        const runtime = runtimeOf(t);
        const existing = health.get(t.tool);
        if (!existing) {
          health.set(t.tool, {
            tool: t.tool,
            latest: {
              runtime,
              ...(t.version !== undefined ? { version: t.version } : {}),
              at: run.run_timestamp,
              runId: run.run_id,
            },
            askedBy: [c.collector],
            absentRuns: t.runtime.kind === "absent" ? 1 : 0,
          });
          unchangedSince.set(t.tool, { at: run.run_timestamp, runId: run.run_id });
          continue;
        }
        if (t.runtime.kind === "absent") existing.absentRuns += 1;
        if (existing.latest.runId === run.run_id) {
          if (!existing.askedBy.includes(c.collector)) existing.askedBy.push(c.collector);
          continue;
        }
        if (existing.changedAt !== undefined) continue; // the change is already dated
        if (runtime === existing.latest.runtime) {
          // still the current answer — the run of first sight moves back
          unchangedSince.set(t.tool, { at: run.run_timestamp, runId: run.run_id });
        } else {
          const since = unchangedSince.get(t.tool)!;
          existing.changedAt = { from: runtime, since: since.at, sinceRunId: since.runId };
        }
      }
    }
  }
  return [...health.values()].sort((a, b) => a.tool.localeCompare(b.tool));
}

/** where the entry-point set came from, in a sentence the reader can act on */
export function entrypointSourceNote(source: string): string {
  switch (source) {
    case "config":
      return "declared in rampscan.config.json — this repo told the scanner where its entry points are";
    case "package.json":
      return "inferred from package.json (main/module/bin/exports) — nothing declared them, so they were read off the manifest";
    case "fallback":
      return "guessed from conventional filenames (index/main/server/app) — nothing declared them and package.json named none, which is the weakest of the three";
    case "none":
      return "NOT DETECTED — no entry point was found at all, so the walk had no root and could prove nothing unreachable";
    case "unavailable":
      return "no graph was available to this run, so there was no entry-point set to read";
    default:
      return source;
  }
}

/** how strong the ground is, for the reader who reads one word and moves on */
export function basisStrength(basis: ClaimBasisRecord): "weak" | "stated" {
  if (basis.degraded !== undefined) return "weak";
  if (basis.entrypoints.length === 0) return "weak";
  if (basis.entrypoint_source === "fallback" || basis.entrypoint_source === "none") return "weak";
  if ((basis.entrypoints_unresolved?.length ?? 0) > 0) return "weak";
  return "stated";
}
