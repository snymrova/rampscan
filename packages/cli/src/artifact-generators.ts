import type {
  CadenceGap,
  MethodCell,
  MethodRegisterRow,
  RegisterRow,
  ScanRunRow,
  ValidationVulnerability,
} from "@rampscan/core";
import type { ArtifactGenerator, CollectorRun, ToolResolution } from "@rampscan/schema";

// Computed artifact bodies (plan R1.2; SPEC §13.3). Artifact 4 is built first,
// before the easy two, because it is the differentiator and its shape should
// drive the object rather than the reverse.
//
//   default_artifacts.KSI[4] — "Verification that the automation in place is
//   accurate and sufficient to demonstrate appropriate measures for the Key
//   Security Indicator, or that automation is not necessary for each measure."
//
// The first half of that sentence is a question about EXECUTION: which tool
// ran, resolved how, at what version, exiting how, over what, and what the
// result rests on. `ScanRun` (J1) has recorded exactly that since the journal
// landed — every resolution and every invocation, signed, whether the
// collector cooperated or not — so this generator is a rendering of a record
// that already exists rather than a new claim about it. That is the thing no
// GRC platform sitting outside the pipeline can produce honestly, and the
// assessor objection docs/RESEARCH-KSI-FULFILMENT.html recorded.
//
// THE SECOND HALF IS NOT OURS. "automation is not necessary for each measure"
// is the provider's claim about their own risk, and §13.4's rule reaches it:
// where a KSI has no automation, this generator REFUSES and returns a reason
// rather than a body that quietly argues none was needed. An absence with a
// reason is a first-class outcome here; a plausible paragraph is not.
//
// Everything below is a pure function of the fold: the same projection at the
// same instant renders the same bytes, which is the reproducibility §13.3
// requires of a computed artifact and R3's metrics are held to as well.

/** how many entries any one bounded list in a body prints before it counts the rest */
const MAX_LIST = 12;

export interface ArtifactGenerationInput {
  repo: string;
  ksiId: string;
  /** the KSI's row of the method register — its methods and their live state */
  row: MethodRegisterRow;
  /** the recipe register, for the run behind each live cell and its fix pointers */
  registers: readonly RegisterRow[];
  /** the signed execution record, newest first, as the fold projects it */
  scanRuns: readonly ScanRunRow[];
  /** cadence lapses the fold computed (I1d) — artifact 2's honest half */
  gaps?: readonly CadenceGap[];
  /** the failure→vulnerability feed (Q3.5, G13) — artifact 5's honest half */
  vulnerabilities?: readonly ValidationVulnerability[];
  /**
   * Which rule each clock family answers to (§12.2), owed-side data passed in
   * rather than written here: the fold strips a window down to its number and
   * unit, and a rule id invented in this file would be a second copy of a
   * pinned fact. Absent members render the family in plain words instead of
   * citing a rule nobody handed us.
   */
  clockRules?: { machine?: string; nonMachine?: string };
  datasetVersion: string;
}

export type ArtifactGeneration =
  | { generated: true; body: string; generator: ArtifactGenerator }
  /** the honest outcome when there is nothing to compute — never a draft */
  | { generated: false; reason: string };

/** one automated method, joined to the run record that produced its live evidence */
interface AutomatedMeasure {
  cell: MethodCell;
  register?: RegisterRow;
  run?: ScanRunRow;
  collectorRun?: CollectorRun;
}

function describeRuntime(resolution: ToolResolution): string {
  const runtime = resolution.runtime;
  if (runtime.kind === "binary") {
    return runtime.path === undefined ? "binary on PATH" : `binary ${runtime.path}`;
  }
  if (runtime.kind === "docker") {
    return runtime.digest === null
      ? `image ${runtime.image} (digest unresolved: ${runtime.digest_reason ?? "no reason recorded"})`
      : `image ${runtime.image} @ ${runtime.digest}`;
  }
  return `did not resolve: ${runtime.reason}`;
}

function toolLabel(resolution: ToolResolution): string {
  return `${resolution.tool} ${resolution.version ?? "(version unreported)"}`;
}

/** bounded, deterministic list rendering — "+N more" rather than a truncation nobody sees */
function bulletList(items: readonly string[]): string[] {
  if (items.length <= MAX_LIST) return items.map((i) => `- ${i}`);
  return [
    ...items.slice(0, MAX_LIST).map((i) => `- ${i}`),
    `- …and ${items.length - MAX_LIST} more, in the run record`,
  ];
}

export function generateArtifact4(input: ArtifactGenerationInput): ArtifactGeneration {
  const registerByRecipe = new Map(
    input.registers.filter((r) => r.repo === input.repo).map((r) => [r.recipeId, r]),
  );
  const runById = new Map(input.scanRuns.filter((r) => r.repo === input.repo).map((r) => [r.runId, r]));

  const automated = input.row.methods.filter((m) => m.automated);
  const manual = input.row.methods.filter((m) => !m.automated);

  // §13.4 in force: with no automation there is nothing whose accuracy this
  // document could verify, and the rule's alternative — "automation is not
  // necessary for each measure" — is the provider's claim about their own
  // risk. rampscan states the absence and stops.
  if (automated.length === 0) {
    return {
      generated: false,
      reason:
        `${input.ksiId} has no automated measure, so there is no automation whose accuracy ` +
        `this artifact could verify. The rule's other half — that automation is not necessary ` +
        `here — is a claim about your risk, and rampscan does not write it (SPEC §13.4).`,
    };
  }

  const measures: AutomatedMeasure[] = automated.map((cell) => {
    const measure: AutomatedMeasure = { cell };
    const register = cell.recipeId === undefined ? undefined : registerByRecipe.get(cell.recipeId);
    if (register !== undefined) measure.register = register;
    const run = register?.runId === undefined ? undefined : runById.get(register.runId);
    if (run !== undefined) {
      measure.run = run;
      // the collector named on the method, matched in the run that produced
      // this cell's live evidence — never the newest run that happens to
      // mention the collector, which would date the automation wrongly
      const collectorRun = run.collectors.find((c) => c.collector === cell.collector);
      if (collectorRun !== undefined) measure.collectorRun = collectorRun;
    }
    return measure;
  });

  const cited = measures.filter((m): m is AutomatedMeasure & { run: ScanRunRow } => m.run !== undefined);
  if (cited.length === 0) {
    return {
      generated: false,
      reason:
        `${input.ksiId} has ${automated.length} automated measure(s), but the ledger holds no ` +
        `signed execution record behind any of them — there is nothing to verify the accuracy ` +
        `of yet. Run a scan and the run record will be there.`,
    };
  }

  // newest first in the projection, so the first cited run is the newest
  const newestRun = cited
    .map((m) => m.run)
    .sort((a, b) => b.timestamp.localeCompare(a.timestamp))[0]!;

  const lines: string[] = [];
  lines.push(`## Automation behind ${input.ksiId}`);
  lines.push("");
  lines.push(
    `Computed by rampscan from the signed execution record in its own ledger — the tool ` +
      `resolutions and process invocations recorded while the measures below were produced. ` +
      `Nothing here is asserted: every statement is a reading of a run record that can be ` +
      `verified offline against its own signature.`,
  );
  lines.push("");

  lines.push(
    `**${automated.length} of ${input.row.methods.length} measure(s) for this indicator are automated.**`,
  );
  lines.push("");

  lines.push("### What produces each automated measure");
  lines.push("");
  const produced: string[] = [];
  for (const measure of measures) {
    const { cell, collectorRun, run } = measure;
    const where = cell.collector ?? "collector not named in the catalog";
    if (run === undefined || collectorRun === undefined) {
      // Two different absences, said differently. A measure with no live
      // evidence has not run; a measure WITH live evidence whose run record
      // cannot be found ran before the journal existed, or under a record the
      // ledger no longer carries. Collapsing them would let "nothing has been
      // measured" read as "the paperwork is behind".
      produced.push(
        cell.bundleDigest === undefined
          ? `\`${cell.methodId}\` — ${where}: nothing has run for this measure, so there is no ` +
              `execution to verify`
          : `\`${cell.methodId}\` — ${where}: evidence stands, but no signed execution record ` +
              `in this ledger accounts for it`,
      );
      continue;
    }
    const tools =
      collectorRun.tools.length === 0
        ? "no external tool — rampscan reads the repository itself"
        : [...collectorRun.tools]
            .sort((a, b) => a.tool.localeCompare(b.tool))
            .map((t) => `${toolLabel(t)} (${describeRuntime(t)})`)
            .join("; ");
    const spawned =
      collectorRun.invocations.length === 0
        ? "spawned nothing"
        : `${collectorRun.invocations.length} invocation(s), exit ${[
            ...new Set(collectorRun.invocations.map((i) => i.exit_code)),
          ]
            .sort((a, b) => a - b)
            .join("/")}`;
    produced.push(
      `\`${cell.methodId}\` — ${where} ${collectorRun.tool_version}: ${tools}; ${spawned}; ` +
        `run ${run.runId} at ${run.timestamp} (record ${run.digest.slice(0, 12)}…)`,
    );
  }
  lines.push(...bulletList(produced));
  lines.push("");

  // ── the limits: what this automation does NOT establish ──────────────────
  const limits: string[] = [];

  const unevidenced = measures.filter((m) => m.cell.bundleDigest === undefined);
  if (unevidenced.length > 0) {
    limits.push(
      `${unevidenced.length} automated measure(s) hold no live evidence, so there is no ` +
        `execution behind them to judge: ${unevidenced
          .map((m) => `\`${m.cell.methodId}\``)
          .join(", ")}`,
    );
  }

  const unaccounted = measures.filter(
    (m) => m.cell.bundleDigest !== undefined && m.collectorRun === undefined,
  );
  if (unaccounted.length > 0) {
    limits.push(
      `${unaccounted.length} measure(s) hold live evidence that no run record in this ledger ` +
        `accounts for — their accuracy cannot be read from an execution record that is not ` +
        `here: ${unaccounted.map((m) => `\`${m.cell.methodId}\``).join(", ")}`,
    );
  }

  const skipped = measures.filter((m) => m.collectorRun?.skip_reason !== undefined);
  for (const measure of skipped) {
    limits.push(
      `\`${measure.cell.methodId}\` — the collector did not run: ${measure.collectorRun!.skip_reason!}`,
    );
  }

  const absentTools = new Set<string>();
  const unpinnedImages = new Set<string>();
  for (const measure of measures) {
    for (const resolution of measure.collectorRun?.tools ?? []) {
      if (resolution.runtime.kind === "absent") {
        absentTools.add(`${resolution.tool} — ${resolution.runtime.reason}`);
      }
      if (resolution.runtime.kind === "docker" && resolution.runtime.digest === null) {
        unpinnedImages.add(
          `${resolution.tool} ran from ${resolution.runtime.image} with the tag unresolved to a ` +
            `digest (${resolution.runtime.digest_reason ?? "no reason recorded"}), so the version ` +
            `pin is a tag rather than content`,
        );
      }
    }
  }
  for (const entry of [...absentTools].sort()) {
    limits.push(`a tool did not resolve, so nothing it would have measured was measured: ${entry}`);
  }
  for (const entry of [...unpinnedImages].sort()) limits.push(entry);

  const cacheHits = measures.filter((m) => m.collectorRun?.cache.state === "hit");
  if (cacheHits.length > 0) {
    limits.push(
      `${cacheHits.length} measure(s) were served from cache on their recorded run — nothing was ` +
        `spawned then, and the invocations above are those of the earlier run that produced the ` +
        `cached result: ${cacheHits.map((m) => `\`${m.cell.methodId}\``).join(", ")}`,
    );
  }

  const failedExits = measures.filter((m) =>
    (m.collectorRun?.invocations ?? []).some((i) => i.exit_code !== 0),
  );
  if (failedExits.length > 0) {
    limits.push(
      `${failedExits.length} measure(s) recorded a non-zero tool exit — a tool that exited badly ` +
        `may have measured less than the whole of what it was pointed at: ${failedExits
          .map((m) => `\`${m.cell.methodId}\``)
          .join(", ")}`,
    );
  }

  // the graph's exact-vs-inferred edge labels (I3f): a call path is only as
  // good as its weakest hop, and a chain of matching NAMES is not a chain of
  // resolved calls. Counted here because accuracy is exactly what artifact 4
  // is asked about.
  let inferredHops = 0;
  let pathsWithInference = 0;
  for (const measure of measures) {
    for (const pointer of measure.register?.pointers ?? []) {
      const hops = pointer.call_path_resolutions ?? [];
      const inferred = hops.filter((h) => h === "inferred").length;
      if (inferred > 0) {
        inferredHops += inferred;
        pathsWithInference += 1;
      }
    }
  }
  if (pathsWithInference > 0) {
    limits.push(
      `${inferredHops} hop(s) across ${pathsWithInference} call path(s) were matched by NAME ` +
        `rather than resolved to a file the walk saw — those paths say a chain of these names ` +
        `exists, not that this call chain does`,
    );
  }

  if (manual.length > 0) {
    limits.push(
      `${manual.length} measure(s) for this indicator are not automated at all ` +
        `(${manual.map((m) => `\`${m.methodId}\``).join(", ")}). This document does not claim ` +
        `automation is unnecessary for them — that half of the rule is a judgment about your ` +
        `risk, and rampscan does not write it.`,
    );
  }

  lines.push("### What this automation does not establish");
  lines.push("");
  lines.push(
    ...(limits.length === 0
      ? [
          "- every automated measure above ran, resolved its tools, and exited cleanly on the " +
            "run recorded beside it",
        ]
      : bulletList(limits)),
  );
  lines.push("");
  lines.push(
    `Verify any line of this yourself: \`rampscan verify ${newestRun.digest.slice(0, 12)}…\` ` +
      `renders the run record this body was computed from.`,
  );

  const toolVersions: Record<string, string> = {};
  for (const measure of measures) {
    for (const resolution of measure.collectorRun?.tools ?? []) {
      if (resolution.version !== undefined) toolVersions[resolution.tool] = resolution.version;
    }
    if (measure.collectorRun !== undefined) {
      toolVersions[measure.collectorRun.collector] = measure.collectorRun.tool_version;
    }
  }

  return {
    generated: true,
    body: lines.join("\n"),
    generator: {
      pins: {
        dataset: input.datasetVersion,
        // the run whose record this body cites newest; every run it cites is
        // named in the body with its own digest, because a KSI's measures can
        // come from different runs and one pointer cannot honestly cover them
        run: newestRun.runId,
        commit: newestRun.commit,
      },
      tool_versions: Object.fromEntries(
        Object.entries(toolVersions).sort(([a], [b]) => a.localeCompare(b)),
      ),
      journal_digest: newestRun.digest,
    },
  };
}

// ---------------------------------------------------------------------------
// Artifact 2 — the cycle (plan R1.3)
//
//   default_artifacts.KSI[2] — "Explanation of the cycle for any measures that
//   are implemented persistently (if applicable)."
//
// The cycle is the scheduler's own contract, and the ledger has been recording
// how it actually ran since M2. Both halves go in the body, because they are
// different facts: the cadence a recipe DECLARES and the window a rule OWES
// are the schedule; the timestamps in the chain are the repetitions that
// happened. A document that printed only the first would be a plan, and
// `SDR-CSX-KSI` item 2 is not asking for a plan.
//
// "(if applicable)" is the provider's call, exactly as artifact 4's second
// half is: where no measure has ever run, this refuses rather than explaining
// why a cycle was not needed.

/** how a measure's owed window reads, cited to the rule that owes it */
function describeWindow(cell: MethodCell, rules: { machine?: string; nonMachine?: string }): string {
  const rule = cell.clock === "machine" ? rules.machine : rules.nonMachine;
  const family = cell.clock === "machine" ? "the machine cadence" : "the non-machine cadence";
  if (cell.window === null) {
    return `no re-validation window was given to this fold for ${rule ?? family}`;
  }
  return `owed every ${cell.window.num} ${cell.window.unit} under ${rule ?? family}`;
}

export function generateArtifact2(input: ArtifactGenerationInput): ArtifactGeneration {
  const rules = input.clockRules ?? {};
  const methods = input.row.methods;
  // "implemented persistently" is a claim about repetition, so it is read from
  // the measures that have actually run: a method with no evidence keeps no
  // cycle, whatever its declared cadence says it would keep.
  const running = methods.filter((m) => m.freshAsOf !== undefined);
  if (running.length === 0) {
    return {
      generated: false,
      reason:
        `no measure for ${input.ksiId} has run even once, so there is no cycle to explain. ` +
        `Whether one is applicable here — the rule's own "(if applicable)" — is a claim about ` +
        `your implementation, and rampscan does not write it (SPEC §13.4).`,
    };
  }

  const registerByRecipe = new Map(
    input.registers.filter((r) => r.repo === input.repo).map((r) => [r.recipeId, r]),
  );
  const recipeIds = new Set(
    methods.map((m) => m.recipeId).filter((id): id is string => id !== undefined),
  );

  const lines: string[] = [];
  lines.push(`## The validation cycle behind ${input.ksiId}`);
  lines.push("");
  lines.push(
    `Computed by rampscan from the pinned cadence rules and its own ledger's record of when each ` +
      `measure last ran. A cycle is a claim about repetition, so what follows is read from the ` +
      `repetitions that are recorded — not from the schedule anyone intended to keep.`,
  );
  lines.push("");
  lines.push(
    `**${running.length} of ${methods.length} measure(s) for this indicator have run at least once.**`,
  );
  lines.push("");

  lines.push("### The cycle each keeps");
  lines.push("");
  lines.push(
    ...bulletList(
      running.map((cell) => {
        const register = cell.recipeId === undefined ? undefined : registerByRecipe.get(cell.recipeId);
        const declared =
          register?.cadence === undefined
            ? "no cadence declared in the catalog"
            : `declared cadence ${register.cadence}`;
        const standing =
          cell.freshMet === null
            ? "nothing to judge it against"
            : cell.freshMet
              ? "inside its window"
              : "PAST its window";
        return (
          `\`${cell.methodId}\` — ${declared}; ${describeWindow(cell, rules)}; last validated ` +
          `${cell.freshAsOf}, ${standing}`
        );
      }),
    ),
  );
  lines.push("");

  // The lapses, from the fold's own cadence-gap computation (I1d): intervals
  // where a cell sat past its owed window unrefreshed. This is the half a
  // schedule cannot supply and the half an assessor is actually asking about.
  const gaps = (input.gaps ?? []).filter(
    (g) => g.repo === input.repo && recipeIds.has(g.recipeId),
  );
  lines.push("### Where the cycle has lapsed");
  lines.push("");
  if (gaps.length === 0) {
    const noWindow = running.every((m) => m.window === null);
    lines.push(
      noWindow
        ? "- no re-validation window was given to this fold, so no lapse can be computed — this " +
            "section states nothing rather than reporting a clean record it never checked"
        : "- no interval past the owed window is recorded for these measures",
    );
  } else {
    const byRecipe = new Map<string, CadenceGap[]>();
    for (const gap of gaps) {
      (byRecipe.get(gap.recipeId) ?? byRecipe.set(gap.recipeId, []).get(gap.recipeId)!).push(gap);
    }
    lines.push(
      ...bulletList(
        [...byRecipe.entries()]
          .sort(([a], [b]) => a.localeCompare(b))
          .map(([recipeId, list]) => {
            const longest = [...list].sort((a, b) => b.durationMs - a.durationMs)[0]!;
            const days = Math.round(longest.durationMs / 86_400_000);
            return (
              `\`${recipeId}\` — ${list.length} interval(s) past the owed window; the longest ran ` +
              `${longest.start} → ${longest.end} (${days}d)` +
              (longest.ongoing ? ", and is still open" : "")
            );
          }),
      ),
    );
  }
  lines.push("");

  const limits: string[] = [];
  const never = methods.filter((m) => m.freshAsOf === undefined);
  if (never.length > 0) {
    limits.push(
      `${never.length} measure(s) have never run, so they keep no cycle yet: ${never
        .map((m) => `\`${m.methodId}\``)
        .join(", ")}`,
    );
  }
  const scoped = methods.filter((m) => m.state === "notApplicable");
  if (scoped.length > 0) {
    limits.push(
      `${scoped.length} measure(s) stand scoped not-applicable by a signed two-key decision — a ` +
        `cycle is not owed where the decision says the measure is not: ${scoped
          .map((m) => `\`${m.methodId}\``)
          .join(", ")}`,
    );
  }
  if (limits.length > 0) {
    lines.push("### What this does not say");
    lines.push("");
    lines.push(...bulletList(limits));
    lines.push("");
  }

  const newest = running
    .map((m) => m.freshAsOf!)
    .sort()
    .at(-1)!;
  return {
    generated: true,
    body: lines.join("\n").trimEnd(),
    generator: {
      pins: { dataset: input.datasetVersion, freshest: newest },
      tool_versions: {},
    },
  };
}

// ---------------------------------------------------------------------------
// Artifact 5 — validation (plan R1.3)
//
//   default_artifacts.KSI[5] — "Validation that the measures are accurately
//   produced and are in place and working as intended, or that the reason for
//   not having them is valid."
//
// This is the register, read out. "In place and working as intended" is the
// verdict standing on each measure; "accurately produced" is what the verdict
// was reached OVER, which is why the population rides every line — evidenced
// over 412 dependencies and evidenced over none are the same word for very
// different facts, and a body that printed only the word would be the second
// of those pretending to be the first.
//
// The rule's other half — "or that the reason for not having them is valid" —
// is a judgment, and the only form of it this body carries is a SIGNED
// two-key scoping quoted with its approver. Quoting a recorded decision is not
// making one, and the body says which it is doing.

export function generateArtifact5(input: ArtifactGenerationInput): ArtifactGeneration {
  const methods = input.row.methods;
  const live = methods.filter((m) => m.bundleDigest !== undefined);
  if (live.length === 0) {
    return {
      generated: false,
      reason:
        `no measure for ${input.ksiId} holds live evidence, so there is nothing whose production ` +
        `or standing this artifact could validate. The rule's other half — that the reason for ` +
        `not having measures is valid — is a claim about your risk, and rampscan does not write ` +
        `it (SPEC §13.4).`,
    };
  }

  const registerByRecipe = new Map(
    input.registers.filter((r) => r.repo === input.repo).map((r) => [r.recipeId, r]),
  );

  const lines: string[] = [];
  lines.push(`## Validation standing behind ${input.ksiId}`);
  lines.push("");
  lines.push(
    `Computed by rampscan from the signed evidence in its own ledger: what each measure currently ` +
      `says, what it was reached over, and what kind of evidence it is. Every line below resolves ` +
      `to a bundle that verifies offline against its own signature.`,
  );
  lines.push("");
  lines.push(
    `**${live.length} of ${methods.length} measure(s) hold live evidence.**`,
  );
  lines.push("");

  lines.push("### What each measure currently says");
  lines.push("");
  lines.push(
    ...bulletList(
      methods.map((cell) => {
        const register = cell.recipeId === undefined ? undefined : registerByRecipe.get(cell.recipeId);
        const parts: string[] = [cell.state];
        if (register?.population !== undefined) {
          parts.push(
            register.population === 0
              ? "over NOTHING — the check found no row to evaluate"
              : `over ${register.population} observation(s)`,
          );
        }
        parts.push(cell.evidenceClass ?? "evidence class unasserted");
        if (cell.freshAsOf !== undefined) {
          parts.push(
            `validated ${cell.freshAsOf}` +
              (cell.freshMet === false ? " (past its window)" : ""),
          );
        }
        if (cell.bundleDigest !== undefined) parts.push(`bundle ${cell.bundleDigest.slice(0, 12)}…`);
        return `\`${cell.methodId}\` — ${parts.join("; ")}`;
      }),
    ),
  );
  lines.push("");

  const recipeIds = new Set(
    methods.map((m) => m.recipeId).filter((id): id is string => id !== undefined),
  );
  const failures = (input.vulnerabilities ?? []).filter(
    (v) => v.repo === input.repo && recipeIds.has(v.recipeId),
  );
  const open = failures.filter((v) => v.status === "open");
  if (failures.length > 0) {
    lines.push("### Where validation has failed");
    lines.push("");
    lines.push(
      ...bulletList(
        [...failures]
          .sort((a, b) => b.detectedAt.localeCompare(a.detectedAt))
          .map(
            (v) =>
              `\`${v.recipeId}\` — failed at ${v.detectedAt} (commit ${v.commit.slice(0, 12)}), ` +
              (v.status === "open"
                ? "still OPEN"
                : `resolved ${v.resolvedAt} by ${v.resolvingDigest?.slice(0, 12) ?? "a later bundle"}…`),
          ),
      ),
    );
    lines.push("");
  }

  const limits: string[] = [];
  const unevidenced = methods.filter((m) => m.state === "unevidenced");
  if (unevidenced.length > 0) {
    limits.push(
      `${unevidenced.length} measure(s) hold no live evidence at all, so nothing here validates ` +
        `them: ${unevidenced.map((m) => `\`${m.methodId}\``).join(", ")}`,
    );
  }
  if (open.length > 0) {
    limits.push(
      `${open.length} validation failure(s) are still open — these measures are in place and are ` +
        `NOT working as intended, and this document says so rather than averaging it away`,
    );
  }
  const pointInTime = live.filter((m) => m.evidenceClass === "point-in-time");
  const processGenerated = live.filter((m) => m.evidenceClass === "process-generated");
  if (pointInTime.length > 0 && processGenerated.length === 0) {
    limits.push(
      `every live measure here is point-in-time evidence with nothing process-generated beside ` +
        `it — FRR-PVA-AA-06 instructs assessors to reject point-in-time evidence as STANDALONE ` +
        `evidence, and this document does not pretend otherwise`,
    );
  }
  const unlabelled = live.filter((m) => m.evidenceClass === undefined);
  if (unlabelled.length > 0) {
    limits.push(
      `${unlabelled.length} live measure(s) assert no evidence class — an unlabelled bundle ` +
        `neither claims to be process-generated nor admits to being point-in-time`,
    );
  }
  const scoped = methods.filter((m) => m.state === "notApplicable");
  for (const cell of scoped) {
    const scoping = cell.recipeId === undefined ? undefined : registerByRecipe.get(cell.recipeId)?.scoping;
    limits.push(
      scoping === undefined
        ? `\`${cell.methodId}\` stands not-applicable`
        : `\`${cell.methodId}\` stands not-applicable by a signed decision of ${scoping.approvedBy} ` +
            `on ${scoping.timestamp}: "${scoping.justification}". rampscan records that decision ` +
            `and does not endorse it — whether the reason is valid is the approver's claim, and ` +
            `their name is on it`,
    );
  }
  if (limits.length > 0) {
    lines.push("### What this does not say");
    lines.push("");
    lines.push(...bulletList(limits));
  }

  const newest = live
    .map((m) => m.freshAsOf)
    .filter((t): t is string => t !== undefined)
    .sort()
    .at(-1);
  return {
    generated: true,
    body: lines.join("\n").trimEnd(),
    generator: {
      pins: {
        dataset: input.datasetVersion,
        ...(newest !== undefined ? { freshest: newest } : {}),
      },
      tool_versions: {},
    },
  };
}
