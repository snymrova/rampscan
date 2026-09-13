import type { ArtifactCell, MethodRegisterRow } from "@rampscan/core";
import type { KsiCatalog, OfferingClass } from "@rampscan/dataset";
import { optionalKsis, requiredKsis } from "@rampscan/dataset";

// `rampscan artifacts` (plan R1.5, §6): 46 rows, five cells each, every cell
// naming its source and its age.
//
// The empty cells are a WORK QUEUE WITH A COMMAND ATTACHED, not a scold. That
// is the whole design brief for this view: a provider opening it should be able
// to tell, per slot, whether the next move is theirs or the appliance's — and
// for the two slots that are theirs (§13.4), the view says so in those words
// rather than printing a red mark and leaving them to guess.
//
// A pure derivation in the shape of `owed` and `frontier`: nothing probed,
// nothing written, no clock read that the fold did not already resolve.

/** how a filled cell's source reads, short enough for five columns */
const SOURCE_LABEL: Record<string, string> = {
  authored: "auth",
  computed: "comp",
  attested: "attn",
  assessed: "assd",
};

export interface ArtifactSlotView {
  artifact: 1 | 2 | 3 | 4 | 5;
  /** the rule's own text for this slot, from default_artifacts.KSI */
  owed: string;
  present: boolean;
  source?: string;
  /** the ledger address of the body, when one stands */
  digest?: string;
  bodyDigest?: string;
  bodyBytes?: number;
  validFrom?: string;
  /** the body has aged past VDR-TFR-NMV; null when the fold judged no window */
  fresh?: boolean | null;
  anchor?: { commit: string; path: string };
  supersedes?: string;
  reviewed?: boolean;
  /** the fold can generate this body and nobody has (2, 4, 5 only) */
  derivable?: boolean;
  /** a body stood here and a scan found its declaration unresolvable */
  absent?: { reason: string; at: string; path: string };
  judgment?: { action: "sufficient" | "insufficient"; appliesToLiveBody: boolean };
  /** what to run next, when the next move is anyone's — the queue's command */
  next?: string;
}

export interface ArtifactRowView {
  ksi: string;
  name: string;
  optional: boolean;
  slots: ArtifactSlotView[];
  filled: number;
}

export interface ArtifactsView {
  repo: string | null;
  offeringClass: OfferingClass;
  datasetVersion: string;
  rows: ArtifactRowView[];
  summary: {
    /** slots owed at this class: obliged KSIs × 5 */
    owed: number;
    filled: number;
    /** slots rampscan may compute and has not (§13.4's 2, 4, 5) */
    derivable: number;
    /** slots only the provider can write (§13.4's 1 and 3), still empty */
    yours: number;
    /** bodies whose declaration a later scan could not resolve */
    lost: number;
    /** bodies past their three-month VDR-TFR-NMV window */
    stale: number;
    optional: readonly string[];
  };
}

function slotOf(
  artifact: 1 | 2 | 3 | 4 | 5,
  owed: string,
  cell: ArtifactCell | undefined,
  ksi: string,
): ArtifactSlotView {
  const slot: ArtifactSlotView = { artifact, owed, present: cell?.present ?? false };
  if (cell === undefined) return slot;
  if (cell.body !== undefined) {
    slot.source = cell.body.source;
    slot.digest = cell.body.digest;
    slot.bodyDigest = cell.body.bodyDigest;
    slot.bodyBytes = cell.body.bodyBytes;
    slot.validFrom = cell.body.validFrom;
    slot.fresh = cell.body.freshMet;
    if (cell.body.anchor !== undefined) slot.anchor = cell.body.anchor;
    if (cell.body.supersedes !== undefined) slot.supersedes = cell.body.supersedes;
    if (cell.body.reviewed !== undefined) slot.reviewed = cell.body.reviewed;
  }
  if (cell.derivable !== undefined) slot.derivable = cell.derivable;
  if (cell.absent !== undefined) slot.absent = cell.absent;
  if (cell.judgment !== undefined) {
    slot.judgment = {
      action: cell.judgment.action,
      appliesToLiveBody: cell.judgment.appliesToLiveBody,
    };
  }

  // The command attached to the queue. Which one it is follows §13.4 exactly:
  // 1 and 3 are the provider's own claims and no amount of evidence produces
  // them, so the only honest instruction is the scaffold; 2, 4 and 5 the
  // appliance can compute the moment it has the material.
  if (!slot.present) {
    if (artifact === 1 || artifact === 3) {
      slot.next = `rampscan artifacts scaffold ${ksi} --artifact ${artifact}`;
    } else if (cell.derivable === true) {
      slot.next = `rampscan artifacts generate ${ksi} --artifact ${artifact}`;
    }
  }
  return slot;
}

export function buildArtifactsView(input: {
  catalog: KsiCatalog;
  offeringClass: OfferingClass;
  /** the repo whose board this is; null when the ledger holds none */
  repo: string | null;
  methodRegisters: readonly MethodRegisterRow[];
}): ArtifactsView {
  const optional = new Set(optionalKsis(input.catalog, input.offeringClass));
  const byKsi = new Map(
    input.methodRegisters
      .filter((r) => input.repo === null || r.repo === input.repo)
      .map((r) => [r.ksi, r]),
  );

  const rows: ArtifactRowView[] = input.catalog.ksis.map((ksi) => {
    const register = byKsi.get(ksi.id);
    const cells = new Map((register?.artifacts ?? []).map((a) => [a.artifact, a]));
    const slots = ([1, 2, 3, 4, 5] as const).map((n) =>
      slotOf(n, input.catalog.defaultArtifacts[n - 1] ?? "", cells.get(n), ksi.id),
    );
    return {
      ksi: ksi.id,
      name: ksi.name,
      optional: optional.has(ksi.id),
      slots,
      filled: slots.filter((s) => s.present).length,
    };
  });

  // The denominator is the obliged KSIs only (§13.7): an optional indicator
  // keeps its row and leaves the meter, exactly as it does on the frontier.
  const obliged = rows.filter((r) => !r.optional);
  const everySlot = obliged.flatMap((r) => r.slots);
  return {
    repo: input.repo,
    offeringClass: input.offeringClass,
    datasetVersion: input.catalog.datasetVersion,
    rows,
    summary: {
      owed: requiredKsis(input.catalog, input.offeringClass).length * 5,
      filled: everySlot.filter((s) => s.present).length,
      derivable: everySlot.filter((s) => !s.present && s.derivable === true).length,
      yours: everySlot.filter((s) => !s.present && (s.artifact === 1 || s.artifact === 3)).length,
      lost: everySlot.filter((s) => s.absent !== undefined).length,
      stale: everySlot.filter((s) => s.present && s.fresh === false).length,
      optional: rows.filter((r) => r.optional).map((r) => r.ksi),
    },
  };
}

/** compact age, in the units a reader of a three-month clock thinks in */
export function age(from: string, now: Date): string {
  const ms = now.getTime() - Date.parse(from);
  if (!Number.isFinite(ms) || ms < 0) return "—";
  const hours = Math.floor(ms / 3_600_000);
  if (hours < 24) return `${hours}h`;
  const days = Math.floor(hours / 24);
  if (days < 60) return `${days}d`;
  return `${Math.floor(days / 30)}mo`;
}

function cellToken(slot: ArtifactSlotView, now: Date): string {
  if (slot.present) {
    const label = SOURCE_LABEL[slot.source ?? ""] ?? "body";
    // `!` is the three-month clock, not a verdict: the body is there and it
    // has not been revisited inside the window VDR-TFR-NMV owes
    return `${label} ${slot.validFrom === undefined ? "—" : age(slot.validFrom, now)}${slot.fresh === false ? "!" : ""}`;
  }
  if (slot.absent !== undefined) return "gone";
  if (slot.judgment?.action === "insufficient" && slot.judgment.appliesToLiveBody) return "insuf";
  if (slot.derivable === true) return "deriv";
  return "—";
}

const COL = 11;

export function renderArtifacts(view: ArtifactsView, now: Date): string {
  const lines: string[] = [
    "rampscan artifacts — the five owed per KSI (SDR-CSX-KSI)",
    `class ${view.offeringClass} · dataset ${view.datasetVersion} · ` +
      (view.repo === null ? "no repo in the ledger" : `repo ${view.repo}`),
    "",
    `  ${"KSI".padEnd(17)}${["1 explain", "2 cycle", "3 verify", "4 automation", "5 validate"]
      .map((h) => h.padEnd(COL + 2))
      .join("")}`,
  ];
  for (const row of view.rows) {
    lines.push(
      `  ${row.ksi.padEnd(17)}${row.slots
        .map((s) => cellToken(s, now).padEnd(COL + 2))
        .join("")}${row.optional ? " optional at this class" : ""}`,
    );
  }

  const s = view.summary;
  lines.push(
    "",
    `  ${s.filled} of ${s.owed} owed slot(s) filled at class ${view.offeringClass}`,
    `  ${s.yours} empty slot(s) are yours to write — 1 and 3 are the provider's own claims,`,
    "    and rampscan will not draft them (SPEC §13.4):",
    "      rampscan artifacts scaffold <KSI>",
  );
  if (s.derivable > 0) {
    lines.push(
      `  ${s.derivable} empty slot(s) the fold can compute now:`,
      "      rampscan artifacts generate <KSI>",
    );
  }
  if (s.lost > 0) {
    lines.push(
      `  ${s.lost} slot(s) held a body that a later scan could not resolve — 'gone' above;`,
      "    `rampscan artifacts show <KSI>` prints what happened to each",
    );
  }
  if (s.stale > 0) {
    lines.push(
      `  ${s.stale} body(ies) are past VDR-TFR-NMV's three months — marked '!' above. A written`,
      "    artifact is not done: SDR-CSX-KSI item 2 asks for the cycle",
    );
  }
  if (s.optional.length > 0) {
    lines.push(
      `  ${s.optional.length} optional at class ${view.offeringClass}, outside the meter above — ${s.optional.join(", ")}`,
    );
  }
  lines.push(
    "",
    "  auth/comp/attn/assd = authored · computed · attested · assessed",
    "  deriv = computable now · gone = the body's declaration stopped resolving",
    "  insuf = a body stands and two keys judged it insufficient · ! = past its clock",
    "",
  );
  return lines.join("\n");
}

/** `rampscan artifacts show <KSI>` — one indicator, its five slots in full */
export function renderArtifact(
  view: ArtifactsView,
  row: ArtifactRowView,
  now: Date,
): string {
  const lines: string[] = [
    `rampscan artifacts ${row.ksi} — the five owed (SDR-CSX-KSI)`,
    `class ${view.offeringClass} · dataset ${view.datasetVersion} · ` +
      (view.repo === null ? "no repo in the ledger" : `repo ${view.repo}`),
    "",
    `  ${row.name}${row.optional ? "   (optional at this class)" : ""}`,
    "",
  ];
  for (const slot of row.slots) {
    lines.push(`  ${slot.artifact} · ${slot.owed}`);
    if (slot.present) {
      const parts = [
        slot.source ?? "unknown source",
        slot.bodyBytes === undefined ? "" : `${slot.bodyBytes} bytes`,
        slot.validFrom === undefined
          ? ""
          : `clock from ${slot.validFrom.slice(0, 10)} (${age(slot.validFrom, now)}${
              slot.fresh === false ? ", PAST VDR-TFR-NMV" : slot.fresh === true ? ", inside VDR-TFR-NMV" : ""
            })`,
      ].filter((p) => p.length > 0);
      lines.push(`      ${parts.join(" · ")}`);
      if (slot.anchor !== undefined) {
        lines.push(`      ${slot.anchor.path} @ ${slot.anchor.commit.slice(0, 12)}`);
      }
      lines.push(
        `      body ${slot.bodyDigest?.slice(0, 16) ?? "—"}… · statement ${slot.digest?.slice(0, 16) ?? "—"}…` +
          (slot.supersedes === undefined ? "" : ` · supersedes ${slot.supersedes.slice(0, 12)}…`),
      );
      // §13.2: a review's absence is PRINTED rather than assumed benign
      lines.push(`      review ${slot.reviewed === true ? "on record" : "none on record"}`);
      if (slot.judgment !== undefined) {
        lines.push(
          `      judged ${slot.judgment.action}` +
            (slot.judgment.appliesToLiveBody
              ? ""
              : " — about bytes that have since been revised, so it decides nothing here"),
        );
      }
    } else if (slot.absent !== undefined) {
      lines.push(
        `      GONE — ${slot.absent.reason} (${slot.absent.path}, seen ${slot.absent.at.slice(0, 10)})`,
      );
    } else if (slot.derivable === true) {
      lines.push("      no body yet, and the fold holds the material to compute one");
    } else if (slot.artifact === 1 || slot.artifact === 3) {
      lines.push("      no body. This one is yours to write — rampscan does not draft it (§13.4)");
    } else {
      lines.push("      no body, and nothing to compute one from yet");
    }
    if (slot.next !== undefined) lines.push(`      → ${slot.next}`);
    lines.push("");
  }
  return lines.join("\n");
}

// ---------------------------------------------------------------------------
// `rampscan artifacts check` (plan R1.5)
//
// The distinction that makes this command worth having beside `frontier`:
// FRONTIER SAYS HOW MUCH IS OWED, CHECK SAYS WHETHER WHAT EXISTS IS SOUND. A
// gate that failed on an unfilled slot would fail on every repository from the
// day it is installed until the day the last artifact is written, and a gate
// that is always red is a gate nobody reads. So an empty slot is not a finding
// here — it is the work queue `list` prints. What IS a finding is a plane that
// has gone wrong: a declaration that stopped resolving, a judgment about bytes
// nobody can read any more, a body that has aged out of the window the rule
// owes, or prose that outgrew what the rule asked for.

export interface ArtifactProblem {
  ksi: string;
  artifact: 1 | 2 | 3 | 4 | 5;
  /** what is wrong, in a sentence an operator can act on */
  problem: string;
}

export function checkArtifacts(view: ArtifactsView): ArtifactProblem[] {
  const problems: ArtifactProblem[] = [];
  for (const row of view.rows) {
    for (const slot of row.slots) {
      if (slot.absent !== undefined) {
        problems.push({
          ksi: row.ksi,
          artifact: slot.artifact,
          problem:
            `a body stood here and its declaration stopped resolving: ${slot.absent.reason} ` +
            `(${slot.absent.path}, seen ${slot.absent.at.slice(0, 10)})`,
        });
      }
      if (slot.present && slot.fresh === false) {
        problems.push({
          ksi: row.ksi,
          artifact: slot.artifact,
          problem:
            `the body has not been revisited since ${slot.validFrom?.slice(0, 10) ?? "?"}, past ` +
            `VDR-TFR-NMV's three months — a written artifact is not done, and SDR-CSX-KSI item 2 ` +
            `asks for the cycle`,
        });
      }
      if (slot.judgment !== undefined && slot.present && !slot.judgment.appliesToLiveBody) {
        problems.push({
          ksi: row.ksi,
          artifact: slot.artifact,
          problem:
            `two keys judged this artifact ${slot.judgment.action}, and the body has been revised ` +
            `since — the standing judgment is about bytes that are no longer here, so this slot ` +
            `is unjudged until it is judged again (§13.6)`,
        });
      }
    }
  }
  return problems;
}

export function renderArtifactCheck(view: ArtifactsView, problems: readonly ArtifactProblem[]): string {
  const lines: string[] = [
    "rampscan artifacts check — is the artifact plane sound?",
    `class ${view.offeringClass} · dataset ${view.datasetVersion} · ` +
      (view.repo === null ? "no repo in the ledger" : `repo ${view.repo}`),
    "",
  ];
  if (problems.length === 0) {
    lines.push(
      `  ok — ${view.summary.filled} of ${view.summary.owed} owed slot(s) filled, and nothing`,
      "  standing in them is broken.",
      "",
      "  An empty slot is not a finding here: how much is owed is `rampscan frontier`'s",
      "  question, and `rampscan artifacts` prints the queue. This command asks only",
      "  whether what EXISTS is sound.",
      "",
    );
    return lines.join("\n");
  }
  lines.push(`  ${problems.length} problem(s):`, "");
  for (const problem of problems) {
    lines.push(`  ${problem.ksi} #${problem.artifact}`, `    ${problem.problem}`, "");
  }
  return lines.join("\n");
}
