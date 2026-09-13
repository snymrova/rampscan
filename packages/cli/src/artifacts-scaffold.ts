import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import type { MethodRegisterRow } from "@rampscan/core";
import type { KsiCatalog } from "@rampscan/dataset";

// `rampscan artifacts scaffold <KSI>` (plan R1.5, §6) — the command that makes
// ground rule 1 concrete.
//
// It writes the file with THE COMPUTED HALVES FILLED AND THE HUMAN HALVES
// CONSPICUOUSLY EMPTY, and it refuses to invent the second. Everything the
// appliance measured about this indicator goes in, labelled `computed`, because
// a provider writing artifact 1 should be looking at what their pipeline
// actually validates rather than reconstructing it from memory. The sentence
// that makes the claim is left blank under a heading that says whose it is.
//
// The alternative — a scaffold that produces a plausible first draft — is the
// single most tempting feature in this whole plan and the one that would end
// it. An LLM in the loop makes it trivially easy, and the moment this appliance
// emits compliance narrative, `SDR-CSX-KSI` becomes a text-generation benchmark
// and every signature in the ledger is worth less (SPEC §13.4).
//
// THE REASON-FOR-ABSENCE PATH IS FIRST-CLASS. Artifact 1 explicitly permits
// "an explanation of the reason and resulting risk to customers for not having
// measures available", so the stub offers that as a labelled alternative rather
// than as a failure state. A provider who writes it has satisfied the rule.

/** the two slots §13.4 reserves to the provider — the only ones with a stub */
export type ScaffoldableArtifact = 1 | 3;

export interface ScaffoldOptions {
  catalog: KsiCatalog;
  ksiId: string;
  artifact: ScaffoldableArtifact;
  /** the repository root the stub is written into */
  root: string;
  /** the KSI's board row, when the ledger has one — the computed half */
  register?: MethodRegisterRow;
  /** where the stub goes; defaults to docs/ksi/<ksi>-<n>.md */
  path?: string;
}

export interface ScaffoldResult {
  path: string;
  /** paste-ready declaration for rampscan.config.json's `artifacts` block */
  declaration: Record<string, unknown>;
  body: string;
}

export function scaffoldPath(ksiId: string, artifact: ScaffoldableArtifact): string {
  return `docs/ksi/${ksiId.toLowerCase()}-${artifact}.md`;
}

/**
 * The stub's text. Pure, so the tests read exactly what a provider gets — and
 * so the refusal to draft is a property of a function rather than a habit.
 */
export function scaffoldBody(options: Omit<ScaffoldOptions, "root" | "path">): string {
  const { catalog, ksiId, artifact, register } = options;
  const ksi = catalog.ksis.find((k) => k.id === ksiId);
  const owed = catalog.defaultArtifacts[artifact - 1] ?? "";
  const lines: string[] = [
    `# ${ksiId} — artifact ${artifact}`,
    "",
    `> **What the rule asks for.** ${owed}`,
    "",
    `> **The indicator.** ${ksi?.statement ?? "(not in the pinned catalog)"}`,
    "",
    "## Your statement",
    "",
    "<!-- This is yours to write. rampscan will not draft it: artifacts 1 and 3 are",
    "     the provider's own claims, and an appliance that wrote them would be",
    "     generating compliance narrative rather than measuring anything",
    "     (SPEC §13.4). Delete this comment and write the claim. -->",
    "",
    "",
    "## …or the reason there are no measures",
    "",
    "<!-- First-class alternative, not a failure. Artifact 1 explicitly permits",
    "     \"an explanation of the reason and resulting risk to customers for not",
    "     having measures available for that Key Security Indicator\". A provider",
    "     who writes this has satisfied the rule. Delete whichever section does",
    "     not apply. -->",
    "",
    "",
    "---",
    "",
    "## What rampscan measured (computed — do not edit)",
    "",
  ];

  if (register === undefined) {
    lines.push(
      "Nothing is folded for this indicator yet: no scan in this ledger has produced a",
      "measure for it. Run a scan and re-scaffold to have this section filled in.",
    );
  } else {
    const automated = register.methods.filter((m) => m.automated);
    const evidenced = register.methods.filter((m) => m.bundleDigest !== undefined);
    lines.push(
      `- **${register.methods.length} validation method(s)** derive this indicator; ` +
        `${automated.length} are automated and ${evidenced.length} hold live evidence.`,
      register.methodFloor === null
        ? "- No automated-method floor is defined for this class."
        : `- The class floor is ${register.methodFloor} automated method(s) per KSI, and this row ` +
          `${register.floorMet ? "meets" : "does NOT meet"} it (FRC-CSX-VVK).`,
      register.staleMethods === 0
        ? "- Every method with a window is inside it."
        : `- ${register.staleMethods} method(s) are past their owed re-validation window.`,
    );
    if (register.methods.length > 0) {
      lines.push("", "The measures, as the register has them:", "");
      for (const method of register.methods) {
        lines.push(
          `- \`${method.methodId}\` — ${method.source}, ${method.automated ? "automated" : "not automated"}, ` +
            `${method.state}${method.freshAsOf === undefined ? "" : ` as of ${method.freshAsOf.slice(0, 10)}`}`,
        );
      }
    }
    lines.push(
      "",
      "These lines are a reading of the ledger at scaffold time. They are here so the",
      "statement above is written against what is actually validated — they are not the",
      "statement, and nothing in this section is signed by writing it here. The signed",
      "record is the fold; `rampscan artifacts show " + ksiId + "` prints it live.",
    );
  }
  lines.push("");
  return lines.join("\n");
}

/**
 * Write the stub. REFUSES to overwrite: a scaffold that clobbered a written
 * artifact would destroy exactly the thing this plane exists to keep, and the
 * mistake is one keystroke away from a command whose whole job is creating a
 * file that was not there.
 */
export async function scaffoldArtifact(options: ScaffoldOptions): Promise<ScaffoldResult> {
  if (!options.catalog.ksis.some((k) => k.id === options.ksiId)) {
    throw new Error(
      `unknown KSI ${options.ksiId} — a scaffold names a slot in the pinned catalog`,
    );
  }
  const rel = options.path ?? scaffoldPath(options.ksiId, options.artifact);
  const absolute = join(options.root, rel);
  const body = scaffoldBody(options);

  await mkdir(dirname(absolute), { recursive: true });
  try {
    await writeFile(absolute, body, { flag: "wx" });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "EEXIST") {
      throw new Error(
        `${rel} already exists — scaffold will not overwrite a written artifact. ` +
          `Edit it, or pass --path to scaffold somewhere else.`,
      );
    }
    throw error;
  }

  return {
    path: rel,
    body,
    declaration: {
      ksi: options.ksiId,
      artifact: options.artifact,
      path: rel,
      description: `Artifact ${options.artifact} for ${options.ksiId}. Replace this with a sentence describing what the file says.`,
    },
  };
}
