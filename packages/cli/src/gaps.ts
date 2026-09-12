import type { MethodRegisterRow, ValidationVulnerability } from "@rampscan/core";
import type { KsiCatalog, OfferingClass } from "@rampscan/dataset";
import type { PipelineMethod } from "@rampscan/schema";
import type { FrontierMap } from "./frontier.js";

// `rampscan gaps` — the gap register as a computation (plan Q3 exit gate):
// every G1–G6, G8 and G13 row, each citing the rule that makes it a gap and
// the evidence digest where evidence exists. Nothing here is judged — every
// row is a join of judgments other modules already made: the fold (G3–G6,
// G13 via the vulnerability feed), the derivation (G1/G2 without a scan),
// the frontier (G8). Rule ids come from the owed side as data wherever the
// catalog carries them (FRC-CSX-VVK, FRC-CSX-MOT, VDR-TFR-MVX/NMV); the two
// the catalog does not carry as floors or windows — FRR-PVA-AA-06 (G6) and
// VDR-CSO-FAV (G13) — are named the way default_artifacts.KSI is: a citation
// in prose, never a number.

export type GapClass = "G1" | "G2" | "G3" | "G4" | "G5" | "G6" | "G8" | "G13";

export interface GapRow {
  /** what the gap is about: a KSI, a (KSI, method) pair, a control, a cell */
  subject: string;
  /** the computed fact, one line */
  detail: string;
  /** the evidence digest, exactly when evidence exists to cite */
  digest?: string;
}

export interface GapSection {
  gapClass: GapClass;
  name: string;
  /** the rule that makes this class a gap; null for G8 (product-level) */
  ruleId: string | null;
  force?: string;
  /**
   * Set when the class cannot be measured — no scanned repo, or a class
   * that owes no number. Unmeasured and empty are different facts, and the
   * register says which one it is.
   */
  unmeasured?: string;
  rows: GapRow[];
}

export interface GapRegisterView {
  offeringClass: OfferingClass;
  datasetVersion: string;
  /** the scanned repo the evidence-side sections read; absent when none */
  repo?: string;
  sections: GapSection[];
  /** gap rows across all sections — the register's one headline number */
  totalRows: number;
}

export interface GapRegisterInput {
  catalog: KsiCatalog;
  offeringClass: OfferingClass;
  /** the derived register (Q2.2) — G1/G2's ground when no scan is recorded */
  methods: PipelineMethod[];
  /** the projector's method register; empty when no scan is recorded */
  methodRegisters: MethodRegisterRow[];
  /** the failure→vulnerability feed (Q3.5) */
  vulnerabilities: ValidationVulnerability[];
  /** the control frontier — the G8 rows */
  frontier: FrontierMap;
}

export function buildGapRegister(input: GapRegisterInput): GapRegisterView {
  const { catalog, offeringClass } = input;
  const floor = catalog.floors[offeringClass];
  const history = catalog.historyFloors[offeringClass];
  const machineWindow = catalog.windows[offeringClass];

  // same convention as the KSI register: one repo's ledger, first by name
  const repos = [...new Set(input.methodRegisters.map((r) => r.repo))].sort();
  const repo = repos[0];
  const folded = input.methodRegisters.filter((r) => r.repo === repo);
  const foldedByKsi = new Map(folded.map((r) => [r.ksi, r]));
  const methodsByKsi = new Map<string, PipelineMethod[]>();
  for (const method of input.methods) {
    (methodsByKsi.get(method.ksi) ?? methodsByKsi.set(method.ksi, []).get(method.ksi)!).push(
      method,
    );
  }

  const sections: GapSection[] = [];

  // G1 coverage — a KSI no method validates at all. Computable with or
  // without a scan: which methods exist is a property of the register.
  const g1: GapRow[] = [];
  for (const entry of catalog.ksis) {
    const count = foldedByKsi.get(entry.id)?.methods.length ?? methodsByKsi.get(entry.id)?.length ?? 0;
    if (count === 0) {
      g1.push({
        subject: entry.id,
        detail: "no validation method derives — nothing to cite is the finding",
      });
    }
  }
  sections.push({
    gapClass: "G1",
    name: "coverage",
    ruleId: floor.requirementId,
    force: floor.force,
    rows: g1,
  });

  // G2 method count — validated, but under the class floor.
  const g2: GapSection = {
    gapClass: "G2",
    name: "method count",
    ruleId: floor.requirementId,
    force: floor.force,
    rows: [],
  };
  if (floor.minPerKsi === null) {
    g2.unmeasured = `class ${offeringClass} owes no number (${floor.requirementId} ${floor.force}, unquantified)`;
  } else {
    for (const entry of catalog.ksis) {
      const row = foldedByKsi.get(entry.id);
      const derived = methodsByKsi.get(entry.id) ?? [];
      const total = row?.methods.length ?? derived.length;
      const automated = row?.automatedMethods ?? derived.filter((m) => m.automated).length;
      if (total > 0 && automated < floor.minPerKsi) {
        g2.rows.push({
          subject: entry.id,
          detail: `${automated} automated method(s) of ${floor.minPerKsi} owed`,
        });
      }
    }
  }
  sections.push(g2);

  // G3 freshness — one row per (KSI, method) whose owed clock is unmet.
  // With a fold, the cell judgment is the fold's; without one, every derived
  // method that owes a clock holds no evidence, which is the same gap.
  const g3: GapSection = {
    gapClass: "G3",
    name: "freshness",
    ruleId: machineWindow?.requirementId ?? catalog.nonMachineWindow.requirementId,
    ...(machineWindow !== null ? { force: machineWindow.force } : {}),
    rows: [],
  };
  if (repo !== undefined) {
    for (const row of folded) {
      for (const cell of row.methods) {
        if (cell.freshMet !== false) continue;
        g3.rows.push({
          subject: `${row.ksi} · ${cell.methodId}`,
          detail:
            cell.freshAsOf === undefined
              ? "no live evidence — nothing re-validates this method at any cadence"
              : `evidence of ${cell.freshAsOf} sits outside the owed ${cell.window!.num}${cell.window!.unit === "days" ? "d" : "mo"} window`,
          ...(cell.bundleDigest !== undefined ? { digest: cell.bundleDigest } : {}),
        });
      }
    }
  } else if (machineWindow === null) {
    g3.unmeasured = `no machine window at class ${offeringClass} — VDR-TFR-MVX defines none (§11 q6)`;
  } else {
    for (const method of input.methods) {
      g3.rows.push({
        subject: `${method.ksi} · ${method.id}`,
        detail: "no scan recorded — no evidence holds any clock",
      });
    }
  }
  sections.push(g3);

  // G4 history — the FRC-CSX-MOT meter, unmet rows only.
  const g4: GapSection = {
    gapClass: "G4",
    name: "history",
    ruleId: history.requirementId,
    force: history.force,
    rows: [],
  };
  if (history.months === null) {
    g4.unmeasured = `class ${offeringClass} owes no number (${history.requirementId} ${history.force}, unquantified)`;
  } else if (repo === undefined) {
    g4.unmeasured = "no scan recorded — a ledger that holds nothing has zero months of history on every KSI";
  } else {
    for (const row of folded) {
      if (row.historyMet !== false) continue;
      g4.rows.push({
        subject: row.ksi,
        detail:
          row.historySince === undefined
            ? `no validation history at all — ${history.months}mo owed`
            : `history since ${row.historySince} — ${history.months}mo owed`,
      });
    }
  }
  sections.push(g4);

  // G5 artifacts — the five owed artifacts, absent ones named per KSI. The
  // digest cited is a standing judgment's (a signed insufficient is a
  // recorded fact); an unjudged artifact has nothing to cite, which is the
  // gap itself.
  const g5: GapSection = {
    gapClass: "G5",
    name: "artifacts",
    ruleId: "default_artifacts.KSI",
    rows: [],
  };
  if (repo === undefined) {
    g5.unmeasured = "no scanned repo — the five owed artifacts are counted against a ledger";
  } else {
    for (const row of folded) {
      // a zero-method KSI's gap is coverage: listing its five absent
      // artifacts would restate the G1 row five times over. Its artifact
      // rows appear the moment a method derives for it.
      if (row.methods.length === 0) continue;
      for (const cell of row.artifacts) {
        if (cell.present) continue;
        g5.rows.push({
          subject: `${row.ksi} · artifact ${cell.artifact}`,
          detail:
            cell.basis === "computed"
              ? cell.artifact === 5
                ? "no live evidence — the validation record is the artifact"
                : "no cadence record — no declared cycle over live evidence"
              : cell.judgment !== undefined
                ? `judged ${cell.judgment.action} by two-key event`
                : "no two-key sufficiency judgment recorded",
          ...(cell.judgment !== undefined ? { digest: cell.judgment.digest } : {}),
        });
      }
    }
  }
  sections.push(g5);

  // G6 evidence class — every asserted point-in-time cell, standalone or
  // corroborated; the row says which, because only standalone is rejectable.
  const g6: GapSection = {
    gapClass: "G6",
    name: "evidence class",
    ruleId: "FRR-PVA-AA-06",
    rows: [],
  };
  if (repo === undefined) {
    g6.unmeasured = "no scanned repo — the class of evidence that does not exist is unmeasured";
  } else {
    for (const row of folded) {
      for (const cell of row.methods) {
        if (cell.evidenceClass !== "point-in-time") continue;
        g6.rows.push({
          subject: `${row.ksi} · ${cell.methodId}`,
          detail:
            row.gap === "G6"
              ? "point-in-time evidence STANDING ALONE — rejectable as standalone evidence"
              : "point-in-time evidence, corroborated by a process-generated method",
          ...(cell.bundleDigest !== undefined ? { digest: cell.bundleDigest } : {}),
        });
      }
    }
  }
  sections.push(g6);

  // G8 adjudication — the unasked question, from the frontier: controls
  // nobody has decided the commit plane's answer for. Product-level; there
  // is no FedRAMP rule that makes an unreviewed adjudication a gap, which
  // is exactly why it must stay printed rather than assumed away.
  const g8: GapSection = { gapClass: "G8", name: "adjudication", ruleId: null, rows: [] };
  for (const row of input.frontier.rows.filter((r) => r.commit === undefined)) {
    g8.rows.push({
      subject: row.displayId,
      detail:
        `${row.family}${row.leverage !== undefined ? ` · leverage ${row.leverage}` : ""}` +
        ` · ${row.ksis.join(" ")}`,
    });
  }
  g8.rows.sort((a, b) => a.subject.localeCompare(b.subject));
  sections.push(g8);

  // G13 failure handling — the vulnerability feed's OPEN records: a failed
  // validation with detection-and-response obligations still owed. Resolved
  // episodes are history, counted in the section detail, not gap rows.
  const g13: GapSection = {
    gapClass: "G13",
    name: "failure handling",
    ruleId: "VDR-CSO-FAV",
    rows: [],
  };
  const vulns = input.vulnerabilities.filter((v) => repo === undefined || v.repo === repo);
  for (const v of vulns) {
    if (v.status !== "open") continue;
    g13.rows.push({
      subject: `${v.ksiIds.join(" ")} · ${v.recipeId}`,
      detail: `open since ${v.detectedAt} at ${v.commit.slice(0, 12)}`,
      digest: v.bundleDigest,
    });
  }
  const resolved = vulns.filter((v) => v.status === "resolved").length;
  if (resolved > 0 && g13.rows.length === 0) {
    // an all-resolved feed is a fact worth one line, not silence
    g13.unmeasured = `no open records — ${resolved} resolved episode(s) in the feed`;
  }
  sections.push(g13);

  return {
    offeringClass,
    datasetVersion: catalog.datasetVersion,
    ...(repo !== undefined ? { repo } : {}),
    sections,
    totalRows: sections.reduce((n, s) => n + s.rows.length, 0),
  };
}

/** the register as text — sections in taxonomy order, every row one line */
export function renderGapRegister(view: GapRegisterView, useColor: boolean): string {
  const paint = (code: string, s: string) => (useColor ? `[${code}m${s}[0m` : s);
  const dim = (s: string) => paint("2", s);
  const bold = (s: string) => paint("1", s);
  const red = (s: string) => paint("31", s);
  const lines: string[] = [];

  lines.push(
    bold("rampscan gaps — the gap register"),
    `class ${view.offeringClass} · dataset ${view.datasetVersion}` +
      (view.repo !== undefined ? dim(` · evidence: ${view.repo}`) : dim(" · no scan recorded")),
    "",
  );

  for (const section of view.sections) {
    const rule =
      section.ruleId === null ? "product-level, not a rule" : section.ruleId;
    const force = section.force !== undefined ? ` (${section.force})` : "";
    lines.push(
      bold(`  ${section.gapClass} ${section.name}`) +
        dim(` — ${rule}${force} · ${section.rows.length} row(s)`),
    );
    if (section.unmeasured !== undefined) {
      lines.push(dim(`    ${section.unmeasured}`));
    }
    for (const row of section.rows) {
      lines.push(
        `    ${red(row.subject.padEnd(44))} ${dim(row.detail)}` +
          (row.digest !== undefined ? dim(` · ${row.digest.slice(0, 12)}…`) : ""),
      );
    }
    if (section.rows.length === 0 && section.unmeasured === undefined) {
      lines.push(dim("    none"));
    }
    lines.push("");
  }

  lines.push(
    dim(
      `  ${view.totalRows} gap row(s) — every row cites its rule; a digest wherever evidence exists to cite`,
    ),
  );
  return lines.join("\n");
}
