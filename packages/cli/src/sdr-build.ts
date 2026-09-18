import { createHash } from "node:crypto";
import type { ArtifactCell, MethodCell, MethodRegisterRow } from "@rampscan/core";
import {
  addressableRules,
  effectiveForce,
  type OfferingClass,
  type RuleRegister,
} from "@rampscan/dataset";
import type { OfferingConfig } from "@rampscan/schema";
import type { FedrampExport } from "./fedramp-exports.js";
import { SDR_SCHEMA } from "./fedramp-schemas.js";
import type { SdrMetrics } from "./sdr-metrics.js";
import { COMPUTED_RULES } from "./submission.js";

// `rampscan sdr` — the Security Decision Record, JSON half (R2.1, #102;
// docs/PLAN-SDR.md). The document that replaced the SSP for 20x: `SDR-CSO-FRR`
// wants a row per applicable FedRAMP rule, `SDR-CSX-KSI` the five artifacts per
// KSI, `SDR-CSO-MTD` the metadata.
//
// A RENDERING, LIKE THE CPO AND OCR. Nothing here is appended or signed, and the
// same ledger at the same instant produces the same bytes. The builder is pure:
// the artifact bodies arrive already read from the ledger, so this file never
// touches a disk and every field it writes is a function of its input.
//
// THE ONE THING IT MUST NEVER DO IS WRITE A SENTENCE NOBODY STOOD BEHIND. The
// schema accepts an empty `ksiImplementation`, and an empty one is what a KSI
// with no artifact 1 gets (D2). The schema would also accept a paragraph, and
// a paragraph would be a claim the provider never made in a document FedRAMP
// reads as theirs. So every string in a narrative field is either a signed
// artifact body, a declared citation or reason, or a sentence naming which
// rampscan surface computes a rule — and the last is labelled as rampscan's.
//
// Two decisions differ from the plan's first draft, both stated where they bite:
// a computed rule the provider never declared gets NO row (D4, below), and
// `ksiImplementationStatus` is computed one-way (D6, `ksiStatus`).

export const SDR_ARTIFACT = "fedramp-security-decision-record.json";

/** `2026-09-12T08:00:00.000Z` → `2026-09-12`, the schema's `date` for evidence */
function day(iso: string): string {
  return iso.slice(0, 10);
}

export interface SdrBuildInput {
  offering: OfferingConfig;
  offeringClass: OfferingClass;
  /** the offering the rows speak for; absent when the ledger holds no scan */
  repo?: string;
  /** the fold's instant — metadata.lastUpdated, never the wall clock */
  projectedAt: string;
  datasetVersion: string;
  /** the newest statement folded, so updateSource names the exact ledger state */
  ledgerHead?: string;
  /** the catalog's indicators in the rules' order — every row's id comes from here */
  ksis: readonly { id: string; name: string }[];
  /** indicators the class does not oblige (§13.7) */
  optionalKsis: readonly string[];
  /** `default_artifacts.KSI`, the five labels in the rules' own order */
  defaultArtifacts: readonly string[];
  /** the method register, already filtered to `repo` */
  methodRegisters: readonly MethodRegisterRow[];
  ruleRegister: RuleRegister;
  /**
   * Artifact bodies, keyed by the ledger digest of the statement that filled
   * the slot (`ArtifactBodyInfo.digest`). A slot whose body is not here is
   * rendered empty and named in problems: the builder never reads the ledger.
   */
  bodies: ReadonlyMap<string, string>;
  /**
   * Historical metrics (R3, docs/PLAN-HISTORY.md), computed by refolding the
   * ledger once per day. Absent means nobody computed them, and the record
   * says so; the builder never reads the ledger itself.
   */
  metrics?: SdrMetrics;
}

export interface SdrOutcome {
  export?: FedrampExport;
  /** why no SDR was written — a refused required field, never a default */
  skipped?: string;
}

// ---------------------------------------------------------------------------
// D8 — evidence type, declared per collector
// ---------------------------------------------------------------------------

type EvidenceType = "Log" | "Report" | "Screenshot" | "Configuration" | "Policy" | "Procedure" | "Audit Record";

/**
 * Which of the schema's seven evidence types each pipeline collector's output
 * is. Declared rather than guessed from a name, and guarded by a test that
 * fails when a collector exists with no entry here, because an unmapped
 * collector would otherwise publish evidence with no type and nobody would
 * notice.
 *
 * Scanners write a report of what they found. Checks over declared structure
 * (repository facts, IaC, the boundary contract, the declared documents) read
 * configuration and report on it, so they are `Configuration`.
 */
export const COLLECTOR_EVIDENCE_TYPES: Readonly<Record<string, EvidenceType>> = {
  checkov: "Configuration",
  contract: "Configuration",
  documents: "Configuration",
  gitleaks: "Report",
  graph: "Report",
  grype: "Report",
  "osv-scanner": "Report",
  reachability: "Report",
  "repo-facts": "Configuration",
  "sast-reachability": "Report",
  semgrep: "Report",
  spectral: "Report",
  syft: "Report",
};

function evidenceTypeOf(cell: MethodCell): EvidenceType | undefined {
  // an ingested AWS or Prowler result is a report of what the scan found; an
  // attestation is a signed record of a person's statement
  if (cell.source === "aws-ingested") return "Report";
  if (cell.source === "attestation") return "Audit Record";
  return cell.collector !== undefined ? COLLECTOR_EVIDENCE_TYPES[cell.collector] : undefined;
}

// ---------------------------------------------------------------------------
// D7 — where a bundle is
// ---------------------------------------------------------------------------

/**
 * An RFC 6920 named-information URI over the bundle's sha256 digest, or the
 * provider's declared publication address. The first names the bundle; only
 * the second locates it, and the document's problems say which one it used.
 */
export function evidenceLocation(digestHex: string, base?: string): string {
  if (base !== undefined) return `${base}/sha256/${digestHex}`;
  return `ni:///sha-256;${Buffer.from(digestHex, "hex").toString("base64url")}`;
}

// ---------------------------------------------------------------------------
// D6 — ksiImplementationStatus, computed one-way
// ---------------------------------------------------------------------------

export type KsiStatus = "Implemented" | "Partially Implemented" | "Not Implemented";

/** every input the status reads, published so a reader can re-derive it */
export interface KsiStatusBasis {
  methods: number;
  /** methods not scoped out by a signed two-key N/A */
  methodsInScope: number;
  /** of those, how many hold live evidence */
  methodsWithEvidence: number;
  /** of those, how many hold live evidence that PASSED (`evidenced`) */
  methodsPassing: number;
  violatedMethods: number;
  staleMethods: number;
  floorMet: boolean | null;
  automatedWithEvidence: number;
  historyMet: boolean | null;
  artifactsPresent: number;
  /** the conditions that kept this row below `Implemented`, in words; empty when none */
  short: string[];
}

/**
 * The owner's call (D6, 2026-09-18): computed, and allowed to understate but
 * never to overstate. `Implemented` needs every condition below. Anything
 * short of it with at least one passing method is `Partially Implemented`. A
 * row with no passing method is `Not Implemented`, and that includes a row
 * whose only evidence is a violated check: a failed measurement is evidence
 * the KSI is not met, not that it is partly met.
 *
 * Every condition is checked on its own terms rather than through a proxy that
 * can be vacuous. `staleMethods == 0` alone would pass a row at class d, where
 * the machine clock owes no window and a method with no evidence is not
 * counted stale, so evidence on every in-scope method is its own condition.
 * `floorMet` counts DERIVED automated methods, not evidenced ones, so where
 * the class owes no floor the row needs an automated method that holds live
 * evidence.
 */
export function ksiStatus(row: MethodRegisterRow | undefined): { status: KsiStatus; basis: KsiStatusBasis } {
  const cells = row?.methods ?? [];
  const inScope = cells.filter((c) => c.state !== "notApplicable");
  const withEvidence = inScope.filter((c) => c.bundleDigest !== undefined);
  const basis: KsiStatusBasis = {
    methods: cells.length,
    methodsInScope: inScope.length,
    methodsWithEvidence: withEvidence.length,
    methodsPassing: withEvidence.filter((c) => c.state === "evidenced").length,
    violatedMethods: inScope.filter((c) => c.state === "violated").length,
    staleMethods: row?.staleMethods ?? 0,
    floorMet: row?.floorMet ?? null,
    automatedWithEvidence: withEvidence.filter((c) => c.automated).length,
    historyMet: row?.historyMet ?? null,
    artifactsPresent: row?.artifactsPresent ?? 0,
    short: [],
  };

  if (basis.methodsPassing === 0) {
    basis.short.push(
      inScope.length === 0
        ? "no validation method is in scope for this KSI"
        : basis.methodsWithEvidence === 0
          ? "no validation method holds live evidence"
          : "no validation method holds passing evidence; every live result is a violation",
    );
    return { status: "Not Implemented", basis };
  }

  if (basis.floorMet === false) basis.short.push("the FRC-CSX-VVK automated-method floor is not met");
  if (basis.floorMet === null && basis.automatedWithEvidence === 0) {
    basis.short.push("the class owes no floor and no automated method holds live evidence");
  }
  if (basis.methodsWithEvidence < basis.methodsInScope) {
    basis.short.push(
      `${basis.methodsInScope - basis.methodsWithEvidence} of ${basis.methodsInScope} in-scope methods hold no live evidence`,
    );
  }
  if (basis.staleMethods > 0) basis.short.push(`${basis.staleMethods} method(s) outside their owed window`);
  if (basis.violatedMethods > 0) basis.short.push(`${basis.violatedMethods} method(s) violated`);
  if (basis.historyMet === false) basis.short.push("the FRC-CSX-MOT history floor is not met");
  if (basis.artifactsPresent < 5) basis.short.push(`${basis.artifactsPresent} of 5 artifacts present`);

  return { status: basis.short.length === 0 ? "Implemented" : "Partially Implemented", basis };
}

// ---------------------------------------------------------------------------
// the KSI half (SDR-CSX-KSI)
// ---------------------------------------------------------------------------

function method(cell: MethodCell): string {
  return `${cell.methodId} — ${cell.source}, ${cell.automated ? "automated" : "not automated"}, ${cell.clock} clock`;
}

interface Rendered {
  statements: string[];
  /** slots with no body to render, and why */
  missing: { artifact: number; why: string }[];
}

/**
 * Artifacts as statements, each prefixed with the rules' own label and the
 * body's provenance, so a reader of the SDR alone can tell a signed authored
 * body from a computed one without opening the ledger.
 */
function render(
  cells: readonly ArtifactCell[],
  slots: readonly number[],
  labels: readonly string[],
  bodies: ReadonlyMap<string, string>,
): Rendered {
  const out: Rendered = { statements: [], missing: [] };
  for (const slot of slots) {
    const cell = cells.find((c) => c.artifact === slot);
    if (cell?.body === undefined) {
      out.missing.push({
        artifact: slot,
        why: cell?.absent !== undefined ? `emptied: ${cell.absent.reason}` : "no body",
      });
      continue;
    }
    const text = bodies.get(cell.body.digest);
    if (text === undefined) {
      out.missing.push({ artifact: slot, why: `body ${cell.body.bodyDigest.slice(0, 12)}… not readable from the ledger` });
      continue;
    }
    const label = labels[slot - 1] ?? `Artifact ${slot}`;
    out.statements.push(
      `**Artifact ${slot} — ${label}** _(${cell.body.source}; body sha256 ${cell.body.bodyDigest.slice(0, 12)}…)_\n\n${text}`,
    );
  }
  return out;
}

// ---------------------------------------------------------------------------
// the builder
// ---------------------------------------------------------------------------

export function buildSecurityDecisionRecord(input: SdrBuildInput): SdrOutcome {
  const cpo = input.offering.report?.certificationPackageOverviewUri;
  if (cpo === undefined) {
    // D5: the one field the SDR schema requires that rampscan cannot compute.
    // The OCR reads it from the same key, so one declaration names one CPO.
    return {
      skipped:
        "no `offering.report.certificationPackageOverviewUri` declared — the Security Decision Record schema requires the address of the certification package overview, and rampscan builds that document but does not host it. Declare where it is published; this appliance does not default a required field",
    };
  }

  const problems: string[] = [];
  const cls = input.offeringClass;
  const optional = new Set(input.optionalKsis);
  const byKsi = new Map(input.methodRegisters.map((r) => [r.ksi, r]));

  if (input.repo === undefined) {
    problems.push(
      "the ledger holds no scan for this offering, so every KSI row below carries no tests, no evidence and no artifacts — a record of what is owed, not of what was done",
    );
  }

  // ---- keySecurityIndicators (D10, D11) ----------------------------------
  const keySecurityIndicators: Record<string, unknown>[] = [];
  const ksiExtension: Record<string, unknown> = {};
  const optionalOmitted: string[] = [];
  const missingBySlot = new Map<number, string[]>();
  const counts: Record<KsiStatus, number> = {
    Implemented: 0,
    "Partially Implemented": 0,
    "Not Implemented": 0,
  };
  let evidenceEntries = 0;

  for (const ksi of input.ksis) {
    const row = byKsi.get(ksi.id);
    const hasEvidence = (row?.methods ?? []).some((c) => c.bundleDigest !== undefined);
    if (optional.has(ksi.id) && !hasEvidence) {
      optionalOmitted.push(ksi.id);
      continue;
    }

    const { status, basis } = ksiStatus(row);
    counts[status] += 1;
    const cells = row?.artifacts ?? [];
    const implementation = render(cells, [1, 2], input.defaultArtifacts, input.bodies);
    const validation = render(cells, [3, 4, 5], input.defaultArtifacts, input.bodies);
    // only obliged rows count toward the missing-artifact problem, which is the
    // denominator the board uses (§13.7)
    if (!optional.has(ksi.id)) {
      for (const m of [...implementation.missing, ...validation.missing]) {
        const list = missingBySlot.get(m.artifact) ?? missingBySlot.set(m.artifact, []).get(m.artifact)!;
        list.push(ksi.id);
      }
    }
    // `assessed` bodies are R4.5's; none exists before then, and the field
    // stays empty rather than borrowing another source's words
    const assessment = cells
      .filter((c) => c.body?.source === "assessed" && input.bodies.has(c.body.digest))
      .map((c) => input.bodies.get(c.body!.digest)!);

    const methods = row?.methods ?? [];
    const evidence: Record<string, unknown>[] = [];
    for (const cell of methods) {
      if (cell.bundleDigest === undefined) continue;
      const entry: Record<string, unknown> = {};
      const type = evidenceTypeOf(cell);
      if (type !== undefined) entry["evidenceType"] = type;
      entry["evidenceDescription"] =
        `${cell.methodId}: ${cell.state}` +
        (cell.evidenceClass !== undefined ? `, ${cell.evidenceClass} evidence` : ", evidence class not asserted by the bundle");
      entry["evidenceLocation"] = evidenceLocation(cell.bundleDigest, input.offering.evidenceBaseUri);
      entry["evidenceText"] = `signed bundle ${cell.bundleDigest}; check it offline with \`rampscan verify ${cell.bundleDigest}\``;
      if (cell.freshAsOf !== undefined) entry["lastUpdated"] = day(cell.freshAsOf);
      evidence.push(entry);
    }
    evidenceEntries += evidence.length;

    keySecurityIndicators.push({
      ksiId: ksi.id,
      ksiImplementationStatus: status,
      ksiImplementation: implementation.statements,
      ksiValidation: validation.statements,
      ksiAssessment: assessment,
      // D9: every derived method, evidenced or not — a method without evidence
      // is a test the provider owes, and listing only the passing ones would
      // make the field a boast
      ksiTests: methods.map(method),
      ksiEvidence: evidence,
    });

    ksiExtension[ksi.id] = {
      name: ksi.name,
      obliged: !optional.has(ksi.id),
      statusBasis: basis,
      ...(row?.gap !== undefined ? { gap: row.gap } : {}),
      methods: methods.map((c) => ({
        methodId: c.methodId,
        state: c.state,
        freshMet: c.freshMet,
        ...(c.freshAsOf !== undefined ? { freshAsOf: c.freshAsOf } : {}),
        ...(c.bundleDigest !== undefined ? { bundleDigest: c.bundleDigest } : {}),
      })),
      artifacts: [1, 2, 3, 4, 5].map((slot) => {
        const cell = cells.find((c) => c.artifact === slot);
        return {
          artifact: slot,
          present: cell?.present ?? false,
          ...(cell?.body !== undefined
            ? { source: cell.body.source, bodyDigest: cell.body.bodyDigest, validFrom: cell.body.validFrom }
            : {}),
          ...(cell?.absent !== undefined ? { absent: cell.absent } : {}),
        };
      }),
    };
  }

  for (const [slot, ids] of [...missingBySlot].sort(([a], [b]) => a - b)) {
    const label = input.defaultArtifacts[slot - 1] ?? `artifact ${slot}`;
    const who =
      slot === 1 || slot === 3
        ? "It is the provider's own claim; rampscan does not write it (`rampscan artifacts scaffold`)"
        : "It is computed; `rampscan artifacts generate` mints it where the fold holds the material";
    // every obliged row is the usual state of a fresh adoption; forty ids in a
    // line would bury the one fact that matters, which is that it is all of them
    const obliged = input.ksis.filter((k) => !optional.has(k.id)).length;
    const where =
      ids.length === obliged ? `every one of the ${obliged} obliged KSI rows` : `${ids.length} obliged KSI row(s): ${ids.join(", ")}`;
    problems.push(
      `SDR-CSX-KSI artifact ${slot} (${label}) has no body on ${where}. ${who}. The row carries nothing in its place.`,
    );
  }
  if (keySecurityIndicators.every((k) => (k["ksiAssessment"] as unknown[]).length === 0)) {
    problems.push(
      "ksiAssessment is empty on every row: it is the independent assessor's summary to supply, and no assessed body is in the ledger",
    );
  }
  if (evidenceEntries > 0 && input.offering.evidenceBaseUri === undefined) {
    problems.push(
      "evidenceLocation is an RFC 6920 `ni:` name over each bundle's digest: it identifies the signed bundle but a reader without this ledger cannot fetch it. Declare `offering.evidenceBaseUri` once the bundles are published",
    );
  }

  // ---- fedRampRequirements (D4) ------------------------------------------
  //
  // One row per rule the provider DECLARED, and none otherwise. The plan's
  // first draft also gave a row to every rule in COMPUTED_RULES. That was
  // wrong, and the reason is §9.3 of the rejection-linter note: `computed` is
  // what this appliance can check, and it excuses nothing. A computed rule
  // with no declaration has no "explanation of how the rule is followed",
  // which is what SDR-CSO-FRR asks for. Giving it a row with an empty
  // `frrImplementation` would read as answered to `submission --sdr` and to
  // FedRAMP, while the provider had said nothing. So it gets no row, and it is
  // named in `unaddressedRules` with the surface that would validate it once
  // declared.
  const byId = new Map(input.ruleRegister.rules.map((r) => [r.id, r]));
  const addressable = addressableRules(input.ruleRegister, cls);
  const addressableIds = new Set(addressable.map((r) => r.id));
  const declared = input.offering.ruleCoverage ?? [];
  const declaredIds = new Set<string>();
  const fedRampRequirements: Record<string, unknown>[] = [];
  const unknownDeclarations: string[] = [];
  const declaredNotAddressable: string[] = [];
  /** force at the class for each declared row — the human half prints it (R2.2) */
  const declaredRuleForce: Record<string, string | null> = {};

  for (const entry of [...declared].sort((a, b) => a.ruleId.localeCompare(b.ruleId))) {
    if (!byId.has(entry.ruleId)) {
      unknownDeclarations.push(entry.ruleId);
      continue;
    }
    declaredIds.add(entry.ruleId);
    declaredRuleForce[entry.ruleId] = effectiveForce(byId.get(entry.ruleId)!, cls);
    if (!addressableIds.has(entry.ruleId)) declaredNotAddressable.push(entry.ruleId);
    const row: Record<string, unknown> = { frrID: entry.ruleId };
    if (entry.status === "not-implemented") {
      // FedRAMP/schemas#21: a rule the provider chooses not to implement is
      // "Not Implemented", with the reason as the statement
      row["frrImplementationStatus"] = "Not Implemented";
      row["frrImplementation"] = [`Not implemented: ${entry.reason}`];
    } else {
      if (entry.implementationStatus !== undefined) row["frrImplementationStatus"] = entry.implementationStatus;
      row["frrImplementation"] = [entry.citation];
    }
    const surface = COMPUTED_RULES[entry.ruleId];
    if (surface !== undefined) {
      row["frrValidation"] = [`Validated by rampscan, which computes this rule: ${surface}.`];
    }
    fedRampRequirements.push(row);
  }

  const unaddressedRules = addressable
    .filter((r) => !declaredIds.has(r.id))
    .map((r) => ({
      ruleId: r.id,
      force: effectiveForce(r, cls),
      ...(COMPUTED_RULES[r.id] !== undefined ? { computedBy: COMPUTED_RULES[r.id] } : {}),
    }))
    .sort((a, b) => a.ruleId.localeCompare(b.ruleId));

  if (unaddressedRules.length > 0) {
    const computed = unaddressedRules.filter((r) => r.computedBy !== undefined).length;
    problems.push(
      `${unaddressedRules.length} of ${addressable.length} rules addressable at class ${cls} have no row: the offering's ruleCoverage does not declare them, and SDR-CSO-FRR wants each one explained as followed or not followed with a reason. Omitting a row is FedRAMP's rejection reason 3 (community #167). ` +
        (computed > 0
          ? `${computed} of them are rules rampscan computes; the evidence exists, and a declaration is what gives it a row. `
          : "") +
        "They are listed in x-rampscan.unaddressedRules",
    );
  }
  if (unknownDeclarations.length > 0) {
    problems.push(
      `ruleCoverage declares ${unknownDeclarations.length} id(s) that name no rule at dataset ${input.ruleRegister.datasetVersion}: ${unknownDeclarations.join(", ")}. No row was written for them, and the rule each one meant is still unaddressed`,
    );
  }

  // ---- SDR-CSX-KMT, carried outside the schema (R3.3, H6) -----------------
  //
  // Metrics only for the rows this record has, so the block and the KSI rows
  // cannot disagree about which indicators the record speaks for.
  const rowIds = new Set(keySecurityIndicators.map((k) => k["ksiId"] as string));
  const metrics: SdrMetrics | undefined =
    input.metrics === undefined
      ? undefined
      : {
          ...input.metrics,
          ksis: Object.fromEntries(
            Object.entries(input.metrics.ksis).filter(([id]) => rowIds.has(id)),
          ),
        };
  const kmt = byId.get("SDR-CSX-KMT");
  const kmtForce = kmt !== undefined ? effectiveForce(kmt, cls) : null;
  if (kmtForce === "MUST" || kmtForce === "SHOULD") {
    if (metrics === undefined) {
      problems.push(
        `SDR-CSX-KMT (${kmtForce} at class ${cls}) wants historical metrics per KSI, and this document carries none: the pinned schema has no field for them (FedRAMP/schemas#10), and none were computed for this record`,
      );
    } else {
      problems.push(
        `SDR-CSX-KMT (${kmtForce} at class ${cls}): historical metrics are carried under x-rampscan.metrics, outside the pinned schema, which has no field for them (FedRAMP/schemas#10). A reviewer reading only the schema's fields will not see them`,
      );
      if (metrics.coveredFrom === undefined) {
        problems.push(
          `the ledger holds no scan of this offering in the ${metrics.reachDays} days the metrics reach, so every day is absent: there is no history to summarize, which is different from a history of zeros`,
        );
      }
    }
  }

  // ---- metadata (D12) ------------------------------------------------------
  const content: Record<string, unknown> = {
    certificationPackageOverviewUri: cpo,
    fedRampRequirements,
    keySecurityIndicators,
  };
  const version = `sha256:${createHash("sha256").update(JSON.stringify(content)).digest("hex").slice(0, 12)}`;
  const document: Record<string, unknown> = {
    certificationPackageOverviewUri: cpo,
    metadata: {
      version,
      lastUpdated: input.projectedAt,
      updateSource:
        `rampscan (automated), rendered from the evidence ledger at ${input.ledgerHead !== undefined ? `head ${input.ledgerHead}` : "an empty head"} ` +
        `against dataset ${input.datasetVersion}`,
    },
    fedRampRequirements,
    keySecurityIndicators,
    "x-rampscan": {
      generator: "rampscan",
      projectedAt: input.projectedAt,
      datasetVersion: input.datasetVersion,
      offeringClass: cls,
      ...(input.repo !== undefined ? { repo: input.repo } : {}),
      // carried so the human-readable half renders from this object alone (D3)
      offering: {
        providerName: input.offering.providerName,
        serviceName: input.offering.serviceName,
        serviceAcronym: input.offering.serviceAcronym,
      },
      artifactLabels: input.defaultArtifacts,
      declaredRuleForce,
      fieldSources: {
        certificationPackageOverviewUri: "declared",
        metadata: "computed",
        fedRampRequirements: "declared",
        keySecurityIndicators: "mixed",
      },
      versionBasis:
        "metadata.version is the first 12 hex of sha256 over the three schema fields above it, so it changes exactly when the record's content does and never with the wall clock",
      summary: {
        ksiRows: keySecurityIndicators.length,
        ksiStatus: counts,
        rulesAddressable: addressable.length,
        rulesDeclared: fedRampRequirements.length,
        rulesUnaddressed: unaddressedRules.length,
      },
      ksis: ksiExtension,
      unaddressedRules,
      ...(declaredNotAddressable.length > 0 ? { declaredNotAddressable } : {}),
      optionalKsis: optionalOmitted,
      statusRule:
        "ksiImplementationStatus is computed and may understate, never overstate. Implemented needs every in-scope method holding live evidence, the automated-method floor met (or, where the class owes none, an automated method with live evidence), no method stale or violated, the history floor not failed, and all five artifacts present. With at least one passing method and any of those short it is Partially Implemented; with no passing method (including a row whose only evidence is violated) it is Not Implemented. Each row's inputs are under ksis.<id>.statusBasis",
      ...(metrics !== undefined ? { metrics } : {}),
      notCarried:
        metrics !== undefined
          ? "The independent assessor's content (R4.5), portsAndProtocols and securityControls (Rev5) are not in this document"
          : "Historical metrics (SDR-CSX-KMT, R3), the independent assessor's content (R4.5), portsAndProtocols and securityControls (Rev5) are not in this document",
    },
  };

  return { export: { filename: SDR_ARTIFACT, schemaFile: SDR_SCHEMA, document, problems } };
}
