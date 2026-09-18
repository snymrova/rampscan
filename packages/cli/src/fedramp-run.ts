import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { DriftEvent, MethodRegisterRow, ValidationVulnerability } from "@rampscan/core";
import type { OfferingClass } from "@rampscan/dataset";
import type { OfferingConfig } from "@rampscan/schema";
import {
  buildOngoingCertificationReport,
  buildPackageOverview,
  type FedrampExport,
} from "./fedramp-exports.js";
import {
  FEDRAMP_SCHEMA_PINS,
  loadPinnedSchema,
  validateAgainst,
  type SchemaViolation,
} from "./fedramp-schemas.js";

// Generating and conformance-checking the two schema-target exports, in one
// place so the scan and the `exports` command produce the same bytes (plan
// Q5.1). The same reason `computeEvidencePackage` is one hand for two surfaces.
//
// A NONCONFORMING DOCUMENT IS STILL WRITTEN, AND CARRIES ITS OWN VERDICT.
// Withholding it would leave nothing to debug, and writing it silently would
// put a document that fails `FRC-CSO-JSN` next to one that passes with no way
// to tell them apart. So every document gets an `x-rampscan.conformance` stamp
// naming the pinned schema, its version, and every violation found — the file
// itself says whether it conforms, the way the evidence package's manifest
// lists the recipes with no evidence. The caller exits nonzero; Q5.2 turns
// that into the CI gate.
//
// The stamp is applied and then the document is validated AGAIN, because a
// stamp that could itself break conformance would be a validator reporting on
// bytes nobody shipped.

export interface FedrampExportRunInput {
  /** the rampscan checkout — where the PINNED schemas live */
  schemaRoot: string;
  /** where to write; created if absent */
  exportsDir: string;
  offering: OfferingConfig;
  offeringClass: OfferingClass;
  repo?: string;
  projectedAt: string;
  datasetVersion: string;
  methodRegisters: MethodRegisterRow[];
  vulnerabilities: ValidationVulnerability[];
  drift: DriftEvent[];
}

export interface WrittenExport {
  filename: string;
  path: string;
  schemaFile: string;
  schemaVersion: string;
  violations: SchemaViolation[];
  /** the builder's stated shortfalls — not schema failures, facts a reader needs */
  problems: string[];
}

export interface FedrampExportRunResult {
  written: WrittenExport[];
  /** why the OCR was not generated, when it was not — never a silent absence */
  ocrSkipped?: string;
  /** true when every written document validated clean */
  conformant: boolean;
}

/**
 * Validate, stamp, re-validate and write one schema-target document. Exported
 * so the SDR (R2.1) is written by the same hand as the CPO and OCR — one stamp
 * shape, one verdict rule, for every document `conformance` later reads.
 */
export async function emit(
  built: FedrampExport,
  input: { schemaRoot: string; exportsDir: string },
): Promise<WrittenExport> {
  const pin = FEDRAMP_SCHEMA_PINS[built.schemaFile];
  if (pin === undefined) {
    throw new Error(`${built.filename} names an unpinned schema ${built.schemaFile}`);
  }
  const loaded = await loadPinnedSchema(input.schemaRoot, built.schemaFile);

  const violations = validateAgainst(loaded, built.document);

  const extension = built.document["x-rampscan"];
  const stamped: Record<string, unknown> = {
    ...built.document,
    "x-rampscan": {
      ...(extension !== null && typeof extension === "object"
        ? (extension as Record<string, unknown>)
        : {}),
      conformance: {
        ruleId: "FRC-CSO-JSN",
        schema: built.schemaFile,
        schemaVersion: pin.schemaVersion,
        schemaSha256: pin.sha256,
        valid: violations.length === 0,
        violations,
      },
      /** the builder's stated shortfalls travel WITH the document, not only to a terminal */
      problems: built.problems,
    },
  };

  // the stamp must not change the verdict — a validator reporting on bytes
  // nobody ships is worse than no validator
  const afterStamp = validateAgainst(loaded, stamped);
  if (afterStamp.length !== violations.length) {
    throw new Error(
      `stamping x-rampscan.conformance changed ${built.filename}'s conformance (${violations.length} → ${afterStamp.length} violations) — the extension block is not free after all, and the stamp must be fixed before either number can be trusted`,
    );
  }

  const path = join(input.exportsDir, built.filename);
  await writeFile(path, JSON.stringify(stamped, null, 2) + "\n");
  return {
    filename: built.filename,
    path,
    schemaFile: built.schemaFile,
    schemaVersion: pin.schemaVersion,
    violations,
    problems: built.problems,
  };
}

export async function writeFedrampExports(
  input: FedrampExportRunInput,
): Promise<FedrampExportRunResult> {
  await mkdir(input.exportsDir, { recursive: true });
  const written: WrittenExport[] = [];

  written.push(await emit(buildPackageOverview(input), input));

  const ocr = buildOngoingCertificationReport(input);
  if (ocr.export !== undefined) written.push(await emit(ocr.export, input));

  const result: FedrampExportRunResult = {
    written,
    conformant: written.every((w) => w.violations.length === 0),
  };
  if (ocr.skipped !== undefined) result.ocrSkipped = ocr.skipped;
  return result;
}

/** The terminal reading — conformance first, because it is the gate. */
export function renderFedrampExports(result: FedrampExportRunResult): string {
  const lines: string[] = [];
  for (const w of result.written) {
    const verdict = w.violations.length === 0 ? "schema-valid" : `${w.violations.length} VIOLATION(S)`;
    lines.push(`${w.filename} → ${verdict}  (${w.schemaFile} @ ${w.schemaVersion})`);
    for (const v of w.violations) {
      lines.push(`    ✗ ${v.path === "" ? "<root>" : v.path}: ${v.message}`);
    }
    for (const p of w.problems) lines.push(`    · ${p}`);
  }
  if (result.ocrSkipped !== undefined) {
    lines.push("", `no Ongoing Certification Report: ${result.ocrSkipped}`);
  }
  return lines.join("\n");
}
