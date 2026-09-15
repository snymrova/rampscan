import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { basename } from "node:path";
import { z } from "zod";
import type { Cadence, IngestSubmission, IngestedArtifact, KsiCrosswalk } from "@rampscan/schema";
import {
  INGEST_SUBMISSION_TYPE,
  KsiCrosswalk as KsiCrosswalkSchema,
  canonicalJson,
} from "@rampscan/schema";
import { parse as parseYaml } from "yaml";

// The package adapter (SPEC §12.8, plan S3-1): `rampscan ingest <package.yaml>`
// over a machine-readable assessment package — Package → Assessment → KSIs →
// Validations → Evidences → Artifacts, the shape the only publicly assessed
// 20x package is published in (docs/RESEARCH-PARAMIFY-PILOT.md §2, §8.3).
// That repository ships no Evidence/ tree output, only the assessed package,
// so "ingest a package that has already passed" is this adapter or nothing.
//
// One native submission per (validation KSI × evidence), which is the
// contract's unit; the adapter's OUTPUT is native submissions, so the digest
// discipline is identical on every path. What it deliberately does not do:
//
//   - It signs no verdict. The package carries a person's reading —
//     `assessmentStatus: True|Partial`, `assessmentSteps[].status: PASS` —
//     and, in the assessed specimen, `validationRules: []` on every evidence
//     (§8.1). None of that is a machine assertion the appliance evaluated,
//     so `assertions` is empty and every bundle is `unevidenced`: a signed
//     record of what the package handed over, never a pass. A 3PAO's reading
//     is the attestation path's business (Q4.2), signed by the reader.
//   - It declares `automated: false`. Whatever produced the artifact — 80 of
//     the specimen's 140 evidences are marked `automated: Yes` — nothing
//     validated it by machine, so the FRC-CSX-VVK numerator does not move.
//   - It declares `point-in-time`. An assessment package is a captured state
//     at `effectiveDate`; there is no process here for the appliance to
//     re-run, and G6 says what that means for standalone evidence.
//   - It invents no digest. The package names its artifacts by reference and
//     ships no bytes; the one digested subject is the package file itself,
//     the bytes the appliance holds. The references ride beside it, as
//     references.
//
// KSI ids are the package's own; when they are an earlier catalog's, a
// reviewed crosswalk (`--crosswalk`) places them, and an indicator with no
// successor is skipped and named — the way a failed run is on the tree path.

/** the assessed package's shape, loosely: what the adapter reads, nothing more */
const PackageArtifact = z.looseObject({
  artifact: z.looseObject({
    name: z.string().optional(),
    reference: z.string().optional(),
    effectiveDate: z.string().optional(),
  }),
});
const PackageEvidence = z.looseObject({
  evidence: z.looseObject({
    id: z.string().optional(),
    name: z.string().optional(),
    instructions: z.string().optional(),
    automated: z.union([z.string(), z.boolean()]).optional(),
    Artifacts: z.array(PackageArtifact).optional(),
  }),
});
const PackageValidation = z.looseObject({
  validation: z.looseObject({
    shortName: z.string().min(1),
    assessmentStatus: z.union([z.string(), z.boolean()]).optional(),
    assessedBy: z.string().optional(),
    assessedOn: z.string().optional(),
    Evidences: z.array(PackageEvidence).optional(),
  }),
});
const PackageKsi = z.looseObject({
  KSI: z.looseObject({
    shortName: z.string().optional(),
    Validations: z.array(PackageValidation).optional(),
  }),
});
const PackageAssessment = z.looseObject({
  Assessment: z.looseObject({
    assessorOrg: z.string().optional(),
    leadAssessor: z.string().optional(),
    date: z.union([z.string(), z.date()]).optional(),
    KSIs: z.array(PackageKsi).optional(),
  }),
});
const MachineReadablePackage = z.looseObject({
  Package: z.looseObject({
    CSPName: z.string().optional(),
    CSO: z.string().optional(),
    Assessments: z.array(PackageAssessment).min(1),
  }),
});

export interface PackageIngestOptions {
  /** the reviewed KSI crosswalk, when the package's ids are an earlier catalog's */
  crosswalk?: string | undefined;
  /** the client's declared cadence — the package schema has no such field, and it is never guessed */
  cadence?: Cadence | undefined;
  /** the pin the crosswalk must resolve into */
  datasetPin: string;
}

/** an evidence the adapter set aside: its indicator has no successor at the pin */
export interface RetiredEvidence {
  ksi: string;
  script: string;
  reason: string;
}

export interface LoadedPackage {
  submissions: IngestSubmission[];
  retired: RetiredEvidence[];
  /** what the package says about itself, for the log — consumed output, no verdict read from it */
  summary: {
    cso: string;
    assessor: string;
    validations: number;
    evidences: number;
    artifacts: number;
    /** the package's own `automated: Yes` count — collection, not validation */
    markedAutomated: number;
    assessmentStatus: Record<string, number>;
    /** evidences one 2026 KSI received from two merged Phase One indicators, and how each was kept */
    merged: string[];
  };
}

/** `Security Group Rules ` → `security-group-rules` — their names, in a key */
function slug(name: string): string {
  return (
    name
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "") || "unnamed"
  );
}

/**
 * The assessment's own date, as the specimen writes it (`7/10/25`) or as ISO.
 * The fallback clock for an evidence whose artifacts carry no date — refused
 * rather than guessed when it cannot be read, because a submission's
 * timestamp is the instant every clock in the register judges.
 */
function assessmentInstant(date: string | Date | undefined): string {
  if (date instanceof Date) return date.toISOString();
  if (date === undefined || date.trim() === "") {
    throw new Error(
      "package: the Assessment carries no date, and an evidence without a dated artifact has no clock",
    );
  }
  const mdy = /^(\d{1,2})\/(\d{1,2})\/(\d{2}|\d{4})$/.exec(date.trim());
  if (mdy !== null) {
    const year = mdy[3]!.length === 2 ? 2000 + Number(mdy[3]) : Number(mdy[3]);
    return new Date(Date.UTC(year, Number(mdy[1]) - 1, Number(mdy[2]))).toISOString();
  }
  const parsed = Date.parse(date);
  if (Number.isNaN(parsed)) {
    throw new Error(
      `package: the Assessment date "${date}" is not a date the adapter can read (M/D/YY or ISO 8601)`,
    );
  }
  return new Date(parsed).toISOString();
}

function isYes(value: string | boolean | undefined): boolean {
  if (typeof value === "boolean") return value;
  return /^(yes|true)$/i.test((value ?? "").trim());
}

async function loadCrosswalk(
  path: string,
  pin: string,
): Promise<Map<string, KsiCrosswalk["entries"][number]>> {
  let crosswalk: KsiCrosswalk;
  try {
    crosswalk = KsiCrosswalkSchema.parse(JSON.parse(await readFile(path, "utf8")));
  } catch (cause) {
    throw new Error(`${path} does not match the KSI crosswalk contract (SPEC §12.8)`, { cause });
  }
  if (crosswalk.to !== pin) {
    throw new Error(
      `${path} resolves into dataset ${crosswalk.to}, but this ingest is pinned to ${pin} — ` +
        `a crosswalk into another pin is refused, not reinterpreted`,
    );
  }
  const byFrom = new Map<string, KsiCrosswalk["entries"][number]>();
  for (const entry of crosswalk.entries) {
    if (byFrom.has(entry.from)) {
      throw new Error(`${path}: ${entry.from} is mapped twice — one entry per indicator`);
    }
    byFrom.set(entry.from, entry);
  }
  return byFrom;
}

export async function loadPackage(
  path: string,
  options: PackageIngestOptions,
): Promise<LoadedPackage> {
  if (options.cadence === undefined) {
    throw new Error(
      `${basename(path)} is an assessment package, which carries no cadence — declare the cycle ` +
        `the evidence is refreshed on with --cadence <continuous|daily|weekly|monthly|quarterly>; it is never guessed`,
    );
  }
  const bytes = await readFile(path);
  let parsed;
  try {
    parsed = MachineReadablePackage.parse(parseYaml(bytes.toString("utf8")));
  } catch (cause) {
    throw new Error(
      `${path} does not parse as a machine-readable package (Package → Assessments → KSIs → Validations → Evidences)`,
      { cause },
    );
  }
  const crosswalk =
    options.crosswalk === undefined
      ? undefined
      : await loadCrosswalk(options.crosswalk, options.datasetPin);

  const pkg = parsed.Package;
  const packageArtifact: IngestedArtifact = {
    name: basename(path),
    sha256: createHash("sha256").update(bytes).digest("hex"),
  };
  // candidates first: a crosswalk that MERGES two Phase One indicators into
  // one 2026 KSI can make one evidence, cited by both, arrive twice under one
  // (recipe, KSI) — resolved below, once every validation has been read
  const candidates: Array<{
    submission: IngestSubmission;
    validation: string;
  }> = [];
  const retired: RetiredEvidence[] = [];
  const summary: LoadedPackage["summary"] = {
    cso: pkg.CSO ?? "",
    assessor: "",
    validations: 0,
    evidences: 0,
    artifacts: 0,
    markedAutomated: 0,
    assessmentStatus: {},
    merged: [],
  };
  const unmapped: string[] = [];

  // the specimen carries one assessment; a package carrying more is read in
  // full, each assessment's own assessor standing behind its own validations
  for (const { Assessment: assessment } of pkg.Assessments) {
    const org = (assessment.assessorOrg ?? "").trim();
    summary.assessor = [org, (assessment.leadAssessor ?? "").trim()]
      .filter((s) => s !== "")
      .join(": ");
    for (const { KSI: theme } of assessment.KSIs ?? []) {
      for (const { validation } of theme.Validations ?? []) {
        summary.validations++;
        const status = String(validation.assessmentStatus ?? "").trim() || "(none)";
        summary.assessmentStatus[status] = (summary.assessmentStatus[status] ?? 0) + 1;

        // where this validation lands at the pin: through the crosswalk when
        // one was given, else the package's id as a mnemonic (`KSI-` prefixed
        // if the package left it off) — the catalog check downstream refuses
        // what does not resolve
        let ksis: string[];
        let retirement: string | undefined;
        if (crosswalk === undefined) {
          const id = validation.shortName.trim();
          ksis = [id.startsWith("KSI-") ? id : `KSI-${id}`];
        } else {
          const entry = crosswalk.get(validation.shortName.trim());
          if (entry === undefined) {
            unmapped.push(validation.shortName.trim());
            continue;
          }
          ksis = entry.to;
          if (ksis.length === 0) retirement = entry.basis;
        }

        // who stands behind this validation: the assessor the package names
        // for it, under the assessing organisation
        const assessedBy =
          (validation.assessedBy ?? "").trim() || (assessment.leadAssessor ?? "").trim();
        const signer = [org, assessedBy].filter((s) => s !== "").join(": ");
        if (signer === "") {
          throw new Error(
            `package: validation ${validation.shortName} names no assessor and the Assessment names no ` +
              `organisation — a submission needs someone who stands behind it`,
          );
        }

        const seen = new Map<string, number>();
        for (const { evidence } of validation.Evidences ?? []) {
          summary.evidences++;
          if (isYes(evidence.automated)) summary.markedAutomated++;
          // their name, as the recipe id; a name the validation repeats gets
          // an ordinal, because two evidences under one name are two records
          const baseId =
            (evidence.id ?? "").trim() !== "" ? slug(evidence.id!) : slug(evidence.name ?? "");
          const n = (seen.get(baseId) ?? 0) + 1;
          seen.set(baseId, n);
          const recipeId = n === 1 ? baseId : `${baseId}~${n}`;

          summary.artifacts += (evidence.Artifacts ?? []).length;
          if (retirement !== undefined) {
            retired.push({
              ksi: validation.shortName.trim(),
              script: recipeId,
              reason: `${validation.shortName.trim()} has no ${options.datasetPin} successor — ${retirement}`,
            });
            continue;
          }

          const artifacts: IngestedArtifact[] = [packageArtifact];
          let latest: string | undefined;
          for (const { artifact } of evidence.Artifacts ?? []) {
            const name = (artifact.name ?? "").trim();
            if (name === "") continue;
            const reference = (artifact.reference ?? "").trim();
            artifacts.push(reference === "" ? { name } : { name, reference });
            const at = (artifact.effectiveDate ?? "").trim();
            if (at !== "" && !Number.isNaN(Date.parse(at))) {
              const iso = new Date(at).toISOString();
              if (latest === undefined || iso > latest) latest = iso;
            }
          }
          const timestamp = latest ?? assessmentInstant(assessment.date);
          const instructions = (evidence.instructions ?? "").trim();

          for (const ksi of ksis) {
            candidates.push({
              validation: validation.shortName.trim(),
              submission: {
                _type: INGEST_SUBMISSION_TYPE,
                recipe_id: recipeId,
                ksi,
                evidence_class: "point-in-time",
                cadence: options.cadence,
                artifacts,
                assertions: [],
                timestamp,
                signer_identity: signer,
                automated: false,
                ...(instructions !== "" ? { reproduce: instructions } : {}),
              },
            });
          }
        }
      }
    }
  }

  if (unmapped.length > 0) {
    throw new Error(
      `${options.crosswalk} does not carry ${unmapped.length} indicator(s) the package names: ` +
        `${[...new Set(unmapped)].join(", ")} — every indicator is placed or retired by a reviewed entry, never dropped`,
    );
  }

  // One (recipe, KSI) per batch is the contract's rule, and a merge in the
  // crosswalk can break it honestly: the specimen cites `okta-authenticators`
  // under both IAM-01 and IAM-02, which both land on KSI-IAM-APM. The same
  // bytes cited twice are ONE record, kept once and noted; different bytes
  // under one name are two records, and each is keyed by the validation that
  // cited it — never dropped, never merged.
  const submissions: IngestSubmission[] = [];
  const merged: string[] = [];
  const byKey = new Map<string, Array<{ submission: IngestSubmission; validation: string }>>();
  for (const c of candidates) {
    const key = `${c.submission.recipe_id}#${c.submission.ksi}`;
    (byKey.get(key) ?? byKey.set(key, []).get(key)!).push(c);
  }
  for (const [key, group] of byKey) {
    if (group.length === 1) {
      submissions.push(group[0]!.submission);
      continue;
    }
    const digests = new Set(group.map((c) => canonicalJson(c.submission)));
    if (digests.size === 1) {
      submissions.push(group[0]!.submission);
      merged.push(
        `${key} cited by ${group.map((c) => c.validation).join(" and ")} — one record, kept once`,
      );
      continue;
    }
    for (const c of group) {
      submissions.push({
        ...c.submission,
        recipe_id: `${c.submission.recipe_id}@${c.validation}`,
      });
    }
    merged.push(
      `${key} cited by ${group.map((c) => c.validation).join(" and ")} with different artifacts — kept as ` +
        group.map((c) => `${c.submission.recipe_id}@${c.validation}`).join(", "),
    );
  }
  return { submissions, retired, summary: { ...summary, merged } };
}
