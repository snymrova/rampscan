import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { ArtifactCell, MethodCell, MethodRegisterRow } from "@rampscan/core";
import {
  DEFAULT_DATASET_PIN,
  loadKsiCatalog,
  loadRuleRegister,
  optionalKsis,
  type KsiCatalog,
  type RuleRegister,
} from "@rampscan/dataset";
import { OfferingConfig } from "@rampscan/schema";
import { buildSecurityDecisionRecord, type SdrBuildInput } from "../src/sdr-build.js";

// Shared by the SDR's builder and renderer tests (R2.1, R2.2): one synthetic
// offering, one register row per KSI on request, and the pinned catalog and
// rule register, so both halves are tested over the same record.

export const root = join(dirname(fileURLToPath(import.meta.url)), "../../..");
export const rulesFile = join(root, "docs/context/fedramp-rules/fedramp-consolidated-rules.json");
export const derivedDir = join(root, "docs/context/ramprules/derived");

let catalogCache: KsiCatalog | undefined;
let registerCache: RuleRegister | undefined;
export async function sources(): Promise<{ catalog: KsiCatalog; register: RuleRegister }> {
  catalogCache ??= await loadKsiCatalog({ derivedDir, rulesFile, pin: DEFAULT_DATASET_PIN });
  registerCache ??= await loadRuleRegister(rulesFile, DEFAULT_DATASET_PIN);
  return { catalog: catalogCache, register: registerCache };
}

export const AT = "2026-09-18T12:00:00.000Z";
export const hex = (c: string) => c.repeat(64);

export const offeringJson = {
  providerName: "Example Cloud Inc.",
  serviceName: "Example Evidence Plane",
  serviceAcronym: "EEP",
  serviceDescription: "A CI/CD evidence plane.",
  certificationType: "20x",
  fedRampPackageId: "Example Cloud Inc. (EEP)",
  website: "https://example.com/eep",
  logo: "https://example.com/logo.svg",
  serviceType: ["SaaS"],
  deploymentModel: "Public Cloud",
  contactInformation: [
    { contactType: "Security", contactName: "Security Team" },
    { contactType: "Sales", contactName: "Sales Team" },
  ],
  report: {
    certificationPackageOverviewUri: "https://trust.example.com/cpo.json",
    plannedCertificationDataChanges: { planningHorizonThrough: "2026-12-31", changes: [] },
    acceptedVulnerabilities: "none accepted",
    transformativeChanges: [],
    updatedRecommendations: [],
    activeAgencies: [],
    reportableIncidents: { incidents: [] },
  },
};
export const offering = (over: Record<string, unknown> = {}) => OfferingConfig.parse({ ...offeringJson, ...over });

/** overrides may unset an optional field by passing undefined */
export type Over<T> = { [K in keyof T]?: T[K] | undefined };
function strip<T extends object>(o: T): T {
  for (const k of Object.keys(o) as (keyof T)[]) if (o[k] === undefined) delete o[k];
  return o;
}

export function cell(over: Over<MethodCell> = {}): MethodCell {
  return strip({
    methodId: "pipeline:secrets-scan",
    source: "pipeline",
    automated: true,
    clock: "machine",
    standing: "full",
    recipeId: "secrets-scan",
    collector: "gitleaks",
    state: "evidenced",
    bundleDigest: hex("a"),
    freshAsOf: "2026-09-17T08:00:00.000Z",
    evidenceClass: "process-generated",
    window: { num: 7, unit: "days" },
    freshMet: true,
    ...over,
  } as MethodCell);
}

/** five artifact cells; `bodies` names which slots hold a body, keyed by slot */
export function artifacts(present: readonly number[]): ArtifactCell[] {
  return ([1, 2, 3, 4, 5] as const).map((slot) => {
    const base: ArtifactCell = {
      artifact: slot,
      basis: slot === 2 || slot === 5 ? "computed" : "judged",
      present: present.includes(slot),
    };
    if (!present.includes(slot)) return base;
    return {
      ...base,
      body: {
        digest: `stmt-${slot}`,
        bodyDigest: hex(String(slot)),
        source: slot === 1 || slot === 3 ? "authored" : "computed",
        validFrom: "2026-09-01T00:00:00.000Z",
        freshMet: true,
        bodyBytes: 20,
        ...(slot === 1 || slot === 3 ? { anchor: { commit: hex("c").slice(0, 40), path: `docs/ksi/${slot}.md` } } : {}),
      },
    };
  });
}

export function row(ksi: string, over: Partial<MethodRegisterRow> = {}): MethodRegisterRow {
  const art = over.artifacts ?? artifacts([1, 2, 3, 4, 5]);
  return {
    repo: "example/eep",
    ksi,
    methods: [cell()],
    automatedMethods: 1,
    methodFloor: 1,
    floorMet: true,
    freshAsOf: "2026-09-17T08:00:00.000Z",
    historySince: "2026-01-01T00:00:00.000Z",
    historyFloorMonths: null,
    historyMet: null,
    staleMethods: 0,
    artifacts: art,
    artifactsPresent: art.filter((a) => a.present).length,
    pointInTimeMethods: 0,
    ...over,
  };
}

export const BODIES = new Map([1, 2, 3, 4, 5].map((s) => [`stmt-${s}`, `Body of artifact ${s}.`]));

export async function input(over: Over<SdrBuildInput> = {}): Promise<SdrBuildInput> {
  const { catalog, register } = await sources();
  return strip({
    offering: offering(),
    offeringClass: "b",
    repo: "example/eep",
    projectedAt: AT,
    datasetVersion: catalog.datasetVersion,
    ledgerHead: hex("f"),
    ksis: catalog.ksis.map((k) => ({ id: k.id, name: k.name })),
    optionalKsis: optionalKsis(catalog, "b"),
    defaultArtifacts: catalog.defaultArtifacts,
    methodRegisters: [row("KSI-SVC-SIN")],
    ruleRegister: register,
    bodies: BODIES,
    ...over,
  } as SdrBuildInput);
}

export function built(i: SdrBuildInput) {
  const out = buildSecurityDecisionRecord(i);
  if (out.export === undefined) throw new Error(`no SDR: ${out.skipped}`);
  return out.export;
}
export const ksiRow = (doc: Record<string, unknown>, id: string) =>
  (doc["keySecurityIndicators"] as Record<string, unknown>[]).find((k) => k["ksiId"] === id);
export const ruleRow = (doc: Record<string, unknown>, id: string) =>
  (doc["fedRampRequirements"] as Record<string, unknown>[]).find((r) => r["frrID"] === id);

