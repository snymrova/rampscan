import type {
  HistoryFloor,
  KsiCatalog,
  MethodFloor,
  OfferingClass,
  ValidationWindow,
} from "@rampscan/dataset";
import { optionalKsis, requiredKsis } from "@rampscan/dataset";

// `rampscan owed` — the Q1 exit gate: the owed state for any (KSI, class)
// pair, every number traceable to the pinned JSON. A pure derivation over the
// KsiCatalog port in the shape of `tools` and `frontier`: nothing probed,
// nothing written. Class here is the REPORTING class of SPEC §12.3 — all four
// are legitimate what-ifs, including d, which the scheduler still refuses.

const CLASS_NAMES: Record<OfferingClass, string> = {
  a: "a (Pilot)",
  b: "b (≈ Low)",
  c: "c (≈ Moderate)",
  d: "d (≈ High)",
};

function describeFloor(floor: MethodFloor): string {
  return floor.minPerKsi === null
    ? `no floor — ${floor.force}, unquantified`
    : `≥${floor.minPerKsi} automated method${floor.minPerKsi === 1 ? "" : "s"} per KSI`;
}

function describeHistory(history: HistoryFloor): string {
  return history.months === null
    ? `no floor — ${history.force}, unquantified`
    : `≥${history.months} months of persistent-validation history`;
}

function describeWindow(window: ValidationWindow | null): string {
  if (window === null) {
    // the dataset speaking, not a gap: VDR-TFR-MVX has no class-d entry
    return "none defined — VDR-TFR-MVX carries no entry for this class (SPEC §11 q6)";
  }
  return `re-validate every ${window.num} ${window.num === 1 ? window.unit.replace(/s$/, "") : window.unit}`;
}

function ruleTag(requirementId: string, force: string): string {
  return `${requirementId} (${force})`;
}

/**
 * The owed block for one class — shared by both views, because the owed
 * numbers are per (class), not per (KSI, class): every KSI at a class owes
 * the same floor, window and artifact count. What varies per KSI is the
 * statement and the crosswalk, which the detail view adds.
 */
function owedLines(catalog: KsiCatalog, cls: OfferingClass): string[] {
  const floor = catalog.floors[cls];
  const history = catalog.historyFloors[cls];
  const window = catalog.windows[cls];
  return [
    `  floor        ${describeFloor(floor).padEnd(52)} ${ruleTag(floor.requirementId, floor.force)}`,
    `  history      ${describeHistory(history).padEnd(52)} ${ruleTag(history.requirementId, history.force)}`,
    `  window       ${describeWindow(window).padEnd(52)} ${window ? ruleTag(window.requirementId, window.force) : "VDR-TFR-MVX"}`,
    `  non-machine  ${describeWindow(catalog.nonMachineWindow).padEnd(52)} ${ruleTag(catalog.nonMachineWindow.requirementId, catalog.nonMachineWindow.force)}`,
    `  artifacts    ${catalog.defaultArtifacts.length} default artifacts owed per KSI`,
  ];
}

/** The register view: every KSI, with the class's owed numbers up top. */
export function renderOwed(catalog: KsiCatalog, cls: OfferingClass): string {
  const lines: string[] = [
    "rampscan owed — the owed side of the register (SPEC §12)",
    `class ${CLASS_NAMES[cls]} · dataset ${catalog.datasetVersion}`,
    "",
    `owed for EACH of the ${requiredKsis(catalog, cls).length} KSIs class ${cls} obliges:`,
    ...owedLines(catalog, cls),
    "",
    `  ${"KSI".padEnd(14)} ${"name".padEnd(38)} controls`,
  ];
  // Optional indicators keep their row and say so — the class does not oblige
  // them, and a provider who evidences one anyway has done real work (§13.7).
  const optional = new Set(optionalKsis(catalog, cls));
  for (const ksi of catalog.ksis) {
    const tag = optional.has(ksi.id) ? `  optional at class ${cls}` : "";
    lines.push(`  ${ksi.id.padEnd(14)} ${ksi.name.padEnd(38)} ${ksi.controls.length}${tag}`);
  }
  lines.push(
    "",
    optional.size === 0
      ? `${catalog.ksis.length} KSIs · ${catalog.themes.length} themes · every number above is read from the pinned JSON, never typed`
      : `${catalog.ksis.length} KSIs, ${catalog.ksis.length - optional.size} owed at class ${cls} · ${catalog.themes.length} themes · every number above is read from the pinned JSON, never typed`,
  );
  return lines.join("\n");
}

/** The (KSI, class) detail view — the exit gate's sentence, one pair at a time. */
export function renderOwedKsi(
  catalog: KsiCatalog,
  cls: OfferingClass,
  ksiId: string,
): string | undefined {
  const ksi = catalog.ksis.find((k) => k.id === ksiId);
  if (!ksi) return undefined;
  const theme = catalog.themes.find((t) => t.key === ksi.themeKey);
  const lines: string[] = [
    `${ksi.id} — ${ksi.name}`,
    `theme ${theme?.name ?? ksi.themeKey} (${ksi.themeKey}) · class ${CLASS_NAMES[cls]} · dataset ${catalog.datasetVersion}`,
    "",
  ];
  if (ksi.statement === null) {
    lines.push(
      "statement: varies by certification class at this pin — the derived slices",
      "  carry no variants; read the rules JSON's varies_by_class for this KSI",
    );
  } else {
    lines.push("statement:", `  ${ksi.statement}`);
  }
  lines.push(
    "",
    `owed at class ${cls}:`,
    ...owedLines(catalog, cls),
    "",
    `controls (${ksi.controls.length}): ${ksi.controls.join(", ")}`,
    "",
    "the artifacts owed:",
    ...catalog.defaultArtifacts.map((a, i) => `  ${i + 1}. ${a}`),
  );
  return lines.join("\n");
}
