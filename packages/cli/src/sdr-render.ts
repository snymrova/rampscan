// The Security Decision Record, human-readable half (R2.2, #103;
// docs/PLAN-SDR.md D3). `SDR-CSO-FRR` wants the record "in both human-readable
// and JSON formats", and two formats computed separately are two chances to
// disagree. So this is a pure function of the JSON object as written, and the
// header carries the sha256 of the JSON file's bytes. `conformance` (R2.3)
// checks that the pair still matches.
//
// It says nothing the JSON does not. Every heading, row and sentence below is
// read from a field of the document or from fixed text about the document's
// shape. Where the JSON is empty, this file says it is empty. It never fills
// the gap.

type Obj = Record<string, unknown>;

const obj = (v: unknown): Obj => (v !== null && typeof v === "object" && !Array.isArray(v) ? (v as Obj) : {});
const arr = <T = unknown>(v: unknown): T[] => (Array.isArray(v) ? (v as T[]) : []);
const str = (v: unknown, fallback = ""): string => (typeof v === "string" ? v : fallback);

/** a table cell: pipes escaped, line breaks flattened */
function cell(v: string): string {
  return v.replace(/\|/g, "\\|").replace(/\r?\n+/g, " ").trim();
}

/** Markdown kept inside a quote so a body's own headings cannot restructure the record */
function quote(body: string): string {
  return body
    .replace(/\s+$/, "")
    .split("\n")
    .map((l) => (l.length > 0 ? `> ${l}` : ">"))
    .join("\n");
}

/** the "**Artifact n — label** _(provenance)_\n\nbody" statements the builder writes */
function splitStatement(s: string): { slot: number; head: string; body: string } | undefined {
  const m = /^\*\*Artifact (\d) — [^\n]*\n\n/.exec(s);
  if (m === null) return undefined;
  return { slot: Number(m[1]), head: s.slice(0, m[0].length).trim(), body: s.slice(m[0].length) };
}

export const SDR_MARKDOWN_ARTIFACT = "fedramp-security-decision-record.md";

/** the literal line that carries the JSON digest — R2.3 reads it back */
export const SDR_DIGEST_LINE = /^JSON sha256: `([0-9a-f]{64})`$/m;

export function renderSdrMarkdown(document: Obj, jsonSha256: string): string {
  const x = obj(document["x-rampscan"]);
  const meta = obj(document["metadata"]);
  const offering = obj(x["offering"]);
  const cls = str(x["offeringClass"], "?");
  const labels = arr<string>(x["artifactLabels"]);
  const ksiExt = obj(x["ksis"]);
  const summary = obj(x["summary"]);
  const conformance = obj(x["conformance"]);
  const problems = arr<string>(x["problems"]);
  const rules = arr<Obj>(document["fedRampRequirements"]);
  const unaddressed = arr<Obj>(x["unaddressedRules"]);
  const forces = obj(x["declaredRuleForce"]);
  const ksis = arr<Obj>(document["keySecurityIndicators"]);

  const out: string[] = [];
  const name = str(offering["serviceName"], "unnamed offering");
  const acronym = str(offering["serviceAcronym"]);
  out.push(`# Security Decision Record — ${name}${acronym !== "" ? ` (${acronym})` : ""}`, "");
  out.push(
    `${str(offering["providerName"], "unnamed provider")} · class ${cls} · dataset ${str(x["datasetVersion"], "?")} · as of ${str(x["projectedAt"], "?")}`,
    "",
    "This is the human-readable half of the record `SDR-CSO-FRR` requires in both formats. It is rendered from `fedramp-security-decision-record.json` and says nothing that file does not.",
    "",
    `JSON sha256: \`${jsonSha256}\``,
    "",
    `- **Version:** ${str(meta["version"], "none")}`,
    `- **Last updated:** ${str(meta["lastUpdated"], "none")}`,
    `- **Update source:** ${str(meta["updateSource"], "none")}`,
    `- **Certification package overview:** ${str(document["certificationPackageOverviewUri"], "none")}`,
    "",
    "**Legend.** *Declared* text is the offering's own, passed through by rampscan unchanged. *Computed* values are derived by rampscan from signed ledger statements. An artifact body is quoted with its source (`authored`, `computed`, `attested` or `assessed`) and the sha256 of its bytes.",
    "",
  );

  // ---- summary ------------------------------------------------------------
  const status = obj(summary["ksiStatus"]);
  const declined = rules.filter((r) => r["frrImplementationStatus"] === "Not Implemented").length;
  out.push("## Summary", "");
  out.push(
    `- **KSI rows:** ${ksis.length} — ${Number(status["Implemented"] ?? 0)} Implemented, ${Number(status["Partially Implemented"] ?? 0)} Partially Implemented, ${Number(status["Not Implemented"] ?? 0)} Not Implemented. The status is *computed*, and may understate but never overstate.`,
    `- **FedRAMP rules addressable at class ${cls}:** ${Number(summary["rulesAddressable"] ?? 0)}. Rows declared: ${rules.length} (${rules.length - declined} addressed, ${declined} not implemented with a reason). Without a row: ${unaddressed.length}.`,
    `- **Schema (FRC-CSO-JSN):** ${
      conformance["valid"] === true
        ? `valid against \`${str(conformance["schema"])}\` @ ${str(conformance["schemaVersion"])}`
        : conformance["valid"] === false
          ? `**${arr(conformance["violations"]).length} violation(s)** against \`${str(conformance["schema"])}\` @ ${str(conformance["schemaVersion"])}`
          : "not stamped"
    }`,
    "",
  );
  if (problems.length > 0) {
    out.push("### Problems", "", "Stated in full, as the JSON carries them:", "");
    for (const p of problems) out.push(`- ${p}`);
    out.push("");
  }

  // ---- KSIs -----------------------------------------------------------------
  out.push("## Key Security Indicators", "");
  for (const k of ksis) {
    const id = str(k["ksiId"]);
    const ext = obj(ksiExt[id]);
    const basis = obj(ext["statusBasis"]);
    const short = arr<string>(basis["short"]);
    const artifacts = arr<Obj>(ext["artifacts"]);
    out.push(`### ${id}${str(ext["name"]) !== "" ? ` — ${str(ext["name"])}` : ""}`, "");
    const st = str(k["ksiImplementationStatus"], "not stated");
    out.push(
      `**Status:** ${st} (computed).${short.length > 0 ? ` Short of Implemented: ${short.join("; ")}.` : ""}`,
      "",
    );

    out.push("#### The five artifacts (SDR-CSX-KSI)", "");
    const statements = [...arr<string>(k["ksiImplementation"]), ...arr<string>(k["ksiValidation"])]
      .map(splitStatement)
      .filter((s): s is NonNullable<typeof s> => s !== undefined);
    for (const slot of [1, 2, 3, 4, 5]) {
      const label = labels[slot - 1] ?? `Artifact ${slot}`;
      const found = statements.find((s) => s.slot === slot);
      if (found !== undefined) {
        out.push(`${slot}. ${found.head}`, "", quote(found.body), "");
        continue;
      }
      const absent = obj(artifacts.find((a) => a["artifact"] === slot)?.["absent"]);
      const why = str(absent["reason"]) !== "" ? ` The slot emptied: ${str(absent["reason"])}.` : "";
      out.push(`${slot}. **Artifact ${slot} — ${label}** — *missing: no body in this record.*${why}`, "");
    }

    const assessment = arr<string>(k["ksiAssessment"]);
    out.push("#### Assessment", "");
    if (assessment.length === 0) out.push("*None: the independent assessor's summary is not in this record.*", "");
    else for (const a of assessment) out.push(quote(a), "");

    const tests = arr<string>(k["ksiTests"]);
    out.push("#### Tests (computed)", "");
    if (tests.length === 0) out.push("*No validation method is derived for this KSI.*", "");
    else out.push(...tests.map((t) => `- ${t}`), "");

    const evidence = arr<Obj>(k["ksiEvidence"]);
    out.push("#### Evidence (computed)", "");
    if (evidence.length === 0) out.push("*No live evidence.*", "");
    else {
      out.push("| Type | Updated | Result | Location |", "|---|---|---|---|");
      for (const e of evidence) {
        out.push(
          `| ${cell(str(e["evidenceType"], "—"))} | ${cell(str(e["lastUpdated"], "—"))} | ${cell(str(e["evidenceDescription"], "—"))} | \`${cell(str(e["evidenceLocation"], "—"))}\` |`,
        );
      }
      out.push("");
    }
  }

  // ---- rules ----------------------------------------------------------------
  out.push("## FedRAMP rules (SDR-CSO-FRR)", "");
  out.push("### Declared by the offering", "");
  if (rules.length === 0) out.push("*The offering declares no rule coverage, so no rule has a row.*", "");
  else {
    out.push(`| Rule | Force at class ${cls} | Status | Statement | Validation |`, "|---|---|---|---|---|");
    for (const r of rules) {
      const id = str(r["frrID"]);
      out.push(
        `| ${id} | ${cell(str(forces[id], "—"))} | ${cell(str(r["frrImplementationStatus"], "not stated"))} | ${cell(arr<string>(r["frrImplementation"]).join(" "))} | ${cell(arr<string>(r["frrValidation"]).join(" ") || "—")} |`,
      );
    }
    out.push("");
  }
  out.push("### Without a row", "");
  if (unaddressed.length === 0) out.push("*Every addressable rule has a row.*", "");
  else {
    out.push(
      "Each rule below is addressable at this class and the offering declares nothing for it, so the record has no row for it. That omission is FedRAMP's rejection reason 3.",
      "",
      `| Rule | Force at class ${cls} | rampscan computes it |`,
      "|---|---|---|",
    );
    for (const r of unaddressed) {
      out.push(
        `| ${str(r["ruleId"])} | ${cell(str(r["force"], "—"))} | ${cell(str(r["computedBy"], "—"))} |`,
      );
    }
    out.push("");
  }

  // ---- what is not here -----------------------------------------------------
  out.push("## What this document does not contain", "");
  const optional = arr<string>(x["optionalKsis"]);
  out.push(`- ${str(x["notCarried"], "Nothing is stated as omitted.")}`);
  if (optional.length > 0) {
    out.push(`- KSIs class ${cls} does not oblige and that hold no evidence: ${optional.join(", ")}.`);
  }
  out.push(
    "- A verification field. The schema has none. The two verifications `SDR-CSX-KSI` asks for (artifacts 3 and 4) are carried under `ksiValidation`, beside validation (artifact 5).",
    "",
  );
  return out.join("\n");
}
