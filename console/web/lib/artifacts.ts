// Artifact viewers (plan J4): the operator finally SEES what a tool said,
// instead of inferring it from a verdict pill.
//
// Everything here is PURE — (name, parsed content) → a table. No fetching, no
// verdicts, no counts that are not a count of the rows in front of you. The
// bytes these functions read were fetched from `/api/artifact?digest=`, which
// re-hashed them before serving, and the evidence page re-hashes them AGAIN in
// the browser before calling anything here: a table rendered from bytes that
// did not hash to the attested digest would be a screenshot with borders.
//
// Three rules the tables obey:
//
//   1. A SECRET IS NEVER RENDERED. gitleaks reports carry the matched secret
//      and its surrounding line; this viewer shows the rule, the file:line and
//      the commit — everything a fix needs and nothing an over-the-shoulder
//      reader can steal. Not masked, not truncated: absent.
//   2. Rows are capped and the cap SAYS SO, with the true total (I2c's
//      offender-count precedent). A table that silently shows the first 200 of
//      1,431 findings is worse than no table.
//   3. An unknown artifact gets NO table rather than a guessed one. The page
//      falls back to the raw bytes and the download, which is a fact about
//      this viewer, not a fact about the artifact.

export const ROW_CAP = 200;

export interface ArtifactTable {
  /** the family this artifact was recognized as */
  family: string;
  columns: string[];
  rows: string[][];
  /** rows the artifact holds — `rows.length` when nothing was cut */
  total: number;
  /** what this table deliberately does not show, said out loud */
  note?: string;
}

type Json = Record<string, unknown>;

const str = (v: unknown): string => (v === undefined || v === null ? "" : String(v));
const arr = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);
const obj = (v: unknown): Json => (v && typeof v === "object" ? (v as Json) : {});

/** cap the rows, and say what was cut */
function capped(
  family: string,
  columns: string[],
  all: string[][],
  note?: string,
): ArtifactTable {
  const table: ArtifactTable = {
    family,
    columns,
    rows: all.slice(0, ROW_CAP),
    total: all.length,
  };
  const cut =
    all.length > ROW_CAP
      ? `showing the first ${ROW_CAP} of ${all.length} rows — the raw artifact carries them all`
      : undefined;
  const notes = [note, cut].filter(Boolean);
  if (notes.length > 0) table.note = notes.join(" · ");
  return table;
}

// ---------------------------------------------------------------------------
// the families
// ---------------------------------------------------------------------------

function semgrepTable(content: Json): ArtifactTable {
  const rows = arr(content["results"]).map((r) => {
    const x = obj(r);
    return [
      str(x["check_id"]),
      `${str(x["path"])}:${str(x["start_line"])}`,
      str(x["severity"]),
      str(x["message"]),
    ];
  });
  const errors = Number(content["error_count"] ?? 0);
  return capped(
    "semgrep",
    ["check id", "file:line", "severity", "message"],
    rows,
    errors > 0
      ? `the run also recorded ${errors} semgrep error(s) — findings are not the whole story of a run, and /runs holds the rest`
      : undefined,
  );
}

function checkovTable(content: Json): ArtifactTable {
  const rows = arr(content["failed"]).map((r) => {
    const x = obj(r);
    return [str(x["check_id"]), str(x["resource"]), str(x["file"]), str(x["framework"])];
  });
  const passed = Number(content["passed_count"] ?? 0);
  return capped(
    "checkov",
    ["check", "resource", "file", "framework"],
    rows,
    // the artifact records passes too, and a table of only failures that did
    // not say so would misstate what the tool looked at
    `${passed} check(s) passed and are not listed here — this table is the failed set`,
  );
}

function spectralTable(content: Json): ArtifactTable {
  const rows = arr(content["results"]).map((r) => {
    const x = obj(r);
    return [
      str(x["code"]),
      `${str(x["file"])}:${str(x["line"])}`,
      str(x["severity"]),
      str(x["message"]),
    ];
  });
  return capped("spectral", ["rule", "file:line", "severity", "message"], rows);
}

function gitleaksTable(content: unknown): ArtifactTable {
  const rows = arr(content).map((r) => {
    const x = obj(r);
    // RuleID · file:line · commit. `Secret` and `Match` are deliberately
    // absent — see rule 1 at the top of this file.
    return [
      str(x["RuleID"]),
      `${str(x["File"])}:${str(x["StartLine"])}`,
      str(x["Commit"]).slice(0, 12),
      str(x["Date"]),
    ];
  });
  return capped(
    "gitleaks",
    ["rule", "file:line", "commit", "date"],
    rows,
    "the matched secret is deliberately not rendered — the rule, the file:line and the commit are what a fix needs",
  );
}

/** the `fixed` events an OSV advisory records for the affected ranges */
function osvFixedIn(vulnerability: Json): string {
  const fixed: string[] = [];
  for (const affected of arr(vulnerability["affected"])) {
    for (const range of arr(obj(affected)["ranges"])) {
      for (const event of arr(obj(range)["events"])) {
        const v = obj(event)["fixed"];
        if (typeof v === "string" && !fixed.includes(v)) fixed.push(v);
      }
    }
  }
  return fixed.join(", ");
}

function osvTable(content: Json): ArtifactTable {
  const rows: string[][] = [];
  for (const result of arr(content["results"])) {
    for (const entry of arr(obj(result)["packages"])) {
      const pkg = obj(obj(entry)["package"]);
      const vulns = arr(obj(entry)["vulnerabilities"]).map(obj);
      for (const group of arr(obj(entry)["groups"])) {
        const g = obj(group);
        const ids = arr(g["ids"]).map(str);
        const advisory = ids.join(", ");
        // the advisory's own record, found by id or alias — that is where the
        // fixed version lives; the group only carries the severity
        const vuln = vulns.find(
          (v) => ids.includes(str(v["id"])) || arr(v["aliases"]).map(str).some((a) => ids.includes(a)),
        );
        rows.push([
          `${str(pkg["name"])}@${str(pkg["version"])}`,
          str(pkg["ecosystem"]),
          advisory,
          str(g["max_severity"]),
          vuln ? osvFixedIn(vuln) : "",
        ]);
      }
    }
  }
  return capped("osv-scanner", ["package", "ecosystem", "advisory", "severity", "fixed in"], rows);
}

function grypeTable(content: Json): ArtifactTable {
  const rows = arr(content["matches"]).map((m) => {
    const x = obj(m);
    const v = obj(x["vulnerability"]);
    const a = obj(x["artifact"]);
    const fix = obj(v["fix"]);
    const versions = arr(fix["versions"]).map(str).join(", ");
    return [
      `${str(a["name"])}@${str(a["version"])}`,
      str(a["type"]),
      str(v["id"]),
      str(v["severity"]),
      versions || str(fix["state"]),
    ];
  });
  return capped("grype", ["package", "type", "vulnerability", "severity", "fixed in"], rows);
}

function openvexTable(content: Json): ArtifactTable {
  const rows = arr(content["statements"]).map((s) => {
    const x = obj(s);
    return [
      str(obj(x["vulnerability"])["name"]),
      arr(x["products"]).map((p) => str(obj(p)["@id"])).join(", "),
      str(x["status"]),
      str(x["justification"]),
      str(x["impact_statement"]),
    ];
  });
  return capped(
    "openvex",
    ["vulnerability", "product", "status", "justification", "impact statement"],
    rows,
    // the standing over-approximation statement: `not_affected` is the loose
    // walk's answer, and unknowns count against us (J5/I3f render its work)
    "`not_affected` is claimed only when even the over-approximating walk cannot reach the package — unknowns count against us",
  );
}

function repoFactsTable(content: Json): ArtifactTable {
  const rows: string[][] = [];
  for (const [fact, values] of Object.entries(content)) {
    for (const value of arr(values)) {
      const x = obj(value);
      rows.push([
        fact,
        Object.entries(x)
          .map(([k, v]) => `${k}=${v === null ? "none" : String(v)}`)
          .join(" · "),
      ]);
    }
  }
  return capped("repo-facts", ["fact", "observed"], rows);
}

/**
 * The repo model (L2). One row per NODE, with that node's outgoing links in
 * its own column — the artifact is nodes AND links, and a table that showed
 * only the nodes would render half a model while looking like a whole one.
 *
 * Two things this table deliberately does NOT do. It does not roll the states
 * up into a coverage number: the board computes coverage, and a second count
 * here could disagree with the one the operator is looking at. And it does not
 * hide `problems` in a footnote — they lead the note, because a model that
 * could not draw a link is exactly the thing a reader of this table is
 * entitled to know before reading any row of it.
 */
function repoModelTable(content: Json): ArtifactTable {
  const nodes = arr(content["nodes"]).map(obj);
  const links = arr(content["links"]).map(obj);
  const problems = arr(content["problems"]).map(str);

  const outgoing = new Map<string, string[]>();
  for (const link of links) {
    const from = str(link["from"]);
    const label =
      link["kind"] === "state"
        ? `state:${str(link["state"])}→${str(link["to"])}`
        : link["kind"] === "consumes"
          ? `consumes:${str(link["artifact"])}→${str(link["to"])}`
          : `${str(link["kind"])}→${str(link["to"])}`;
    outgoing.set(from, [...(outgoing.get(from) ?? []), label]);
  }

  // what each node kind says about itself, in its own terms — never a shared
  // "label" field the artifact does not carry
  const detail = (n: Json): string => {
    switch (str(n["kind"])) {
      case "repo":
        return str(n["repo"]);
      case "recipe":
        return [
          n["inCatalog"] === false ? "not in the catalog — its evidence outlived it" : "",
          n["cadence"] ? `cadence ${str(n["cadence"])}` : "",
          n["automatable"] ? `automatable ${str(n["automatable"])}` : "",
        ]
          .filter(Boolean)
          .join(" · ");
      case "collector":
        return n["pure"] === true ? "pure — spawns no external tool" : "";
      case "tool":
        return [
          n["pinnedVersion"] ? `pinned ${str(n["pinnedVersion"])}` : "no pin in tools.json",
          str(n["image"]),
        ]
          .filter(Boolean)
          .join(" · ");
      case "contract-rule":
        return `${str(n["ruleKind"])} · ${str(n["declaration"])}`;
      case "graph":
        return [
          `${str(n["nodeCount"])} nodes, ${str(n["edgeCount"])} edges (${str(n["inferredEdgeCount"])} name-inferred)`,
          `@ ${str(n["commit"]).slice(0, 12)}`,
          `roots: ${arr(n["entrypoints"]).map(str).join(", ") || "none"} (${str(n["entrypointSource"])})`,
          `from ${str(obj(n["from"])["recipeId"])}`,
        ].join(" · ");
      default:
        return "";
    }
  };

  const rows = nodes.map((n) => [
    str(n["kind"]),
    str(n["id"]),
    detail(n),
    (outgoing.get(str(n["id"])) ?? []).join(" · "),
  ]);

  const note = [
    problems.length > 0
      ? `${problems.length} problem(s) the model states about itself: ${problems.join(" · ")}`
      : "",
    `model v${str(content["version"])} over crosswalk ${str(content["dataset_version"])} · ${links.length} link(s), each shown on the row of the node it leaves`,
    "no clock and no coverage number: the same ledger yields the same bytes, and the board owns the counts",
  ]
    .filter(Boolean)
    .join(" · ");

  return capped("repo model", ["kind", "id", "detail", "links out"], rows, note);
}

function cyclonedxTable(content: Json): ArtifactTable {
  const rows = arr(content["components"]).map((c) => {
    const x = obj(c);
    return [str(x["name"]), str(x["version"]), str(x["type"]), str(x["purl"])];
  });
  return capped("cyclonedx sbom", ["component", "version", "type", "purl"], rows);
}

// ---------------------------------------------------------------------------
// dispatch
// ---------------------------------------------------------------------------

/**
 * The artifact's family, decided by the name the SIGNED STATEMENT attests —
 * not by sniffing the content. The subject name is part of what was signed;
 * the shape of the bytes is not, and a viewer that guessed from content could
 * be steered by the bytes into rendering them as something they are not.
 */
export function artifactFamily(name: string): string | null {
  const base = name.split("/").pop() ?? name;
  if (base === "semgrep-results.json") return "semgrep";
  if (base === "checkov-results.json") return "checkov";
  if (base === "spectral-results.json") return "spectral";
  if (base === "gitleaks-report.json") return "gitleaks";
  if (base === "osv-results.json") return "osv-scanner";
  if (base === "grype-report.json") return "grype";
  if (base === "openvex.json") return "openvex";
  if (base === "repo-facts.json") return "repo-facts";
  if (base === "sbom.cdx.json") return "cyclonedx sbom";
  if (base === "repo-model.json") return "repo model";
  return null;
}

/**
 * A table for an artifact this viewer knows, or null. Null is an honest answer
 * — `graph.db` is a binary SQLite graph and `semgrep-raw.json` is the tool's
 * own unnormalized output; both download byte-exact and neither gets a table
 * invented for it here.
 */
export function artifactTable(name: string, content: unknown): ArtifactTable | null {
  const family = artifactFamily(name);
  if (family === null) return null;
  if (family === "gitleaks") return gitleaksTable(content);
  const c = obj(content);
  switch (family) {
    case "semgrep":
      return semgrepTable(c);
    case "checkov":
      return checkovTable(c);
    case "spectral":
      return spectralTable(c);
    case "osv-scanner":
      return osvTable(c);
    case "grype":
      return grypeTable(c);
    case "openvex":
      return openvexTable(c);
    case "repo-facts":
      return repoFactsTable(c);
    case "cyclonedx sbom":
      return cyclonedxTable(c);
    case "repo model":
      return repoModelTable(c);
    default:
      return null;
  }
}

/**
 * Why an artifact has no table, for the reader who expected one. A family this
 * viewer does not know is a fact about the VIEWER; the bytes are still here
 * and still verifiable, which is what this sentence has to make clear.
 */
export function noTableReason(name: string): string {
  const base = name.split("/").pop() ?? name;
  if (base === "graph.db") {
    return "a binary SQLite call graph — no table here; the download is byte-exact and `rampscan` reads it";
  }
  if (base.endsWith("-raw.json")) {
    return "the tool's own unnormalized output, kept for reproduction — the normalized artifact beside it is the one with a table";
  }
  return "no viewer for this artifact family — the bytes below are byte-exact and hash to the attested digest";
}
