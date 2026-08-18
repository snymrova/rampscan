import { readFile, stat } from "node:fs/promises";
import { join } from "node:path";
import type { Collector, CollectOutput, ObservationRows } from "@rampscan/core";
import type { DeclaredDocument, DocumentKind, Finding } from "@rampscan/schema";
import { DocumentsConfig } from "@rampscan/schema";
import { GRAPH_CONFIG_FILE } from "@rampscan/graph";
import { fileSha256, makeFinding } from "./support.js";

// documents — the N1b wave-1 gate: the scanned repo DECLARES its governing
// documents in rampscan.config.json's `documents` array, and this collector
// checks the declaration against the checkout. Pure: it reads files and spawns
// nothing.
//
// The claim is deliberately narrow, and both adjudication records that ride it
// draw the same line in their remainders:
//
//   AC-01  "a recipe over this control can prove a policy file is there and
//           cannot prove it is a policy"
//   SA-05  existence, currency and integrity — distribution is the remainder
//
// So this collector reads a path, a size and a content hash, and never the
// document. What it adds over a human's assertion that the policy exists is
// the anchor: the file's content hash rides the bundle, so an edit kills the
// evidence with the killing commit named instead of the claim ageing quietly.
// Currency is NOT claimed — nothing in the collector set reads git history
// metadata, which the batch-1 audit established by cutting that limb from both
// records rather than by anyone asserting it here.
//
// The empty-set discipline, in the two shapes the join distinguishes:
//   - no config file, no `documents` key, or an empty array → a stated SKIP.
//     A repository that declares nothing has not failed a documentation
//     control; it has not made a claim, and the board must say so.
//   - a block that declares documents of ONE kind → the other kind's
//     observation key is omitted (Guard), so its recipe reads unevidenced
//     rather than passing over zero rows.
//   - a declared document that is MISSING → a row with `present: false`, which
//     violates. This is the negative-witness pattern contract.ts uses for a
//     rule that matches nothing: a declaration pointing at a path that is not
//     there must fail the thing it mistyped, never waive it.
//   - an invalid block → a thrown CONFIG ERROR. A misspelled `kind` must not
//     read as "nothing to check".

export const DOCUMENTS_VERSION = "0.1.0";

export const POLICY_RECIPE = "access-control-policy-present";
export const SYSTEM_DOCS_RECIPE = "system-documentation-present";

/** which recipe answers for each declared kind — one kind, one recipe, no fan-out */
const RECIPE_FOR_KIND: Record<DocumentKind, string> = {
  "access-control-policy": POLICY_RECIPE,
  "system-documentation": SYSTEM_DOCS_RECIPE,
};

const KSI_FOR_KIND: Record<DocumentKind, string[]> = {
  "access-control-policy": ["KSI-SVC-SIN"],
  "system-documentation": ["KSI-SVC-ACM"],
};

const CONTROL_FOR_KIND: Record<DocumentKind, string[]> = {
  "access-control-policy": ["ac-1"],
  "system-documentation": ["sa-5"],
};

/**
 * The declared block, parsed strictly. `undefined` when the file or the key is
 * honestly absent — the callers' skip case. A PRESENT block that fails the
 * schema throws, for contract.ts's stated reason: a mistyped declaration must
 * not silently waive itself.
 */
export async function loadDocuments(root: string): Promise<DeclaredDocument[] | undefined> {
  let raw: string;
  try {
    raw = await readFile(join(root, GRAPH_CONFIG_FILE), "utf8");
  } catch {
    return undefined;
  }
  const parsed = JSON.parse(raw) as Record<string, unknown>;
  if (parsed["documents"] === undefined) return undefined;
  try {
    return DocumentsConfig.parse(parsed["documents"]);
  } catch (cause) {
    const issue =
      cause instanceof Error && "issues" in cause
        ? (cause as { issues: Array<{ path: Array<string | number>; message: string }> }).issues
            .map((i) => `${["documents", ...i.path].join(".")}: ${i.message}`)
            .join("; ")
        : String(cause);
    throw new Error(
      `the documents block in ${GRAPH_CONFIG_FILE} failed validation (exit refused): ${issue} — a mistyped declaration must not silently waive itself`,
      { cause },
    );
  }
}

interface DocumentState {
  present: boolean;
  bytes: number;
}

async function inspect(root: string, rel: string): Promise<DocumentState> {
  try {
    const info = await stat(join(root, rel));
    // a directory at the declared path is not the document: the declaration
    // names a file, and a reader following the path finds nothing to read
    if (!info.isFile()) return { present: false, bytes: 0 };
    return { present: true, bytes: info.size };
  } catch {
    return { present: false, bytes: 0 };
  }
}

export const documents: Collector = {
  manifest: {
    name: "documents",
    toolVersion: DOCUMENTS_VERSION,
    recipes: [POLICY_RECIPE, SYSTEM_DOCS_RECIPE],
    // the declaration lives in the config file and the documents live at paths
    // the config names, which a static manifest cannot enumerate — so the whole
    // tree is in scope. Cheap: this collector reads a stat and a hash per
    // declared document and spawns nothing.
    cacheScope: [GRAPH_CONFIG_FILE, "@tree"],
    tools: [],
  },

  async collect(ctx): Promise<CollectOutput> {
    const { root } = ctx.workspace;
    const reproduce = `rampscan scan <repo> (documents: the ${GRAPH_CONFIG_FILE} documents block × the checkout)`;

    const declared = await loadDocuments(root);
    if (declared === undefined || declared.length === 0) {
      return {
        findings: [],
        artifacts: [],
        observations: {},
        toolVersion: DOCUMENTS_VERSION,
        exitCode: 0,
        skipped: {
          reason:
            declared === undefined
              ? `no documents declared in ${GRAPH_CONFIG_FILE} — nothing of its kind to check, and an undeclared document set is a claim never made rather than a claim broken`
              : `the documents block in ${GRAPH_CONFIG_FILE} is empty — nothing of its kind to check`,
        },
      };
    }

    const observations: Record<string, ObservationRows> = {};
    const anchors: Record<string, Array<{ path: string; contentHash: string }>> = {};
    const findings: Finding[] = [];
    const provenance = { analyzer: "documents", version: DOCUMENTS_VERSION, runId: ctx.runId };
    const configHash = await fileSha256(join(root, GRAPH_CONFIG_FILE));

    for (const kind of Object.keys(RECIPE_FOR_KIND) as DocumentKind[]) {
      const forKind = declared.filter((d) => d.kind === kind);
      // Guard: this repo declared none of this kind. Omitting the key leaves the
      // recipe honestly unevidenced — emitting [] here would let the count
      // assertions below pass over zero rows, which is the vacuous pass itself.
      if (forKind.length === 0) continue;

      const recipeId = RECIPE_FOR_KIND[kind];
      const rows: ObservationRows = [];
      // every claim about a declared document is a claim about the declaration
      // too, so the config file anchors every row
      const anchorPaths: Array<{ path: string; contentHash: string }> = [
        { path: GRAPH_CONFIG_FILE, contentHash: configHash },
      ];

      for (const doc of [...forKind].sort((a, b) => a.id.localeCompare(b.id))) {
        const state = await inspect(root, doc.path);
        rows.push({
          document_id: doc.id,
          kind: doc.kind,
          path: doc.path,
          present: state.present,
          bytes: state.bytes,
          non_empty: state.present && state.bytes > 0,
        });
        if (state.present) {
          anchorPaths.push({
            path: doc.path,
            contentHash: await fileSha256(join(root, doc.path)),
          });
        }
        if (!state.present) {
          findings.push(
            makeFinding(
              {
                variable: "documents",
                // the missing file cannot anchor a finding about itself, so the
                // declaration does — which is also the file that has to change
                // for the finding to go away by any route other than writing
                // the document
                anchorNode: GRAPH_CONFIG_FILE,
                anchorContentHash: configHash,
                signature: `declared-document-missing ${doc.id}`,
                severity: "medium",
                summary: `declared document "${doc.id}" is not in the checkout at ${doc.path}`,
                failureScenario:
                  "the repository states this document governs the system and the file is not there — an assessor following the declaration finds nothing, and every later claim that cites the document cites an absence",
                evidence: [
                  {
                    kind: "file",
                    path: GRAPH_CONFIG_FILE,
                    note: `declares "${doc.id}" (${doc.kind}) at ${doc.path}, which does not exist`,
                  },
                ],
                reproduce: `test -f ${doc.path}`,
                ksiIds: KSI_FOR_KIND[kind],
                controlIds: CONTROL_FOR_KIND[kind],
              },
              provenance,
            ),
          );
        } else if (state.bytes === 0) {
          findings.push(
            makeFinding(
              {
                variable: "documents",
                anchorNode: doc.path,
                anchorContentHash: await fileSha256(join(root, doc.path)),
                signature: `declared-document-empty ${doc.id}`,
                severity: "medium",
                summary: `declared document "${doc.id}" (${doc.path}) is an empty file`,
                failureScenario:
                  "the path resolves and the document says nothing — a placeholder committed to satisfy a checklist reads on every surface exactly like the document it stands in for",
                evidence: [{ kind: "file", path: doc.path, note: "0 bytes" }],
                reproduce: `wc -c ${doc.path}`,
                ksiIds: KSI_FOR_KIND[kind],
                controlIds: CONTROL_FOR_KIND[kind],
              },
              provenance,
            ),
          );
        }
      }

      observations[recipeId] = rows;
      anchors[recipeId] = anchorPaths;
    }

    return {
      findings,
      artifacts: [],
      observations,
      anchors,
      toolVersion: DOCUMENTS_VERSION,
      exitCode: 0,
      reproduce,
    };
  },
};
