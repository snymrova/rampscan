import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { LedgerStore, MethodRegisterRow } from "@rampscan/core";
import { artifactBodyDigest, isArtifact } from "@rampscan/schema";
import { emit, type WrittenExport } from "./fedramp-run.js";
import { buildSecurityDecisionRecord, type SdrBuildInput } from "./sdr-build.js";
import { SDR_MARKDOWN_ARTIFACT, renderSdrMarkdown } from "./sdr-render.js";

// Writing the Security Decision Record (R2.1): read the artifact bodies the
// projection points at, build, then validate/stamp/re-validate/write through
// the same `emit` the CPO and OCR use. The builder stays pure; the ledger read
// lives here.

export interface SdrBodies {
  /** ledger digest of the filling statement → the body text */
  bodies: Map<string, string>;
  /** slots the projection names a body for that the ledger could not produce */
  problems: string[];
}

/**
 * Fetch every live artifact body from the ledger, and check each against the
 * digest the projection carries. A body whose bytes hash to something else is
 * not rendered: the SDR would otherwise publish text under a digest that does
 * not name it.
 */
export async function readArtifactBodies(
  ledger: LedgerStore,
  rows: readonly MethodRegisterRow[],
): Promise<SdrBodies> {
  const bodies = new Map<string, string>();
  const problems: string[] = [];
  for (const row of rows) {
    for (const cell of row.artifacts) {
      if (cell.body === undefined || bodies.has(cell.body.digest)) continue;
      const entry = await ledger.get(cell.body.digest);
      if (entry === undefined || !isArtifact(entry.bundle)) {
        problems.push(
          `${row.ksi} artifact ${cell.artifact}: the projection names statement ${cell.body.digest}, and the ledger holds no Artifact under that digest`,
        );
        continue;
      }
      const body = entry.bundle.predicate.body;
      if (artifactBodyDigest(body) !== cell.body.bodyDigest) {
        problems.push(
          `${row.ksi} artifact ${cell.artifact}: the body in the ledger does not hash to the body digest the projection carries (${cell.body.bodyDigest.slice(0, 12)}…), so it is not rendered`,
        );
        continue;
      }
      bodies.set(cell.body.digest, body);
    }
  }
  return { bodies, problems };
}

export interface SdrRunInput extends Omit<SdrBuildInput, "bodies"> {
  /** the rampscan checkout — where the PINNED schemas live */
  schemaRoot: string;
  exportsDir: string;
  ledger: LedgerStore;
}

export interface SdrRunResult {
  written?: WrittenExport;
  /** the human-readable half, rendered from the JSON bytes as written (R2.2) */
  markdown?: { filename: string; path: string; jsonSha256: string };
  /** why no SDR was written — never a silent absence */
  skipped?: string;
  conformant: boolean;
}

export async function writeSecurityDecisionRecord(input: SdrRunInput): Promise<SdrRunResult> {
  const { bodies, problems: readProblems } = await readArtifactBodies(
    input.ledger,
    input.methodRegisters,
  );
  const built = buildSecurityDecisionRecord({ ...input, bodies });
  if (built.export === undefined) {
    return { skipped: built.skipped ?? "no Security Decision Record was built", conformant: false };
  }
  built.export.problems.unshift(...readProblems);
  await mkdir(input.exportsDir, { recursive: true });
  const written = await emit(built.export, input);

  // D3: render from the bytes on disk, not from the object in memory, so the
  // digest in the Markdown names exactly the file beside it
  const bytes = await readFile(written.path);
  const jsonSha256 = createHash("sha256").update(bytes).digest("hex");
  const markdownPath = join(input.exportsDir, SDR_MARKDOWN_ARTIFACT);
  await writeFile(
    markdownPath,
    renderSdrMarkdown(JSON.parse(bytes.toString("utf8")) as Record<string, unknown>, jsonSha256),
  );
  return {
    written,
    markdown: { filename: SDR_MARKDOWN_ARTIFACT, path: markdownPath, jsonSha256 },
    conformant: written.violations.length === 0,
  };
}

export function renderSdr(result: SdrRunResult): string {
  if (result.written === undefined) return `no Security Decision Record: ${result.skipped ?? "unknown"}`;
  const w = result.written;
  const verdict = w.violations.length === 0 ? "schema-valid" : `${w.violations.length} VIOLATION(S)`;
  const lines = [`${w.filename} → ${verdict}  (${w.schemaFile} @ ${w.schemaVersion})`];
  for (const v of w.violations) lines.push(`    ✗ ${v.path === "" ? "<root>" : v.path}: ${v.message}`);
  for (const p of w.problems) lines.push(`    · ${p}`);
  if (result.markdown !== undefined) {
    lines.push(
      `${result.markdown.filename} → the human-readable half, rendered from the JSON (sha256 ${result.markdown.jsonSha256.slice(0, 12)}…)`,
    );
  }
  return lines.join("\n");
}
