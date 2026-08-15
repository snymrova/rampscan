import { createHash } from "node:crypto";
import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import type { RegisterState, RollupCounts, RollupRow, RegisterRow } from "@rampscan/core";
import { isEvidenceBundle } from "@rampscan/schema";
import { createLocalLedger } from "@rampscan/ledger";
import { foldEntries } from "@rampscan/projector";
import { loadRecipes } from "./recipes.js";

// Export (plan I3e): the auditor takes the record with them.
//
// A per-control evidence package is a plain tar of exactly what an assessor
// needs to check the claim WITHOUT rampscan: every mapped recipe's signed DSSE
// envelope byte-for-byte from the ledger's object store, the artifacts those
// envelopes name (when the scan output still holds them), the public key, a
// manifest, and instructions. Nothing here is re-serialized from the
// projection — the same discipline as I3b's downloads, for the same reason:
// the envelope's payload IS the canonical statement, and a re-serialization
// would be a copy that merely looks like the record.
//
// Two honesty rules, both load-bearing:
//
//   1. Artifacts are matched by DIGEST, never by name. Artifacts live in the
//      scan output dir and are overwritten by later runs; a file that happens
//      to share a name with the one a bundle attested is not that artifact.
//      Mismatches are recorded as missing WITH the reason, never shipped.
//   2. Every recipe mapped to the control appears in the manifest — including
//      the unevidenced ones. A package that silently contains only the good
//      news is the screenshot folder this product exists to replace.

// ---------------------------------------------------------------------------
// tar, hand-rolled
// ---------------------------------------------------------------------------
// No dependency: this is a bounded, testable job (ustar headers are a fixed
// 512-byte layout), and the house has declined a dependency for exactly this
// shape of work before — DSSE without cosign, setTimeout without node-cron.
// Uncompressed by choice too: `tar xf` needs no flags and an assessor can read
// the member names out of the raw bytes.

export interface TarEntry {
  /** path inside the archive, ≤ 100 bytes (ustar's name field) */
  name: string;
  bytes: Uint8Array;
}

const BLOCK = 512;

function octal(value: number, width: number): string {
  // width includes the trailing NUL ustar writes after the digits
  return value.toString(8).padStart(width - 1, "0") + "\0";
}

function writeAscii(block: Uint8Array, offset: number, text: string, width: number): void {
  const bytes = Buffer.from(text, "ascii");
  if (bytes.length > width) {
    throw new Error(`tar field overflows ${width} bytes: ${text}`);
  }
  block.set(bytes, offset);
}

/**
 * A ustar archive of the given entries, in the given order. `mtime` is one
 * clock for every member (the package's generation instant), so two exports of
 * the same evidence at the same instant are byte-identical.
 */
export function tar(entries: TarEntry[], mtimeSeconds: number): Uint8Array {
  const blocks: Uint8Array[] = [];
  for (const entry of entries) {
    const header = new Uint8Array(BLOCK);
    if (Buffer.byteLength(entry.name, "utf8") > 100) {
      throw new Error(`tar member name exceeds 100 bytes: ${entry.name}`);
    }
    writeAscii(header, 0, entry.name, 100);
    writeAscii(header, 100, octal(0o644, 8), 8); // mode
    writeAscii(header, 108, octal(0, 8), 8); // uid
    writeAscii(header, 116, octal(0, 8), 8); // gid
    writeAscii(header, 124, octal(entry.bytes.length, 12), 12);
    writeAscii(header, 136, octal(mtimeSeconds, 12), 12);
    header.fill(0x20, 148, 156); // checksum field is spaces while it is computed
    writeAscii(header, 156, "0", 1); // typeflag: regular file
    writeAscii(header, 257, "ustar\0", 6);
    writeAscii(header, 263, "00", 2);
    writeAscii(header, 265, "rampscan", 32); // uname
    writeAscii(header, 297, "rampscan", 32); // gname

    let sum = 0;
    for (const byte of header) sum += byte;
    // ustar's checksum: 6 octal digits, NUL, space
    writeAscii(header, 148, sum.toString(8).padStart(6, "0") + "\0 ", 8);

    blocks.push(header);
    blocks.push(entry.bytes);
    const remainder = entry.bytes.length % BLOCK;
    if (remainder !== 0) blocks.push(new Uint8Array(BLOCK - remainder));
  }
  // two zero blocks terminate the archive
  blocks.push(new Uint8Array(BLOCK * 2));

  const total = blocks.reduce((n, b) => n + b.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const block of blocks) {
    out.set(block, offset);
    offset += block.length;
  }
  return out;
}

// ---------------------------------------------------------------------------
// the per-control evidence package
// ---------------------------------------------------------------------------

/**
 * What a subject IS decides whether the package can ship it:
 *
 *   artifact      — a collector output, retained under the scan output dir
 *   anchor        — repo content at the scanned commit. NOT shipped: it is the
 *                   client's own source, retrievable with `git show`, and a
 *                   package that quietly bundled source would be exporting the
 *                   codebase rather than the evidence about it
 *   justification — a scoping event's subject; the text is in the signed
 *                   predicate already, so shipping a second copy would create
 *                   two things to disagree
 */
export type SubjectKind = "artifact" | "anchor" | "justification";

export interface PackageArtifact {
  /** the name the statement's subject attests */
  name: string;
  /** the sha256 the statement's subject attests */
  sha256: string;
  kind: SubjectKind;
  /** path inside the package — set only when the bytes are here */
  path?: string;
  /** why the bytes are not here, said plainly */
  missing?: string;
}

export interface PackageRow {
  recipeId: string;
  state: RegisterState;
  ksiIds: string[];
  controlIds: string[];
  /** the live bundle (evidenced/violated) or the scoping event (notApplicable) */
  digest?: string;
  /** path inside the package of the signed envelope, when one exists */
  envelopePath?: string;
  /** path inside the package of the raw statement — unsigned statements only */
  statementPath?: string;
  commit?: string;
  timestamp?: string;
  artifacts: PackageArtifact[];
  /** honest flags a reader must see, never smoothed over */
  problems: string[];
}

export interface EvidencePackageManifest {
  register: "controls" | "ksis";
  id: string;
  repo: string;
  /** the rollup verdict for this id, as the projection computed it */
  state: RegisterState;
  counts: RollupCounts;
  datasetVersion: string;
  generatedAt: string;
  /** the offline verify invocation, as the serve stamped it (I3b) */
  verifyCommand: string;
  rows: PackageRow[];
}

export interface EvidencePackageOptions {
  ledgerDir: string;
  keysDir: string;
  recipesDir: string;
  /** the scan output's artifacts root (`<outDir>/artifacts`); absent → no artifacts shipped */
  artifactsDir?: string;
  register: "controls" | "ksis";
  /** a control id ("ra-5") or a KSI id ("KSI-SCR-MIT") */
  id: string;
  /** required only when the ledger holds more than one repo */
  repo?: string;
  /** the serve's stamped verify command; falls back to the bare form */
  verifyCommand?: string;
  now?: Date;
}

export interface EvidencePackage {
  filename: string;
  bytes: Uint8Array;
  manifest: EvidencePackageManifest;
}

function slug(text: string): string {
  return text.toLowerCase().replaceAll(/[^a-z0-9._-]+/g, "-");
}

/** every file under `dir`, one level deep per collector subdir: name → paths */
async function indexArtifacts(dir: string): Promise<Map<string, string[]>> {
  const index = new Map<string, string[]>();
  let collectors: string[];
  try {
    collectors = await readdir(dir);
  } catch {
    return index;
  }
  for (const collector of collectors) {
    let names: string[];
    try {
      names = await readdir(join(dir, collector));
    } catch {
      continue; // a file where a collector dir was expected — not an artifact
    }
    for (const name of names) {
      const paths = index.get(name) ?? [];
      paths.push(join(dir, collector, name));
      index.set(name, paths);
    }
  }
  return index;
}

/**
 * The one hand that builds an evidence package (I3e), for both surfaces: the
 * console's export route calls this, and so would a CLI export. One as-of-free
 * fold of the append-only ledger plus byte-exact reads of the object store —
 * nothing here writes anything, anywhere.
 */
export async function computeEvidencePackage(
  options: EvidencePackageOptions,
): Promise<EvidencePackage> {
  const now = options.now ?? new Date();
  const generatedAt = now.toISOString();
  const objectsDir = join(options.ledgerDir, "objects");

  const entries = await createLocalLedger(options.ledgerDir).list();
  const recipes = await loadRecipes(options.recipesDir);
  const projection = foldEntries(entries, generatedAt, { recipes });

  const rollups: RollupRow[] =
    options.register === "controls" ? projection.controls : projection.ksis;
  const matches = rollups.filter((r) => r.id === options.id);
  if (matches.length === 0) {
    throw new Error(
      `no ${options.register === "controls" ? "control" : "KSI"} "${options.id}" in the register`,
    );
  }
  const rollup = options.repo
    ? matches.find((r) => r.repo === options.repo)
    : matches.length === 1
      ? matches[0]
      : undefined;
  if (!rollup) {
    throw new Error(
      options.repo
        ? `"${options.id}" is not in the register for repo ${options.repo}`
        : `"${options.id}" spans ${matches.length} repos (${matches.map((r) => r.repo).join(", ")}) — name one`,
    );
  }

  const registerByRecipe = new Map<string, RegisterRow>(
    projection.registers.filter((r) => r.repo === rollup.repo).map((r) => [r.recipeId, r]),
  );
  const artifactIndex = options.artifactsDir
    ? await indexArtifacts(options.artifactsDir)
    : new Map<string, string[]>();

  const files: TarEntry[] = [];
  const seen = new Set<string>();
  const push = (name: string, bytes: Uint8Array): void => {
    if (seen.has(name)) return; // one copy per content address
    seen.add(name);
    files.push({ name, bytes });
  };

  const rows: PackageRow[] = [];
  for (const recipeId of rollup.recipeIds) {
    const register = registerByRecipe.get(recipeId);
    if (!register) {
      rows.push({
        recipeId,
        state: "unevidenced",
        ksiIds: [],
        controlIds: [],
        artifacts: [],
        problems: [
          "mapped to this id by the catalog but absent from the register projection — the package cannot speak for it",
        ],
      });
      continue;
    }

    const row: PackageRow = {
      recipeId,
      state: register.state,
      ksiIds: register.ksiIds,
      controlIds: register.controlIds,
      artifacts: [],
      problems: [],
    };
    if (register.commit) row.commit = register.commit;
    if (register.freshAsOf) row.timestamp = register.freshAsOf;

    const digest = register.bundleDigest ?? register.scoping?.digest;
    if (!digest) {
      row.problems.push(
        register.state === "unevidenced"
          ? "no evidence bundle — nothing has evidenced this recipe, and that gap is part of the record"
          : `state ${register.state} carries no ledger digest`,
      );
      rows.push(row);
      continue;
    }
    row.digest = digest;
    if (register.state === "notApplicable" && register.scoping) {
      row.timestamp = register.scoping.timestamp;
      row.problems.push(
        `scoped out of the assessment by ${register.scoping.approvedBy} — the signed justification is in this package`,
      );
    }

    // the envelope's EXACT bytes, never a re-serialization (I3b's rule)
    let envelope: Buffer | undefined;
    try {
      envelope = await readFile(join(objectsDir, `${digest}.envelope.json`));
    } catch {
      envelope = undefined;
    }
    if (envelope) {
      const path = `bundles/${digest}.envelope.json`;
      push(path, new Uint8Array(envelope));
      row.envelopePath = path;
    } else {
      try {
        const statement = await readFile(join(objectsDir, `${digest}.json`));
        const path = `bundles/${digest}.statement.json`;
        push(path, new Uint8Array(statement));
        row.statementPath = path;
        row.problems.push(
          "the ledger holds this statement unsigned — there is no envelope to verify",
        );
      } catch {
        row.problems.push(
          `the ledger cannot produce ${digest} — the projection names a digest the object store does not hold`,
        );
        rows.push(row);
        continue;
      }
    }

    // artifacts: matched by digest against the statement's subjects
    const ledgerEntry = entries.find((e) => e.digest === digest);
    const statement = ledgerEntry?.bundle;
    const isEvidence = statement !== undefined && isEvidenceBundle(statement);
    // a subject named by anchor_paths is repo content, not a collector output
    const anchorNames = new Set(
      isEvidence ? statement.predicate.anchor_paths.map((a) => a.path) : [],
    );
    for (const subject of statement?.subject ?? []) {
      const sha256 = subject.digest.sha256 ?? "";
      const kind: SubjectKind = !isEvidence
        ? "justification"
        : anchorNames.has(subject.name)
          ? "anchor"
          : "artifact";
      const artifact: PackageArtifact = { name: subject.name, sha256, kind };
      if (kind === "anchor") {
        artifact.missing = `repo content at commit ${register.commit ?? "?"} — not shipped; \`git show ${(register.commit ?? "HEAD").slice(0, 12)}:${subject.name}\` reproduces these bytes`;
        row.artifacts.push(artifact);
        continue;
      }
      if (kind === "justification") {
        artifact.missing =
          "the justification text is in the signed predicate — a second copy would be a second thing to disagree";
        row.artifacts.push(artifact);
        continue;
      }
      if (!options.artifactsDir) {
        artifact.missing =
          "artifacts are not available to this export (no scan output dir configured)";
        row.artifacts.push(artifact);
        continue;
      }
      const candidates = artifactIndex.get(subject.name) ?? [];
      let matched: { path: string; bytes: Buffer } | undefined;
      for (const candidate of candidates) {
        const bytes = await readFile(candidate);
        if (createHash("sha256").update(bytes).digest("hex") === sha256) {
          matched = { path: candidate, bytes };
          break;
        }
      }
      if (matched) {
        const path = `artifacts/${sha256}/${subject.name}`;
        push(path, new Uint8Array(matched.bytes));
        artifact.path = path;
      } else {
        artifact.missing =
          candidates.length === 0
            ? "not retained — no file of this name under the scan output dir"
            : "not retained — the file of this name on disk is from a later run and does not match the attested digest";
      }
      row.artifacts.push(artifact);
    }

    rows.push(row);
  }

  // the public key, so verification needs nothing from this machine but the tar
  try {
    push("rampscan.pub", new Uint8Array(await readFile(join(options.keysDir, "rampscan.pub"))));
  } catch {
    // recorded on every row rather than silently absent
    for (const row of rows) {
      if (row.envelopePath) {
        row.problems.push("the signing public key was not readable — verify with your own copy");
      }
    }
  }

  const verifyCommand = options.verifyCommand ?? "pnpm rampscan verify <digest>";
  const manifest: EvidencePackageManifest = {
    register: options.register,
    id: rollup.id,
    repo: rollup.repo,
    state: rollup.state,
    counts: rollup.counts,
    datasetVersion: projection.datasetVersion,
    generatedAt,
    verifyCommand,
    rows,
  };

  push("MANIFEST.json", Buffer.from(JSON.stringify(manifest, null, 2) + "\n", "utf8"));
  push("VERIFY.md", Buffer.from(renderVerifyDoc(manifest), "utf8"));

  // MANIFEST/VERIFY/key first, then bundles, then artifacts — a reader
  // extracting the head of the stream gets the map before the territory
  const rank = (name: string): number =>
    name === "MANIFEST.json" ? 0 : name === "VERIFY.md" ? 1 : name === "rampscan.pub" ? 2 : name.startsWith("bundles/") ? 3 : 4;
  files.sort((a, b) => rank(a.name) - rank(b.name) || a.name.localeCompare(b.name));

  const label = options.register === "controls" ? "control" : "ksi";
  return {
    filename: `rampscan-evidence-${label}-${slug(rollup.id)}-${generatedAt.slice(0, 10)}.tar`,
    bytes: tar(files, Math.floor(now.getTime() / 1000)),
    manifest,
  };
}

function renderVerifyDoc(manifest: EvidencePackageManifest): string {
  const kind = manifest.register === "controls" ? "control" : "KSI";
  const signed = manifest.rows.filter((r) => r.envelopePath);
  const lines: string[] = [
    `# Evidence package — ${kind} ${manifest.id}`,
    "",
    `- **repo:** \`${manifest.repo}\``,
    `- **rolled-up state:** ${manifest.state}`,
    `- **mapped recipes:** ${manifest.counts.total} — ${manifest.counts.evidenced} evidenced, ${manifest.counts.violated} violated, ${manifest.counts.unevidenced} unevidenced, ${manifest.counts.notApplicable} not applicable`,
    `- **dataset:** \`${manifest.datasetVersion}\``,
    `- **generated:** ${manifest.generatedAt}`,
    "",
    "## What is in here",
    "",
    "- `MANIFEST.json` — every recipe mapped to this " +
      kind +
      ", its state, its ledger digest, and the artifacts each bundle attests. Recipes with no evidence are listed too: the gap is part of the record.",
    "- `bundles/<digest>.envelope.json` — the DSSE envelope exactly as the ledger stores it. The base64 `payload` **is** the canonical in-toto statement; sha256 of the decoded payload bytes reproduces the digest in the filename.",
    "- `artifacts/<sha256>/<name>` — the collector outputs those statements attest, where the scan output still held bytes matching the attested digest. Artifacts are matched by DIGEST, never by name: a later run's file of the same name is not the artifact that was attested, and the manifest says so rather than shipping it.",
    "- `rampscan.pub` — the signing public key (SPKI PEM, ECDSA P-256).",
    "",
    "Two kinds of subject are deliberately **not** here. **Anchors** are your own repo content at the scanned commit — the manifest gives the `git show` line that reproduces each one, and a package that bundled source would be exporting the codebase rather than the evidence about it. A scoping event's **justification** is already inside its signed predicate; a second copy would be a second thing to disagree.",
    "",
    "## Verify without rampscan",
    "",
    "Every envelope is a standard DSSE envelope over an in-toto statement, signed ECDSA P-256 / SHA-256 — cosign's attestation envelope format. Independent verification needs no rampscan code:",
    "",
    "```sh",
    "# 1. the payload is the statement, and its hash is the address",
    "jq -r .payload bundles/<digest>.envelope.json | base64 -d > statement.json",
    "sha256sum statement.json          # must equal <digest>",
    "",
    "# 2. the signature covers the DSSE pre-authentication encoding:",
    "#    DSSEv1 <len(payloadType)> <payloadType> <len(payload)> <payload>",
    "#    verify it against rampscan.pub with any ECDSA P-256 implementation",
    "```",
    "",
    "## Verify with rampscan",
    "",
    "```sh",
    manifest.verifyCommand.replace("<digest>", signed[0]?.digest ?? "<digest>"),
    "```",
    "",
    "## The recipes",
    "",
    "| recipe | state | digest | artifacts |",
    "|---|---|---|---|",
  ];
  for (const row of manifest.rows) {
    const shipped = row.artifacts.filter((a) => a.kind === "artifact");
    const anchors = row.artifacts.filter((a) => a.kind === "anchor").length;
    const artifacts = [
      ...shipped.map((a) => (a.path ? a.name : `${a.name} (not retained)`)),
      ...(anchors > 0 ? [`${anchors} anchor${anchors === 1 ? "" : "s"} (in your repo)`] : []),
    ];
    lines.push(
      `| \`${row.recipeId}\` | ${row.state} | ${row.digest ? `\`${row.digest.slice(0, 12)}…\`` : "—"} | ${artifacts.length > 0 ? artifacts.join(", ") : "—"} |`,
    );
  }
  const problems = manifest.rows.flatMap((r) => r.problems.map((p) => `- \`${r.recipeId}\`: ${p}`));
  if (problems.length > 0) {
    lines.push("", "## Stated plainly", "", ...problems);
  }
  lines.push("");
  return lines.join("\n");
}
