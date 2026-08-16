import { createHash } from "node:crypto";
import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { isEvidenceBundle, isScopingEvent } from "@rampscan/schema";
import { createLocalLedger } from "@rampscan/ledger";

// Artifact resolution (plan J4): the operator finally SEES what a tool said,
// instead of inferring it from a verdict pill.
//
// Artifacts are not in the ledger. They live under the scan output dir and are
// addressed by the sha256 a signed statement's subject attests — so getting
// from a digest to bytes is a lookup that can go wrong in exactly the ways
// that matter, and every one of them is answered here rather than guessed:
//
//   1. Only bytes some SIGNED STATEMENT attests are resolvable at all. The
//      digest is the address, and a digest no statement names is not an
//      artifact of this system — it is a request to read an arbitrary file,
//      and it is refused as one.
//   2. Bytes are matched by DIGEST, never by name (I3e's rule, same hand).
//      The output dir is overwritten by later runs; a file that happens to
//      share a name with the one a bundle attested is NOT that artifact.
//   3. The bytes are re-hashed before they are handed out, and the hash is
//      the match — serving by path without re-hashing would let a modified
//      file on disk render under a signed bundle's digest, which is the exact
//      confusion the whole architecture exists to prevent.
//
// A refusal here is an ANSWER, with the reason stated: "not retained" and "on
// disk but from a later run" are different facts, and the second one is the
// one an operator needs to hear out loud.

/**
 * What a subject IS decides whether its bytes can be served:
 *
 *   artifact      — a collector output, retained under the scan output dir
 *   anchor        — repo content at the scanned commit; `git show` reproduces
 *                   it, and this system does not serve the client's source
 *   justification — a scoping event's subject; the text is in the signed
 *                   predicate already
 */
export type SubjectKind = "artifact" | "anchor" | "justification";

export interface ArtifactResolution {
  /** the sha256 asked for — and, when bytes are present, their actual hash */
  digest: string;
  /** the name the signed statement attests for these bytes */
  name: string;
  kind: SubjectKind;
  /** ledger digests of the statements attesting this artifact — its provenance */
  attestedBy: string[];
  /** the commit the attesting evidence was anchored to, when it names one */
  commit?: string;
  /** present only when a file on disk re-hashed to `digest` */
  bytes?: Uint8Array;
  /** why the bytes are not here, said plainly. Set whenever `bytes` is not. */
  reason?: string;
}

export interface ResolveArtifactOptions {
  ledgerDir: string;
  /** the scan output's artifacts root (`<outDir>/artifacts`); absent → nothing to serve */
  artifactsDir?: string;
  /** the sha256 a statement's subject attests */
  digest: string;
}

/** Thrown when the request itself is malformed or names nothing in the ledger. */
export class ArtifactNotAttestedError extends Error {}

/** every file under `dir`, one level deep per collector subdir: name → paths */
export async function indexArtifacts(dir: string): Promise<Map<string, string[]>> {
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
 * The candidate whose bytes hash to `sha256`, or undefined. This is the ONE
 * hand that decides a file on disk is the artifact a statement attested —
 * I3e's package and J4's viewer both call it, so they cannot come to
 * different conclusions about the same file.
 */
export async function matchByDigest(
  candidates: string[],
  sha256: string,
): Promise<{ path: string; bytes: Buffer } | undefined> {
  for (const candidate of candidates) {
    let bytes: Buffer;
    try {
      bytes = await readFile(candidate);
    } catch {
      continue; // vanished between readdir and read — simply not a match
    }
    if (createHash("sha256").update(bytes).digest("hex") === sha256) {
      return { path: candidate, bytes };
    }
  }
  return undefined;
}

/**
 * The one hand behind the artifact viewer and its raw download (J4): digest →
 * the bytes a signed statement attests, or a stated reason there are none.
 * Reads the append-only ledger and the scan output dir; writes nothing.
 */
export async function resolveArtifact(
  options: ResolveArtifactOptions,
): Promise<ArtifactResolution> {
  const digest = options.digest.toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(digest)) {
    throw new ArtifactNotAttestedError(
      `not a sha256: ${options.digest} — an artifact is addressed by the digest its statement attests`,
    );
  }

  const entries = await createLocalLedger(options.ledgerDir).list();

  // Walk every statement's subjects. A digest can be attested by MORE than one
  // statement — the same artifact backs several recipes — and every one of
  // them is provenance worth naming, so they are all collected rather than
  // the first one winning.
  let name: string | undefined;
  let kind: SubjectKind | undefined;
  let commit: string | undefined;
  const attestedBy: string[] = [];
  for (const entry of entries) {
    const statement = entry.bundle;
    const isEvidence = isEvidenceBundle(statement);
    const anchorNames = new Set(
      isEvidence ? statement.predicate.anchor_paths.map((a) => a.path) : [],
    );
    for (const subject of statement.subject ?? []) {
      if (subject.digest.sha256 !== digest) continue;
      attestedBy.push(entry.digest);
      name ??= subject.name;
      // Classified by the STATEMENT KIND that named these bytes, not by
      // "is it evidence or isn't it". A run record's subjects are the run's
      // artifacts (L2's repo-model.json is attested by nothing else), and
      // calling them justifications would refuse to serve them with a sentence
      // about a scoping event that does not exist.
      //
      // A scoping event's justification loses to any other classification: the
      // same bytes seen as an artifact somewhere are an artifact.
      const thisKind: SubjectKind = isScopingEvent(statement)
        ? "justification"
        : isEvidence && anchorNames.has(subject.name)
          ? "anchor"
          : "artifact";
      if (kind === undefined || (kind === "justification" && thisKind !== "justification")) {
        kind = thisKind;
      }
      if (isEvidence && commit === undefined) commit = statement.predicate.commit;
    }
  }

  if (name === undefined || kind === undefined) {
    throw new ArtifactNotAttestedError(
      `no signed statement in this ledger attests sha256 ${digest} — this system serves attested artifacts, not files`,
    );
  }

  const resolution: ArtifactResolution = { digest, name, kind, attestedBy };
  if (commit !== undefined) resolution.commit = commit;

  if (kind === "anchor") {
    resolution.reason = `repo content at commit ${commit ?? "?"} — not served; \`git show ${(commit ?? "HEAD").slice(0, 12)}:${name}\` reproduces these bytes`;
    return resolution;
  }
  if (kind === "justification") {
    resolution.reason =
      "the justification text is in the signed predicate — a second copy would be a second thing to disagree";
    return resolution;
  }
  if (!options.artifactsDir) {
    resolution.reason =
      "artifacts are not available to this console (no scan output dir configured — `rampscan serve` sets RAMPSCAN_OUT_DIR)";
    return resolution;
  }

  const candidates = (await indexArtifacts(options.artifactsDir)).get(name) ?? [];
  const matched = await matchByDigest(candidates, digest);
  if (matched) {
    resolution.bytes = new Uint8Array(matched.bytes);
    return resolution;
  }
  resolution.reason =
    candidates.length === 0
      ? `not retained — no file named ${name} under the scan output dir`
      : `not retained — the ${candidates.length === 1 ? "file" : "files"} named ${name} on disk ${candidates.length === 1 ? "is" : "are"} from a later run and do${candidates.length === 1 ? "es" : ""} not match the attested digest`;
  return resolution;
}
