import { toArtifact } from "@rampscan/core";
import type { Digest, Projection } from "@rampscan/core";
import { loadKsiCatalogFromSlices } from "@rampscan/dataset";
import type { OfferingClass } from "@rampscan/dataset";
import { createLocalLedger } from "@rampscan/ledger";
import type {
  ArtifactAnchor,
  ArtifactGenerator,
  ArtifactReview,
  ArtifactSlot,
  ArtifactSource,
} from "@rampscan/schema";
import { Artifact, isArtifact } from "@rampscan/schema";
import { createLocalSigner } from "@rampscan/signer";
import { generateArtifact2, generateArtifact4, generateArtifact5 } from "./artifact-generators.js";

// The artifact plane's write path (plan R1.1, SPEC §13.2) — `recordScoping`,
// `recordArtifactJudgment` and `recordAttestation`'s fourth sibling, and the
// one that is NOT a two-key write. §13.3 is explicit about why: appending an
// authored artifact is a collector observation signed like evidence, because
// the repository's own review is the second key, and adding a ceremony the
// pull request already performed would teach people to click through it.
//
// (Its neighbour `artifact.ts` is a different thing entirely: J4's resolution
// of TOOL artifacts — sboms, scan reports — by digest out of the output dir.)
//
// Everything a body must satisfy is checked HERE, at the append, against the
// schema rather than against a convention: the 64 KiB bound, the refusal to
// compute artifacts 1 and 3 (§13.4), and the anchor discipline that makes an
// authored body die when the file it quotes moves.

export interface RecordArtifactOptions {
  repo: string;
  ksiId: string;
  /** 1-based into `default_artifacts.KSI`, the rules' own order */
  artifact: ArtifactSlot;
  source: ArtifactSource;
  /** Markdown — a short, high-level summary, bounded at 64 KiB by the schema */
  body: string;
  /** authored only: where the body lives, and what kills it when it moves */
  anchor?: ArtifactAnchor;
  /** computed only: the pin set, the tool versions, the exec-journal digest */
  generator?: ArtifactGenerator;
  /** R4's forge plane, when it knows — never asserted here */
  review?: ArtifactReview;
  /**
   * The clock's start (§13.5). Omit and it falls to the append instant, which
   * is right for a computed, attested or assessed body. An AUTHORED one should
   * pass its anchor commit's date: dating it from the scan that found it would
   * restart a three-month clock every time anyone ran a scan.
   */
  validFrom?: string;
  datasetDir: string;
  datasetPin: string;
  ledgerDir: string;
  keysDir: string;
  now?: Date;
  log?: (line: string) => void;
}

export async function recordArtifact(
  options: RecordArtifactOptions,
): Promise<{ digest: Digest; bodyDigest: string; supersedes?: string }> {
  const log = options.log ?? (() => {});
  const body = options.body.trim();
  if (body.length === 0) {
    throw new Error(
      "an artifact requires a body — an empty slot is an absence, and SPEC §13.4 says an " +
        "absence is recorded with a reason rather than signed as a blank",
    );
  }

  const catalog = await loadKsiCatalogFromSlices(options.datasetDir, options.datasetPin);
  if (!catalog.ksis.some((k) => k.id === options.ksiId)) {
    throw new Error(`unknown KSI ${options.ksiId} — an artifact must reference the pinned catalog`);
  }

  const ledger = createLocalLedger(options.ledgerDir);
  // What this body revises, read from the record rather than asked for: the
  // live body in this slot is the one being replaced, and a caller who forgot
  // to say so would leave a supersession chain with a hole in it. Sorted by
  // append order — the same "latest wins" the fold applies (§13.2).
  let supersededDigest: string | undefined;
  for (const entry of await ledger.list({ repo: options.repo })) {
    if (!isArtifact(entry.bundle)) continue;
    const p = entry.bundle.predicate;
    if (p.ksi_id !== options.ksiId || p.artifact !== options.artifact) continue;
    supersededDigest = p.body_digest; // list is append-ordered: the last wins
  }

  const statement = toArtifact({
    repo: options.repo,
    ksiId: options.ksiId,
    artifact: options.artifact,
    source: options.source,
    body,
    ...(options.anchor !== undefined ? { anchor: options.anchor } : {}),
    ...(options.generator !== undefined ? { generator: options.generator } : {}),
    ...(options.review !== undefined ? { review: options.review } : {}),
    ...(options.validFrom !== undefined ? { validFrom: options.validFrom } : {}),
    datasetVersion: catalog.datasetVersion,
    timestamp: (options.now ?? new Date()).toISOString(),
  });
  // an identical body is not a revision of itself — re-signing the same bytes
  // restarts the clock (§13.5) and supersedes nothing
  if (supersededDigest !== undefined && supersededDigest !== statement.predicate.body_digest) {
    statement.predicate.supersedes = supersededDigest;
  }

  const parsed = Artifact.safeParse(statement);
  if (!parsed.success) {
    throw new Error(
      `this artifact cannot be appended:\n  ` +
        parsed.error.issues.map((i) => `${i.path.join(".") || "statement"}: ${i.message}`).join("\n  "),
    );
  }

  const signer = createLocalSigner(options.keysDir, { log });
  const envelope = await signer.sign(parsed.data);
  const digest = await ledger.append(parsed.data, envelope);
  log(
    `artifact recorded: ${options.ksiId} #${options.artifact} (${options.source}) for ` +
      `${options.repo} → ${digest.slice(0, 12)}…` +
      (statement.predicate.supersedes !== undefined
        ? ` — supersedes ${statement.predicate.supersedes.slice(0, 12)}…`
        : ""),
  );
  const result: { digest: Digest; bodyDigest: string; supersedes?: string } = {
    digest,
    bodyDigest: parsed.data.predicate.body_digest,
  };
  if (statement.predicate.supersedes !== undefined) {
    result.supersedes = statement.predicate.supersedes;
  }
  return result;
}

/**
 * Mint a computed artifact from the fold (plan R1.2 — artifact 4 today, 2 and
 * 5 in R1.3) and append it, or report the reason there was nothing to compute.
 *
 * The refusal is a first-class outcome, not an error: SPEC §13.4 makes an
 * absence with a reason the generator's honest output for an artifact nobody
 * has grounds to write, and a caller that treated it as a failure would push
 * whoever runs it toward writing the paragraph by hand to make the tool stop
 * complaining. `rampscan artifacts` (R1.5) prints these as a work queue.
 */
export interface MintComputedArtifactOptions {
  repo: string;
  ksiId: string;
  /** the computed slots — 2, 4 and 5 are the only ones §13.4 allows */
  artifact: 2 | 4 | 5;
  /** a fold of the ledger this artifact will be appended to */
  projection: Projection;
  /**
   * The offering's class, so artifact 2 can cite the RULE its machine window
   * comes from. The number itself already rode in on the fold; only the rule
   * id is class-dependent, and naming one without knowing the class would be
   * a citation we made up.
   */
  offeringClass: OfferingClass;
  datasetDir: string;
  datasetPin: string;
  ledgerDir: string;
  keysDir: string;
  now?: Date;
  log?: (line: string) => void;
}

export type MintedArtifact =
  | { minted: true; digest: Digest; bodyDigest: string; supersedes?: string }
  | { minted: false; reason: string };

// Minting the same bytes twice is not an error and is not skipped. §13.5 is
// explicit that a computed artifact's clock restarts at each generation that
// produces it — "the body was recomputed from current evidence at that
// instant" is a true and useful statement, and suppressing the append to save
// a ledger entry would leave a recomputed artifact ageing out at three months
// as though nobody had looked. `supersedes` stays absent when the bytes are
// identical, because identical bytes are not a revision of themselves.

export async function mintComputedArtifact(
  options: MintComputedArtifactOptions,
): Promise<MintedArtifact> {
  const row = options.projection.methodRegisters.find(
    (r) => r.repo === options.repo && r.ksi === options.ksiId,
  );
  if (row === undefined) {
    return {
      minted: false,
      reason:
        `${options.ksiId} has no row on ${options.repo}'s method register — nothing has been ` +
        `folded for it, so there is nothing to compute from`,
    };
  }

  const catalog = await loadKsiCatalogFromSlices(options.datasetDir, options.datasetPin);
  // §13.4 at this layer too. The schema is the structural backstop and would
  // refuse the append anyway, but a caller reaching past the type deserves the
  // rule's own sentence rather than a parse error that happens to say it — and
  // the dispatch below must never quietly hand artifact 1 to another slot's
  // generator on its way there.
  if (options.artifact !== 2 && options.artifact !== 4 && options.artifact !== 5) {
    return {
      minted: false,
      reason:
        `artifact ${options.artifact} is not computed: artifacts 1 and 3 are the provider's own ` +
        `claims and rampscan does not write them (SPEC §13.4). An absence with a reason is the ` +
        `honest output here; a draft is not.`,
    };
  }

  const machineRule = catalog.windows[options.offeringClass]?.requirementId;
  const input = {
    repo: options.repo,
    ksiId: options.ksiId,
    row,
    registers: options.projection.registers,
    scanRuns: options.projection.scanRuns,
    gaps: options.projection.gaps,
    vulnerabilities: options.projection.vulnerabilities,
    clockRules: {
      ...(machineRule !== undefined ? { machine: machineRule } : {}),
      nonMachine: catalog.nonMachineWindow.requirementId,
    },
    datasetVersion: catalog.datasetVersion,
  };
  const generated =
    options.artifact === 2
      ? generateArtifact2(input)
      : options.artifact === 4
        ? generateArtifact4(input)
        : generateArtifact5(input);
  if (!generated.generated) return { minted: false, reason: generated.reason };

  const recorded = await recordArtifact({
    repo: options.repo,
    ksiId: options.ksiId,
    artifact: options.artifact,
    source: "computed",
    body: generated.body,
    generator: generated.generator,
    datasetDir: options.datasetDir,
    datasetPin: options.datasetPin,
    ledgerDir: options.ledgerDir,
    keysDir: options.keysDir,
    ...(options.now !== undefined ? { now: options.now } : {}),
    ...(options.log !== undefined ? { log: options.log } : {}),
  });
  const result: MintedArtifact = {
    minted: true,
    digest: recorded.digest,
    bodyDigest: recorded.bodyDigest,
  };
  if (recorded.supersedes !== undefined) result.supersedes = recorded.supersedes;
  return result;
}
