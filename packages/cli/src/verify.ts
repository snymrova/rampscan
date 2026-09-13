import type { LedgerEntry } from "@rampscan/core";
import { ARTIFACT_CLOCK_RULE } from "@rampscan/core";
import {
  canonicalJson,
  isArtifact,
  isAttestation,
  isEvidenceBundle,
  isScanRun,
  isScopingEvent,
  methodOfIngestedBundle,
} from "@rampscan/schema";
import { bundleDigest, createLocalLedger } from "@rampscan/ledger";
import { createLocalSigner, statementFromEnvelope } from "@rampscan/signer";

// `rampscan verify <digest>` — offline check of one bundle (plan M2):
//   1. the stored object still hashes to its address (ledger.get enforces it)
//   2. the DSSE signature over the payload checks out against the local key
//   3. the signed payload IS the stored bundle, byte for byte
// No network, no scan, no trust in the index — just content and keys.

export interface VerifyReport {
  ok: boolean;
  lines: string[];
}

export async function verify(options: {
  digest: string;
  ledgerDir: string;
  keysDir: string;
}): Promise<VerifyReport> {
  const lines: string[] = [];
  const ledger = createLocalLedger(options.ledgerDir);

  const entry = await ledger.get(options.digest);
  if (!entry) {
    return { ok: false, lines: [`no ledger entry with digest ${options.digest}`] };
  }
  // Q4.4 (SPEC §12.8): an ingested bundle verifies with exactly the same
  // machinery as a native one — same envelope, same address discipline — but
  // it must not RENDER as one. Two things differ and both matter to an
  // assessor: it anchors to no commit (so the native `repo @ commit` line has
  // nothing to put after the `@`), and the facts worth pulling on are the
  // handoff's — who signed the result and which submission bytes were
  // accepted. Those live in the predicate precisely so this report can quote
  // them (FRR-PVA-AA-06).
  const ingested = isEvidenceBundle(entry.bundle) ? entry.bundle.predicate.ingest : undefined;
  if (isEvidenceBundle(entry.bundle) && ingested !== undefined) {
    const p = entry.bundle.predicate;
    // The method id is the register's join key, so a bundle whose carried key
    // disagrees with what its own signed content derives would COUNT on a
    // different method than it describes. Checking it is the offline half of
    // "same as native ones": a derivation, reproducible from the bundle alone.
    let derived: string | undefined;
    let derivationError: string | undefined;
    try {
      derived = methodOfIngestedBundle(p).id;
    } catch (error) {
      derivationError = error instanceof Error ? error.message : String(error);
    }
    lines.push(
      `ingest   ${options.digest.slice(0, 16)}…`,
      `method   ${p.method_id ?? derived ?? "(none carried)"} → ${p.verdict}`,
      ...(p.evidence_class !== undefined ? [`class    ${p.evidence_class}`] : []),
      // no `@ commit`: ingested evidence has no anchor, so it dies superseded
      // or goes stale, never by anchor drift — said here rather than left as a
      // dangling separator
      `repo     ${p.repo} (no commit anchor — ingested evidence)`,
      `signer   ${ingested.signer_identity}`,
      `handoff  ${ingested.ingest_digest.slice(0, 16)}… — the submission this bundle accepted`,
      `signed   ${p.timestamp} (run ${p.run_id})`,
    );
    const rest = await verifyEnvelope(entry, options.keysDir, lines);
    const derivationOk = derivationError === undefined && derived === p.method_id;
    lines.push(
      derivationOk
        ? "derived  ok — the carried method id is what this content derives"
        : `derived  MISMATCH — carries ${p.method_id ?? "no method id"}, content derives ` +
          `${derived ?? `nothing (${derivationError})`}`,
    );
    if (rest.ok && derivationOk) {
      // The honest limit, stated where an assessor reads the verdict: the
      // signature is ours and covers the HANDOFF, not the cloud. Leaving this
      // implicit is how a report starts being read as the appliance vouching
      // for AWS — which is the one thing the no-execution boundary means it
      // cannot do.
      lines.push(
        "",
        "This verifies the handoff, not the cloud: the appliance signed that this submission,",
        "at this digest, was accepted under the contract — it executed no AWS call and vouches",
        "for no account state. The submission's own bytes are the client's to produce, and the",
        "handoff digest above is the address to demand exactly those bytes by.",
      );
    }
    return { ok: rest.ok && derivationOk, lines };
  }
  if (isEvidenceBundle(entry.bundle)) {
    const p = entry.bundle.predicate;
    lines.push(
      `bundle   ${options.digest.slice(0, 16)}…`,
      `recipe   ${p.recipe_id} → ${p.verdict}`,
      // the evidence-class assertion (Q3.4, G6), quoted only when the signed
      // predicate states one — a pre-Q3.4 bundle asserted nothing, and this
      // report never fills in what a signature did not say
      ...(p.evidence_class !== undefined ? [`class    ${p.evidence_class}`] : []),
      `repo     ${p.repo} @ ${p.commit.slice(0, 12)}`,
      `signed   ${p.timestamp} (run ${p.run_id})`,
    );
  } else if (isScanRun(entry.bundle)) {
    // a run record verifies exactly like a bundle — same envelope, same
    // address discipline. It says what RAN, so the summary counts collectors
    // and skips, and deliberately quotes no verdict.
    const p = entry.bundle.predicate;
    const skipped = p.collectors.filter((c) => c.skip_reason !== undefined).length;
    lines.push(
      `scan-run ${options.digest.slice(0, 16)}…`,
      `run      ${p.run_id} (${p.trigger}) — ${p.collectors.length} collector(s), ${skipped} skipped`,
      `repo     ${p.repo} @ ${p.commit.slice(0, 12)}`,
      `signed   ${p.timestamp} (started ${p.started_at}, ${p.duration_ms} ms)`,
    );
  } else if (isScopingEvent(entry.bundle)) {
    const p = entry.bundle.predicate;
    lines.push(
      `scoping  ${options.digest.slice(0, 16)}…`,
      `recipe   ${p.recipe_id} → ${p.action}`,
      `repo     ${p.repo}`,
      `signed   ${p.timestamp} (proposed ${p.proposed_by}, approved ${p.approved_by})`,
    );
  } else if (isAttestation(entry.bundle)) {
    // an attestation (Q4.2, SPEC §12.9) verifies exactly like the other two
    // two-key writes. It quotes the ROLE, not the signer: the two identities
    // below say who turned the keys, and the role says whose accountability
    // the claim rests on — an assessor pulls on both.
    const p = entry.bundle.predicate;
    lines.push(
      `attest   ${options.digest.slice(0, 16)}…`,
      `claim    ${p.statement_id}#${p.ksi_id} → ${p.action} (${p.attestor_role})`,
      `repo     ${p.repo}`,
      `signed   ${p.timestamp} (proposed ${p.proposed_by}, approved ${p.approved_by})`,
    );
  } else if (isArtifact(entry.bundle)) {
    // an artifact body (R1.1, SPEC §13.2) verifies exactly like every other
    // statement — same envelope, same address discipline. What it adds to the
    // rendering is the artifact plane's own three questions: whose sentence
    // this is (`source`), when its three-month VDR-TFR-NMV clock started
    // (`valid_from`), and whether anyone is on record as having reviewed it.
    //
    // The review line is printed even when there is nothing to print, because
    // §13.2 says its absence is stated rather than assumed benign: "reviewed
    // by nobody on record" is a fact an assessor should have to read, not one
    // they have to notice is missing.
    const p = entry.bundle.predicate;
    const bytes = Buffer.byteLength(p.body, "utf8");
    lines.push(
      `artifact ${options.digest.slice(0, 16)}…`,
      `slot     ${p.ksi_id} #${p.artifact} — ${p.source}`,
      `body     ${p.body_digest.slice(0, 16)}… (${bytes} bytes)` +
        (p.supersedes !== undefined ? `, supersedes ${p.supersedes.slice(0, 12)}…` : ""),
      ...(p.anchor !== undefined
        ? [`anchor   ${p.anchor.path} @ ${p.anchor.commit.slice(0, 12)}`]
        : []),
      `review   ${
        p.review !== undefined
          ? `${p.review.source} ${p.review.reference} (${p.review.approvers.join(", ") || "no approvers named"})`
          : "none on record"
      }`,
      `repo     ${p.repo}`,
      `clock    ${ARTIFACT_CLOCK_RULE} from ${p.valid_from}`,
      `signed   ${p.timestamp}`,
    );
  } else {
    // an artifact-sufficiency judgment (Q3.3) verifies exactly like a
    // scoping — same envelope, same address discipline, same two identities
    const p = entry.bundle.predicate;
    lines.push(
      `judgment ${options.digest.slice(0, 16)}…`,
      `artifact ${p.ksi_id} #${p.artifact} → ${p.action}`,
      `repo     ${p.repo}`,
      `signed   ${p.timestamp} (proposed ${p.proposed_by}, approved ${p.approved_by})`,
    );
  }

  const rest = await verifyEnvelope(entry, options.keysDir, lines);
  return { ok: rest.ok, lines };
}

/**
 * The checks every statement kind gets, identical for all of them — which is
 * what "ingested bundles verify offline, same as native ones" (Q4.4) means
 * concretely: the address, the signature, and the coverage are one code path,
 * and only the rendering above knows what kind of statement it is reading.
 */
async function verifyEnvelope(
  entry: LedgerEntry,
  keysDir: string,
  lines: string[],
): Promise<{ ok: boolean }> {
  lines.push(`content  ok — object hashes to its address`); // get() would have thrown otherwise

  if (!entry.envelope) {
    lines.push("signature MISSING — bundle was appended unsigned");
    return { ok: false };
  }

  const signer = createLocalSigner(keysDir);
  const signatureOk = await signer.verify(entry.envelope);
  lines.push(signatureOk ? "signature ok — DSSE envelope verifies" : "signature FAILED");

  const signedStatement = statementFromEnvelope(entry.envelope);
  const payloadMatches =
    canonicalJson(signedStatement) === canonicalJson(entry.bundle) &&
    bundleDigest(signedStatement) === entry.digest;
  lines.push(
    payloadMatches
      ? "payload  ok — the signature covers exactly this bundle"
      : "payload  MISMATCH — the envelope signs different content than stored",
  );

  return { ok: signatureOk && payloadMatches };
}
