import { canonicalJson, isEvidenceBundle } from "@rampscan/schema";
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
  if (isEvidenceBundle(entry.bundle)) {
    const p = entry.bundle.predicate;
    lines.push(
      `bundle   ${options.digest.slice(0, 16)}…`,
      `recipe   ${p.recipe_id} → ${p.verdict}`,
      `repo     ${p.repo} @ ${p.commit.slice(0, 12)}`,
      `signed   ${p.timestamp} (run ${p.run_id})`,
    );
  } else {
    const p = entry.bundle.predicate;
    lines.push(
      `scoping  ${options.digest.slice(0, 16)}…`,
      `recipe   ${p.recipe_id} → ${p.action}`,
      `repo     ${p.repo}`,
      `signed   ${p.timestamp} (proposed ${p.proposed_by}, approved ${p.approved_by})`,
    );
  }

  lines.push(`content  ok — object hashes to its address`); // get() would have thrown otherwise

  if (!entry.envelope) {
    lines.push("signature MISSING — bundle was appended unsigned");
    return { ok: false, lines };
  }

  const signer = createLocalSigner(options.keysDir);
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

  return { ok: signatureOk && payloadMatches, lines };
}
