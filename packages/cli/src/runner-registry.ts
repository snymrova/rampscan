import { createHash, createPublicKey, verify as cryptoVerify } from "node:crypto";
import { toRunnerRegistration } from "@rampscan/core";
import type { Digest, LedgerStore, SignedEnvelope } from "@rampscan/core";
import { createLocalLedger } from "@rampscan/ledger";
import { RUN_TRANSCRIPT_PAYLOAD_TYPE, RunTranscript, RunnerName, isRunnerRegistration } from "@rampscan/schema";
import type { RunnerRegistration } from "@rampscan/schema";
import { createLocalSigner } from "@rampscan/signer";

// The runner registry (docs/PLAN-CLOUD-RUNNER.md T3-2, SPEC §14): the
// appliance's side of the runner key. `recordRunnerRegistration` is the
// approver's key turn — `recordAttestation`'s fourth sibling — over a
// public key an operator proposed; `runnerRegistry` folds the ledger to
// what stands (a later `revoked` supersedes a `registered`, per runner
// name); `verifyRunnerTranscript` is the first check intake makes, before
// the payload reaches `intakeTranscript`: the envelope's signature against
// the registered key, and nothing else about the run.

export interface RecordRunnerRegistrationOptions {
  action: "registered" | "revoked";
  runnerName: string;
  /** SPKI PEM, ECDSA P-256, as `rampscan-runner init` printed it */
  publicKeyPem: string;
  host: string;
  account: string;
  partition: "aws" | "aws-us-gov";
  repo: string;
  proposedBy: string;
  approvedBy: string;
  datasetVersion: string;
  ledgerDir: string;
  keysDir: string;
  now?: Date;
  log?: (line: string) => void;
}

/** sha256 over the SPKI DER — the keyid the runner's envelopes carry */
export function keyIdOfPem(publicKeyPem: string): string {
  const key = createPublicKey(publicKeyPem);
  if (key.asymmetricKeyType !== "ec" || key.asymmetricKeyDetails?.namedCurve !== "prime256v1") {
    throw new Error("a runner key is ECDSA P-256 (prime256v1); refused");
  }
  return createHash("sha256").update(key.export({ type: "spki", format: "der" })).digest("hex");
}

export async function recordRunnerRegistration(options: RecordRunnerRegistrationOptions): Promise<{ digest: Digest; keyid: string }> {
  const log = options.log ?? (() => {});
  const name = RunnerName.safeParse(options.runnerName);
  if (!name.success) {
    throw new Error(`runner name "${options.runnerName}" is not slug-shaped — it becomes part of a signer identity (runner:<name>) and the registry key`);
  }
  const keyid = keyIdOfPem(options.publicKeyPem);
  const event = toRunnerRegistration({
    action: options.action,
    runnerName: name.data,
    publicKeyPem: options.publicKeyPem,
    keyid,
    host: options.host,
    account: options.account,
    partition: options.partition,
    repo: options.repo,
    proposedBy: options.proposedBy,
    approvedBy: options.approvedBy,
    datasetVersion: options.datasetVersion,
    timestamp: (options.now ?? new Date()).toISOString(),
  });
  const signer = createLocalSigner(options.keysDir, { log });
  const envelope = await signer.sign(event);
  const digest = await createLocalLedger(options.ledgerDir).append(event, envelope);
  log(`runner ${options.action}: ${name.data} (keyid ${keyid.slice(0, 12)}…) on ${options.host}, expected in ${options.account} — ${digest.slice(0, 12)}…`);
  return { digest, keyid };
}

export interface RegisteredRunner {
  name: string;
  keyid: string;
  publicKeyPem: string;
  host: string;
  account: string;
  partition: "aws" | "aws-us-gov";
  registeredAt: string;
  approvedBy: string;
}

/** the registry over a ledger directory — the console's read */
export function runnerRegistryAt(ledgerDir: string): Promise<Map<string, RegisteredRunner>> {
  return runnerRegistry(createLocalLedger(ledgerDir));
}

/** what stands: per runner name, the latest registration, dropped when the latest is a revocation */
export async function runnerRegistry(ledger: LedgerStore): Promise<Map<string, RegisteredRunner>> {
  const latest = new Map<string, RunnerRegistration>();
  for (const entry of await ledger.list()) {
    const s = entry.bundle;
    if (!isRunnerRegistration(s)) continue;
    const prior = latest.get(s.predicate.runner_name);
    if (prior === undefined || prior.predicate.timestamp <= s.predicate.timestamp) latest.set(s.predicate.runner_name, s);
  }
  const out = new Map<string, RegisteredRunner>();
  for (const [name, s] of latest) {
    if (s.predicate.action !== "registered") continue;
    out.set(name, {
      name,
      keyid: s.predicate.keyid,
      publicKeyPem: s.predicate.public_key,
      host: s.predicate.host,
      account: s.predicate.account,
      partition: s.predicate.partition,
      registeredAt: s.predicate.timestamp,
      approvedBy: s.predicate.approved_by,
    });
  }
  return out;
}

function pae(payloadType: string, payload: Buffer): Buffer {
  return Buffer.concat([Buffer.from(`DSSEv1 ${payloadType.length} ${payloadType} ${payload.length} `), payload]);
}

export type EnvelopeVerification = { ok: true; payload: unknown; runner: RegisteredRunner } | { ok: false; reason: string };

/**
 * A runner's envelope against the registry: the payload type is the one
 * expected (a transcript's or a claim's — never a ledger statement's), the
 * keyid names a runner that stands, the signature verifies against that
 * key. The payload comes back parsed as JSON and judged by nobody yet.
 */
export function verifyRunnerEnvelope(envelope: SignedEnvelope, registry: ReadonlyMap<string, RegisteredRunner>, payloadType: string): EnvelopeVerification {
  if (envelope.payloadType !== payloadType) {
    return { ok: false, reason: `payload type ${envelope.payloadType} is not ${payloadType === RUN_TRANSCRIPT_PAYLOAD_TYPE ? "a run transcript's" : `a ${payloadType}`}` };
  }
  const byKeyid = new Map([...registry.values()].map((r) => [r.keyid, r]));
  const payload = Buffer.from(envelope.payload, "base64");
  const signed = pae(envelope.payloadType, payload);
  let runner: RegisteredRunner | undefined;
  for (const s of envelope.signatures) {
    const r = byKeyid.get(s.keyid);
    if (r === undefined) continue;
    if (cryptoVerify("sha256", signed, createPublicKey(r.publicKeyPem), Buffer.from(s.sig, "base64"))) {
      runner = r;
      break;
    }
  }
  if (runner === undefined) {
    const keyids = envelope.signatures.map((s) => s.keyid.slice(0, 12)).join(", ");
    return { ok: false, reason: `no signature verifies against a registered runner key (envelope keyids: ${keyids || "none"})` };
  }
  try {
    return { ok: true, payload: JSON.parse(payload.toString("utf8")) as unknown, runner };
  } catch {
    return { ok: false, reason: "the signed payload is not JSON" };
  }
}

export type TranscriptVerification =
  | { ok: true; transcript: RunTranscript; runner: RegisteredRunner }
  | { ok: false; reason: string };

/**
 * The first check on a transcript: the envelope (above), the payload as
 * the contract, and the transcript's own `runner.name` the registered one.
 * Nothing about the run is judged here.
 */
export function verifyRunnerTranscript(envelope: SignedEnvelope, registry: ReadonlyMap<string, RegisteredRunner>): TranscriptVerification {
  const v = verifyRunnerEnvelope(envelope, registry, RUN_TRANSCRIPT_PAYLOAD_TYPE);
  if (!v.ok) return v;
  const parsed = RunTranscript.safeParse(v.payload);
  if (!parsed.success) return { ok: false, reason: `the signed payload is not a run transcript: ${parsed.error.issues[0]?.message ?? "invalid"}` };
  if (parsed.data.runner.name !== v.runner.name) {
    return { ok: false, reason: `the transcript names runner ${parsed.data.runner.name}; the key belongs to ${v.runner.name}` };
  }
  return { ok: true, transcript: parsed.data, runner: v.runner };
}
