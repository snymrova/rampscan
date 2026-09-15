import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign as cryptoSign, verify as cryptoVerify } from "node:crypto";
import type { KeyObject } from "node:crypto";
import { chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { RunTranscript } from "@rampscan/schema";

// The runner's own key (docs/PLAN-CLOUD-RUNNER.md T3-2). ECDSA P-256, a DSSE
// envelope over the canonical transcript — the same envelope shape and key
// type the appliance's ledger uses, so `cosign verify-blob-attestation` can
// check a transcript too — but a DIFFERENT payload type, so a transcript
// can never be mistaken for a ledger statement, and a different key: the
// runner signs transcripts and nothing else; the appliance signs bundles
// and never a transcript. Implemented with node:crypto alone, because the
// runner imports no rampscan package by value (T3-5).

export const RUN_TRANSCRIPT_PAYLOAD_TYPE = "application/vnd.rampscan.run-transcript+json";

const PRIVATE_KEY_FILE = "runner.key";
const PUBLIC_KEY_FILE = "runner.pub";

/** the DSSE envelope, as the appliance reads it */
export interface TranscriptEnvelope {
  payload: string;
  payloadType: string;
  signatures: Array<{ keyid: string; sig: string }>;
}

/**
 * Canonical JSON — JCS-style, sorted keys, no whitespace — the same bytes
 * `@rampscan/schema`'s `canonicalJson` produces (a test holds them equal).
 * Duplicated here on purpose: the runner may not import that package.
 */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value === "number" || typeof value === "boolean") {
    if (typeof value === "number" && !Number.isFinite(value)) throw new Error("canonical JSON cannot represent NaN/Infinity");
    return JSON.stringify(value);
  }
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((v) => canonicalJson(v === undefined ? null : v)).join(",")}]`;
  if (typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, v]) => v !== undefined)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`).join(",")}}`;
  }
  throw new Error(`canonical JSON cannot represent ${typeof value}`);
}

/** DSSE Pre-Authentication Encoding — what is actually signed */
export function pae(payloadType: string, payload: Buffer): Buffer {
  return Buffer.concat([Buffer.from(`DSSEv1 ${payloadType.length} ${payloadType} ${payload.length} `), payload]);
}

/** sha256 over the SPKI DER — the `keyid` every envelope carries and the registration records */
export function keyIdOf(publicKey: KeyObject): string {
  return createHash("sha256").update(publicKey.export({ type: "spki", format: "der" })).digest("hex");
}

export interface RunnerKeys {
  privateKey: KeyObject;
  publicKey: KeyObject;
  keyid: string;
  publicKeyPem: string;
}

/** `rampscan-runner init`: generate the pair once; print the public half for the operator to propose */
export async function initRunnerKeys(dir: string): Promise<RunnerKeys & { created: boolean }> {
  const privatePath = join(dir, PRIVATE_KEY_FILE);
  const publicPath = join(dir, PUBLIC_KEY_FILE);
  try {
    const privateKey = createPrivateKey(await readFile(privatePath, "utf8"));
    const publicKey = createPublicKey(await readFile(publicPath, "utf8"));
    return { privateKey, publicKey, keyid: keyIdOf(publicKey), publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(), created: false };
  } catch {
    // first run, or unreadable: generate
  }
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  await mkdir(dir, { recursive: true });
  await writeFile(privatePath, privateKey.export({ type: "pkcs8", format: "pem" }), { flag: "wx" });
  await chmod(privatePath, 0o600);
  const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
  await writeFile(publicPath, publicKeyPem, { flag: "wx" });
  return { privateKey, publicKey, keyid: keyIdOf(publicKey), publicKeyPem, created: true };
}

export async function loadRunnerKeys(dir: string): Promise<RunnerKeys> {
  const privateKey = createPrivateKey(await readFile(join(dir, PRIVATE_KEY_FILE), "utf8"));
  const publicKey = createPublicKey(await readFile(join(dir, PUBLIC_KEY_FILE), "utf8"));
  return { privateKey, publicKey, keyid: keyIdOf(publicKey), publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString() };
}

/** the envelope the runner hands back: the canonical transcript, signed */
export function signTranscript(transcript: RunTranscript, keys: RunnerKeys): TranscriptEnvelope {
  const payload = Buffer.from(canonicalJson(transcript));
  const sig = cryptoSign("sha256", pae(RUN_TRANSCRIPT_PAYLOAD_TYPE, payload), keys.privateKey);
  return { payload: payload.toString("base64"), payloadType: RUN_TRANSCRIPT_PAYLOAD_TYPE, signatures: [{ keyid: keys.keyid, sig: sig.toString("base64") }] };
}

/** the check the appliance makes, offered here so the runner can verify its own output before sending */
export function verifyTranscriptEnvelope(envelope: TranscriptEnvelope, publicKeyPem: string): boolean {
  if (envelope.payloadType !== RUN_TRANSCRIPT_PAYLOAD_TYPE) return false;
  const publicKey = createPublicKey(publicKeyPem);
  const keyid = keyIdOf(publicKey);
  const signed = pae(envelope.payloadType, Buffer.from(envelope.payload, "base64"));
  return envelope.signatures.some((s) => s.keyid === keyid && cryptoVerify("sha256", signed, publicKey, Buffer.from(s.sig, "base64")));
}
