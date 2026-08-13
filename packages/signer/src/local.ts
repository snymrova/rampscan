import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as cryptoSign,
  verify as cryptoVerify,
  type KeyObject,
} from "node:crypto";
import { chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { LedgerStatement, canonicalJson } from "@rampscan/schema";
import type { SignedEnvelope, Signer } from "@rampscan/core";

// Local Signer (plan M2): DSSE envelope over the canonical in-toto statement,
// ECDSA P-256 / SHA-256 — the same envelope format and key type cosign uses
// for attestations, implemented with node:crypto so the prototype needs no
// cosign binary. Keys are plain PKCS#8 / SPKI PEM on disk (cosign's own
// private-key file adds passphrase encryption; deferred with KMS to the
// appliance). `cosign verify-blob-attestation --key rampscan.pub` can verify
// these envelopes independently — the format is standard, only the storage
// is simplified.

export const DSSE_PAYLOAD_TYPE = "application/vnd.in-toto+json";

const PRIVATE_KEY_FILE = "rampscan.key";
const PUBLIC_KEY_FILE = "rampscan.pub";

/** DSSE Pre-Authentication Encoding — what actually gets signed. */
function pae(payloadType: string, payload: Buffer): Buffer {
  return Buffer.concat([
    Buffer.from(`DSSEv1 ${payloadType.length} ${payloadType} ${payload.length} `),
    payload,
  ]);
}

function keyId(publicKey: KeyObject): string {
  const der = publicKey.export({ type: "spki", format: "der" });
  return createHash("sha256").update(der).digest("hex");
}

async function loadOrCreateKeypair(
  keyDir: string,
  log: (line: string) => void,
): Promise<{ privateKey: KeyObject; publicKey: KeyObject }> {
  const privatePath = join(keyDir, PRIVATE_KEY_FILE);
  const publicPath = join(keyDir, PUBLIC_KEY_FILE);
  try {
    const privateKey = createPrivateKey(await readFile(privatePath, "utf8"));
    const publicKey = createPublicKey(await readFile(publicPath, "utf8"));
    return { privateKey, publicKey };
  } catch {
    // fall through to generation — first run, or the pair is unreadable
  }
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  await mkdir(keyDir, { recursive: true });
  await writeFile(privatePath, privateKey.export({ type: "pkcs8", format: "pem" }), { flag: "wx" });
  await chmod(privatePath, 0o600);
  await writeFile(publicPath, publicKey.export({ type: "spki", format: "pem" }), { flag: "wx" });
  log(`generated new signing keypair at ${keyDir} (ECDSA P-256; keyid ${keyId(publicKey).slice(0, 12)}…)`);
  return { privateKey, publicKey };
}

export function createLocalSigner(
  keyDir: string,
  options: { log?: (line: string) => void } = {},
): Signer {
  const log = options.log ?? (() => {});
  let keys: Promise<{ privateKey: KeyObject; publicKey: KeyObject }> | undefined;
  const getKeys = () => (keys ??= loadOrCreateKeypair(keyDir, log));

  return {
    async sign(statement): Promise<SignedEnvelope> {
      const { privateKey, publicKey } = await getKeys();
      const payload = Buffer.from(canonicalJson(LedgerStatement.parse(statement)));
      const sig = cryptoSign("sha256", pae(DSSE_PAYLOAD_TYPE, payload), privateKey);
      return {
        payload: payload.toString("base64"),
        payloadType: DSSE_PAYLOAD_TYPE,
        signatures: [{ keyid: keyId(publicKey), sig: sig.toString("base64") }],
      };
    },

    async verify(envelope): Promise<boolean> {
      const { publicKey } = await getKeys();
      if (envelope.payloadType !== DSSE_PAYLOAD_TYPE) return false;
      const payload = Buffer.from(envelope.payload, "base64");
      const signed = pae(envelope.payloadType, payload);
      return envelope.signatures.some((s) =>
        cryptoVerify("sha256", signed, publicKey, Buffer.from(s.sig, "base64")),
      );
    },
  };
}

/** The statement inside an envelope — for showing what a signature covers. */
export function statementFromEnvelope(envelope: SignedEnvelope): LedgerStatement {
  return LedgerStatement.parse(
    JSON.parse(Buffer.from(envelope.payload, "base64").toString("utf8")),
  );
}
