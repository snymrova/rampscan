import { mkdtemp, readFile, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import type { EvidenceBundle } from "@rampscan/schema";
import { createLocalSigner, statementFromEnvelope } from "../src/index.js";

const bundle: EvidenceBundle = {
  _type: "https://in-toto.io/Statement/v1",
  subject: [{ name: "sbom.cdx.json", digest: { sha256: "e".repeat(64) } }],
  predicateType: "https://rampscan.dev/evidence/v1",
  predicate: {
    recipe_id: "sbom-exists-and-fresh",
    ksi_ids: ["KSI-SCR-INV"],
    control_ids: ["cm-8"],
    verdict: "evidenced",
    repo: "fixtures/app",
    commit: "c".repeat(40),
    anchor_paths: [{ path: "package.json", contentHash: "a".repeat(64) }],
    dataset_version: "2026.07.14.01",
    tool_versions: { syft: "1.51.0" },
    assertions: [{ description: "sbom generated", passed: true }],
    cadence: "weekly",
    run_id: "run-test",
    timestamp: "2026-08-13T00:00:00.000Z",
  },
};

async function tempKeyDir(): Promise<string> {
  return mkdtemp(join(tmpdir(), "rampscan-keys-"));
}

describe("local signer (DSSE / ECDSA P-256)", () => {
  it("sign → verify round-trips, and the payload is the statement itself", async () => {
    const signer = createLocalSigner(await tempKeyDir());
    const envelope = await signer.sign(bundle);
    expect(envelope.payloadType).toBe("application/vnd.in-toto+json");
    expect(envelope.signatures).toHaveLength(1);
    expect(await signer.verify(envelope)).toBe(true);
    expect(statementFromEnvelope(envelope)).toEqual(bundle);
  });

  it("generates the keypair on first use, private key locked to 0600", async () => {
    const dir = await tempKeyDir();
    const lines: string[] = [];
    const signer = createLocalSigner(dir, { log: (l) => lines.push(l) });
    await signer.sign(bundle);
    expect(lines.join("\n")).toContain("generated new signing keypair");
    expect((await stat(join(dir, "rampscan.key"))).mode & 0o777).toBe(0o600);
    expect(await readFile(join(dir, "rampscan.pub"), "utf8")).toContain("PUBLIC KEY");
  });

  it("a tampered payload fails verification", async () => {
    const signer = createLocalSigner(await tempKeyDir());
    const envelope = await signer.sign(bundle);
    const forged = {
      ...bundle,
      predicate: { ...bundle.predicate, verdict: "violated" as const },
    };
    const tampered = {
      ...envelope,
      payload: Buffer.from(JSON.stringify(forged)).toString("base64"),
    };
    expect(await signer.verify(tampered)).toBe(false);
  });

  it("a signature from a different keypair fails verification", async () => {
    const alice = createLocalSigner(await tempKeyDir());
    const mallory = createLocalSigner(await tempKeyDir());
    const envelope = await mallory.sign(bundle);
    expect(await alice.verify(envelope)).toBe(false);
  });

  it("the same key signs consistently across signer instances (keys persist)", async () => {
    const dir = await tempKeyDir();
    const first = createLocalSigner(dir);
    const envelope = await first.sign(bundle);
    const second = createLocalSigner(dir); // fresh instance, same key dir
    expect(await second.verify(envelope)).toBe(true);
  });
});
