import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { DEFAULT_DATASET_PIN } from "@rampscan/dataset";
import { createLocalLedger } from "@rampscan/ledger";
import type { EvidenceBundle } from "@rampscan/schema";
import { createLocalSigner } from "@rampscan/signer";
import { ingest } from "../src/ingest.js";
import { verify } from "../src/verify.js";

// Q4.4 (SPEC §12.8): `rampscan verify` checks ingested bundles offline, the
// same as native ones. The checks ARE the same code path — address, signature,
// coverage — so what Q4.4 adds is the part that cannot be shared: an ingested
// bundle must not render as a native one. It anchors to no commit, so the
// native `repo @ commit` line has nothing to put after the `@`; and the facts
// an assessor pulls on are the handoff's — who signed the result, and which
// submission bytes were accepted (FRR-PVA-AA-06).
//
// It also gains one check a native bundle does not need: the carried
// `method_id` is the register's join key, so a bundle whose key disagrees with
// what its own signed content derives would COUNT on a different method than
// it describes.

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const DATASET_DIR = join(REPO_ROOT, "docs/context/ramprules/derived");
const TREE = join(REPO_ROOT, "fixtures/ingest-evidence-tree");
const REPO = "fixtures/vulnerable-app";

/** a handcrafted bundle, signed and appended — for the shapes `ingest` refuses to mint */
async function appendSigned(work: string, bundle: EvidenceBundle): Promise<string> {
  const envelope = await createLocalSigner(join(work, "keys")).sign(bundle);
  return createLocalLedger(join(work, "ledger")).append(bundle, envelope);
}

function ingestedBundle(over: {
  methodId?: string | undefined;
  ksiIds?: string[];
}): EvidenceBundle {
  return {
    _type: "https://in-toto.io/Statement/v1",
    subject: [{ name: "out.json", digest: { sha256: "f".repeat(64) } }],
    predicateType: "https://rampscan.dev/evidence/v1",
    predicate: {
      recipe_id: "KSI-CNA-RVP.sh",
      ...(over.methodId !== undefined ? { method_id: over.methodId } : {}),
      evidence_class: "process-generated",
      ingest: { signer_identity: "ops@client.example", ingest_digest: "a".repeat(64) },
      ksi_ids: over.ksiIds ?? ["KSI-CNA-RVP"],
      control_ids: [],
      verdict: "evidenced",
      repo: REPO,
      commit: "",
      anchor_paths: [],
      dataset_version: "2026.07.14.01",
      tool_versions: {},
      assertions: [{ description: "check", passed: true }],
      cadence: "monthly",
      run_id: "ingest:handcrafted",
      timestamp: "2026-09-10T14:00:00Z",
    },
  };
}

describe("rampscan verify — ingested bundles (Q4.4)", () => {
  it("renders the handoff rather than a native bundle, and states what the signature covers", async () => {
    const work = await mkdtemp(join(tmpdir(), "rampscan-q44-"));
    const outcome = await ingest({
      path: TREE,
      repo: REPO,
      datasetDir: DATASET_DIR,
      datasetPin: DEFAULT_DATASET_PIN,
      ledgerDir: join(work, "ledger"),
      keysDir: join(work, "keys"),
    });
    const rvp = outcome.appended.find((r) => r.methodId.includes("KSI-CNA-RVP"))!;

    const report = await verify({
      digest: rvp.digest,
      ledgerDir: join(work, "ledger"),
      keysDir: join(work, "keys"),
    });
    const text = report.lines.join("\n");
    expect(report.ok, text).toBe(true);

    // the same three checks a native bundle gets — offline, no network
    expect(text).toContain("content  ok — object hashes to its address");
    expect(text).toContain("signature ok — DSSE envelope verifies");
    expect(text).toContain("payload  ok — the signature covers exactly this bundle");
    // plus the one only an ingested bundle needs
    expect(text).toContain("derived  ok — the carried method id is what this content derives");

    // it says WHAT it is, and names the handoff facts
    expect(text).toContain("ingest   ");
    expect(text).toContain("method   aws-ingested:KSI-CNA-RVP.sh#KSI-CNA-RVP → evidenced");
    expect(text).toContain("signer   compliance-ops@synthetic-csp.example");
    expect(text).toContain("handoff  ");
    // no commit anchor, said rather than left as a dangling separator
    expect(text).toContain("(no commit anchor — ingested evidence)");
    expect(text).not.toMatch(/@\s*$/m);
    // and it does not masquerade as something the appliance produced
    expect(text).not.toContain("bundle   ");

    // the honest limit, where the verdict is read
    expect(text).toContain("This verifies the handoff, not the cloud");
    expect(text).toContain("executed no AWS call");
  });

  it("a native bundle still renders as one — the ingested path is additive", async () => {
    const work = await mkdtemp(join(tmpdir(), "rampscan-q44-native-"));
    const native = ingestedBundle({ methodId: "pipeline:lockfile-pinned-deps#KSI-SCR-MIT" });
    // make it genuinely native: a real commit anchor and no ingest handoff
    const predicate = { ...native.predicate, recipe_id: "lockfile-pinned-deps", commit: "1".repeat(40) };
    delete (predicate as { ingest?: unknown }).ingest;
    const digest = await appendSigned(work, { ...native, predicate });

    const report = await verify({
      digest,
      ledgerDir: join(work, "ledger"),
      keysDir: join(work, "keys"),
    });
    const text = report.lines.join("\n");
    expect(report.ok, text).toBe(true);
    expect(text).toContain("bundle   ");
    expect(text).toContain("recipe   lockfile-pinned-deps → evidenced");
    expect(text).toContain(`repo     ${REPO} @ 111111111111`);
    expect(text).not.toContain("ingest   ");
    expect(text).not.toContain("derived  ");
    expect(text).not.toContain("This verifies the handoff");
  });

  it("refuses a bundle whose carried method id is not what its content derives", async () => {
    const work = await mkdtemp(join(tmpdir(), "rampscan-q44-tampered-"));
    // signed, addressed and covered — and still wrong: this key would count the
    // result on another KSI's method than the one its own content describes
    const digest = await appendSigned(
      work,
      ingestedBundle({ methodId: "aws-ingested:KSI-CNA-RVP.sh#KSI-IAM-AAM" }),
    );
    const report = await verify({
      digest,
      ledgerDir: join(work, "ledger"),
      keysDir: join(work, "keys"),
    });
    const text = report.lines.join("\n");
    expect(report.ok).toBe(false);
    expect(text).toContain("signature ok"); // the crypto is fine; the claim is not
    expect(text).toContain("derived  MISMATCH");
    expect(text).toContain("aws-ingested:KSI-CNA-RVP.sh#KSI-CNA-RVP");
    // a failed verification never prints the reassurance
    expect(text).not.toContain("This verifies the handoff");
  });

  it("reports a bundle carrying no method id at all, rather than inventing one", async () => {
    const work = await mkdtemp(join(tmpdir(), "rampscan-q44-nomethod-"));
    const digest = await appendSigned(work, ingestedBundle({ methodId: undefined }));
    const report = await verify({
      digest,
      ledgerDir: join(work, "ledger"),
      keysDir: join(work, "keys"),
    });
    expect(report.ok).toBe(false);
    expect(report.lines.join("\n")).toContain("derived  MISMATCH — carries no method id");
  });

  it("reports an off-contract multi-KSI ingestion instead of throwing mid-report", async () => {
    const work = await mkdtemp(join(tmpdir(), "rampscan-q44-multiksi-"));
    // the contract mints exactly one KSI per submission and `ingest` refuses
    // anything else — so this can only reach a ledger by hand, and `verify` is
    // where an assessor finds out, as a verdict rather than a stack trace
    const digest = await appendSigned(
      work,
      ingestedBundle({
        methodId: "aws-ingested:KSI-CNA-RVP.sh#KSI-CNA-RVP",
        ksiIds: ["KSI-CNA-RVP", "KSI-IAM-AAM"],
      }),
    );
    const report = await verify({
      digest,
      ledgerDir: join(work, "ledger"),
      keysDir: join(work, "keys"),
    });
    const text = report.lines.join("\n");
    expect(report.ok).toBe(false);
    expect(text).toContain("derived  MISMATCH");
    expect(text).toContain("exactly one per submission");
  });
});
