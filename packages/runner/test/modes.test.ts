import { createHash } from "node:crypto";
import { mkdtemp } from "node:fs/promises";
import { createServer } from "node:http";
import type { IncomingMessage, Server } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import type { RunRequest } from "@rampscan/schema";
import { RUN_CLAIM_PAYLOAD_TYPE, initRunnerKeys, verifyTranscriptEnvelope } from "../src/keys.js";
import type { TranscriptEnvelope } from "../src/keys.js";
import { decodeOnceToken, encodeOnceToken, once, poll } from "../src/modes.js";
import type { IntakePost, RunAssignment } from "../src/modes.js";
import { DENIAL_PROBES } from "../src/selfcheck.js";

// T3-4 (docs/PLAN-CLOUD-RUNNER.md, #179): the two hosts against a console
// stub that speaks the wire shapes T4-2's routes will serve. `poll` proves
// key possession with a signed claim, runs what it is handed, posts the
// signed transcript and the bytes; `once` decodes a token, runs under an
// ephemeral key, posts the token beside the transcript. The stub verifies
// what it can (the claim's key, the envelope's key) so the runner's side
// of the protocol is pinned here; the appliance's side is T4-2's.

const HERE = dirname(fileURLToPath(import.meta.url));
const SHIM = resolve(HERE, "aws-shim.mjs");
const sha256 = (s: string) => createHash("sha256").update(s).digest("hex");
const IDENTITY = JSON.stringify({ Account: "111111111111", Arn: "arn:aws:sts::111111111111:assumed-role/rampscan-runner/i-0abc" });
const SIMULATE = `iam simulate-principal-policy --policy-source-arn arn:aws:iam::111111111111:role/rampscan-runner --action-names ${DENIAL_PROBES.join(" ")} --output json`;
const DENIED = JSON.stringify({ EvaluationResults: DENIAL_PROBES.map((a) => ({ EvalActionName: a, EvalDecision: "implicitDeny" })) });

const REQUEST: RunRequest = {
  _type: "https://rampscan.dev/run-request/v1",
  nonce: "5f2c9a1e7b3d4c6a8e0f1a2b3c4d5e6f",
  recipe_id: "iam-list-roles",
  recipe_digest: sha256("recipe"),
  ksi: "KSI-IAM-ELP",
  params: {},
  issued_at: "2026-09-16T09:00:00Z",
  expires_at: "2026-09-16T11:00:00Z",
  requester: "operator@example.test",
};
const ASSIGNMENT: RunAssignment = { request: REQUEST, request_digest: sha256("request"), steps: [["aws", "iam", "list-roles"]] };

function shim() {
  const spec = JSON.stringify({ "sts get-caller-identity --output json": { stdout: IDENTITY }, [SIMULATE]: { stdout: DENIED }, "iam list-roles": { stdout: '{"Roles": []}\n' } });
  return { binary: SHIM, env: { ...process.env, AWS_SHIM_SPEC: spec } };
}

async function body(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  for await (const c of req) chunks.push(c as Buffer);
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

/** a console stub: one assignment to hand out, and it records what it was posted */
function consoleStub(opts: { registeredPem?: string; assignments: RunAssignment[]; tokenSig?: string }) {
  const seen: { claims: TranscriptEnvelope[]; intakes: IntakePost[]; tokens: string[] } = { claims: [], intakes: [], tokens: [] };
  const queue = [...opts.assignments];
  const server: Server = createServer(async (req, res) => {
    const json = (status: number, v: unknown) => {
      res.writeHead(status, { "content-type": "application/json" });
      res.end(v === undefined ? "" : JSON.stringify(v));
    };
    const posted = (await body(req)) as Record<string, unknown>;
    if (req.url === "/api/runs/next") {
      if (typeof posted["token"] === "string") {
        seen.tokens.push(posted["token"]);
        const { token } = decodeOnceToken(posted["token"]);
        const a = queue.find((x) => x.request.nonce === token.nonce);
        return a === undefined ? json(404, { reason: "no such request" }) : json(200, a);
      }
      const claim = posted as unknown as TranscriptEnvelope;
      seen.claims.push(claim);
      if (opts.registeredPem === undefined || !verifyTranscriptEnvelope(claim, opts.registeredPem, RUN_CLAIM_PAYLOAD_TYPE)) return json(401, { reason: "not registered" });
      const next = queue.shift();
      return next === undefined ? json(204, undefined) : json(200, next);
    }
    if (req.url === "/api/runs/intake") {
      const post = posted as unknown as IntakePost;
      seen.intakes.push(post);
      const pem = post.public_key ?? opts.registeredPem;
      if (pem === undefined || !verifyTranscriptEnvelope(post.envelope, pem)) return json(403, { kind: "refused", reason: "signature" });
      return json(200, { kind: "submission", digest: "d".repeat(64) });
    }
    return json(404, { reason: "no such route" });
  });
  return new Promise<{ url: string; seen: typeof seen; close: () => void }>((resolveUrl) => {
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address() as { port: number };
      resolveUrl({ url: `http://127.0.0.1:${addr.port}`, seen, close: () => server.close() });
    });
  });
}

let stubs: Array<{ close: () => void }> = [];
afterEach(() => {
  for (const s of stubs) s.close();
  stubs = [];
});

describe("poll — the sidecar (T3-4)", () => {
  it("claims work under its key, runs the assignment, posts the signed transcript and the bytes, stops at 204", async () => {
    const keys = await initRunnerKeys(join(await mkdtemp(join(tmpdir(), "rampscan-poll-")), "keys"));
    const stub = await consoleStub({ registeredPem: keys.publicKeyPem, assignments: [ASSIGNMENT] });
    stubs.push(stub);
    const lines: string[] = [];
    const { handled } = await poll({ console: stub.url, keys, runner: { name: "sidecar-1", region: "us-east-1" }, maxRequests: 5, log: (l) => lines.push(l), ...shim() });
    expect(handled).toBe(1);
    expect(stub.seen.claims).toHaveLength(2); // one that got work, one that got 204
    expect(stub.seen.claims[0]!.payloadType).toBe(RUN_CLAIM_PAYLOAD_TYPE);
    expect(JSON.parse(Buffer.from(stub.seen.claims[0]!.payload, "base64").toString())).toMatchObject({ runner: "sidecar-1" });
    const post = stub.seen.intakes[0]!;
    expect(verifyTranscriptEnvelope(post.envelope, keys.publicKeyPem)).toBe(true);
    const transcript = JSON.parse(Buffer.from(post.envelope.payload, "base64").toString()) as { steps: Array<{ stdout_sha256: string }>; self_check: unknown; runner: { name: string } };
    expect(transcript.runner.name).toBe("sidecar-1");
    expect(transcript.self_check).toEqual({ probes: [...DENIAL_PROBES], all_denied: true });
    expect(Object.keys(post.outputs)).toEqual([transcript.steps[0]!.stdout_sha256]);
    expect(Buffer.from(post.outputs[transcript.steps[0]!.stdout_sha256]!, "base64").toString()).toBe('{"Roles": []}\n');
    expect(post.token).toBeUndefined();
    expect(lines.join("\n")).toMatch(/intake 200: submission/);
  });

  it("a key the console does not know stops the loop with the reason", async () => {
    const keys = await initRunnerKeys(join(await mkdtemp(join(tmpdir(), "rampscan-poll-")), "keys"));
    const stub = await consoleStub({ assignments: [ASSIGNMENT] });
    stubs.push(stub);
    await expect(poll({ console: stub.url, keys, runner: { name: "sidecar-1", region: "us-east-1" }, maxRequests: 1, ...shim() })).rejects.toThrow(/does not accept this runner's key \(401\): not registered/);
    expect(stub.seen.intakes).toHaveLength(0);
  });
});

describe("once — the CloudShell one-shot (T3-4)", () => {
  it("decodes the token, fetches the assignment it names, runs under an ephemeral key, posts token and public key", async () => {
    const stub = await consoleStub({ assignments: [ASSIGNMENT] });
    stubs.push(stub);
    const encoded = encodeOnceToken(
      { _type: "https://rampscan.dev/run-token/v1", console: stub.url, nonce: REQUEST.nonce, request_digest: ASSIGNMENT.request_digest, expires_at: "2126-01-01T00:00:00Z" },
      "appliance-signature-checked-by-T4-2",
    );
    const reply = await once({ token: encoded, region: "us-east-1", ...shim() });
    expect(reply).toEqual({ kind: "submission", digest: "d".repeat(64) });
    expect(stub.seen.tokens).toEqual([encoded]);
    const post = stub.seen.intakes[0]!;
    expect(post.token).toBe(encoded);
    expect(post.public_key).toMatch(/^-----BEGIN PUBLIC KEY-----/);
    expect(verifyTranscriptEnvelope(post.envelope, post.public_key!)).toBe(true);
    const transcript = JSON.parse(Buffer.from(post.envelope.payload, "base64").toString()) as { runner: { name: string } };
    expect(transcript.runner.name).toBe(`once-${REQUEST.nonce.slice(0, 8)}`);
  });

  it("an expired token, a token the console does not know, and an assignment that is not the token's are refused before anything runs", async () => {
    const stub = await consoleStub({ assignments: [ASSIGNMENT] });
    stubs.push(stub);
    const expired = encodeOnceToken({ _type: "https://rampscan.dev/run-token/v1", console: stub.url, nonce: REQUEST.nonce, request_digest: ASSIGNMENT.request_digest, expires_at: "2020-01-01T00:00:00Z" }, "sig");
    await expect(once({ token: expired, region: "us-east-1", ...shim() })).rejects.toThrow(/expired/);
    const unknown = encodeOnceToken({ _type: "https://rampscan.dev/run-token/v1", console: stub.url, nonce: "0".repeat(32), request_digest: ASSIGNMENT.request_digest, expires_at: "2126-01-01T00:00:00Z" }, "sig");
    await expect(once({ token: unknown, region: "us-east-1", ...shim() })).rejects.toThrow(/did not hand out the request .*404/);
    const mismatched = encodeOnceToken({ _type: "https://rampscan.dev/run-token/v1", console: stub.url, nonce: REQUEST.nonce, request_digest: "e".repeat(64), expires_at: "2126-01-01T00:00:00Z" }, "sig");
    await expect(once({ token: mismatched, region: "us-east-1", ...shim() })).rejects.toThrow(/does not match the token/);
    expect(stub.seen.intakes).toHaveLength(0);
    expect(() => decodeOnceToken(Buffer.from("{}").toString("base64url"))).toThrow(/not a run token/);
  });
});
