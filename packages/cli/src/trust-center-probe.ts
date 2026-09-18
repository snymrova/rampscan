import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { z } from "zod";
import {
  OCR_SCHEMA,
  PACKAGE_OVERVIEW_SCHEMA,
  SDR_SCHEMA,
  loadPinnedSchema,
  validateAgainst,
} from "./fedramp-schemas.js";

// The trust-center probe (P4, #213; docs/RESEARCH-TRUST-CENTER-PROBE.md).
//
// WHAT IT MEASURES. FedRAMP's first listed reason for rejecting a 20x
// submission (FedRAMP/community#167) is a Trust Center that makes a reviewer
// accept an NDA, terms of service or a privacy policy before the data is
// readable — against CDS-TRC-USH ("without interruption"). That is a
// property of a live URL, so no
// file rampscan reads can answer it, and `rampscan submission` has printed it
// as `unmeasured` since P2. (The trust center's programmatic-access rule asks
// for DOCUMENTED access; a document reached by a program is not documentation,
// so the probe does not claim that rule.)
//
// THE BOUNDARY. The appliance still makes no fetch on its own account: this
// is a separate, explicit command (`rampscan probe`) that GETs only the URLs
// the operator names, anonymously — no cookie, no credential, no JavaScript —
// and writes a transcript. `rampscan submission` reads that transcript OFFLINE,
// the way it reads an SDR. Nothing here is credentialed, which is why the
// cloud runner's two-program answer (an AWS role the appliance never holds)
// is not needed: the question IS what an anonymous reader gets.
//
// THE RULE THIS FILE IS BUILT AROUND — a negative is proven positively, never
// inferred from a 200 (ground rule 7; GHSA-7jff-6v53-r56x's class). A landing
// page that loads proves a page loaded. A script-rendered click-through, an
// NDA modal, a "request access" button behind a SPA shell are all invisible
// to a fetch, so a clean-looking 200 on HTML is `undetermined`, never `open`.
// The ONLY thing that reads `open` is a named certification DOCUMENT whose
// bytes came back to an anonymous GET and validate against one of the pinned
// FedRAMP schemas — the data itself, reached without a gate. "Gated", in the
// other direction, needs positive evidence too: a refusal status, a redirect
// into a login flow, or a click-through marker in the page, each recorded
// with the exact thing that matched.
//
// TWO KINDS OF GATE, AND ONLY ONE IS REASON 1. FedRAMP PERMITS an
// authenticated trust center — the package schema's repository carries
// `authenticationRequired` and requires `accessRequestInstructions` exactly
// when it is true, and CDS-TRC-USH's own note prefers just-in-time access
// provisioning. What #167 rejects is ACCEPTANCE: an NDA, terms of service or
// a privacy policy the reviewer must acknowledge. So a gated target says
// which it met: `click-through` (reason 1 itself) or `authentication` (a
// login the offering may have declared, and behind which this probe cannot
// see whether a click-through waits).

export const TRUST_CENTER_PROBE_TYPE = "https://rampscan.dev/trust-center-probe/v1" as const;

/** what a target is, which decides what it can prove */
export const ProbeRole = z.enum(["trust-center", "document"]);
export type ProbeRole = z.infer<typeof ProbeRole>;

/**
 * `open` — a certification document reached anonymously and validating against
 *   a pinned schema. Only a `document` target can be open.
 * `gated` — positive evidence of a gate, named in `reasons`.
 * `undetermined` — neither: a page loaded, a fetch failed, a body that is not
 *   certification data. Never read as either of the others.
 */
export const ProbeOutcome = z.enum(["open", "gated", "undetermined"]);
export type ProbeOutcome = z.infer<typeof ProbeOutcome>;

/** which gate a gated target met — see the header: only `click-through` is reason 1 */
export const ProbeGate = z.enum(["click-through", "authentication"]);
export type ProbeGate = z.infer<typeof ProbeGate>;

export const ProbeHop = z.strictObject({
  url: z.string().min(1),
  status: z.number().int(),
  location: z.string().optional(),
});
export type ProbeHop = z.infer<typeof ProbeHop>;

export const ProbeTarget = z.strictObject({
  url: z.string().url(),
  role: ProbeRole,
  /** every response in order, the redirects included */
  hops: z.array(ProbeHop),
  /** the network failure, when there was no final response */
  error: z.string().optional(),
  content_type: z.string().optional(),
  bytes: z.number().int().optional(),
  sha256: z
    .string()
    .regex(/^[0-9a-f]{64}$/)
    .optional(),
  /** the pinned schema a document validated against, when it did */
  schema: z.string().optional(),
  outcome: ProbeOutcome,
  /** present exactly when `outcome` is gated */
  gate: ProbeGate.optional(),
  reasons: z.array(z.string().min(1)).min(1),
});
export type ProbeTarget = z.infer<typeof ProbeTarget>;

export const TrustCenterProbe = z.strictObject({
  _type: z.literal(TRUST_CENTER_PROBE_TYPE),
  /** the trust center the probe was about — compared against the offering's declaration */
  trust_center: z.string().url(),
  probed_at: z.iso.datetime({ offset: true }),
  user_agent: z.string().min(1),
  targets: z.array(ProbeTarget).min(1),
  outcome: ProbeOutcome,
});
export type TrustCenterProbe = z.infer<typeof TrustCenterProbe>;

/** the schemas a fetched document may prove itself against — the three documents a package carries */
export const PROBE_DOCUMENT_SCHEMAS = [PACKAGE_OVERVIEW_SCHEMA, OCR_SCHEMA, SDR_SCHEMA] as const;

/** a redirect into one of these is a login flow, not a document */
const LOGIN_PATH = /(^|\/)(login|log-in|signin|sign-in|sso|auth|oauth2?|saml2?|authorize|session\/new)(\/|\?|#|$)/i;
const LOGIN_HOST =
  /(^|\.)(okta\.com|oktapreview\.com|auth0\.com|login\.microsoftonline\.com|login\.microsoft\.com|accounts\.google\.com|onelogin\.com|pingidentity\.com|pingone\.com|duosecurity\.com)$/i;

/**
 * Click-through markers, each a positive statement a page makes about itself.
 * A bare "Privacy Policy" footer link is on every page on the web and proves
 * nothing, so policy and terms language counts ONLY beside an acceptance
 * control; an NDA, a password field and a "request access" flow count alone.
 */
const ACCEPT_CONTROL =
  /\b(i\s+agree|i\s+accept|accept\s+(and|&)\s+continue|agree\s+(and|&)\s+continue|accept\s+(the\s+)?terms|agree\s+to\s+the|by\s+(clicking|continuing)[^.]{0,80}\b(agree|accept))/i;
const POLICY_LANGUAGE = /\b(terms\s+of\s+(service|use)|privacy\s+policy|acceptable\s+use\s+policy)\b/i;
const ALONE: ReadonlyArray<readonly [RegExp, string, ProbeGate]> = [
  [
    /\bnon[-\s]?disclosure\s+agreement\b|\bsign\s+(an?\s+|the\s+)?nda\b|\bnda\s+(required|must)\b/i,
    "a non-disclosure agreement",
    "click-through",
  ],
  [/<input[^>]+type\s*=\s*["']?password/i, "a password field", "authentication"],
  [/\brequest\s+access\b/i, "a request-access flow", "authentication"],
];

export interface GateMarker {
  gate: ProbeGate;
  reason: string;
}

/** the gate markers a page body carries, each named — empty when none */
export function clickThroughMarkers(body: string): GateMarker[] {
  const found: GateMarker[] = [];
  for (const [re, name, gate] of ALONE) {
    const m = re.exec(body);
    if (m !== null) found.push({ gate, reason: `${name} ("${m[0].trim().slice(0, 60)}")` });
  }
  const accept = ACCEPT_CONTROL.exec(body);
  const policy = POLICY_LANGUAGE.exec(body);
  if (accept !== null && policy !== null) {
    found.push({
      gate: "click-through",
      reason: `acceptance of ${policy[0].toLowerCase()} ("${accept[0].trim().slice(0, 60)}")`,
    });
  }
  return found;
}

/** a redirect's target, when it is a login flow — the reason, or undefined */
export function loginRedirect(from: string, location: string): string | undefined {
  let target: URL;
  try {
    target = new URL(location, from);
  } catch {
    return undefined;
  }
  if (LOGIN_HOST.test(target.hostname)) return `redirected to the identity provider ${target.hostname}`;
  if (LOGIN_PATH.test(target.pathname)) return `redirected into a login flow (${target.pathname})`;
  return undefined;
}

/** what a response is, for the classifier — the fetcher's output, and a test's input */
export interface ProbeResponse {
  hops: ProbeHop[];
  error?: string;
  contentType?: string;
  body?: Buffer;
  truncated?: boolean;
}

/** a document validator: the pinned schema it validates against, or undefined */
export type DocumentValidator = (json: unknown) => string | undefined;

/**
 * Classify one target. Pure: the network is the fetcher's, the verdict is
 * this function's, so every branch is testable without a socket.
 */
export function classifyTarget(
  url: string,
  role: ProbeRole,
  response: ProbeResponse,
  validate: DocumentValidator,
): ProbeTarget {
  const base: Omit<ProbeTarget, "outcome" | "reasons"> = {
    url,
    role,
    hops: response.hops,
    ...(response.error !== undefined ? { error: response.error } : {}),
    ...(response.contentType !== undefined ? { content_type: response.contentType } : {}),
    ...(response.body !== undefined
      ? {
          bytes: response.body.byteLength,
          sha256: createHash("sha256").update(response.body).digest("hex"),
        }
      : {}),
  };

  // a login redirect anywhere in the chain is a gate, whatever came after it
  for (const hop of response.hops) {
    if (hop.location === undefined) continue;
    const login = loginRedirect(hop.url, hop.location);
    if (login !== undefined) {
      return { ...base, outcome: "gated", gate: "authentication", reasons: [login] };
    }
  }

  if (response.error !== undefined) {
    return {
      ...base,
      outcome: "undetermined",
      reasons: [`no response (${response.error}) — a fetch that failed says nothing about a gate`],
    };
  }
  const last = response.hops.at(-1);
  if (last === undefined) {
    return { ...base, outcome: "undetermined", reasons: ["no response was recorded"] };
  }
  if (last.status === 401 || last.status === 403 || last.status === 407) {
    return {
      ...base,
      outcome: "gated",
      gate: "authentication",
      reasons: [`HTTP ${last.status} to an anonymous reader — the server refused before any data`],
    };
  }
  if (last.status >= 300 && last.status < 400) {
    return {
      ...base,
      outcome: "undetermined",
      reasons: [`the redirect chain did not end (HTTP ${last.status} at hop ${response.hops.length})`],
    };
  }
  if (last.status !== 200) {
    return {
      ...base,
      outcome: "undetermined",
      reasons: [
        last.status === 404
          ? "HTTP 404 — nothing is at this URL, which is a missing document, not a gate"
          : `HTTP ${last.status} — neither data nor a refusal`,
      ],
    };
  }

  const body = response.body ?? Buffer.alloc(0);
  const text = body.toString("utf8");
  const markers = clickThroughMarkers(text);
  if (markers.length > 0) {
    // a click-through anywhere on the page is reason 1, whatever else it asks
    const gate: ProbeGate = markers.some((m) => m.gate === "click-through")
      ? "click-through"
      : "authentication";
    return {
      ...base,
      outcome: "gated",
      gate,
      reasons: markers.map((m) => `the page asks for ${m.reason}`),
    };
  }

  if (role === "trust-center") {
    return {
      ...base,
      outcome: "undetermined",
      reasons: [
        "the page loaded and carries no gate marker a fetch can see — which proves a page loaded, not that the data behind it is ungated; a script-rendered click-through is invisible here. Name a certification document with --document to prove the data itself",
      ],
    };
  }
  if (response.truncated === true) {
    return {
      ...base,
      outcome: "undetermined",
      reasons: ["the body exceeded the probe's cap and was not read whole, so it was not validated"],
    };
  }

  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    return {
      ...base,
      outcome: "undetermined",
      reasons: [
        `HTTP 200, but the body is not JSON (${response.contentType ?? "no content type"}) — a machine-readable certification document is what proves the data is reachable`,
      ],
    };
  }
  const schema = validate(json);
  if (schema === undefined) {
    return {
      ...base,
      outcome: "undetermined",
      reasons: [
        "HTTP 200 and JSON, but it validates against none of the pinned FedRAMP document schemas — an error body served with a 200 is not certification data",
      ],
    };
  }
  return {
    ...base,
    schema,
    outcome: "open",
    reasons: [`an anonymous GET returned a document that validates against ${schema}`],
  };
}

/** the probe's overall reading: any gate gates; open needs a proven document */
export function probeOutcome(targets: readonly ProbeTarget[]): ProbeOutcome {
  if (targets.some((t) => t.outcome === "gated")) return "gated";
  if (targets.some((t) => t.role === "document" && t.outcome === "open")) return "open";
  return "undetermined";
}

export interface FetchOptions {
  userAgent: string;
  /** per request, milliseconds */
  timeoutMs?: number;
  maxRedirects?: number;
  /** bytes read of a body before it is cut and marked truncated */
  maxBytes?: number;
  fetchImpl?: typeof fetch;
}

/**
 * GET one URL anonymously, following redirects BY HAND so every hop is on
 * the record. No cookie jar: a gate that a first visit sets a cookie for and
 * a second visit honours is still a gate to the reviewer's first visit.
 */
export async function fetchTarget(url: string, options: FetchOptions): Promise<ProbeResponse> {
  const doFetch = options.fetchImpl ?? fetch;
  const maxRedirects = options.maxRedirects ?? 10;
  const maxBytes = options.maxBytes ?? 5 * 1024 * 1024;
  const hops: ProbeHop[] = [];
  let current = url;
  for (let i = 0; i <= maxRedirects; i++) {
    let res: Response;
    try {
      res = await doFetch(current, {
        method: "GET",
        redirect: "manual",
        headers: { "user-agent": options.userAgent, accept: "application/json, text/html;q=0.9, */*;q=0.1" },
        signal: AbortSignal.timeout(options.timeoutMs ?? 15_000),
      });
    } catch (err) {
      return { hops, error: (err as Error).message };
    }
    const location = res.headers.get("location") ?? undefined;
    hops.push({ url: current, status: res.status, ...(location !== undefined ? { location } : {}) });
    if (res.status >= 300 && res.status < 400 && location !== undefined) {
      await res.body?.cancel();
      current = new URL(location, current).toString();
      continue;
    }
    const contentType = res.headers.get("content-type") ?? undefined;
    const chunks: Buffer[] = [];
    let total = 0;
    let truncated = false;
    if (res.body !== null) {
      const reader = res.body.getReader();
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        total += value.byteLength;
        if (total > maxBytes) {
          truncated = true;
          await reader.cancel();
          break;
        }
        chunks.push(Buffer.from(value));
      }
    }
    return {
      hops,
      ...(contentType !== undefined ? { contentType } : {}),
      body: Buffer.concat(chunks),
      ...(truncated ? { truncated } : {}),
    };
  }
  return { hops, error: `more than ${maxRedirects} redirects` };
}

/** a validator over the pinned document schemas, loaded once */
export async function pinnedDocumentValidator(repoRoot: string): Promise<DocumentValidator> {
  const loaded = await Promise.all(PROBE_DOCUMENT_SCHEMAS.map((s) => loadPinnedSchema(repoRoot, s)));
  return (json) => loaded.find((l) => validateAgainst(l, json).length === 0)?.filename;
}

export interface ProbeInput {
  trustCenter: string;
  documents: readonly string[];
  validate: DocumentValidator;
  fetch: FetchOptions;
  now?: Date;
}

/** probe the trust center and every named document, and read the whole */
export async function probeTrustCenter(input: ProbeInput): Promise<TrustCenterProbe> {
  const plan: Array<[string, ProbeRole]> = [
    [input.trustCenter, "trust-center"],
    ...input.documents.map((d): [string, ProbeRole] => [d, "document"]),
  ];
  const targets: ProbeTarget[] = [];
  for (const [url, role] of plan) {
    targets.push(classifyTarget(url, role, await fetchTarget(url, input.fetch), input.validate));
  }
  return {
    _type: TRUST_CENTER_PROBE_TYPE,
    trust_center: input.trustCenter,
    probed_at: (input.now ?? new Date()).toISOString(),
    user_agent: input.fetch.userAgent,
    targets,
    outcome: probeOutcome(targets),
  };
}

/**
 * Read a probe transcript for `rampscan submission`. The overall outcome is
 * RECOMPUTED from the targets and a disagreement refused: a hand-edited
 * `"outcome": "open"` over a gated target is the stamp-disagreement case
 * `fedramp-conformance.ts` refuses for documents, and for the same reason.
 */
export async function loadTrustCenterProbe(path: string): Promise<TrustCenterProbe> {
  let raw: unknown;
  try {
    raw = JSON.parse(await readFile(path, "utf8"));
  } catch (err) {
    throw new Error(`${path}: not a readable probe transcript (${(err as Error).message})`);
  }
  const parsed = TrustCenterProbe.safeParse(raw);
  if (!parsed.success) {
    throw new Error(`${path}: does not match the trust-center probe transcript (${parsed.error.issues[0]?.message ?? "invalid"})`);
  }
  const recomputed = probeOutcome(parsed.data.targets);
  if (recomputed !== parsed.data.outcome) {
    throw new Error(
      `${path}: states outcome "${parsed.data.outcome}" but its own targets read "${recomputed}" — a transcript whose summary disagrees with its evidence is refused, not believed`,
    );
  }
  for (const t of parsed.data.targets) {
    if ((t.outcome === "gated") !== (t.gate !== undefined)) {
      throw new Error(`${path}: ${t.url} — a gated target names its gate, and only a gated one does`);
    }
    if (t.outcome === "open" && (t.role !== "document" || t.schema === undefined || t.sha256 === undefined)) {
      throw new Error(
        `${path}: ${t.url} reads open without a validated document's schema and digest — only a certification document proven by its bytes can be open`,
      );
    }
  }
  return parsed.data;
}
