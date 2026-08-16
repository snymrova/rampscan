import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { Draft, DraftRequest, ModelResolution, ModelRunner } from "@rampscan/core";
import { renderContext, systemPrompt } from "./prompts.js";

export interface ModelManifest {
  runtime: string;
  endpoint: string;
  model: string;
}

let manifestCache: Promise<ModelManifest> | undefined;

/** path via dirname(fileURLToPath(…)) — the `tools.ts` precedent, same reason. */
export function loadModelManifest(): Promise<ModelManifest> {
  manifestCache ??= readFile(join(dirname(fileURLToPath(import.meta.url)), "..", "models.json"), "utf8").then(
    (raw) => JSON.parse(raw) as ModelManifest,
  );
  return manifestCache;
}

/** Every request is bounded: a stalled daemon must not hang a scan or a page. */
const PROBE_TIMEOUT_MS = 2_000;
const DRAFT_TIMEOUT_MS = 120_000;

async function req(url: string, timeoutMs: number, body?: unknown): Promise<Response> {
  const signal = AbortSignal.timeout(timeoutMs);
  return body === undefined
    ? await fetch(url, { signal })
    : await fetch(url, {
        signal,
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
      });
}

/**
 * The reference adapter (plan L4a, work item 1). The endpoint is loopback by
 * default and OLLAMA_HOST overrides it, which is the one way this port can
 * reach off-box — an operator who sets it has chosen that, and `resolve()`
 * reports the endpoint it used so the choice is visible rather than assumed.
 *
 * This adapter NEVER calls /api/pull. Absent weights resolve to
 * "unprovisioned" with the pull command in the reason, so the download is the
 * operator's action on their own machine and never a side effect of a scan.
 */
export class OllamaRunner implements ModelRunner {
  constructor(private readonly manifest?: ModelManifest) {}

  private async config(): Promise<ModelManifest> {
    const m = this.manifest ?? (await loadModelManifest());
    return { ...m, endpoint: process.env.OLLAMA_HOST ?? m.endpoint };
  }

  async resolve(): Promise<ModelResolution> {
    const { endpoint, model, runtime } = await this.config();

    let runtimeVersion: string;
    try {
      const res = await req(`${endpoint}/api/version`, PROBE_TIMEOUT_MS);
      if (!res.ok) return { state: "absent", reason: `${runtime} at ${endpoint} answered HTTP ${res.status}` };
      runtimeVersion = ((await res.json()) as { version?: string }).version ?? "unknown";
    } catch {
      // Not answering covers every way a daemon can be unavailable — stopped,
      // never installed, listening elsewhere. The reason names the endpoint
      // rather than guessing which, because guessing wrong sends the operator
      // to install software they already have.
      return { state: "absent", reason: `no ${runtime} runtime answered at ${endpoint}` };
    }

    try {
      const res = await req(`${endpoint}/api/show`, PROBE_TIMEOUT_MS, { name: model });
      if (!res.ok) {
        return {
          state: "unprovisioned",
          runtime,
          runtimeVersion,
          reason: `${runtime} is running but the pinned model ${model} is not on this machine — \`${runtime} pull ${model}\` provisions it`,
        };
      }
      const shown = (await res.json()) as { digest?: string; model_info?: Record<string, unknown> };
      return {
        state: "ready",
        runtime,
        runtimeVersion,
        model,
        // Relayed, not verified — see the Draft.weightsDigest comment.
        weightsDigest: shown.digest ?? "unreported",
      };
    } catch {
      return {
        state: "unprovisioned",
        runtime,
        runtimeVersion,
        reason: `${runtime} is running but did not report the pinned model ${model}`,
      };
    }
  }

  async draft(request: DraftRequest): Promise<Draft> {
    const resolution = await this.resolve();
    if (resolution.state !== "ready") {
      // Callers ask resolve() first and render the absence; reaching here is a
      // programming error, so it reads as one rather than as an empty draft.
      throw new Error(`model runner is not ready (${resolution.state}); draft() must not be called`);
    }

    const { endpoint, model } = await this.config();
    const res = await req(`${endpoint}/api/generate`, DRAFT_TIMEOUT_MS, {
      model,
      system: systemPrompt(request.task),
      prompt: renderContext(request),
      stream: false,
      // Temperature 0 fixes the SELECTION RULE, not the logits — identical
      // bytes run to run are not promised by this and no test asserts them
      // against a live runtime. It is set because an advisory draft should be
      // the model's least surprising answer, not because it makes it stable.
      options: { temperature: 0, seed: 0 },
    });
    if (!res.ok) throw new Error(`${model} draft failed: HTTP ${res.status}`);

    const body = (await res.json()) as { response?: string; eval_count?: number };
    return {
      text: (body.response ?? "").trim(),
      model,
      weightsDigest: resolution.weightsDigest,
      // Omitted rather than set to undefined (exactOptionalPropertyTypes): a
      // runtime that reports no token count and one that reports zero are
      // different facts, and the absent key is how the first one reads.
      ...(body.eval_count === undefined ? {} : { costTokens: body.eval_count }),
    };
  }
}
