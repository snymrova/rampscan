import type { Draft, DraftRequest, ModelResolution, ModelRunner } from "@rampscan/core";
import { renderContext, systemPrompt } from "./prompts.js";

/**
 * The port's own test double (plan L4a, decision D4) — shipped beside the
 * adapter rather than invented inside each test file, and the reason is not
 * tidiness: CI has no model, so the canned response is the ONLY path CI ever
 * walks. A mock written in a test would make byte-stability a property of that
 * test; here it is a property of the port, and every caller's absence handling
 * is exercised against the same three states the real adapter can return.
 *
 * It runs the REAL prompt module, so a prompt that stops rendering breaks the
 * double too — a double that skipped the prompts would pass while the thing it
 * stands in for was broken.
 */
export class FakeModelRunner implements ModelRunner {
  /** What the last draft() was actually asked, for tests that assert the ask. */
  lastPrompt?: { system: string; user: string };

  constructor(
    private readonly resolution: ModelResolution = {
      state: "ready",
      runtime: "fake",
      runtimeVersion: "0.0.0",
      model: "fake-model",
      weightsDigest: "sha256:fake",
    },
    private readonly response = "Canned draft.",
  ) {}

  async resolve(): Promise<ModelResolution> {
    return this.resolution;
  }

  async draft(request: DraftRequest): Promise<Draft> {
    if (this.resolution.state !== "ready") {
      throw new Error(`model runner is not ready (${this.resolution.state}); draft() must not be called`);
    }
    this.lastPrompt = { system: systemPrompt(request.task), user: renderContext(request) };
    return {
      text: this.response,
      model: this.resolution.model,
      weightsDigest: this.resolution.weightsDigest,
      costTokens: 0,
    };
  }
}

/** A runner with no runtime — the state CI is always in. */
export const absentRunner = (reason = "no fake runtime answered"): FakeModelRunner =>
  new FakeModelRunner({ state: "absent", reason });

/** A runner whose daemon is up and whose pinned weights are missing. */
export const unprovisionedRunner = (reason = "the pinned model is not on this machine"): FakeModelRunner =>
  new FakeModelRunner({ state: "unprovisioned", runtime: "fake", runtimeVersion: "0.0.0", reason });
