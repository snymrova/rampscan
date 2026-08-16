import { describe, expect, it } from "vitest";
import type { ModelResolution } from "@rampscan/core";
import {
  FakeModelRunner,
  OllamaRunner,
  absentRunner,
  allPrompts,
  loadModelManifest,
  renderContext,
  systemPrompt,
  unprovisionedRunner,
} from "../src/index.js";

// L4a. CI has no model runtime, so the tests that matter here are the ABSENCE
// tests and the guard tests — the present path is exercised by a manual smoke
// (see the plan's D6). Nothing below asserts bytes out of a live runtime.

describe("resolution states", () => {
  it("distinguishes absent from unprovisioned — the operator's fix differs", async () => {
    const absent = await absentRunner().resolve();
    const unprovisioned = await unprovisionedRunner().resolve();
    expect(absent.state).toBe("absent");
    expect(unprovisioned.state).toBe("unprovisioned");
    // The whole point of the third state: one of these says install, the other
    // says provision. Collapsing them would send an operator to install
    // software they already have running.
    expect(absent.state).not.toBe(unprovisioned.state);
  });

  it("every non-ready state carries a reason — I15, structurally", async () => {
    for (const runner of [absentRunner(), unprovisionedRunner()]) {
      const r = await runner.resolve();
      expect(r.state).not.toBe("ready");
      const reason = (r as Extract<ModelResolution, { reason: string }>).reason;
      expect(reason.length).toBeGreaterThan(0);
    }
  });

  it("draft() throws rather than returning empty text when not ready", async () => {
    for (const runner of [absentRunner(), unprovisionedRunner()]) {
      await expect(runner.draft({ task: "scoping-justification", context: {} })).rejects.toThrow(/not ready/);
    }
  });

  it("the real adapter reports absent — not a crash — when no daemon answers", async () => {
    const runner = new OllamaRunner({
      runtime: "ollama",
      // a port nothing is listening on: the honest-absence path, run for real
      endpoint: "http://127.0.0.1:1",
      model: "unused",
    });
    const r = await runner.resolve();
    expect(r.state).toBe("absent");
    expect((r as { reason: string }).reason).toContain("127.0.0.1:1");
  });
});

describe("the pinned manifest", () => {
  it("pins a runtime, an endpoint and a model, and the endpoint is loopback", async () => {
    const m = await loadModelManifest();
    expect(m.runtime).toBe("ollama");
    expect(m.model.length).toBeGreaterThan(0);
    // I8: the shipped default must not reach off-box. OLLAMA_HOST can override
    // it, which is the operator's explicit choice and is reported by resolve().
    expect(m.endpoint).toMatch(/^http:\/\/(127\.0\.0\.1|localhost):/);
  });
});

describe("prompt guard (I1, the plain.test.ts posture applied to instructions)", () => {
  // Authored instructions may describe the writing task. They may not put a
  // verdict word, a state word or a digit in front of the model, because a
  // prompt that names a verdict is one paraphrase away from asking for one.
  const BANNED = /\b(violated|evidenced|unevidenced|passing|failing|compliant|non-compliant|verdict|finding)s?\b/i;

  it("no prompt states a verdict or a repository fact", () => {
    for (const p of allPrompts()) {
      expect(p).not.toMatch(BANNED);
      expect(p).not.toMatch(/\d/);
    }
  });

  it("the ban is phrased without planting the vocabulary it bans", () => {
    // If a future edit rewrites the prohibition as a word list, the assertion
    // above goes red — this test records WHY, so the fix is to rephrase the
    // instruction rather than to loosen the grep.
    expect(systemPrompt("scoping-justification")).toMatch(/do not characterise the outcome/i);
  });

  it("instructs the model to stop rather than invent when context is thin", () => {
    // \s+ not a space: the prompt is line-joined, so the wrap moves as the
    // text is edited and a space-literal test would break on rewording alone.
    expect(systemPrompt("scoping-justification")).toMatch(/cannot\s+safely edit an invented one/i);
  });
});

describe("context rendering", () => {
  it("is key-order independent — the same circumstances build the same bytes", () => {
    const a = renderContext({ task: "scoping-justification", context: { repo: "r", recipe: "x" } });
    const b = renderContext({ task: "scoping-justification", context: { recipe: "x", repo: "r" } });
    expect(a).toBe(b);
  });

  it("says so when there are no circumstances, rather than sending an empty turn", () => {
    expect(renderContext({ task: "scoping-justification", context: {} })).toContain("no circumstances");
  });
});

describe("the exported double (D4)", () => {
  it("is byte-stable across runs — the only determinism this suite claims", async () => {
    const runner = new FakeModelRunner();
    const first = await runner.draft({ task: "scoping-justification", context: { repo: "r" } });
    const second = await runner.draft({ task: "scoping-justification", context: { repo: "r" } });
    expect(JSON.stringify(first)).toBe(JSON.stringify(second));
  });

  it("drives the REAL prompt module, so a broken prompt breaks the double too", async () => {
    const runner = new FakeModelRunner();
    await runner.draft({ task: "scoping-justification", context: { repo: "acme/app" } });
    expect(runner.lastPrompt?.system).toBe(systemPrompt("scoping-justification"));
    expect(runner.lastPrompt?.user).toContain("acme/app");
  });

  it("relays a weights digest it never verified, and the field name says so", async () => {
    const draft = await new FakeModelRunner().draft({ task: "scoping-justification", context: {} });
    expect(draft).toHaveProperty("weightsDigest");
    // Not `weights_sha256`: rampscan cannot read the daemon's blob store, so a
    // name implying a checked hash would overstate what this value is.
    expect(draft).not.toHaveProperty("weights_sha256");
  });
});
