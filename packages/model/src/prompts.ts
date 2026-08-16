import type { DraftRequest, DraftTask } from "@rampscan/core";

// Drafting prompts live in ONE module so a test can walk every word this
// system ever puts in front of a model — the `plain.test.ts` posture, applied
// to instructions instead of catalog prose.
//
// These strings are held to the same rule as the catalog's `plain` triple:
// they describe the WRITING TASK and state nothing about any repository. Note
// how the prohibitions are phrased — "do not characterise the outcome" rather
// than a list of the words that would characterise it. Naming the forbidden
// vocabulary would plant that vocabulary in the prompt, and the grep that
// polices this file cannot tell a ban from a use. A prohibition that fails its
// own test is a prohibition that gets deleted the first time CI goes red.

const SCOPING_JUSTIFICATION = [
  "You draft a first sentence or two for a compliance operator, who will edit",
  "your text and is the person accountable for what it finally says.",
  "",
  "Write only from the circumstances listed below. Do not describe the state of",
  "any codebase, do not characterise the outcome of any check, and do not",
  "quantify anything. If the circumstances do not support a reason, say that",
  "plainly and stop — an operator can edit a short honest note and cannot",
  "safely edit an invented one.",
  "",
  "Write prose, no lists, no headings, no preamble about what you are doing.",
].join("\n");

const SYSTEM: Record<DraftTask, string> = {
  "scoping-justification": SCOPING_JUSTIFICATION,
};

/** The system instruction for a task — exported so the guard test can read it. */
export function systemPrompt(task: DraftTask): string {
  return SYSTEM[task];
}

/** Every prompt this system can send, for the guard test to walk. */
export function allPrompts(): string[] {
  return Object.values(SYSTEM);
}

/**
 * The user turn: the caller's context, rendered. Keys are sorted so the same
 * context builds the same bytes — a drafting request is not evidence, but a
 * request that reordered itself run to run would make even the canned-response
 * test unstable for a reason that has nothing to do with the model.
 */
export function renderContext(req: DraftRequest): string {
  const lines = Object.keys(req.context)
    .sort()
    .map((k) => `${k}: ${req.context[k]}`);
  return lines.length > 0 ? lines.join("\n") : "(no circumstances were provided)";
}
