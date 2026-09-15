import { describe, expect, it } from "vitest";
import { controlFamily, ksiTheme } from "../lib/types";

// The two derivations `lib/types.ts` holds beside its record shapes (S4-3).
// Both group the board — by KSI theme and by control family — so a wrong
// split puts a row under the wrong heading with no other symptom.

describe("ksiTheme", () => {
  it("is the middle segment of a 2026 KSI id", () => {
    expect(ksiTheme("KSI-SVC-CLS")).toBe("SVC");
    expect(ksiTheme("KSI-CNA-RNT")).toBe("CNA");
  });
  it("is the second segment of a Phase One id, and the id itself when there is no segment", () => {
    expect(ksiTheme("CNA-01")).toBe("01");
    expect(ksiTheme("orphan")).toBe("orphan");
  });
});

describe("controlFamily", () => {
  it("is the leading alpha token, lower-cased", () => {
    expect(controlFamily("si-7.1")).toBe("si");
    expect(controlFamily("AC-2(6)")).toBe("ac");
    expect(controlFamily("sr-11.2")).toBe("sr");
  });
  it("returns the id unchanged when it has no leading letters", () => {
    expect(controlFamily("7.1")).toBe("7.1");
    expect(controlFamily("")).toBe("");
  });
});
