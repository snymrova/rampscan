import { execFileSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");

function doctor(): { out: string; status: number } {
  try {
    return { out: execFileSync("node", [join(root, "scripts/doctor.mjs")], { encoding: "utf8" }), status: 0 };
  } catch (e) {
    const err = e as { stdout?: string; status?: number };
    return { out: err.stdout ?? "", status: err.status ?? 1 };
  }
}

describe("the doctor's model row (L4a)", () => {
  const { out } = doctor();
  const row = out.split("\n").find((l) => l.includes("ollama"));

  it("reports the runtime at all", () => {
    expect(row).toBeDefined();
  });

  it("carries exactly one of the port's three states, in doctor's vocabulary", () => {
    // ready → ok · unprovisioned → no-model · absent → absent. Whichever this
    // machine is in, it must be one of them and not something invented.
    const states = ["ok", "no-model", "absent"].filter((s) => row?.trimStart().startsWith(s));
    expect(states).toHaveLength(1);
  });

  it("NEVER reads MISSING — an absent model must not read as a broken scan", () => {
    // MISSING is the word that counts toward doctor's failure total. The model
    // has no standing in the evidence path, so its absence changes nothing
    // about a scan, and a doctor that failed over it would say otherwise.
    expect(row).not.toContain("MISSING");
  });

  it("says the drafting model is optional wherever it is not ready", () => {
    if (row?.trimStart().startsWith("ok")) {
      expect(row).toContain("nothing signed");
    } else {
      expect(row).toMatch(/optional/);
    }
  });
});
