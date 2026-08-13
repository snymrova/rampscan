import { describe, expect, it } from "vitest";
import {
  createLocalLedger,
  createLocalRepoSource,
  createLocalRunner,
  createLocalScheduler,
  createLocalSigner,
  createProjector,
} from "../src/index.js";

// M0 only asserts the ports exist and the stubs fail loudly rather than
// silently succeeding — a stub that returns fake data is worse than none.

describe("local adapter stubs", () => {
  it("every stubbed port rejects with its landing milestone", async () => {
    const ledger = createLocalLedger("/tmp/nowhere");
    await expect(ledger.list()).rejects.toThrow(/M2/);

    const signer = createLocalSigner("/tmp/nokey");
    await expect(signer.verify({ payload: "", payloadType: "", signatures: [] })).rejects.toThrow(/M2/);

    await expect(
      createLocalRunner().run(
        { name: "repo-facts", toolVersion: "0", recipes: [] },
        { root: "/tmp", repo: "x", commit: "0".repeat(40) },
      ),
    ).rejects.toThrow(/M1/);

    await expect(
      createLocalScheduler().ensureCadence("b", { repo: "x" }),
    ).rejects.toThrow(/M5/);

    await expect(createLocalRepoSource().fetch({ repo: "x" })).rejects.toThrow(/M1/);

    await expect(createProjector().fold(ledger)).rejects.toThrow(/M2/);
  });
});
