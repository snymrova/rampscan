import { describe, expect, it } from "vitest";
import { cloudRunPill, describeCloudRun, sortCloudRuns } from "../lib/cloud-runs";
import type { CloudRunRow } from "../lib/cloud-runs";

// T4-3: how a cloud run reads — the console's floor over the pure half.

const base: CloudRunRow = {
  nonce: "5f2c9a1e7b3d4c6a8e0f1a2b3c4d5e6f",
  recipe_id: "iam-credential-report",
  ksi: "KSI-IAM-APM",
  requester: "operator@example.test",
  issued_at: "2026-09-16T10:00:00Z",
  expires_at: "2026-09-16T11:00:00Z",
  state: "requested",
  request_event_digest: "a".repeat(64),
  updated_at: "2026-09-16T10:00:00Z",
};

describe("cloud runs (T4-3)", () => {
  it("a failed run is a row with its class, a refusal a row with its reason, an acceptance a link to the evidence", () => {
    expect(describeCloudRun({ ...base, state: "failed", class: "denied", runner: "sidecar-1", reason: "step 2 exited 254 with stderr access-denied" })).toBe(
      "failed (denied) by sidecar-1: step 2 exited 254 with stderr access-denied",
    );
    expect(describeCloudRun({ ...base, state: "refused", reason: "nonce was already accepted" })).toBe("refused: nonce was already accepted");
    expect(describeCloudRun({ ...base, state: "accepted", runner: "once-5f2c9a1e", evidence_digest: "b".repeat(64) })).toBe("accepted from once-5f2c9a1e — evidence bbbbbbbbbbbb…");
    expect(describeCloudRun({ ...base, state: "expired" })).toMatch(/expired .* with no runner claiming it/);
  });

  it("pills borrow the register's three so a run reads like evidence: accepted evidenced, failed/refused violated, the rest pending", () => {
    expect(cloudRunPill("accepted")).toBe("evidenced");
    expect(cloudRunPill("failed")).toBe("violated");
    expect(cloudRunPill("refused")).toBe("violated");
    for (const s of ["requested", "claimed", "submitted", "expired"] as const) expect(cloudRunPill(s)).toBe("unevidenced");
  });

  it("sorts newest first", () => {
    const rows = sortCloudRuns([base, { ...base, nonce: "b".repeat(32), issued_at: "2026-09-16T12:00:00Z" }]);
    expect(rows.map((r) => r.issued_at)).toEqual(["2026-09-16T12:00:00Z", "2026-09-16T10:00:00Z"]);
  });
});
