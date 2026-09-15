// The cloud-run lifecycle as the Runs page shows it (docs/PLAN-CLOUD-RUNNER.md
// T4-3): `requested → claimed → submitted → accepted | refused(reason) |
// failed(class)`, with `expired` read from the clock. Folded from the
// ledger by the appliance (`runsLifecycleAt`); this module only says how a
// row reads — a failed run is a row with its class, never an absence.

export type CloudRunState = "requested" | "claimed" | "submitted" | "accepted" | "refused" | "failed" | "expired";

export interface CloudRunRow {
  nonce: string;
  recipe_id: string;
  ksi: string;
  requester: string;
  issued_at: string;
  expires_at: string;
  state: CloudRunState;
  runner?: string;
  reason?: string;
  class?: string;
  evidence_digest?: string;
  request_event_digest: string;
  updated_at: string;
}

/** the pill class a state renders with: the register's own three, so a run reads like evidence does */
export function cloudRunPill(state: CloudRunState): "evidenced" | "violated" | "unevidenced" {
  switch (state) {
    case "accepted":
      return "evidenced";
    case "refused":
    case "failed":
      return "violated";
    default:
      return "unevidenced";
  }
}

/** one line per row: what happened, in the words the state deserves */
export function describeCloudRun(row: CloudRunRow): string {
  switch (row.state) {
    case "requested":
      return `waiting for a runner (expires ${row.expires_at})`;
    case "claimed":
      return `claimed by ${row.runner ?? "a runner"}, running`;
    case "submitted":
      return `transcript received from ${row.runner ?? "a runner"}, being judged`;
    case "accepted":
      return `accepted from ${row.runner ?? "a runner"} — evidence ${row.evidence_digest?.slice(0, 12) ?? "?"}…`;
    case "refused":
      return `refused${row.runner ? ` (${row.runner})` : ""}: ${row.reason ?? "no reason recorded"}`;
    case "failed":
      return `failed (${row.class ?? "error"})${row.runner ? ` by ${row.runner}` : ""}: ${row.reason ?? "the account was not seen"}`;
    case "expired":
      return `expired ${row.expires_at} with no runner claiming it`;
  }
}

/** newest first, so the run the operator just clicked is at the top */
export function sortCloudRuns(rows: readonly CloudRunRow[]): CloudRunRow[] {
  return [...rows].sort((a, b) => (a.issued_at < b.issued_at ? 1 : a.issued_at > b.issued_at ? -1 : 0));
}
